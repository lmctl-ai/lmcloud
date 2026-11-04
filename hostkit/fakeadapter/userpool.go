// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

type poolUserState struct {
	UID                  string            `json:"uid"`
	Username             string            `json:"username"`
	Enabled              bool              `json:"enabled"`
	Status               string            `json:"status"`
	Attrs                map[string]string `json:"attrs,omitempty"`
	CreatedAt            int64             `json:"created_at"`
	PasswordSaltHex      string            `json:"password_salt_hex,omitempty"`
	PasswordDerivedHex   string            `json:"password_derived_hex,omitempty"`
	HasPermanentPassword bool              `json:"has_permanent_password,omitempty"`
	SessionGen           uint64            `json:"session_gen"`
	OwnerToken           string            `json:"owner_token,omitempty"`
	ChildSeq             uint64            `json:"child_seq,omitempty"`
}

func (u *poolUserState) toSnapshot() hostkit.UserSnapshot {
	if u == nil {
		return hostkit.UserSnapshot{}
	}
	attrs := make(map[string]string, len(u.Attrs))
	for k, v := range u.Attrs {
		attrs[k] = v
	}
	status := u.Status
	if status == "" {
		status = hostkit.UserStatusForceChangePassword
	}
	sgen := u.SessionGen
	if sgen == 0 {
		sgen = 1
	}
	createdAt := u.CreatedAt
	if createdAt <= 0 {
		createdAt = 1
	}
	return hostkit.UserSnapshot{
		Exists:     true,
		Username:   u.Username,
		Sub:        u.UID,
		Enabled:    u.Enabled,
		Status:     status,
		Attributes: attrs,
		CreatedAt:  createdAt,
		SessionGen: sgen,
		OwnerToken: u.OwnerToken,
		ChildSeq:   u.ChildSeq,
	}
}

type poolGroupState struct {
	GID        string `json:"gid"`
	Name       string `json:"name"`
	OwnerToken string `json:"owner_token,omitempty"`
}

type userpoolState struct {
	Name          string                     `json:"name"`
	PoolID        string                     `json:"pool_id"`
	ClientID      string                     `json:"client_id"`
	Issuer        string                     `json:"issuer"`
	IncarnationID string                     `json:"incarnation_id"`
	OwnerToken    string                     `json:"owner_token"`
	MaxGeneration uint64                     `json:"max_generation"`
	ChildSeq      uint64                     `json:"child_seq"`
	NextUserSeq   int64                      `json:"next_user_seq"`
	NextGroupSeq  int64                      `json:"next_group_seq"`
	KeyID         string                     `json:"key_id"`
	PrivateKeyPEM string                     `json:"private_key_pem"`
	PublicKeyPEM  string                     `json:"public_key_pem"`
	RotatedKeys   map[string]string          `json:"rotated_keys,omitempty"`
	Users         map[string]*poolUserState  `json:"users,omitempty"`
	Groups        map[string]*poolGroupState `json:"groups,omitempty"`
	Memberships   map[string]map[string]bool `json:"memberships,omitempty"`
	ForeignUsers  map[string]bool            `json:"foreign_users,omitempty"`
	ForeignGroups map[string]bool            `json:"foreign_groups,omitempty"`
	ReverseOrder  bool                       `json:"reverse_order,omitempty"`
}

func ensureUserpoolMaps(up *userpoolState) {
	if up.RotatedKeys == nil {
		up.RotatedKeys = map[string]string{}
	}
	if up.Users == nil {
		up.Users = map[string]*poolUserState{}
	}
	if up.Groups == nil {
		up.Groups = map[string]*poolGroupState{}
	}
	if up.Memberships == nil {
		up.Memberships = map[string]map[string]bool{}
	}
	if up.ForeignUsers == nil {
		up.ForeignUsers = map[string]bool{}
	}
	if up.ForeignGroups == nil {
		up.ForeignGroups = map[string]bool{}
	}
}

func compactUserMap(m map[string]*poolUserState) map[string]*poolUserState {
	out := make(map[string]*poolUserState, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func compactGroupMap(m map[string]*poolGroupState) map[string]*poolGroupState {
	out := make(map[string]*poolGroupState, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func compactMembershipMap(m map[string]map[string]bool) map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(m))
	for g, members := range m {
		if len(members) == 0 {
			continue
		}
		gm := make(map[string]bool, len(members))
		for u, ok := range members {
			if ok {
				gm[u] = true
			}
		}
		if len(gm) > 0 {
			out[g] = gm
		}
	}
	return out
}

func compactUserpoolMap(m map[string]*userpoolState) map[string]*userpoolState {
	out := make(map[string]*userpoolState, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (up *userpoolState) toInfo() hostkit.UserpoolInfo {
	if up == nil {
		return hostkit.UserpoolInfo{}
	}
	var rot map[string]string
	if len(up.RotatedKeys) > 0 {
		rot = make(map[string]string, len(up.RotatedKeys))
		for k, v := range up.RotatedKeys {
			rot[k] = v
		}
	}
	return hostkit.UserpoolInfo{
		Name:          up.Name,
		PoolID:        up.PoolID,
		IncarnationID: up.IncarnationID,
		OwnerToken:    up.OwnerToken,
		Generation:    up.MaxGeneration,
		PublicKeyPEM:  up.PublicKeyPEM,
		KeyID:         up.KeyID,
		RotatedKeys:   rot,
		Issuer:        up.Issuer,
		ClientID:      up.ClientID,
		ChildSeq:      up.ChildSeq,
	}
}

func verifyUserpoolWriteFence(ctx context.Context, up *userpoolState, name, expOwner, expInc string, gen uint64) error {
	fence := hostkit.UserpoolMutationFenceFrom(ctx)
	if expOwner == "" {
		expOwner = fence.OwnerToken
	}
	if expOwner == "" {
		expOwner = hostkit.CreateToken(ctx)
	}
	if expInc == "" {
		expInc = fence.IncarnationID
	}
	if gen == 0 {
		gen = fence.Generation
	}
	if !validOwnerToken(up.OwnerToken) || !validOwnerToken(expOwner) || up.OwnerToken != expOwner {
		return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
			fmt.Sprintf("userpool %q owner token mismatch", name))
	}
	if expInc != "" && up.IncarnationID != "" && up.IncarnationID != expInc {
		return hostkit.ProviderError(hostkit.Conflict, 409, "StaleIncarnation",
			fmt.Sprintf("userpool %q incarnation mismatch: got %q, want %q", name, up.IncarnationID, expInc))
	}
	if gen > 0 && gen < up.MaxGeneration {
		return hostkit.ProviderError(hostkit.Conflict, 409, "StaleGeneration",
			fmt.Sprintf("stale generation %d < %d for userpool %q", gen, up.MaxGeneration, name))
	}
	return nil
}

func (f *Fake) maybeFaultUserpool(op string) error {
	f.mu.Lock()
	fault := f.opts.FaultUserpoolMutatorAfterCommit
	f.mu.Unlock()
	if fault != nil {
		return fault(op)
	}
	return nil
}

// SetFaultUserpoolMutatorAfterCommitForTesting configures a post-commit fault callback on userpool mutators.
func (f *Fake) SetFaultUserpoolMutatorAfterCommitForTesting(fn func(op string) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts.FaultUserpoolMutatorAfterCommit = fn
}

// InjectUnmarkedUserpoolForTesting inserts a userpool with the given ownerToken directly into state.
func (f *Fake) InjectUnmarkedUserpoolForTesting(name, ownerToken string) error {
	return f.doSilent(true, func(s *state) error {
		if s.Userpools == nil {
			s.Userpools = map[string]*userpoolState{}
		}
		inc := randomHex16()
		privPEM, pubPEM, kid, err := hostkit.GeneratePoolRSAKeyPair()
		if err != nil {
			return err
		}
		poolID := fmt.Sprintf("lmpool-%s-%s", name, inc[:8])
		up := &userpoolState{
			Name:          name,
			PoolID:        poolID,
			ClientID:      fmt.Sprintf("lmclient-%s-%s", name, inc[:8]),
			Issuer:        fmt.Sprintf("https://userpool.lmcloud.local/%s", poolID),
			IncarnationID: inc,
			OwnerToken:    ownerToken,
			MaxGeneration: 1,
			KeyID:         kid,
			PrivateKeyPEM: privPEM,
			PublicKeyPEM:  pubPEM,
		}
		ensureUserpoolMaps(up)
		s.Userpools[name] = up
		return nil
	})
}

// InjectForeignPoolChildForTesting injects a foreign user or group into an existing pool.
func (f *Fake) InjectForeignPoolChildForTesting(pool, kind, childName, ownerToken string) error {
	return f.doSilent(true, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		ensureUserpoolMaps(up)
		switch kind {
		case "user":
			up.NextUserSeq++
			up.Users[childName] = &poolUserState{
				UID:        fmt.Sprintf("usr-%s-%d", up.IncarnationID[:8], up.NextUserSeq),
				Username:   childName,
				Enabled:    true,
				Status:     hostkit.UserStatusConfirmed,
				CreatedAt:  f.opts.Now().Unix(),
				SessionGen: 1,
				OwnerToken: ownerToken,
			}
			up.ForeignUsers[childName] = true
		case "group":
			up.NextGroupSeq++
			up.Groups[childName] = &poolGroupState{
				GID:        fmt.Sprintf("grp-%s-%d", up.IncarnationID[:8], up.NextGroupSeq),
				Name:       childName,
				OwnerToken: ownerToken,
			}
			up.ForeignGroups[childName] = true
		}
		return nil
	})
}

// RotateUserpoolSigningKeyForTesting rotates the active signing key for pool while keeping the old public key in RotatedKeys.
func (f *Fake) RotateUserpoolSigningKeyForTesting(pool string) (string, error) {
	var newKID string
	err := f.doSilent(true, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		ensureUserpoolMaps(up)
		if up.KeyID != "" && up.PublicKeyPEM != "" {
			up.RotatedKeys[up.KeyID] = up.PublicKeyPEM
		}
		privPEM, pubPEM, kid, err := hostkit.GeneratePoolRSAKeyPair()
		if err != nil {
			return err
		}
		newKID = kid
		up.KeyID = newKID
		up.PrivateKeyPEM = privPEM
		up.PublicKeyPEM = pubPEM
		return nil
	})
	return newKID, err
}

// SetUserpoolReverseListOrderForTesting makes ListUserIndex return native pages in reverse order to test host-side global sorting.
func (f *Fake) SetUserpoolReverseListOrderForTesting(pool string, reverse bool) error {
	return f.doSilent(true, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		up.ReverseOrder = reverse
		return nil
	})
}

// UserpoolSigningKeyMaterialForTesting returns signing material for test token fabrication.
func (f *Fake) UserpoolSigningKeyMaterialForTesting(pool string) (privPEM, pubPEM, kid, issuer, clientID, poolID, incarnation string, ok bool) {
	_ = f.doSilent(false, func(s *state) error {
		up, exists := s.Userpools[pool]
		if !exists || up == nil {
			return nil
		}
		privPEM = up.PrivateKeyPEM
		pubPEM = up.PublicKeyPEM
		kid = up.KeyID
		issuer = up.Issuer
		clientID = up.ClientID
		poolID = up.PoolID
		incarnation = up.IncarnationID
		ok = true
		return nil
	})
	return
}

// UserpoolRawPasswordEntryForTesting returns the stored PBKDF2 salt, hash, and iteration count for (pool, username).
func (f *Fake) UserpoolRawPasswordEntryForTesting(pool, username string) (saltHex, hashHex string, iterations int, ok bool) {
	_ = f.doSilent(false, func(s *state) error {
		up, exists := s.Userpools[pool]
		if !exists || up == nil {
			return nil
		}
		u, uok := up.Users[username]
		if !uok || u == nil || !u.HasPermanentPassword {
			return nil
		}
		saltHex = u.PasswordSaltHex
		hashHex = u.PasswordDerivedHex
		iterations = hostkit.PBKDF2Iterations
		ok = true
		return nil
	})
	return
}

// UserpoolOwnerToken implements hostkit.UserpoolOwnershipReader.
func (f *Fake) UserpoolOwnerToken(_ context.Context, name string) (string, bool, error) {
	var tok string
	var exists bool
	err := f.doTarget("UserpoolOwnerToken", name, func(s *state) error {
		up, ok := s.Userpools[name]
		if !ok || up == nil {
			exists = false
			return nil
		}
		exists = true
		tok = up.OwnerToken
		return nil
	})
	return tok, exists, err
}

// PeekDryUserpoolState implements hostkit.UserpoolDryStatePeeker.
func (f *Fake) PeekDryUserpoolState(_ context.Context, name string) (hostkit.UserpoolInfo, map[string]hostkit.UserSnapshot, map[string]bool, map[string][]string, bool) {
	var (
		info        hostkit.UserpoolInfo
		users       map[string]hostkit.UserSnapshot
		groups      map[string]bool
		memberships map[string][]string
		found       bool
	)
	_ = f.doSilent(false, func(s *state) error {
		up, ok := s.Userpools[name]
		if !ok || up == nil {
			return nil
		}
		ensureUserpoolMaps(up)
		info = up.toInfo()
		users = make(map[string]hostkit.UserSnapshot, len(up.Users))
		for k, u := range up.Users {
			users[k] = u.toSnapshot()
		}
		groups = make(map[string]bool, len(up.Groups))
		for k := range up.Groups {
			groups[k] = true
		}
		memberships = make(map[string][]string, len(up.Memberships))
		for g, m := range up.Memberships {
			var list []string
			for u, ok := range m {
				if ok {
					list = append(list, u)
				}
			}
			sort.Strings(list)
			if len(list) > 0 {
				memberships[g] = list
			}
		}
		found = true
		return nil
	})
	return info, users, groups, memberships, found
}

// CreateUserPool implements hostkit.Userpools.
func (f *Fake) CreateUserPool(ctx context.Context, in hostkit.UserpoolCreateInput) (bool, hostkit.UserpoolInfo, error) {
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["CreateUserPool"]++
		f.mu.Unlock()
		return false, hostkit.UserpoolInfo{}, f.echoToken(ctx, "userpool")
	}
	var created bool
	var out hostkit.UserpoolInfo
	name := in.Name
	err := f.doTarget("CreateUserPool", name, func(s *state) error {
		if s.Userpools == nil {
			s.Userpools = map[string]*userpoolState{}
		}
		ownerTok := in.OwnerToken
		if ownerTok == "" {
			ownerTok = hostkit.CreateToken(ctx)
		}
		if existing, ok := s.Userpools[name]; ok && existing != nil {
			if !validOwnerToken(existing.OwnerToken) || (ownerTok != "" && existing.OwnerToken != ownerTok) || (in.ExpectedOwnerToken != "" && existing.OwnerToken != in.ExpectedOwnerToken) {
				return hostkit.ProviderError(hostkit.Conflict, 409, "ResourceConflictException",
					fmt.Sprintf("userpool %q already exists under a different owner", name))
			}
			if in.Generation > 0 && in.Generation < existing.MaxGeneration {
				return hostkit.ProviderError(hostkit.Conflict, 409, "StaleGeneration",
					fmt.Sprintf("stale generation %d < %d for userpool %q", in.Generation, existing.MaxGeneration, name))
			}
			if in.Generation > existing.MaxGeneration {
				existing.MaxGeneration = in.Generation
			}
			created = false
			out = existing.toInfo()
			return nil
		}

		inc := in.IncarnationID
		if inc == "" {
			inc = randomHex16()
		}
		privPEM, pubPEM, kid, err := hostkit.GeneratePoolRSAKeyPair()
		if err != nil {
			return hostkit.ProviderError(hostkit.Internal, 500, "KeyGenError", "failed to generate pool signing key")
		}
		poolID := fmt.Sprintf("lmpool-%s-%s", name, inc[:8])
		up := &userpoolState{
			Name:          name,
			PoolID:        poolID,
			ClientID:      fmt.Sprintf("lmclient-%s-%s", name, inc[:8]),
			Issuer:        fmt.Sprintf("https://userpool.lmcloud.local/%s", poolID),
			IncarnationID: inc,
			OwnerToken:    ownerTok,
			MaxGeneration: in.Generation,
			KeyID:         kid,
			PrivateKeyPEM: privPEM,
			PublicKeyPEM:  pubPEM,
		}
		ensureUserpoolMaps(up)
		s.Userpools[name] = up
		created = true
		out = up.toInfo()
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("CreateUserPool"); ferr != nil {
			return false, hostkit.UserpoolInfo{}, ferr
		}
	}
	return created, out, err
}

// DeleteUserPool implements hostkit.Userpools.
func (f *Fake) DeleteUserPool(ctx context.Context, name string) (bool, error) {
	var existed bool
	err := f.doTarget("DeleteUserPool", name, func(s *state) error {
		up, ok := s.Userpools[name]
		if !ok || up == nil {
			existed = false
			return nil
		}
		if err := verifyUserpoolWriteFence(ctx, up, name, "", "", 0); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		if len(up.ForeignUsers) > 0 || len(up.ForeignGroups) > 0 {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignChildPresent",
				fmt.Sprintf("userpool %q contains foreign child resources and cannot be deleted", name))
		}
		delete(s.Userpools, name)
		s.Userpools = compactUserpoolMap(s.Userpools)
		deleteTargetPolicies(s, name)
		existed = true
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("DeleteUserPool"); ferr != nil {
			return false, ferr
		}
	}
	return existed, err
}

// UserPoolExists implements hostkit.Userpools.
func (f *Fake) UserPoolExists(_ context.Context, name string) (bool, error) {
	var exists bool
	err := f.doTarget("UserPoolExists", name, func(s *state) error {
		up, ok := s.Userpools[name]
		exists = ok && up != nil
		return nil
	})
	return exists, err
}

// DescribeUserPool implements hostkit.Userpools.
func (f *Fake) DescribeUserPool(_ context.Context, name string) (hostkit.UserpoolInfo, error) {
	var out hostkit.UserpoolInfo
	err := f.doTarget("DescribeUserPool", name, func(s *state) error {
		up, ok := s.Userpools[name]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", name))
		}
		out = up.toInfo()
		return nil
	})
	return out, err
}

// ListUserPools implements hostkit.Userpools.
func (f *Fake) ListUserPools(_ context.Context) ([]string, error) {
	var out []string
	err := f.do("ListUserPools", func(s *state) error {
		names := make([]string, 0, len(s.Userpools))
		for name, up := range s.Userpools {
			if up != nil {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		out = names
		return nil
	})
	return out, err
}

// CreateUser implements hostkit.Userpools.
func (f *Fake) CreateUser(ctx context.Context, in hostkit.UserCreateInput) (hostkit.UserSnapshot, error) {
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["CreateUser"]++
		f.mu.Unlock()
		return hostkit.UserSnapshot{}, f.echoToken(ctx, "user")
	}
	var out hostkit.UserSnapshot
	pool := in.Pool
	username := in.Username
	err := f.doTarget("CreateUser", pool+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, in.OwnerToken, in.IncarnationID, in.Generation); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		if existing, exists := up.Users[username]; exists && existing != nil {
			return hostkit.ProviderError(hostkit.Conflict, 409, "UsernameExistsException",
				fmt.Sprintf("user %q already exists in userpool %q", username, pool))
		}
		if len(up.Users) >= hostkit.MaxUsersPerPool {
			return hostkit.ProviderError(hostkit.InvalidArgument, 400, "TooManyUsersException",
				fmt.Sprintf("userpool %q user count exceeds maximum (%d)", pool, hostkit.MaxUsersPerPool))
		}
		up.NextUserSeq++
		up.ChildSeq++
		clonedAttrs := make(map[string]string, len(in.Attributes))
		for k, v := range in.Attributes {
			clonedAttrs[k] = v
		}
		createdAt := in.NowUnix
		if createdAt <= 0 {
			createdAt = f.opts.Now().Unix()
		}
		if createdAt <= 0 {
			createdAt = 1
		}
		u := &poolUserState{
			UID:        fmt.Sprintf("usr-%s-%d", up.IncarnationID[:8], up.NextUserSeq),
			Username:   username,
			Enabled:    true,
			Status:     hostkit.UserStatusForceChangePassword,
			Attrs:      clonedAttrs,
			CreatedAt:  createdAt,
			SessionGen: 1,
			OwnerToken: up.OwnerToken,
			ChildSeq:   up.ChildSeq,
		}
		up.Users[username] = u
		gen := in.Generation
		if gen == 0 {
			gen = hostkit.UserpoolMutationFenceFrom(ctx).Generation
		}
		if gen > up.MaxGeneration {
			up.MaxGeneration = gen
		}
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		out = u.toSnapshot()
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("CreateUser"); ferr != nil {
			return hostkit.UserSnapshot{}, ferr
		}
	}
	return out, err
}

// GetUser implements hostkit.Userpools.
func (f *Fake) GetUser(_ context.Context, pool, username string) (hostkit.UserSnapshot, error) {
	var out hostkit.UserSnapshot
	err := f.doTarget("GetUser", pool+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		ensureUserpoolMaps(up)
		u, exists := up.Users[username]
		if !exists || u == nil {
			out = hostkit.UserSnapshot{Exists: false, Username: username}
			return nil
		}
		out = u.toSnapshot()
		return nil
	})
	return out, err
}

// DeleteUser implements hostkit.Userpools.
func (f *Fake) DeleteUser(ctx context.Context, pool, username string) error {
	err := f.doTarget("DeleteUser", pool+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, "", "", 0); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		u, exists := up.Users[username]
		if !exists || u == nil {
			fence := hostkit.UserpoolMutationFenceFrom(ctx)
			if fence.Generation > up.MaxGeneration {
				up.MaxGeneration = fence.Generation
			}
			up.ChildSeq++
			hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
			return nil
		}
		if up.ForeignUsers[username] {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
				fmt.Sprintf("user %q in pool %q belongs to another owner", username, pool))
		}
		delete(up.Users, username)
		up.Users = compactUserMap(up.Users)
		for g, members := range up.Memberships {
			if members[username] {
				delete(members, username)
				up.Memberships[g] = members
			}
		}
		up.Memberships = compactMembershipMap(up.Memberships)
		fence := hostkit.UserpoolMutationFenceFrom(ctx)
		if fence.Generation > up.MaxGeneration {
			up.MaxGeneration = fence.Generation
		}
		up.ChildSeq++
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("DeleteUser"); ferr != nil {
			return ferr
		}
	}
	return err
}

// SetUserEnabled implements hostkit.Userpools.
func (f *Fake) SetUserEnabled(ctx context.Context, pool, username string, enabled bool) (hostkit.UserSnapshot, error) {
	var out hostkit.UserSnapshot
	err := f.doTarget("SetUserEnabled", pool+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, "", "", 0); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		u, exists := up.Users[username]
		if !exists || u == nil {
			return f.notFound(hostkit.AbsentUser, "UserNotFoundException", fmt.Sprintf("user %q not found in pool %q", username, pool))
		}
		if up.ForeignUsers[username] {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
				fmt.Sprintf("user %q in pool %q belongs to another owner", username, pool))
		}
		u.Enabled = enabled
		if !enabled {
			u.SessionGen++
		}
		fence := hostkit.UserpoolMutationFenceFrom(ctx)
		if fence.Generation > up.MaxGeneration {
			up.MaxGeneration = fence.Generation
		}
		up.ChildSeq++
		u.ChildSeq = up.ChildSeq
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		out = u.toSnapshot()
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("SetUserEnabled"); ferr != nil {
			return hostkit.UserSnapshot{}, ferr
		}
	}
	return out, err
}

// SetUserPassword implements hostkit.Userpools.
func (f *Fake) SetUserPassword(ctx context.Context, pool, username, password string) (hostkit.UserSnapshot, error) {
	saltHex, derivedHex, err := hostkit.DerivePasswordPBKDF2(password)
	if err != nil {
		return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Internal, 500, "PasswordKDFError", "failed to derive password key")
	}
	var out hostkit.UserSnapshot
	err = f.doTarget("SetUserPassword", pool+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, "", "", 0); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		u, exists := up.Users[username]
		if !exists || u == nil {
			return f.notFound(hostkit.AbsentUser, "UserNotFoundException", fmt.Sprintf("user %q not found in pool %q", username, pool))
		}
		if up.ForeignUsers[username] {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
				fmt.Sprintf("user %q in pool %q belongs to another owner", username, pool))
		}
		u.PasswordSaltHex = saltHex
		u.PasswordDerivedHex = derivedHex
		u.HasPermanentPassword = true
		u.Status = hostkit.UserStatusConfirmed
		u.SessionGen++
		fence := hostkit.UserpoolMutationFenceFrom(ctx)
		if fence.Generation > up.MaxGeneration {
			up.MaxGeneration = fence.Generation
		}
		up.ChildSeq++
		u.ChildSeq = up.ChildSeq
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		out = u.toSnapshot()
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("SetUserPassword"); ferr != nil {
			return hostkit.UserSnapshot{}, ferr
		}
	}
	return out, err
}

// ListUserIndex implements hostkit.Userpools.
func (f *Fake) ListUserIndex(_ context.Context, pool, afterUsername string, maxItems int) (hostkit.UserIndexPage, error) {
	var out hostkit.UserIndexPage
	err := f.doTarget("ListUserIndex", pool, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		ensureUserpoolMaps(up)
		names := make([]string, 0, len(up.Users))
		for uname, u := range up.Users {
			if u != nil {
				names = append(names, uname)
			}
		}
		sort.Strings(names)
		if up.ReverseOrder && afterUsername == "" {
			for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
				names[i], names[j] = names[j], names[i]
			}
		}
		limit := f.opts.PageSize
		if maxItems > 0 && maxItems < limit {
			limit = maxItems
		}
		var pageNames []string
		hasMore := false
		for _, n := range names {
			if afterUsername != "" && n <= afterUsername {
				continue
			}
			if len(pageNames) == limit {
				hasMore = true
				break
			}
			pageNames = append(pageNames, n)
		}
		out = hostkit.UserIndexPage{
			PoolID:        up.PoolID,
			IncarnationID: up.IncarnationID,
			Usernames:     pageNames,
			HasMore:       hasMore,
		}
		return nil
	})
	return out, err
}

// SignIn implements hostkit.Userpools.
func (f *Fake) SignIn(_ context.Context, in hostkit.UserSignInInput) (hostkit.SessionSnapshot, error) {
	var out hostkit.SessionSnapshot
	genericAuthErr := hostkit.ProviderError(hostkit.Unauthenticated, 401, "NotAuthorizedException", "invalid username or password")
	pool := in.Pool
	username := in.Username
	password := in.Password
	err := f.doTarget("SignIn", pool+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		ensureUserpoolMaps(up)
		u, exists := up.Users[username]
		if !exists || u == nil || !u.HasPermanentPassword {
			hostkit.DummyVerifyPasswordPBKDF2(password)
			return genericAuthErr
		}
		if !hostkit.VerifyPasswordPBKDF2(password, u.PasswordSaltHex, u.PasswordDerivedHex) {
			return genericAuthErr
		}
		if !u.Enabled {
			return genericAuthErr
		}
		nowUnix := in.NowUnix
		if nowUnix <= 0 {
			nowUnix = f.opts.Now().Unix()
		}
		ttl := in.TTLSeconds
		if ttl <= 0 || ttl > hostkit.DefaultSessionTTLSeconds {
			ttl = hostkit.DefaultSessionTTLSeconds
		}
		expUnix := nowUnix + ttl
		sgen := u.SessionGen
		if sgen == 0 {
			sgen = 1
		}
		claimsPayload := map[string]any{
			"sub":        u.UID,
			"username":   u.Username,
			"iss":        up.Issuer,
			"client_id":  up.ClientID,
			"token_use":  "access",
			"jti":        randomHex16(),
			"iat":        nowUnix,
			"exp":        expUnix,
		}
		token, err := hostkit.MintRS256JWT(up.PrivateKeyPEM, up.KeyID, claimsPayload)
		if err != nil {
			return hostkit.ProviderError(hostkit.Internal, 500, "TokenMintError", "failed to mint session token")
		}
		out = hostkit.SessionSnapshot{
			AccessToken:   token,
			ExpiresIn:     ttl,
			PoolID:        up.PoolID,
			IncarnationID: up.IncarnationID,
			SessionGen:    sgen,
			IssuedAt:      nowUnix,
			ExpiresAt:     expUnix,
			Claims: map[string]string{
				"sub":       u.UID,
				"username":  u.Username,
				"iss":       up.Issuer,
				"client_id": up.ClientID,
				"token_use": "access",
				"iat":       strconv.FormatInt(nowUnix, 10),
				"exp":       strconv.FormatInt(expUnix, 10),
			},
		}
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("SignIn"); ferr != nil {
			return hostkit.SessionSnapshot{}, ferr
		}
	}
	return out, err
}

// CreateGroup implements hostkit.Userpools.
func (f *Fake) CreateGroup(ctx context.Context, in hostkit.GroupCreateInput) (bool, error) {
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["CreateGroup"]++
		f.mu.Unlock()
		return false, f.echoToken(ctx, "group")
	}
	var created bool
	pool := in.Pool
	group := in.Group
	err := f.doTarget("CreateGroup", pool+"/"+group, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, in.OwnerToken, in.IncarnationID, in.Generation); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		if existing, exists := up.Groups[group]; exists && existing != nil {
			if up.ForeignGroups[group] {
				return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
					fmt.Sprintf("group %q in pool %q belongs to another owner", group, pool))
			}
			gen := in.Generation
			if gen == 0 {
				gen = hostkit.UserpoolMutationFenceFrom(ctx).Generation
			}
			if gen > up.MaxGeneration {
				up.MaxGeneration = gen
			}
			up.ChildSeq++
			hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
			created = false
			return nil
		}
		if len(up.Groups) >= hostkit.MaxGroupsPerPool {
			return hostkit.ProviderError(hostkit.InvalidArgument, 400, "TooManyGroupsException",
				fmt.Sprintf("userpool %q group count exceeds maximum (%d)", pool, hostkit.MaxGroupsPerPool))
		}
		up.NextGroupSeq++
		up.Groups[group] = &poolGroupState{
			GID:        fmt.Sprintf("grp-%s-%d", up.IncarnationID[:8], up.NextGroupSeq),
			Name:       group,
			OwnerToken: up.OwnerToken,
		}
		gen := in.Generation
		if gen == 0 {
			gen = hostkit.UserpoolMutationFenceFrom(ctx).Generation
		}
		if gen > up.MaxGeneration {
			up.MaxGeneration = gen
		}
		up.ChildSeq++
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		created = true
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("CreateGroup"); ferr != nil {
			return false, ferr
		}
	}
	return created, err
}

// DeleteGroup implements hostkit.Userpools.
func (f *Fake) DeleteGroup(ctx context.Context, pool, group string) (bool, error) {
	var existed bool
	err := f.doTarget("DeleteGroup", pool+"/"+group, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, "", "", 0); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		g, exists := up.Groups[group]
		if !exists || g == nil {
			fence := hostkit.UserpoolMutationFenceFrom(ctx)
			if fence.Generation > up.MaxGeneration {
				up.MaxGeneration = fence.Generation
			}
			up.ChildSeq++
			hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
			existed = false
			return nil
		}
		if up.ForeignGroups[group] {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
				fmt.Sprintf("group %q in pool %q belongs to another owner", group, pool))
		}
		delete(up.Groups, group)
		up.Groups = compactGroupMap(up.Groups)
		delete(up.Memberships, group)
		up.Memberships = compactMembershipMap(up.Memberships)
		fence := hostkit.UserpoolMutationFenceFrom(ctx)
		if fence.Generation > up.MaxGeneration {
			up.MaxGeneration = fence.Generation
		}
		up.ChildSeq++
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		existed = true
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("DeleteGroup"); ferr != nil {
			return false, ferr
		}
	}
	return existed, err
}

// ListGroups implements hostkit.Userpools.
func (f *Fake) ListGroups(_ context.Context, pool string) ([]string, error) {
	var out []string
	err := f.doTarget("ListGroups", pool, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		ensureUserpoolMaps(up)
		names := make([]string, 0, len(up.Groups))
		for gname, g := range up.Groups {
			if g != nil {
				names = append(names, gname)
			}
		}
		sort.Strings(names)
		out = names
		return nil
	})
	return out, err
}

// AddUserToGroup implements hostkit.Userpools.
func (f *Fake) AddUserToGroup(ctx context.Context, pool, group, username string) (bool, error) {
	var added bool
	err := f.doTarget("AddUserToGroup", pool+"/"+group+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, "", "", 0); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		if _, gok := up.Groups[group]; !gok {
			return f.notFound(hostkit.AbsentGroup, "ResourceNotFoundException", fmt.Sprintf("group %q not found in pool %q", group, pool))
		}
		if _, uok := up.Users[username]; !uok {
			return f.notFound(hostkit.AbsentUser, "UserNotFoundException", fmt.Sprintf("user %q not found in pool %q", username, pool))
		}
		if up.Memberships[group] != nil && up.Memberships[group][username] {
			fence := hostkit.UserpoolMutationFenceFrom(ctx)
			if fence.Generation > up.MaxGeneration {
				up.MaxGeneration = fence.Generation
			}
			up.ChildSeq++
			hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
			added = false
			return nil
		}
		userGroupCount := 0
		for _, members := range up.Memberships {
			if members[username] {
				userGroupCount++
			}
		}
		if userGroupCount >= hostkit.MaxGroupsPerUser {
			return hostkit.ProviderError(hostkit.InvalidArgument, 400, "TooManyMembershipsException",
				fmt.Sprintf("user %q membership count exceeds maximum (%d)", username, hostkit.MaxGroupsPerUser))
		}
		if up.Memberships[group] == nil {
			up.Memberships[group] = map[string]bool{}
		}
		up.Memberships[group][username] = true
		fence := hostkit.UserpoolMutationFenceFrom(ctx)
		if fence.Generation > up.MaxGeneration {
			up.MaxGeneration = fence.Generation
		}
		up.ChildSeq++
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		added = true
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("AddUserToGroup"); ferr != nil {
			return false, ferr
		}
	}
	return added, err
}

// RemoveUserFromGroup implements hostkit.Userpools.
func (f *Fake) RemoveUserFromGroup(ctx context.Context, pool, group, username string) error {
	err := f.doTarget("RemoveUserFromGroup", pool+"/"+group+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		if err := verifyUserpoolWriteFence(ctx, up, pool, "", "", 0); err != nil {
			return err
		}
		ensureUserpoolMaps(up)
		if _, gok := up.Groups[group]; !gok {
			return f.notFound(hostkit.AbsentGroup, "ResourceNotFoundException", fmt.Sprintf("group %q not found in pool %q", group, pool))
		}
		if _, uok := up.Users[username]; !uok {
			return f.notFound(hostkit.AbsentUser, "UserNotFoundException", fmt.Sprintf("user %q not found in pool %q", username, pool))
		}
		if up.Memberships[group] == nil || !up.Memberships[group][username] {
			fence := hostkit.UserpoolMutationFenceFrom(ctx)
			if fence.Generation > up.MaxGeneration {
				up.MaxGeneration = fence.Generation
			}
			up.ChildSeq++
			hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
			return nil
		}
		delete(up.Memberships[group], username)
		up.Memberships = compactMembershipMap(up.Memberships)
		fence := hostkit.UserpoolMutationFenceFrom(ctx)
		if fence.Generation > up.MaxGeneration {
			up.MaxGeneration = fence.Generation
		}
		up.ChildSeq++
		hostkit.ReportUserpoolChildMutationSeq(ctx, up.ChildSeq)
		return nil
	})
	if err == nil {
		if ferr := f.maybeFaultUserpool("RemoveUserFromGroup"); ferr != nil {
			return ferr
		}
	}
	return err
}

// ListUserGroups implements hostkit.Userpools.
func (f *Fake) ListUserGroups(_ context.Context, pool, username string) ([]string, error) {
	var out []string
	err := f.doTarget("ListUserGroups", pool+"/"+username, func(s *state) error {
		up, ok := s.Userpools[pool]
		if !ok || up == nil {
			return f.notFound(hostkit.AbsentUserpool, "ResourceNotFoundException", fmt.Sprintf("userpool %q not found", pool))
		}
		ensureUserpoolMaps(up)
		if _, uok := up.Users[username]; !uok {
			return f.notFound(hostkit.AbsentUser, "UserNotFoundException", fmt.Sprintf("user %q not found in pool %q", username, pool))
		}
		var groups []string
		for g, members := range up.Memberships {
			if _, gok := up.Groups[g]; gok && members[username] {
				groups = append(groups, g)
			}
		}
		sort.Strings(groups)
		out = groups
		return nil
	})
	return out, err
}
