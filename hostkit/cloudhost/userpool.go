// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func missingUserpools() *hostkit.CloudError {
	return hostkit.ProviderError(hostkit.Internal, 0, "UserpoolsNotConfigured",
		"host was constructed without a Userpools adapter")
}

func pageTokenKeyFilePath(cfg Config) string {
	if cfg.CampaignStatePath != "" {
		return cfg.CampaignStatePath + ".pagetoken.key"
	}
	if cfg.Journal != nil && cfg.Journal.Path() != "" {
		return cfg.Journal.Path() + ".pagetoken.key"
	}
	return ""
}

func initAndRotatePageTokenKey(cfg Config, errs *hostkit.ErrorState) []byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		for i := range key {
			key[i] = byte(i + 1)
		}
	}
	if errs != nil {
		errs.AddRedaction(hex.EncodeToString(key[:]))
	}
	keyPath := pageTokenKeyFilePath(cfg)
	if keyPath != "" {
		_ = writePageTokenKeyFile(keyPath, key[:])
	}
	return key[:]
}

func writePageTokenKeyFile(keyPath string, key []byte) error {
	dir := filepath.Dir(keyPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(key)
	_ = f.Chmod(0o600)
	_ = f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// PageTokenKeyPath returns the path of the 0600 run-state page-token HMAC key file, if persisted.
func (h *Host) PageTokenKeyPath() string {
	return pageTokenKeyFilePath(h.cfg)
}

// RotatePageTokenKey rotates the run-state page-token HMAC key in memory and on disk (0600).
func (h *Host) RotatePageTokenKey() error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	if h.errs != nil {
		h.errs.AddRedaction(hex.EncodeToString(key[:]))
	}
	h.pageTokenKey = key[:]
	if keyPath := pageTokenKeyFilePath(h.cfg); keyPath != "" {
		return writePageTokenKeyFile(keyPath, key[:])
	}
	return nil
}

// User is the immutable readback snapshot of a directory user.
type User struct {
	exists     bool
	username   string
	enabled    bool
	status     string
	attributes map[string]string
	createdAt  int64
}

func (u *User) Exists() bool {
	if u == nil {
		return false
	}
	return u.exists
}

func (u *User) Username() string {
	if u == nil {
		return ""
	}
	return u.username
}

func (u *User) Enabled() bool {
	if u == nil {
		return false
	}
	return u.enabled
}

func (u *User) Status() string {
	if u == nil {
		return ""
	}
	return u.status
}

func (u *User) Attributes() map[string]string {
	if u == nil || len(u.attributes) == 0 {
		return map[string]string{}
	}
	return copyMap(u.attributes)
}

func (u *User) Attribute(name string) string {
	if u == nil || u.attributes == nil {
		return ""
	}
	return u.attributes[name]
}

func (u *User) CreatedAt() int64 {
	if u == nil {
		return 0
	}
	return u.createdAt
}

func missingUser(username string) *User {
	return &User{
		exists:     false,
		username:   username,
		attributes: map[string]string{},
	}
}

func snapshotToUser(snap hostkit.UserSnapshot, exists bool) *User {
	return &User{
		exists:     exists,
		username:   snap.Username,
		enabled:    snap.Enabled,
		status:     snap.Status,
		attributes: copyMap(snap.Attributes),
		createdAt:  snap.CreatedAt,
	}
}

// UserPage is a single page of User items returned by UserList.
type UserPage struct {
	Items     []*User
	NextToken string
}

// Session is the immutable session returned by UserSignIn and UserVerifyToken.
type Session struct {
	accessToken string
	expiresIn   int64
	claims      map[string]string
}

func (s *Session) AccessToken() string {
	if s == nil {
		return ""
	}
	return s.accessToken
}

func (s *Session) ExpiresIn() int64 {
	if s == nil {
		return 0
	}
	return s.expiresIn
}

func (s *Session) Claims() map[string]string {
	if s == nil || len(s.claims) == 0 {
		return map[string]string{}
	}
	return copyMap(s.claims)
}

func emptySession() *Session {
	return &Session{
		claims: map[string]string{},
	}
}

type tokenBindingRecord struct {
	TokenSHA256   string `json:"token_sha256"`
	Sub           string `json:"sub"`
	Username      string `json:"username"`
	PoolID        string `json:"pool_id"`
	IncarnationID string `json:"incarnation_id"`
	SessionGen    uint64 `json:"sgen"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	Scope         string `json:"scope,omitempty"`
}

type persistedUserpoolCatalogState struct {
	Pool          hostkit.UserpoolInfo            `json:"pool"`
	Users         map[string]hostkit.UserSnapshot `json:"users,omitempty"`
	Groups        map[string]bool                 `json:"groups,omitempty"`
	Memberships   map[string][]string             `json:"memberships,omitempty"`
	TokenBindings map[string][]tokenBindingRecord `json:"token_bindings,omitempty"`
	ChildSeq      uint64                          `json:"child_seq,omitempty"`
	UserSeq       map[string]uint64               `json:"user_seq,omitempty"`
	GroupSeq      map[string]uint64               `json:"group_seq,omitempty"`
	MembershipSeq map[string]uint64               `json:"membership_seq,omitempty"`
}

func sanitizeUserSnapshotForJournal(u hostkit.UserSnapshot) hostkit.UserSnapshot {
	cp := u.Clone()
	if len(cp.Attributes) > 0 {
		clean := make(map[string]string, len(cp.Attributes))
		for k, v := range cp.Attributes {
			if strings.Contains(k, "password") || strings.Contains(v, "eyJ") || strings.Contains(v, "private_key") || strings.Contains(v, "access_token") {
				continue
			}
			clean[k] = v
		}
		cp.Attributes = clean
	}
	return cp
}

func encodePersistedUserpoolState(st persistedUserpoolCatalogState) string {
	if len(st.Users) > 0 {
		cleanUsers := make(map[string]hostkit.UserSnapshot, len(st.Users))
		for k, u := range st.Users {
			cleanUsers[k] = sanitizeUserSnapshotForJournal(u)
		}
		st.Users = cleanUsers
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return ""
	}
	return string(raw)
}

func decodePersistedUserpoolState(raw string) (persistedUserpoolCatalogState, bool) {
	if raw == "" {
		return persistedUserpoolCatalogState{
			Users:         map[string]hostkit.UserSnapshot{},
			Groups:        map[string]bool{},
			Memberships:   map[string][]string{},
			TokenBindings: map[string][]tokenBindingRecord{},
			UserSeq:       map[string]uint64{},
			GroupSeq:      map[string]uint64{},
			MembershipSeq: map[string]uint64{},
		}, false
	}
	var st persistedUserpoolCatalogState
	if err := json.Unmarshal([]byte(raw), &st); err != nil || st.Pool.Name == "" {
		return persistedUserpoolCatalogState{
			Users:         map[string]hostkit.UserSnapshot{},
			Groups:        map[string]bool{},
			Memberships:   map[string][]string{},
			TokenBindings: map[string][]tokenBindingRecord{},
			UserSeq:       map[string]uint64{},
			GroupSeq:      map[string]uint64{},
			MembershipSeq: map[string]uint64{},
		}, false
	}
	if st.Users == nil {
		st.Users = map[string]hostkit.UserSnapshot{}
	}
	if st.Groups == nil {
		st.Groups = map[string]bool{}
	}
	if st.Memberships == nil {
		st.Memberships = map[string][]string{}
	}
	if st.TokenBindings == nil {
		st.TokenBindings = map[string][]tokenBindingRecord{}
	}
	if st.UserSeq == nil {
		st.UserSeq = map[string]uint64{}
	}
	if st.GroupSeq == nil {
		st.GroupSeq = map[string]uint64{}
	}
	if st.MembershipSeq == nil {
		st.MembershipSeq = map[string]uint64{}
	}
	return st, true
}

func (h *Host) userpoolScopeFingerprint() string {
	if h.cost == nil {
		return h.cfg.Provider
	}
	if h.cost.journal != nil {
		m := h.cost.journal.Meta()
		return m.Provider + "|" + m.Account + "|" + m.Tenant + "|" + m.Scope + "|" + m.Region
	}
	return h.cfg.Provider
}

func (h *Host) checkUserpoolRouteAllowed(ctx context.Context) *hostkit.CloudError {
	ctx = hostkit.WithForbidLiveRoute(ctx)
	if ep := hostkit.EndpointFrom(ctx); ep != "" && !hostkit.IsLoopbackEndpoint(ep) {
		return hostkit.ProviderError(hostkit.PermissionDenied, 403, "LiveModeUnsupported",
			"live mode refuses userpool operations: live userpool slice is not enabled")
	}
	if ce := checkAdapterLiveRouteAllowed(ctx, h.cfg.Userpools); ce != nil {
		return ce
	}
	if h.cost != nil {
		if ce := h.cost.checkUserpoolAllowed(); ce != nil {
			return ce
		}
	}
	return nil
}

func isDefinitiveUserpoolRefusal(ce *hostkit.CloudError) bool {
	if ce == nil {
		return false
	}
	if ce.Preflight {
		return true
	}
	switch ce.Code {
	case hostkit.InvalidArgument, hostkit.Unauthenticated, hostkit.PermissionDenied, hostkit.NotFound, hostkit.Conflict, hostkit.PreconditionFailed, hostkit.CostCapExceeded:
		return true
	default:
		return false
	}
}

func userpoolFenceCtx(ctx context.Context, ownerToken, incarnation, generationStr string) context.Context {
	if ownerToken != "" {
		ctx = hostkit.WithCreateToken(ctx, ownerToken)
	}
	genNum, _ := strconv.ParseUint(generationStr, 10, 64)
	if ownerToken != "" || incarnation != "" || genNum > 0 {
		ctx = hostkit.WithUserpoolMutationFence(ctx, hostkit.UserpoolMutationFence{
			OwnerToken:    ownerToken,
			IncarnationID: incarnation,
			Generation:    genNum,
		})
	}
	return ctx
}

func (h *Host) meteredUserpoolOwnerToken(ctx context.Context, name string) (string, bool, *hostkit.CloudError) {
	if h.cfg.Userpools == nil {
		return "", false, missingUserpools()
	}
	rawUp := unwrapGuardAdapter(h.cfg.Userpools)
	r, ok := rawUp.(hostkit.UserpoolOwnershipReader)
	if !ok {
		return "", false, nil
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "userpool_read_ownership", safety.AttemptPricingInput{
		Operation: "userpool_read_ownership",
	}, safety.KindUserpool, name)
	if cerr != nil {
		return "", false, cerr
	}
	tok, exists, err := r.UserpoolOwnerToken(mctx, name)
	err = hostkit.NilIfTyped(err)
	_, _, aerr := scope.finish(0, 0, err == nil, err == nil)
	if aerr != nil {
		return "", false, aerr
	}
	if err != nil {
		return "", false, hostkit.AsCloudError(err)
	}
	if tok != "" {
		h.errs.AddRedaction(tok)
	}
	return tok, exists, nil
}

func (h *Host) checkUserpoolOwnershipInScope(mctx context.Context, name, expectedOwnerToken string, hasJournalOwnership bool) (bool, *hostkit.CloudError) {
	rawUp := unwrapGuardAdapter(h.cfg.Userpools)
	r, ok := rawUp.(hostkit.UserpoolOwnershipReader)
	if !ok {
		if !hasJournalOwnership {
			return false, nil
		}
		return true, nil
	}
	tok, ex, err := r.UserpoolOwnerToken(mctx, name)
	err = hostkit.NilIfTyped(err)
	if err != nil {
		return false, hostkit.AsCloudError(err)
	}
	if tok != "" {
		h.errs.AddRedaction(tok)
	}
	if !ex {
		return false, nil
	}
	if !hasJournalOwnership || expectedOwnerToken == "" || tok == "" || tok != expectedOwnerToken {
		return true, hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
			fmt.Sprintf("userpool %q exists but is not owned by this run", name))
	}
	return true, nil
}

func resolveUserpoolDryPeeker(ctx context.Context, up hostkit.Userpools) hostkit.UserpoolDryStatePeeker {
	raw := unwrapGuardAdapter(up)
	switch r := raw.(type) {
	case hostkit.Router:
		if r.Pick == nil {
			return nil
		}
		be, err := r.Pick(hostkit.WithForbidLiveRoute(ctx))
		if err != nil || be == nil {
			return nil
		}
		raw = unwrapGuardAdapter(be)
	case *hostkit.Router:
		if r == nil || r.Pick == nil {
			return nil
		}
		be, err := r.Pick(hostkit.WithForbidLiveRoute(ctx))
		if err != nil || be == nil {
			return nil
		}
		raw = unwrapGuardAdapter(be)
	}
	p, ok := raw.(hostkit.UserpoolDryStatePeeker)
	if !ok {
		return nil
	}
	return p
}

func (h *Host) dryResolveUserpool(ctx context.Context, name string) (dryUserpool, *hostkit.CloudError) {
	if du, ok := h.ov(ctx).userpool(name); ok {
		return du, nil
	}
	if h.cfg.Userpools == nil {
		return dryUserpool{}, missingUserpools()
	}
	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, name)
	if cerr != nil {
		return dryUserpool{}, cerr
	}
	if hasAmb {
		return dryUserpool{}, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp))
	}
	if peeker := resolveUserpoolDryPeeker(ctx, h.cfg.Userpools); peeker != nil {
		info, users, groups, rawMemberships, found := peeker.PeekDryUserpoolState(ctx, name)
		if !found {
			return dryUserpool{
				exists:      false,
				users:       map[string]hostkit.UserSnapshot{},
				deletedUser: map[string]bool{},
				groups:      map[string]bool{},
				memberships: map[string]map[string]bool{},
			}, nil
		}
		if !hasAct || act.OwnerToken == "" || info.OwnerToken == "" || info.OwnerToken != act.OwnerToken {
			return dryUserpool{}, hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
				fmt.Sprintf("userpool %q exists but is not owned by this run", name))
		}
		memberships := make(map[string]map[string]bool, len(rawMemberships))
		for g, list := range rawMemberships {
			m := make(map[string]bool, len(list))
			for _, u := range list {
				m[u] = true
			}
			memberships[g] = m
		}
		du := dryUserpool{
			exists:      true,
			createdNow:  false,
			users:       users,
			deletedUser: map[string]bool{},
			groups:      groups,
			memberships: memberships,
		}
		h.ov(ctx).setUserpool(name, du)
		return du, nil
	}
	if hasAct && act.StateJSON != "" {
		if st, ok := decodePersistedUserpoolState(act.StateJSON); ok {
			memberships := make(map[string]map[string]bool, len(st.Memberships))
			for g, list := range st.Memberships {
				m := make(map[string]bool, len(list))
				for _, u := range list {
					m[u] = true
				}
				memberships[g] = m
			}
			du := dryUserpool{
				exists:      true,
				createdNow:  false,
				users:       st.Users,
				deletedUser: map[string]bool{},
				groups:      st.Groups,
				memberships: memberships,
			}
			h.ov(ctx).setUserpool(name, du)
			return du, nil
		}
	}
	return dryUserpool{
		exists:      false,
		users:       map[string]hostkit.UserSnapshot{},
		deletedUser: map[string]bool{},
		groups:      map[string]bool{},
		memberships: map[string]map[string]bool{},
	}, nil
}

// reconcileUserForCatalog performs an admitted sub-operation read of the current
// user state when an adapter does not report a monotonic ChildSeq and concurrent
// mutations modified the catalog state while the user operation was in flight.
func (h *Host) reconcileUserForCatalog(ctx context.Context, pool, username string, isCleanup bool) (hostkit.UserSnapshot, bool) {
	const readOp = "user_get"
	readCtx, readScope, cerr := h.beginAttemptScope(ctx, readOp, safety.AttemptPricingInput{
		Operation: readOp,
		IsCleanup: isCleanup,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		return hostkit.UserSnapshot{}, false
	}
	snap, gerr := h.cfg.Userpools.GetUser(readCtx, pool, username)
	gce := hostkit.AsCloudError(gerr)
	_, _, abortErr := readScope.finish(0, 0, gce == nil || isDefinitiveUserpoolRefusal(gce), false)
	if abortErr != nil {
		return hostkit.UserSnapshot{}, false
	}
	if gerr == nil {
		return snap, true
	}
	if isNotFound(gce) {
		return hostkit.UserSnapshot{Exists: false, Username: username}, true
	}
	return hostkit.UserSnapshot{}, false
}

// reconcileGroupsForCatalog performs an admitted sub-operation read of the current
// pool groups when an adapter does not report a monotonic ChildSeq and concurrent
// mutations modified the catalog state while the group operation was in flight.
func (h *Host) reconcileGroupsForCatalog(ctx context.Context, pool string, isCleanup bool) (map[string]bool, bool) {
	const readOp = "group_list"
	readCtx, readScope, cerr := h.beginAttemptScope(ctx, readOp, safety.AttemptPricingInput{
		Operation: readOp,
		IsCleanup: isCleanup,
	}, safety.KindUserpool, pool)
	if cerr != nil {
		return nil, false
	}
	groups, gerr := h.cfg.Userpools.ListGroups(readCtx, pool)
	gce := hostkit.AsCloudError(gerr)
	_, _, abortErr := readScope.finish(0, 0, gce == nil || isDefinitiveUserpoolRefusal(gce), false)
	if abortErr != nil || gerr != nil {
		return nil, false
	}
	m := make(map[string]bool, len(groups))
	for _, g := range groups {
		m[g] = true
	}
	return m, true
}

// reconcileUserGroupsForCatalog performs an admitted sub-operation read of a user's
// group memberships when an adapter does not report a monotonic ChildSeq and
// concurrent mutations modified the catalog state while the membership operation was in flight.
func (h *Host) reconcileUserGroupsForCatalog(ctx context.Context, pool, username string, isCleanup bool) (map[string]bool, bool) {
	const readOp = "user_groups"
	readCtx, readScope, cerr := h.beginAttemptScope(ctx, readOp, safety.AttemptPricingInput{
		Operation: readOp,
		IsCleanup: isCleanup,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		return nil, false
	}
	groups, gerr := h.cfg.Userpools.ListUserGroups(readCtx, pool, username)
	gce := hostkit.AsCloudError(gerr)
	_, _, abortErr := readScope.finish(0, 0, gce == nil || isDefinitiveUserpoolRefusal(gce), false)
	if abortErr != nil {
		return nil, false
	}
	if gerr != nil {
		if isNotFound(gce) {
			return map[string]bool{}, true
		}
		return nil, false
	}
	m := make(map[string]bool, len(groups))
	for _, g := range groups {
		m[g] = true
	}
	return m, true
}

// UserpoolCreate implements userpool_create(name).
func (h *Host) UserpoolCreate(dry bool, name string) (bool, error) {
	const op = "userpool_create"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(name); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		if du.exists {
			h.ok()
			return false, nil
		}
		h.ov(ctx).setUserpool(name, dryUserpool{
			exists:      true,
			createdNow:  true,
			users:       map[string]hostkit.UserSnapshot{},
			deletedUser: map[string]bool{},
			groups:      map[string]bool{},
			memberships: map[string]map[string]bool{},
		})
		h.ok()
		return true, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return false, h.fail(op, name, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if hasAmb && amb.IntentOp != "create" {
		failed = true
		return false, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and is quarantined until reconciled", name, amb.IntentOp)))
	}
	if !hasAct && !hasAmb {
		if ce := h.cost.checkUserpoolCreateHeadroom(ep, name); ce != nil {
			failed = true
			return false, h.fail(op, name, ce)
		}
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindUserpool, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}

	incarnation := ""
	if hasAct && act.Incarnation != "" {
		incarnation = act.Incarnation
	} else if hasAmb && amb.Incarnation != "" {
		incarnation = amb.Incarnation
	} else {
		incarnation = safety.NewToken128()
	}

	entry, cerr := h.cost.beginUserpoolIntent(ep, name, "create", incarnation)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return false, h.fail(op, name, cerr)
	}
	h.errs.AddRedaction(entry.OwnerToken)
	genNum, _ := strconv.ParseUint(entry.Generation, 10, 64)
	expectedOwner := act.OwnerToken
	if expectedOwner == "" && hasAmb {
		expectedOwner = amb.OwnerToken
	}

	mctx = hostkit.WithCreateToken(mctx, entry.OwnerToken)
	created, createdInfo, err := h.cfg.Userpools.CreateUserPool(mctx, hostkit.UserpoolCreateInput{
		Name:               name,
		IncarnationID:      entry.Incarnation,
		OwnerToken:         entry.OwnerToken,
		ExpectedOwnerToken: expectedOwner,
		Generation:         genNum,
		IntentID:           entry.IntentID,
	})
	ce := hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveUserpoolRefusal(ce)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, err == nil || definitiveRefusal, !definitiveRefusal)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, name, abortErr)
	}
	if err != nil {
		if ce.Code == hostkit.Conflict && !hasAct {
			tok, exists, terr := h.meteredUserpoolOwnerToken(ctx, name)
			if terr != nil {
				failed = true
				return false, h.fail(op, name, terr)
			}
			if exists && tok != "" && tok == entry.OwnerToken {
				entry.StateJSON = encodePersistedUserpoolState(persistedUserpoolCatalogState{
					Pool: hostkit.UserpoolInfo{
						Name:          name,
						PoolID:        "pool-" + name,
						IncarnationID: entry.Incarnation,
						OwnerToken:    entry.OwnerToken,
						Generation:    genNum,
					},
				})
				if cerr := h.cost.confirmUserpoolIntent(entry); cerr != nil {
					failed = true
					return false, h.fail(op, name, cerr)
				}
				h.cost.lockResourceCleanupIfNeeded(ep, op, safety.KindUserpool, name)
				h.ok()
				return true, nil
			}
		}
		failed = true
		if definitiveRefusal {
			_ = h.cost.abortUserpoolIntent(entry)
		}
		return false, h.fail(op, name, ce)
	}

	if createdInfo.Name == "" {
		createdInfo = hostkit.UserpoolInfo{
			Name:          name,
			PoolID:        "pool-" + name,
			IncarnationID: entry.Incarnation,
			OwnerToken:    entry.OwnerToken,
			Generation:    genNum,
		}
	}
	if createdInfo.IncarnationID != "" {
		entry.Incarnation = createdInfo.IncarnationID
	}
	if hasAct && act.StateJSON != "" {
		if st, ok := decodePersistedUserpoolState(act.StateJSON); ok {
			st.Pool = createdInfo
			entry.StateJSON = encodePersistedUserpoolState(st)
		} else {
			entry.StateJSON = act.StateJSON
		}
	} else {
		entry.StateJSON = encodePersistedUserpoolState(persistedUserpoolCatalogState{
			Pool: createdInfo,
		})
	}
	if cerr := h.cost.confirmUserpoolIntent(entry); cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if !hasAct {
		h.cost.lockResourceCleanupIfNeeded(ep, op, safety.KindUserpool, name)
	}
	h.ok()
	return created, nil
}

// UserpoolDelete implements userpool_delete(name).
func (h *Host) UserpoolDelete(dry bool, name string) (bool, error) {
	const op = "userpool_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(name); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		h.ov(ctx).setUserpool(name, dryUserpool{
			exists:      false,
			users:       map[string]hostkit.UserSnapshot{},
			deletedUser: map[string]bool{},
			groups:      map[string]bool{},
			memberships: map[string]map[string]bool{},
		})
		h.ok()
		return du.exists, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return false, h.fail(op, name, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	ownerToken := act.OwnerToken
	if ownerToken == "" && hasAmb {
		ownerToken = amb.OwnerToken
	}
	incarnation := act.Incarnation
	if incarnation == "" && hasAmb {
		incarnation = amb.Incarnation
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
		IsCleanup: true,
	}, safety.KindUserpool, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, name, ownerToken, hasAct || hasAmb)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return false, h.fail(op, name, ownErr)
	}
	if !exists && !hasAct && !hasAmb {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, name, abortErr)
		}
		h.ok()
		return false, nil
	}

	entry, cerr := h.cost.beginUserpoolIntent(ep, name, "delete", incarnation)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if ownerToken != "" {
		h.errs.AddRedaction(ownerToken)
	}

	// Cascade journaled children in strict order (memberships -> users -> groups -> pool)
	// before deleting the pool itself (design 17 §4.2 & §4.4).
	stateJSON := act.StateJSON
	if stateJSON == "" && hasAmb {
		stateJSON = amb.StateJSON
	}
	if st, ok := decodePersistedUserpoolState(stateJSON); ok {
		groupNames := make([]string, 0, len(st.Memberships))
		for g := range st.Memberships {
			groupNames = append(groupNames, g)
		}
		sort.Strings(groupNames)
		for _, g := range groupNames {
			members := append([]string(nil), st.Memberships[g]...)
			sort.Strings(members)
			for _, u := range members {
				subCtx, subScope, scerr := h.beginAttemptScope(ctx, "group_remove_user", safety.AttemptPricingInput{
					Operation: "group_remove_user",
					IsCleanup: true,
				}, safety.KindPoolMembership, name+"/"+g+"/"+u)
				if scerr != nil {
					_, _, _ = scope.finish(0, 0, false, false)
					failed = true
					return false, h.fail(op, name, scerr)
				}
				subCtx = userpoolFenceCtx(subCtx, ownerToken, incarnation, entry.Generation)
				rerr := h.cfg.Userpools.RemoveUserFromGroup(subCtx, name, g, u)
				rce := hostkit.AsCloudError(rerr)
				if isNotFound(rce) {
					rerr = nil
					rce = nil
				}
				_, _, subAbort := subScope.finish(0, 0, rerr == nil, rerr == nil)
				if subAbort != nil {
					_, _, _ = scope.finish(0, 0, false, false)
					failed = true
					return false, h.fail(op, name, subAbort)
				}
				if rerr != nil {
					_, _, _ = scope.finish(0, 0, false, false)
					failed = true
					return false, h.fail(op, name, rce)
				}
			}
		}

		userNames := make([]string, 0, len(st.Users))
		for u := range st.Users {
			userNames = append(userNames, u)
		}
		sort.Strings(userNames)
		for _, u := range userNames {
			subCtx, subScope, scerr := h.beginAttemptScope(ctx, "user_delete", safety.AttemptPricingInput{
				Operation: "user_delete",
				IsCleanup: true,
			}, safety.KindPoolUser, name+"/"+u)
			if scerr != nil {
				_, _, _ = scope.finish(0, 0, false, false)
				failed = true
				return false, h.fail(op, name, scerr)
			}
			subCtx = userpoolFenceCtx(subCtx, ownerToken, incarnation, entry.Generation)
			derr := h.cfg.Userpools.DeleteUser(subCtx, name, u)
			dce := hostkit.AsCloudError(derr)
			if isNotFound(dce) {
				derr = nil
				dce = nil
			}
			_, _, subAbort := subScope.finish(0, 0, derr == nil, derr == nil)
			if subAbort != nil {
				_, _, _ = scope.finish(0, 0, false, false)
				failed = true
				return false, h.fail(op, name, subAbort)
			}
			if derr != nil {
				_, _, _ = scope.finish(0, 0, false, false)
				failed = true
				return false, h.fail(op, name, dce)
			}
		}

		grpList := make([]string, 0, len(st.Groups))
		for g := range st.Groups {
			grpList = append(grpList, g)
		}
		sort.Strings(grpList)
		for _, g := range grpList {
			subCtx, subScope, scerr := h.beginAttemptScope(ctx, "group_delete", safety.AttemptPricingInput{
				Operation: "group_delete",
				IsCleanup: true,
			}, safety.KindPoolGroup, name+"/"+g)
			if scerr != nil {
				_, _, _ = scope.finish(0, 0, false, false)
				failed = true
				return false, h.fail(op, name, scerr)
			}
			subCtx = userpoolFenceCtx(subCtx, ownerToken, incarnation, entry.Generation)
			_, derr := h.cfg.Userpools.DeleteGroup(subCtx, name, g)
			dce := hostkit.AsCloudError(derr)
			if isNotFound(dce) {
				derr = nil
				dce = nil
			}
			_, _, subAbort := subScope.finish(0, 0, derr == nil, derr == nil)
			if subAbort != nil {
				_, _, _ = scope.finish(0, 0, false, false)
				failed = true
				return false, h.fail(op, name, subAbort)
			}
			if derr != nil {
				_, _, _ = scope.finish(0, 0, false, false)
				failed = true
				return false, h.fail(op, name, dce)
			}
		}
	}

	mctx = userpoolFenceCtx(mctx, ownerToken, incarnation, entry.Generation)
	existed, err := h.cfg.Userpools.DeleteUserPool(mctx, name)
	ce := hostkit.AsCloudError(err)
	if isNotFound(ce) {
		ce = nil
		err = nil
		existed = false
	}
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, err == nil, err == nil)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, name, abortErr)
	}
	if err != nil {
		failed = true
		if isDefinitiveUserpoolRefusal(ce) && ce.ProviderCode != "ForeignChildPresent" {
			_ = h.cost.abortUserpoolIntent(entry)
		}
		return false, h.fail(op, name, ce)
	}

	if cerr := h.cost.confirmUserpoolDelete(entry); cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	h.ok()
	return existed, nil
}

// UserpoolExists implements userpool_exists(name).
func (h *Host) UserpoolExists(dry bool, name string) (bool, error) {
	const op = "userpool_exists"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(name); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		h.ok()
		return du.exists, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return false, h.fail(op, name, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	_, _, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return false, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindUserpool, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	exists, err := h.cfg.Userpools.UserPoolExists(mctx, name)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil, ce == nil)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, name, abortErr)
	}
	if ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}
	h.ok()
	return exists, nil
}

// UserpoolList implements userpool_list().
func (h *Host) UserpoolList(dry bool) ([]string, error) {
	const op = "userpool_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return nil, h.fail(op, "", ce)
	}

	ep := hostkit.EndpointFrom(ctx)
	ambList, cerr := h.cost.listAmbiguousUserpoolsForEndpoint(ep)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, "", cerr)
	}
	if len(ambList) > 0 {
		failed = true
		return nil, h.fail(op, ambList[0].Name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", ambList[0].Name, ambList[0].IntentOp)))
	}

	if dry {
		if h.cfg.Userpools == nil {
			failed = true
			return nil, h.fail(op, "", missingUserpools())
		}
		names, err := h.cfg.Userpools.ListUserPools(ctx)
		if err != nil {
			failed = true
			return nil, h.fail(op, "", hostkit.AsCloudError(err))
		}
		merged := h.ov(ctx).mergeUserpools(names)
		h.ok()
		return merged, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return nil, h.fail(op, "", missingUserpools())
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, "", "")
	if cerr != nil {
		failed = true
		return nil, h.fail(op, "", cerr)
	}
	names, err := h.cfg.Userpools.ListUserPools(mctx)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil, ce == nil)
	if abortErr != nil {
		failed = true
		return nil, h.fail(op, "", abortErr)
	}
	if ce != nil {
		failed = true
		return nil, h.fail(op, "", ce)
	}
	sort.Strings(names)
	h.ok()
	return names, nil
}

// UserCreate implements user_create(pool, username) and user_create(pool, username, attrs).
func (h *Host) UserCreate(dry bool, pool, username string, attrs map[string]string) (*User, error) {
	const op = "user_create"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return missingUser(username), h.fail(op, username, ce)
	}
	if ce := hostkit.ValidatePoolAttributes(attrs); ce != nil {
		failed = true
		return missingUser(username), h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return missingUser(username), h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return missingUser(username), h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		if _, exists := du.users[username]; exists && !du.deletedUser[username] {
			failed = true
			return missingUser(username), h.fail(op, username, hostkit.ProviderError(hostkit.Conflict, 409, "UsernameExistsException",
				fmt.Sprintf("user %q already exists in userpool %q (dry-run preview)", username, pool)))
		}
		activeCount := 0
		for u := range du.users {
			if !du.deletedUser[u] {
				activeCount++
			}
		}
		if activeCount >= hostkit.MaxUsersPerPool {
			failed = true
			return missingUser(username), h.fail(op, pool, hostkit.Preflightf("userpool %q user count exceeds maximum (%d)", pool, hostkit.MaxUsersPerPool))
		}
		nowUnix := h.cfg.Now().UTC().Unix()
		if nowUnix <= 0 {
			nowUnix = 1
		}
		snap := hostkit.UserSnapshot{
			Exists:     true,
			Username:   username,
			Sub:        "dry-sub-" + username,
			Enabled:    true,
			Status:     hostkit.UserStatusForceChangePassword,
			Attributes: copyMap(attrs),
			CreatedAt:  nowUnix,
			SessionGen: 1,
		}
		if du.users == nil {
			du.users = map[string]hostkit.UserSnapshot{}
		}
		du.users[username] = snap
		if du.deletedUser != nil {
			delete(du.deletedUser, username)
		}
		h.ov(ctx).setUserpool(pool, du)
		h.ok()
		return snapshotToUser(snap, true), nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return missingUser(username), h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return missingUser(username), h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}
	if hasAct && act.StateJSON != "" {
		if st, ok := decodePersistedUserpoolState(act.StateJSON); ok {
			if _, exists := st.Users[username]; !exists && len(st.Users) >= hostkit.MaxUsersPerPool {
				failed = true
				return missingUser(username), h.fail(op, pool, hostkit.Preflightf("userpool %q user count exceeds maximum (%d)", pool, hostkit.MaxUsersPerPool))
			}
		}
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return missingUser(username), h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return missingUser(username), h.fail(op, pool, abortErr)
		}
		failed = true
		return missingUser(username), h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	genNum, _ := strconv.ParseUint(act.Generation, 10, 64)
	snap, err := h.cfg.Userpools.CreateUser(mctx, hostkit.UserCreateInput{
		Pool:          pool,
		Username:      username,
		Attributes:    attrs,
		OwnerToken:    act.OwnerToken,
		IncarnationID: act.Incarnation,
		Generation:    genNum,
		NowUnix:       h.cfg.Now().UTC().Unix(),
	})
	ce := hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveUserpoolRefusal(ce)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, err == nil || definitiveRefusal, !definitiveRefusal)
	if abortErr != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, abortErr)
	}
	if err != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, ce)
	}
	if snap.SessionGen == 0 {
		snap.SessionGen = 1
	}

	var reconciledUser hostkit.UserSnapshot
	var hasReconciledUser bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledUser, hasReconciledUser = h.reconcileUserForCatalog(ctx, pool, username, false)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			st.Pool = hostkit.UserpoolInfo{Name: pool, IncarnationID: act.Incarnation, OwnerToken: act.OwnerToken}
		}
		if childSeq > 0 {
			if st.UserSeq[username] > childSeq {
				return cur
			}
			st.UserSeq[username] = childSeq
			st.Users[username] = snap.Clone()
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledUser {
			if !reconciledUser.Exists {
				delete(st.Users, username)
			} else {
				if reconciledUser.SessionGen == 0 {
					reconciledUser.SessionGen = 1
				}
				st.Users[username] = reconciledUser.Clone()
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		st.Users[username] = snap.Clone()
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, cerr)
	}

	h.ok()
	return snapshotToUser(snap, true), nil
}

// UserGet implements user_get(pool, username).
func (h *Host) UserGet(dry bool, pool, username string) (*User, error) {
	const op = "user_get"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return missingUser(username), h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return missingUser(username), h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return missingUser(username), h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		if u, ok := du.users[username]; ok && !du.deletedUser[username] {
			h.ok()
			return snapshotToUser(u, true), nil
		}
		h.ok()
		return missingUser(username), nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return missingUser(username), h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	_, _, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return missingUser(username), h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, cerr)
	}
	snap, err := h.cfg.Userpools.GetUser(mctx, pool, username)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), ce == nil)
	if abortErr != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return missingUser(username), h.fail(op, pool, ce)
	}
	if !snap.Exists {
		h.ok()
		return missingUser(username), nil
	}
	h.ok()
	return snapshotToUser(snap, true), nil
}

// UserDelete implements user_delete(pool, username).
func (h *Host) UserDelete(dry bool, pool, username string) error {
	const op = "user_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		delete(du.users, username)
		if du.deletedUser == nil {
			du.deletedUser = map[string]bool{}
		}
		du.deletedUser[username] = true
		for g := range du.memberships {
			delete(du.memberships[g], username)
		}
		h.ov(ctx).setUserpool(pool, du)
		h.ok()
		return nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
		IsCleanup: true,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return h.fail(op, pool, abortErr)
		}
		failed = true
		return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	err := h.cfg.Userpools.DeleteUser(mctx, pool, username)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), ce == nil)
	if abortErr != nil {
		failed = true
		return h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	var reconciledUser hostkit.UserSnapshot
	var hasReconciledUser bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledUser, hasReconciledUser = h.reconcileUserForCatalog(ctx, pool, username, true)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			return cur
		}
		if childSeq > 0 {
			if st.UserSeq[username] <= childSeq {
				st.UserSeq[username] = childSeq
				delete(st.Users, username)
				delete(st.TokenBindings, username)
			}
			for g, members := range st.Memberships {
				mKey := g + "/" + username
				if st.MembershipSeq[mKey] > childSeq {
					continue
				}
				st.MembershipSeq[mKey] = childSeq
				filtered := members[:0]
				for _, m := range members {
					if m != username {
						filtered = append(filtered, m)
					}
				}
				if len(filtered) == 0 {
					delete(st.Memberships, g)
				} else {
					st.Memberships[g] = filtered
				}
			}
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledUser {
			if !reconciledUser.Exists {
				delete(st.Users, username)
				delete(st.TokenBindings, username)
			} else {
				st.Users[username] = reconciledUser.Clone()
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		delete(st.Users, username)
		delete(st.TokenBindings, username)
		for g, members := range st.Memberships {
			filtered := members[:0]
			for _, m := range members {
				if m != username {
					filtered = append(filtered, m)
				}
			}
			if len(filtered) == 0 {
				delete(st.Memberships, g)
			} else {
				st.Memberships[g] = filtered
			}
		}
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	h.ok()
	return nil
}

// UserSetEnabled implements user_set_enabled(pool, username, enabled).
func (h *Host) UserSetEnabled(dry bool, pool, username string, enabled bool) error {
	const op = "user_set_enabled"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		u, ok := du.users[username]
		if !ok || du.deletedUser[username] {
			failed = true
			return h.fail(op, username, notFound(hostkit.AbsentUser, fmt.Sprintf("user %q does not exist in userpool %q (dry-run preview)", username, pool)))
		}
		u.Enabled = enabled
		if !enabled {
			u.SessionGen++
		}
		du.users[username] = u
		h.ov(ctx).setUserpool(pool, du)
		h.ok()
		return nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return h.fail(op, pool, abortErr)
		}
		failed = true
		return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	updatedUser, err := h.cfg.Userpools.SetUserEnabled(mctx, pool, username, enabled)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), false)
	if abortErr != nil {
		failed = true
		return h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	var reconciledUser hostkit.UserSnapshot
	var hasReconciledUser bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledUser, hasReconciledUser = h.reconcileUserForCatalog(ctx, pool, username, false)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			return cur
		}
		if childSeq > 0 {
			if st.UserSeq[username] > childSeq {
				return cur
			}
			st.UserSeq[username] = childSeq
			u, uok := st.Users[username]
			if !uok {
				u = updatedUser.Clone()
				if u.SessionGen == 0 {
					u.SessionGen = 1
				}
			} else {
				u.Enabled = enabled
				if !enabled {
					if u.SessionGen == 0 {
						u.SessionGen = 1
					}
					u.SessionGen++
				}
				if updatedUser.SessionGen > u.SessionGen {
					u.SessionGen = updatedUser.SessionGen
				}
			}
			st.Users[username] = u
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledUser {
			if !reconciledUser.Exists {
				delete(st.Users, username)
				delete(st.TokenBindings, username)
			} else {
				u, uok := st.Users[username]
				if uok && u.SessionGen > reconciledUser.SessionGen {
					reconciledUser.SessionGen = u.SessionGen
				}
				if !reconciledUser.Enabled && uok && u.Enabled {
					reconciledUser.SessionGen++
				}
				st.Users[username] = reconciledUser.Clone()
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		u, uok := st.Users[username]
		if !uok {
			u = updatedUser.Clone()
			if u.SessionGen == 0 {
				u.SessionGen = 1
			}
		} else {
			u.Enabled = enabled
			if !enabled {
				if u.SessionGen == 0 {
					u.SessionGen = 1
				}
				u.SessionGen++
			}
			if updatedUser.SessionGen > u.SessionGen {
				u.SessionGen = updatedUser.SessionGen
			}
		}
		st.Users[username] = u
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	h.ok()
	return nil
}

// UserSetPassword implements user_set_password(pool, username, password).
func (h *Host) UserSetPassword(dry bool, pool, username, password string) error {
	const op = "user_set_password"
	if password != "" {
		h.errs.AddRedaction(password)
	}
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return h.fail(op, username, ce)
	}
	if ce := hostkit.ValidatePoolPassword(password); ce != nil {
		failed = true
		return h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		u, ok := du.users[username]
		if !ok || du.deletedUser[username] {
			failed = true
			return h.fail(op, username, notFound(hostkit.AbsentUser, fmt.Sprintf("user %q does not exist in userpool %q (dry-run preview)", username, pool)))
		}
		u.Status = hostkit.UserStatusConfirmed
		u.SessionGen++
		du.users[username] = u
		h.ov(ctx).setUserpool(pool, du)
		h.ok()
		return nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return h.fail(op, pool, abortErr)
		}
		failed = true
		return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	updatedUser, err := h.cfg.Userpools.SetUserPassword(mctx, pool, username, password)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), false)
	if abortErr != nil {
		failed = true
		return h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	var reconciledUser hostkit.UserSnapshot
	var hasReconciledUser bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledUser, hasReconciledUser = h.reconcileUserForCatalog(ctx, pool, username, false)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			return cur
		}
		if childSeq > 0 {
			if st.UserSeq[username] > childSeq {
				if u, uok := st.Users[username]; uok && updatedUser.SessionGen > u.SessionGen {
					u.SessionGen = updatedUser.SessionGen
					st.Users[username] = u
					return encodePersistedUserpoolState(st)
				}
				return cur
			}
			st.UserSeq[username] = childSeq
			u, uok := st.Users[username]
			if !uok {
				u = updatedUser.Clone()
				if u.SessionGen == 0 {
					u.SessionGen = 2
				}
			} else {
				u.Status = hostkit.UserStatusConfirmed
				if u.SessionGen == 0 {
					u.SessionGen = 1
				}
				u.SessionGen++
				if updatedUser.SessionGen > u.SessionGen {
					u.SessionGen = updatedUser.SessionGen
				}
			}
			st.Users[username] = u
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledUser {
			if !reconciledUser.Exists {
				delete(st.Users, username)
				delete(st.TokenBindings, username)
			} else {
				u, uok := st.Users[username]
				if uok && u.SessionGen >= reconciledUser.SessionGen {
					reconciledUser.SessionGen = u.SessionGen + 1
				} else if reconciledUser.SessionGen <= 1 {
					reconciledUser.SessionGen = 2
				}
				st.Users[username] = reconciledUser.Clone()
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		u, uok := st.Users[username]
		if !uok {
			u = updatedUser.Clone()
			if u.SessionGen == 0 {
				u.SessionGen = 2
			}
		} else {
			u.Status = hostkit.UserStatusConfirmed
			if u.SessionGen == 0 {
				u.SessionGen = 1
			}
			u.SessionGen++
			if updatedUser.SessionGen > u.SessionGen {
				u.SessionGen = updatedUser.SessionGen
			}
		}
		st.Users[username] = u
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	h.ok()
	return nil
}

// UserList implements user_list(pool) and user_list(pool, maxItems, pageToken).
func (h *Host) UserList(dry bool, pool string, maxItems int64, pageToken string) (*UserPage, error) {
	const op = "user_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	emptyPage := &UserPage{Items: []*User{}}
	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return emptyPage, h.fail(op, pool, ce)
	}
	limit, ce := hostkit.ValidateUserListMaxItems(maxItems)
	if ce != nil {
		failed = true
		return emptyPage, h.fail(op, pool, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return emptyPage, h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return emptyPage, h.fail(op, pool, ce)
	}

	ep := hostkit.EndpointFrom(ctx)
	scopeFP := h.userpoolScopeFingerprint()
	nowUnix := h.cfg.Now().UTC().Unix()

	var parsedToken hostkit.UserListPageTokenPayload
	if pageToken != "" {
		parsedToken, ce = hostkit.VerifyUserListPageToken(h.pageTokenKey, pageToken, ep, scopeFP, pool, limit, nowUnix)
		if ce != nil {
			failed = true
			return emptyPage, h.fail(op, pool, ce)
		}
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return emptyPage, h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return emptyPage, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		var names []string
		for u := range du.users {
			if !du.deletedUser[u] {
				names = append(names, u)
			}
		}
		sort.Strings(names)
		var window []string
		hasMore := false
		for _, u := range names {
			if parsedToken.CursorUsername != "" && u <= parsedToken.CursorUsername {
				continue
			}
			if len(window) < limit {
				window = append(window, u)
			} else {
				hasMore = true
				break
			}
		}
		items := make([]*User, 0, len(window))
		for _, u := range window {
			items = append(items, snapshotToUser(du.users[u], true))
		}
		nextTok := ""
		if hasMore && len(window) > 0 {
			var serr error
			nextTok, serr = hostkit.SignUserListPageToken(h.pageTokenKey, hostkit.UserListPageTokenPayload{
				Endpoint:       ep,
				Scope:          scopeFP,
				PoolName:       pool,
				MaxItems:       limit,
				CursorUsername: window[len(window)-1],
				IssuedAt:       nowUnix,
				ExpiresAt:      nowUnix + hostkit.PageTokenTTLSeconds,
			})
			if serr != nil {
				failed = true
				return emptyPage, h.fail(op, pool, hostkit.Preflightf("failed to sign page token: %v", serr))
			}
		}
		h.ok()
		return &UserPage{Items: items, NextToken: nextTok}, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return emptyPage, h.fail(op, pool, missingUserpools())
	}

	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return emptyPage, h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return emptyPage, h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	// Build the pool-scoped globally sorted username index snapshot (<=2000 entries, <=2 MiB)
	// via metered native index pages (design 17 §2.5).
	var indexUsernames []string
	seenIndexUser := map[string]bool{}
	seenCursors := map[string]bool{}
	afterCursor := ""
	var indexBytes int64
	var poolID, poolIncarnation string
	pageCount := 0

	for {
		pageCount++
		if pageCount > h.cfg.MaxPages {
			failed = true
			return emptyPage, h.fail(op, pool, hostkit.ProviderError(hostkit.Internal, 500, "PaginationLoopDetected",
				fmt.Sprintf("user_list exceeded maximum native index pages (%d)", h.cfg.MaxPages)))
		}

		mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
			Operation: op,
		}, safety.KindUserpool, pool)
		if cerr != nil {
			failed = true
			return emptyPage, h.fail(op, pool, cerr)
		}
		if pageCount == 1 {
			exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
			if ownErr != nil {
				retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
				failed = true
				return emptyPage, h.fail(op, pool, ownErr)
			}
			if !exists {
				var abortErr *hostkit.CloudError
				retries, throttles, abortErr = scope.finish(0, 0, true, false)
				if abortErr != nil {
					failed = true
					return emptyPage, h.fail(op, pool, abortErr)
				}
				failed = true
				return emptyPage, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
			}
		}

		idxPage, err := h.cfg.Userpools.ListUserIndex(mctx, pool, afterCursor, hostkit.MaxUsersPerPool)
		ce := hostkit.AsCloudError(err)
		r, t, abortErr := scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), false)
		retries += r
		throttles += t
		if abortErr != nil {
			failed = true
			return emptyPage, h.fail(op, pool, abortErr)
		}
		if ce != nil {
			failed = true
			return emptyPage, h.fail(op, pool, ce)
		}
		if idxPage.PoolID != "" {
			poolID = idxPage.PoolID
		}
		if idxPage.IncarnationID != "" {
			poolIncarnation = idxPage.IncarnationID
		}

		newItemsInPage := 0
		var lastInPage string
		for _, u := range idxPage.Usernames {
			lastInPage = u
			if seenIndexUser[u] {
				continue
			}
			newItemsInPage++
			seenIndexUser[u] = true
			indexBytes += int64(len(u) + 64)
			if len(indexUsernames) >= hostkit.MaxUsersPerPool || indexBytes > hostkit.MaxUserIndexBytes {
				failed = true
				return emptyPage, h.fail(op, pool, hostkit.ProviderError(hostkit.InvalidArgument, 0, "UserIndexLimitExceeded",
					fmt.Sprintf("userpool %q user index exceeds portable bound", pool)))
			}
			indexUsernames = append(indexUsernames, u)
		}

		if !idxPage.HasMore {
			break
		}
		if lastInPage == "" || newItemsInPage == 0 || seenCursors[lastInPage] {
			failed = true
			return emptyPage, h.fail(op, pool, hostkit.ProviderError(hostkit.Internal, 500, "PaginationLoopDetected",
				"native user index pagination made no progress"))
		}
		seenCursors[lastInPage] = true
		afterCursor = lastInPage
	}

	if poolID == "" && hasAct && act.StateJSON != "" {
		if st, ok := decodePersistedUserpoolState(act.StateJSON); ok && st.Pool.PoolID != "" {
			poolID = st.Pool.PoolID
		}
	}
	if poolIncarnation == "" {
		poolIncarnation = act.Incarnation
	}
	if pageToken != "" {
		if (parsedToken.PoolIncarnation != "" && poolIncarnation != "" && parsedToken.PoolIncarnation != poolIncarnation) ||
			(parsedToken.PoolID != "" && poolID != "" && parsedToken.PoolID != poolID) {
			failed = true
			return emptyPage, h.fail(op, pool, hostkit.Preflightf("page_token comes from a stale userpool incarnation"))
		}
	}

	sort.Strings(indexUsernames)

	var window []string
	hasMore := false
	for _, u := range indexUsernames {
		if parsedToken.CursorUsername != "" && u <= parsedToken.CursorUsername {
			continue
		}
		if len(window) < limit {
			window = append(window, u)
		} else {
			hasMore = true
			break
		}
	}

	items := make([]*User, 0, len(window))
	var pageProfileBytes int64
	for _, u := range window {
		gctx, gscope, cerr := h.beginAttemptScope(ctx, "user_get", safety.AttemptPricingInput{
			Operation: "user_get",
		}, safety.KindPoolUser, pool+"/"+u)
		if cerr != nil {
			failed = true
			return emptyPage, h.fail(op, pool, cerr)
		}
		snap, gerr := h.cfg.Userpools.GetUser(gctx, pool, u)
		gce := hostkit.AsCloudError(gerr)
		r, t, abortErr := gscope.finish(0, 0, gce == nil || isDefinitiveUserpoolRefusal(gce), false)
		retries += r
		throttles += t
		if abortErr != nil {
			failed = true
			return emptyPage, h.fail(op, pool, abortErr)
		}
		if gce != nil {
			failed = true
			return emptyPage, h.fail(op, pool, gce)
		}
		if !snap.Exists {
			continue
		}
		entrySize := int64(len(snap.Username) + len(snap.Sub) + len(snap.Status) + 64)
		for k, v := range snap.Attributes {
			entrySize += int64(len(k) + len(v))
		}
		pageProfileBytes += entrySize
		if pageProfileBytes > hostkit.MaxUserPageProfileBytes {
			failed = true
			return emptyPage, h.fail(op, pool, hostkit.ProviderError(hostkit.InvalidArgument, 0, "PageProfileBudgetExceeded",
				fmt.Sprintf("user_list page profile size %d exceeds maximum of %d bytes", pageProfileBytes, hostkit.MaxUserPageProfileBytes)))
		}
		items = append(items, snapshotToUser(snap, true))
	}

	nextTok := ""
	if hasMore && len(window) > 0 {
		var serr error
		nextTok, serr = hostkit.SignUserListPageToken(h.pageTokenKey, hostkit.UserListPageTokenPayload{
			Endpoint:        ep,
			Scope:           scopeFP,
			PoolName:        pool,
			PoolID:          poolID,
			PoolIncarnation: poolIncarnation,
			MaxItems:        limit,
			CursorUsername:  window[len(window)-1],
			IssuedAt:        nowUnix,
			ExpiresAt:       nowUnix + hostkit.PageTokenTTLSeconds,
		})
		if serr != nil {
			failed = true
			return emptyPage, h.fail(op, pool, hostkit.Preflightf("failed to sign page token: %v", serr))
		}
	}

	h.ok()
	return &UserPage{Items: items, NextToken: nextTok}, nil
}

// UserSignIn implements user_sign_in(pool, username, password).
func (h *Host) UserSignIn(dry bool, pool, username, password string) (*Session, error) {
	const op = "user_sign_in"
	if password != "" {
		h.errs.AddRedaction(password)
	}
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return emptySession(), h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return emptySession(), h.fail(op, username, ce)
	}
	if ce := hostkit.ValidatePoolPassword(password); ce != nil {
		failed = true
		return emptySession(), h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return emptySession(), h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return emptySession(), h.fail(op, pool, ce)
	}

	if dry {
		failed = true
		return emptySession(), h.fail(op, pool, hostkit.Preflightf("user_sign_in is not supported in dry-run mode (dry mode does not authenticate)"))
	}

	if h.cfg.Userpools == nil {
		failed = true
		return emptySession(), h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return emptySession(), h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return emptySession(), h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindUserpool, pool)
	if cerr != nil {
		failed = true
		return emptySession(), h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return emptySession(), h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return emptySession(), h.fail(op, pool, abortErr)
		}
		failed = true
		return emptySession(), h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	nowUnix := h.cfg.Now().UTC().Unix()
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	out, err := h.cfg.Userpools.SignIn(mctx, hostkit.UserSignInInput{
		Pool:       pool,
		Username:   username,
		Password:   password,
		NowUnix:    nowUnix,
		TTLSeconds: hostkit.DefaultSessionTTLSeconds,
	})
	if out.AccessToken != "" {
		h.errs.AddRedaction(out.AccessToken)
		for _, seg := range strings.Split(out.AccessToken, ".") {
			if len(seg) >= 8 {
				h.errs.AddRedaction(seg)
			}
		}
	}
	ce := hostkit.AsCloudError(err)
	if ce != nil && ce.Code == hostkit.Unauthenticated {
		// Enforce fixed generic message for all sign-in authentication failures (enumeration protection + zero secret echo).
		ce = hostkit.ProviderError(hostkit.Unauthenticated, 400, "NotAuthorizedException", hostkit.GenericSignInErrorMessage)
	}
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), false)
	if abortErr != nil {
		failed = true
		return emptySession(), h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return emptySession(), h.fail(op, pool, ce)
	}

	sum := sha256.Sum256([]byte(out.AccessToken))
	tokenHash := hex.EncodeToString(sum[:])
	iat := out.IssuedAt
	if iat == 0 {
		iat, _ = strconv.ParseInt(out.Claims["iat"], 10, 64)
	}
	exp := out.ExpiresAt
	if exp == 0 {
		exp, _ = strconv.ParseInt(out.Claims["exp"], 10, 64)
	}
	sub := out.Claims["sub"]
	scopeFP := h.userpoolScopeFingerprint()

	var preSGen uint64
	if preSt, ok := decodePersistedUserpoolState(act.StateJSON); ok {
		if u, uok := preSt.Users[username]; uok && u.SessionGen > 0 {
			preSGen = u.SessionGen
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			st.Pool = hostkit.UserpoolInfo{Name: pool, PoolID: out.PoolID, IncarnationID: act.Incarnation, OwnerToken: act.OwnerToken}
		}
		sgen := out.SessionGen
		if sgen == 0 {
			if preSGen > 0 {
				sgen = preSGen
			} else if u, uok := st.Users[username]; uok && u.SessionGen > 0 {
				sgen = u.SessionGen
			} else {
				sgen = 1
			}
		}
		poolID := out.PoolID
		if poolID == "" && st.Pool.PoolID != "" {
			poolID = st.Pool.PoolID
		}
		incID := act.Incarnation
		if incID == "" {
			incID = out.IncarnationID
		}
		existing := st.TokenBindings[username]
		live := make([]tokenBindingRecord, 0, len(existing)+1)
		for _, b := range existing {
			if b.ExpiresAt > nowUnix {
				live = append(live, b)
			}
		}
		live = append(live, tokenBindingRecord{
			TokenSHA256:   tokenHash,
			Sub:           sub,
			Username:      username,
			PoolID:        poolID,
			IncarnationID: incID,
			SessionGen:    sgen,
			IssuedAt:      iat,
			ExpiresAt:     exp,
			Scope:         scopeFP,
		})
		if len(live) > hostkit.MaxSessionBindingsPerUser {
			live = live[len(live)-hostkit.MaxSessionBindingsPerUser:]
		}
		st.TokenBindings[username] = live
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return emptySession(), h.fail(op, pool, cerr)
	}

	h.ok()
	return &Session{
		accessToken: out.AccessToken,
		expiresIn:   out.ExpiresIn,
		claims:      copyMap(out.Claims),
	}, nil
}

// UserVerifyToken implements user_verify_token(pool, token).
func (h *Host) UserVerifyToken(dry bool, pool, token string) (*Session, error) {
	const op = "user_verify_token"
	if token != "" {
		h.errs.AddRedaction(token)
		for _, seg := range strings.Split(token, ".") {
			if len(seg) >= 8 {
				h.errs.AddRedaction(seg)
			}
		}
	}
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return emptySession(), h.fail(op, pool, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return emptySession(), h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return emptySession(), h.fail(op, pool, ce)
	}

	if dry {
		failed = true
		return emptySession(), h.fail(op, pool, hostkit.Preflightf("user_verify_token is not supported in dry-run mode (no tokens exist in dry mode)"))
	}

	// Stage 1: Structural validation (INVALID_ARGUMENT, http_status == 0) BEFORE pool existence check (design 17 §2.6).
	parsedJWT, ce := hostkit.ValidateJWTFormatAndParseUntrusted(token)
	if ce != nil {
		failed = true
		return emptySession(), h.fail(op, pool, ce)
	}

	if h.cfg.Userpools == nil {
		failed = true
		return emptySession(), h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return emptySession(), h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return emptySession(), h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindUserpool, pool)
	if cerr != nil {
		failed = true
		return emptySession(), h.fail(op, pool, cerr)
	}

	// Stage 2: Pool existence & ownership check (NOT_FOUND if pool does not exist).
	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return emptySession(), h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return emptySession(), h.fail(op, pool, abortErr)
		}
		failed = true
		return emptySession(), h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	poolInfo, derr := h.cfg.Userpools.DescribeUserPool(mctx, pool)
	dce := hostkit.AsCloudError(derr)
	if dce != nil {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, isDefinitiveUserpoolRefusal(dce), false)
		if abortErr != nil {
			failed = true
			return emptySession(), h.fail(op, pool, abortErr)
		}
		failed = true
		return emptySession(), h.fail(op, pool, dce)
	}

	// Stage 3: Trust & revocation verification (all failures -> UNAUTHENTICATED with fixed template message).
	unauthErr := hostkit.ProviderError(hostkit.Unauthenticated, 401, "InvalidToken", "token verification failed")
	nowUnix := h.cfg.Now().UTC().Unix()

	verified, vce := hostkit.VerifyRS256JWTWithKeySet(parsedJWT, poolInfo.PublicKeyPEM, poolInfo.KeyID, poolInfo.RotatedKeys, poolInfo.Issuer, nowUnix)
	ce = nil
	if vce != nil {
		ce = unauthErr
	} else if poolInfo.ClientID != "" && verified.ClientID != "" && verified.ClientID != poolInfo.ClientID {
		ce = unauthErr
	} else {
		// Journaled token-binding registry lookup by SHA-256 digest + per-user session_generation equality.
		sum := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(sum[:])
		scopeFP := h.userpoolScopeFingerprint()
		st, ok := decodePersistedUserpoolState(act.StateJSON)
		if !ok {
			ce = unauthErr
		} else {
			username := verified.Username
			var matched *tokenBindingRecord
			for i := range st.TokenBindings[username] {
				b := &st.TokenBindings[username][i]
				if b.TokenSHA256 == tokenHash {
					matched = b
					break
				}
			}
			if matched == nil {
				ce = unauthErr
			} else if matched.IncarnationID != act.Incarnation || (poolInfo.PoolID != "" && matched.PoolID != "" && matched.PoolID != poolInfo.PoolID) || matched.Scope != scopeFP {
				ce = unauthErr
			} else if nowUnix >= matched.ExpiresAt || matched.IssuedAt > nowUnix+hostkit.MaxClockSkewSeconds {
				ce = unauthErr
			} else {
				u, uok := st.Users[username]
				if !uok || !u.Enabled || u.SessionGen != matched.SessionGen {
					ce = unauthErr
				}
			}
		}
	}

	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, false)
	if abortErr != nil {
		failed = true
		return emptySession(), h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return emptySession(), h.fail(op, pool, ce)
	}

	h.ok()
	return &Session{
		accessToken: token,
		expiresIn:   verified.ExpiresIn,
		claims:      copyMap(verified.ClaimsMap),
	}, nil
}

// GroupCreate implements group_create(pool, group).
func (h *Host) GroupCreate(dry bool, pool, group string) (bool, error) {
	const op = "group_create"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return false, h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolGroupName(group); ce != nil {
		failed = true
		return false, h.fail(op, group, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return false, h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return false, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		if du.groups[group] {
			h.ok()
			return false, nil
		}
		if len(du.groups) >= hostkit.MaxGroupsPerPool {
			failed = true
			return false, h.fail(op, pool, hostkit.Preflightf("userpool %q group count exceeds maximum (%d)", pool, hostkit.MaxGroupsPerPool))
		}
		if du.groups == nil {
			du.groups = map[string]bool{}
		}
		du.groups[group] = true
		h.ov(ctx).setUserpool(pool, du)
		h.ok()
		return true, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return false, h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return false, h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return false, h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}
	if hasAct && act.StateJSON != "" {
		if st, ok := decodePersistedUserpoolState(act.StateJSON); ok {
			if !st.Groups[group] && len(st.Groups) >= hostkit.MaxGroupsPerPool {
				failed = true
				return false, h.fail(op, pool, hostkit.Preflightf("userpool %q group count exceeds maximum (%d)", pool, hostkit.MaxGroupsPerPool))
			}
		}
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindPoolGroup, pool+"/"+group)
	if cerr != nil {
		failed = true
		return false, h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return false, h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, pool, abortErr)
		}
		failed = true
		return false, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	genNum, _ := strconv.ParseUint(act.Generation, 10, 64)
	created, err := h.cfg.Userpools.CreateGroup(mctx, hostkit.GroupCreateInput{
		Pool:          pool,
		Group:         group,
		OwnerToken:    act.OwnerToken,
		IncarnationID: act.Incarnation,
		Generation:    genNum,
	})
	ce := hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveUserpoolRefusal(ce)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, err == nil || definitiveRefusal, created || !definitiveRefusal)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, pool, abortErr)
	}
	if err != nil {
		failed = true
		return false, h.fail(op, pool, ce)
	}

	var reconciledGroups map[string]bool
	var hasReconciledGroups bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledGroups, hasReconciledGroups = h.reconcileGroupsForCatalog(ctx, pool, false)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			st.Pool = hostkit.UserpoolInfo{Name: pool, IncarnationID: act.Incarnation, OwnerToken: act.OwnerToken}
		}
		if childSeq > 0 {
			if st.GroupSeq[group] > childSeq {
				return cur
			}
			st.GroupSeq[group] = childSeq
			st.Groups[group] = true
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledGroups {
			if reconciledGroups[group] {
				st.Groups[group] = true
			} else {
				delete(st.Groups, group)
				delete(st.Memberships, group)
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		st.Groups[group] = true
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return false, h.fail(op, pool, cerr)
	}

	h.ok()
	return created, nil
}

// GroupDelete implements group_delete(pool, group).
func (h *Host) GroupDelete(dry bool, pool, group string) (bool, error) {
	const op = "group_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return false, h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolGroupName(group); ce != nil {
		failed = true
		return false, h.fail(op, group, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return false, h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return false, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		existed := du.groups[group]
		delete(du.groups, group)
		delete(du.memberships, group)
		h.ov(ctx).setUserpool(pool, du)
		h.ok()
		return existed, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return false, h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return false, h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return false, h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
		IsCleanup: true,
	}, safety.KindPoolGroup, pool+"/"+group)
	if cerr != nil {
		failed = true
		return false, h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return false, h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, pool, abortErr)
		}
		failed = true
		return false, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	existed, err := h.cfg.Userpools.DeleteGroup(mctx, pool, group)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), ce == nil)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return false, h.fail(op, pool, ce)
	}

	var reconciledGroups map[string]bool
	var hasReconciledGroups bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledGroups, hasReconciledGroups = h.reconcileGroupsForCatalog(ctx, pool, true)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			return cur
		}
		if childSeq > 0 {
			if st.GroupSeq[group] <= childSeq {
				st.GroupSeq[group] = childSeq
				delete(st.Groups, group)
			}
			if members, gok := st.Memberships[group]; gok {
				filtered := members[:0]
				for _, m := range members {
					mKey := group + "/" + m
					if st.MembershipSeq[mKey] > childSeq {
						filtered = append(filtered, m)
					} else {
						st.MembershipSeq[mKey] = childSeq
					}
				}
				if len(filtered) == 0 {
					delete(st.Memberships, group)
				} else {
					st.Memberships[group] = filtered
				}
			}
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledGroups {
			if reconciledGroups[group] {
				st.Groups[group] = true
			} else {
				delete(st.Groups, group)
				delete(st.Memberships, group)
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		delete(st.Groups, group)
		delete(st.Memberships, group)
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return false, h.fail(op, pool, cerr)
	}

	h.ok()
	return existed, nil
}

// GroupList implements group_list(pool).
func (h *Host) GroupList(dry bool, pool string) ([]string, error) {
	const op = "group_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return nil, h.fail(op, pool, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return nil, h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return nil, h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return nil, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		out := make([]string, 0, len(du.groups))
		for g := range du.groups {
			out = append(out, g)
		}
		sort.Strings(out)
		h.ok()
		return out, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return nil, h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	_, _, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return nil, h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindUserpool, pool)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, pool, cerr)
	}
	groups, err := h.cfg.Userpools.ListGroups(mctx, pool)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), false)
	if abortErr != nil {
		failed = true
		return nil, h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return nil, h.fail(op, pool, ce)
	}
	sort.Strings(groups)
	h.ok()
	return groups, nil
}

// GroupAddUser implements group_add_user(pool, group, username).
func (h *Host) GroupAddUser(dry bool, pool, group, username string) error {
	const op = "group_add_user"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolGroupName(group); ce != nil {
		failed = true
		return h.fail(op, group, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		if !du.groups[group] {
			failed = true
			return h.fail(op, group, notFound(hostkit.AbsentGroup, fmt.Sprintf("group %q does not exist in userpool %q (dry-run preview)", group, pool)))
		}
		if _, ok := du.users[username]; !ok || du.deletedUser[username] {
			failed = true
			return h.fail(op, username, notFound(hostkit.AbsentUser, fmt.Sprintf("user %q does not exist in userpool %q (dry-run preview)", username, pool)))
		}
		if du.memberships == nil {
			du.memberships = map[string]map[string]bool{}
		}
		if du.memberships[group] == nil {
			du.memberships[group] = map[string]bool{}
		}
		if !du.memberships[group][username] {
			userGrpCount := 0
			for g, m := range du.memberships {
				if du.groups[g] && m[username] {
					userGrpCount++
				}
			}
			if userGrpCount >= hostkit.MaxGroupsPerUser {
				failed = true
				return h.fail(op, username, hostkit.Preflightf("user %q group membership count exceeds maximum (%d)", username, hostkit.MaxGroupsPerUser))
			}
			du.memberships[group][username] = true
			h.ov(ctx).setUserpool(pool, du)
		}
		h.ok()
		return nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindPoolMembership, pool+"/"+group+"/"+username)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return h.fail(op, pool, abortErr)
		}
		failed = true
		return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	added, err := h.cfg.Userpools.AddUserToGroup(mctx, pool, group, username)
	ce := hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveUserpoolRefusal(ce)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, err == nil || definitiveRefusal, added || !definitiveRefusal)
	if abortErr != nil {
		failed = true
		return h.fail(op, pool, abortErr)
	}
	if err != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	var reconciledUserGroups map[string]bool
	var hasReconciledUserGroups bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledUserGroups, hasReconciledUserGroups = h.reconcileUserGroupsForCatalog(ctx, pool, username, false)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			st.Pool = hostkit.UserpoolInfo{Name: pool, IncarnationID: act.Incarnation, OwnerToken: act.OwnerToken}
		}
		mKey := group + "/" + username
		if childSeq > 0 {
			if st.MembershipSeq[mKey] > childSeq {
				return cur
			}
			if st.GroupSeq[group] > childSeq && !st.Groups[group] {
				return cur
			}
			if _, uok := st.Users[username]; st.UserSeq[username] > childSeq && !uok {
				return cur
			}
			st.MembershipSeq[mKey] = childSeq
			members := st.Memberships[group]
			found := false
			for _, m := range members {
				if m == username {
					found = true
					break
				}
			}
			if !found {
				members = append(members, username)
				sort.Strings(members)
				st.Memberships[group] = members
			}
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledUserGroups {
			members := st.Memberships[group]
			if reconciledUserGroups[group] {
				found := false
				for _, m := range members {
					if m == username {
						found = true
						break
					}
				}
				if !found {
					members = append(members, username)
					sort.Strings(members)
					st.Memberships[group] = members
				}
			} else {
				filtered := members[:0]
				for _, m := range members {
					if m != username {
						filtered = append(filtered, m)
					}
				}
				if len(filtered) == 0 {
					delete(st.Memberships, group)
				} else {
					st.Memberships[group] = filtered
				}
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		members := st.Memberships[group]
		found := false
		for _, m := range members {
			if m == username {
				found = true
				break
			}
		}
		if !found {
			members = append(members, username)
			sort.Strings(members)
			st.Memberships[group] = members
		}
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	h.ok()
	return nil
}

// GroupRemoveUser implements group_remove_user(pool, group, username).
func (h *Host) GroupRemoveUser(dry bool, pool, group, username string) error {
	const op = "group_remove_user"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolGroupName(group); ce != nil {
		failed = true
		return h.fail(op, group, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		if !du.groups[group] {
			failed = true
			return h.fail(op, group, notFound(hostkit.AbsentGroup, fmt.Sprintf("group %q does not exist in userpool %q (dry-run preview)", group, pool)))
		}
		if _, ok := du.users[username]; !ok || du.deletedUser[username] {
			failed = true
			return h.fail(op, username, notFound(hostkit.AbsentUser, fmt.Sprintf("user %q does not exist in userpool %q (dry-run preview)", username, pool)))
		}
		if du.memberships != nil && du.memberships[group] != nil {
			delete(du.memberships[group], username)
			h.ov(ctx).setUserpool(pool, du)
		}
		h.ok()
		return nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
		IsCleanup: true,
	}, safety.KindPoolMembership, pool+"/"+group+"/"+username)
	if cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	exists, ownErr := h.checkUserpoolOwnershipInScope(mctx, pool, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveUserpoolRefusal(ownErr), false)
		failed = true
		return h.fail(op, pool, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return h.fail(op, pool, abortErr)
		}
		failed = true
		return h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist", pool)))
	}

	var childSeq uint64
	mctx = userpoolFenceCtx(mctx, act.OwnerToken, act.Incarnation, act.Generation)
	mctx = hostkit.WithUserpoolChildMutationSeqOut(mctx, &childSeq)
	err := h.cfg.Userpools.RemoveUserFromGroup(mctx, pool, group, username)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), ce == nil)
	if abortErr != nil {
		failed = true
		return h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return h.fail(op, pool, ce)
	}

	var reconciledUserGroups map[string]bool
	var hasReconciledUserGroups bool
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupUserpoolEntry(ep, pool); hasCur && curAct.StateJSON != act.StateJSON {
			reconciledUserGroups, hasReconciledUserGroups = h.reconcileUserGroupsForCatalog(ctx, pool, username, true)
		}
	}

	if cerr := h.cost.updateUserpoolState(ep, pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, ok := decodePersistedUserpoolState(cur)
		if !ok {
			return cur
		}
		mKey := group + "/" + username
		if childSeq > 0 {
			if st.MembershipSeq[mKey] > childSeq {
				return cur
			}
			st.MembershipSeq[mKey] = childSeq
			if members, gok := st.Memberships[group]; gok {
				filtered := members[:0]
				for _, m := range members {
					if m != username {
						filtered = append(filtered, m)
					}
				}
				if len(filtered) == 0 {
					delete(st.Memberships, group)
				} else {
					st.Memberships[group] = filtered
				}
			}
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedUserpoolState(st)
		}
		if hasReconciledUserGroups {
			members := st.Memberships[group]
			if reconciledUserGroups[group] {
				found := false
				for _, m := range members {
					if m == username {
						found = true
						break
					}
				}
				if !found {
					members = append(members, username)
					sort.Strings(members)
					st.Memberships[group] = members
				}
			} else {
				filtered := members[:0]
				for _, m := range members {
					if m != username {
						filtered = append(filtered, m)
					}
				}
				if len(filtered) == 0 {
					delete(st.Memberships, group)
				} else {
					st.Memberships[group] = filtered
				}
			}
			return encodePersistedUserpoolState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		if members, gok := st.Memberships[group]; gok {
			filtered := members[:0]
			for _, m := range members {
				if m != username {
					filtered = append(filtered, m)
				}
			}
			if len(filtered) == 0 {
				delete(st.Memberships, group)
			} else {
				st.Memberships[group] = filtered
			}
		}
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		failed = true
		return h.fail(op, pool, cerr)
	}

	h.ok()
	return nil
}

// UserGroups implements user_groups(pool, username).
func (h *Host) UserGroups(dry bool, pool, username string) ([]string, error) {
	const op = "user_groups"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateUserpoolName(pool); ce != nil {
		failed = true
		return nil, h.fail(op, pool, ce)
	}
	if ce := hostkit.ValidatePoolUsername(username); ce != nil {
		failed = true
		return nil, h.fail(op, username, ce)
	}

	ctx, cancel, e := h.opCtx("userpool", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, pool, e)
	}
	defer cancel()

	if ce := h.checkUserpoolRouteAllowed(ctx); ce != nil {
		failed = true
		return nil, h.fail(op, pool, ce)
	}

	if dry {
		du, e := h.dryResolveUserpool(ctx, pool)
		if e != nil {
			failed = true
			return nil, h.fail(op, pool, e)
		}
		if !du.exists {
			failed = true
			return nil, h.fail(op, pool, notFound(hostkit.AbsentUserpool, fmt.Sprintf("userpool %q does not exist (dry-run preview)", pool)))
		}
		if _, ok := du.users[username]; !ok || du.deletedUser[username] {
			failed = true
			return nil, h.fail(op, username, notFound(hostkit.AbsentUser, fmt.Sprintf("user %q does not exist in userpool %q (dry-run preview)", username, pool)))
		}
		var out []string
		for g, m := range du.memberships {
			if du.groups[g] && m[username] {
				out = append(out, g)
			}
		}
		sort.Strings(out)
		h.ok()
		return out, nil
	}

	if h.cfg.Userpools == nil {
		failed = true
		return nil, h.fail(op, pool, missingUserpools())
	}

	ep := hostkit.EndpointFrom(ctx)
	_, _, amb, hasAmb, cerr := h.cost.lookupUserpoolEntry(ep, pool)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, pool, cerr)
	}
	if hasAmb {
		failed = true
		return nil, h.fail(op, pool, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
			fmt.Sprintf("userpool %q has an unresolved ambiguous operation (%s) and requires reconciliation", pool, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindPoolUser, pool+"/"+username)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, pool, cerr)
	}
	groups, err := h.cfg.Userpools.ListUserGroups(mctx, pool, username)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveUserpoolRefusal(ce), false)
	if abortErr != nil {
		failed = true
		return nil, h.fail(op, pool, abortErr)
	}
	if ce != nil {
		failed = true
		return nil, h.fail(op, pool, ce)
	}
	sort.Strings(groups)
	h.ok()
	return groups, nil
}
