// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

type functionArtifact struct {
	CodeSHA256        string `json:"code_sha256"`
	TargetID          string `json:"target_id,omitempty"`
	PendingOpID       string `json:"pending_op_id,omitempty"`
	OpStartedUnixMS   int64  `json:"op_started_unix_ms,omitempty"`
	OperationTerminal bool   `json:"operation_terminal,omitempty"`
}

type functionSlot struct {
	InvocationID    string `json:"invocation_id"`
	CodeSHA256      string `json:"code_sha256"`
	TargetID        string `json:"target_id,omitempty"`
	ExpiresAtUnixMS int64  `json:"expires_at_unix_ms"`
}

type functionState struct {
	State             string                              `json:"state"`
	IncarnationID     string                              `json:"incarnation_id"`
	OpGen             uint64                              `json:"op_gen"`
	OwnerToken        string                              `json:"owner_token"`
	MaxGeneration     uint64                              `json:"max_generation"`
	ChildSeq          uint64                              `json:"child_seq,omitempty"`
	NextRevSeq        int64                               `json:"next_rev_seq"`
	NextVersion       int                                 `json:"next_version"`
	Latest            hostkit.FunctionSnapshot            `json:"latest"`
	Candidate         *functionArtifact                   `json:"candidate,omitempty"`
	PendingGC         []functionArtifact                  `json:"pending_gc,omitempty"`
	Versions          map[string]hostkit.FunctionSnapshot `json:"versions,omitempty"`
	VersionOrder      []string                            `json:"version_order,omitempty"`
	Aliases           map[string]string                   `json:"aliases,omitempty"`
	Bundles           map[string][]byte                   `json:"bundles,omitempty"`
	Slots             map[string]functionSlot             `json:"slots,omitempty"`
	ActiveInvocations map[string]functionSlot             `json:"active_invocations,omitempty"`
}

func ensureFunctionMaps(fn *functionState) {
	if fn.Versions == nil {
		fn.Versions = map[string]hostkit.FunctionSnapshot{}
	}
	if fn.Aliases == nil {
		fn.Aliases = map[string]string{}
	}
	if fn.Bundles == nil {
		fn.Bundles = map[string][]byte{}
	}
	if fn.Slots == nil {
		fn.Slots = map[string]functionSlot{}
	}
	if fn.ActiveInvocations == nil {
		fn.ActiveInvocations = map[string]functionSlot{}
	}
}

func nextFunctionRevisionID(fn *functionState, name string) string {
	fn.NextRevSeq++
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", name, fn.IncarnationID, fn.NextRevSeq)))
	return hex.EncodeToString(sum[:16])
}

func randomHex16() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0123456789abcdef0123456789abcdef"
	}
	return hex.EncodeToString(b[:])
}

func cleanExpiredFunctionInvocations(fn *functionState, nowMS int64) {
	ensureFunctionMaps(fn)
	for k, sl := range fn.Slots {
		if sl.ExpiresAtUnixMS <= nowMS {
			delete(fn.Slots, k)
		}
	}
	for k, sl := range fn.ActiveInvocations {
		if sl.ExpiresAtUnixMS <= nowMS {
			delete(fn.ActiveInvocations, k)
		}
	}
}

func isArtifactPinned(fn *functionState, art functionArtifact, nowMS int64) bool {
	if art.PendingOpID != "" && !art.OperationTerminal {
		return true
	}
	for _, sl := range fn.Slots {
		if sl.ExpiresAtUnixMS > nowMS && sl.CodeSHA256 == art.CodeSHA256 && (art.TargetID == "" || sl.TargetID == "" || sl.TargetID == art.TargetID) {
			return true
		}
	}
	for _, sl := range fn.ActiveInvocations {
		if sl.ExpiresAtUnixMS > nowMS && sl.CodeSHA256 == art.CodeSHA256 && (art.TargetID == "" || sl.TargetID == "" || sl.TargetID == art.TargetID) {
			return true
		}
	}
	return false
}

func isBundleSHA256Pinned(fn *functionState, sha string, nowMS int64) bool {
	for _, sl := range fn.Slots {
		if sl.ExpiresAtUnixMS > nowMS && sl.CodeSHA256 == sha {
			return true
		}
	}
	for _, sl := range fn.ActiveInvocations {
		if sl.ExpiresAtUnixMS > nowMS && sl.CodeSHA256 == sha {
			return true
		}
	}
	for _, art := range fn.PendingGC {
		if art.CodeSHA256 == sha && art.PendingOpID != "" && !art.OperationTerminal {
			return true
		}
	}
	return false
}

func isBundleSHA256Referenced(fn *functionState, sha string) bool {
	if fn.Latest.CodeSHA256 == sha {
		return true
	}
	if fn.Candidate != nil && fn.Candidate.CodeSHA256 == sha {
		return true
	}
	for _, vsnap := range fn.Versions {
		if vsnap.CodeSHA256 == sha {
			return true
		}
	}
	for _, art := range fn.PendingGC {
		if art.CodeSHA256 == sha {
			return true
		}
	}
	return false
}

func drainFunctionPendingGC(fn *functionState, nowMS int64) {
	cleanExpiredFunctionInvocations(fn, nowMS)
	if len(fn.PendingGC) > 0 {
		kept := fn.PendingGC[:0]
		for _, art := range fn.PendingGC {
			if isArtifactPinned(fn, art, nowMS) {
				kept = append(kept, art)
			}
		}
		fn.PendingGC = kept
	}
	for sha := range fn.Bundles {
		if !isBundleSHA256Referenced(fn, sha) && !isBundleSHA256Pinned(fn, sha, nowMS) {
			delete(fn.Bundles, sha)
		}
	}
}

func resolveFunctionSnapshot(fn *functionState, qualifier string) (hostkit.FunctionSnapshot, bool) {
	ensureFunctionMaps(fn)
	if qualifier == "" || qualifier == "$LATEST" {
		snap := fn.Latest.Clone()
		snap.Version = "$LATEST"
		snap.OwnerToken = fn.OwnerToken
		snap.IncarnationID = fn.IncarnationID
		return snap, true
	}
	if vsnap, ok := fn.Versions[qualifier]; ok {
		snap := vsnap.Clone()
		snap.Version = qualifier
		snap.OwnerToken = fn.OwnerToken
		snap.IncarnationID = fn.IncarnationID
		return snap, true
	}
	if targetVer, ok := fn.Aliases[qualifier]; ok {
		if vsnap, vok := fn.Versions[targetVer]; vok {
			snap := vsnap.Clone()
			snap.Version = targetVer
			snap.OwnerToken = fn.OwnerToken
			snap.IncarnationID = fn.IncarnationID
			return snap, true
		}
	}
	return hostkit.FunctionSnapshot{}, false
}

func isFunctionVisible(fn *functionState) bool {
	return fn != nil && fn.State != hostkit.FunctionStateCreating && fn.State != hostkit.FunctionStateDeleting
}

func verifyFunctionWriteFence(ctx context.Context, fn *functionState, name, expOwner string, gen uint64) error {
	fence := hostkit.FunctionMutationFenceFrom(ctx)
	if expOwner == "" {
		expOwner = fence.OwnerToken
	}
	if expOwner == "" {
		expOwner = hostkit.CreateToken(ctx)
	}
	if gen == 0 {
		gen = fence.Generation
	}
	if !validOwnerToken(fn.OwnerToken) || !validOwnerToken(expOwner) || fn.OwnerToken != expOwner {
		return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
			fmt.Sprintf("function %q owner token mismatch", name))
	}
	if fence.IncarnationID != "" && fn.IncarnationID != "" && fn.IncarnationID != fence.IncarnationID {
		return hostkit.ProviderError(hostkit.Conflict, 409, "StaleIncarnation",
			fmt.Sprintf("function %q incarnation mismatch: got %q, want %q", name, fn.IncarnationID, fence.IncarnationID))
	}
	if gen > 0 && gen < fn.MaxGeneration {
		return hostkit.ProviderError(hostkit.Conflict, 409, "StaleGeneration",
			fmt.Sprintf("stale generation %d < %d for function %q", gen, fn.MaxGeneration, name))
	}
	return nil
}

// doSilent accesses or mutates state under the process mutex and file lock without
// incrementing user-visible adapter call counters or checking enforce-mode auth.
func (f *Fake) doSilent(write bool, fn func(s *state) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.opts.StatePath == "" {
		return fn(f.mem)
	}
	lock, err := lockFile(f.opts.StatePath + ".lock")
	if err != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state lock: "+err.Error())
	}
	defer lock.unlock()
	s := newState()
	if raw, err := os.ReadFile(f.opts.StatePath); err == nil && len(raw) > 0 {
		if len(raw) > 64<<20 {
			return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state exceeds 64 MiB limit")
		}
		if err := json.Unmarshal(raw, s); err != nil {
			return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state is corrupt: "+err.Error())
		}
		if s.Buckets == nil {
			s.Buckets = map[string]map[string]*object{}
		}
		if s.Queues == nil {
			s.Queues = map[string][]*message{}
		}
		if s.Tables == nil {
			s.Tables = map[string]*tableState{}
		}
		if s.Policies == nil {
			s.Policies = map[string]hostkit.PolicyAttachment{}
		}
		if s.Functions == nil {
			s.Functions = map[string]*functionState{}
		}
		if s.Userpools == nil {
			s.Userpools = map[string]*userpoolState{}
		}
		if s.PolicyGenerations == nil {
			s.PolicyGenerations = map[string]uint64{}
		}
		if s.PolicyOwners == nil {
			s.PolicyOwners = map[string]string{}
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state read: "+err.Error())
	}
	ferr := fn(s)
	if !write {
		return ferr
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state encode: "+err.Error())
	}
	tmp := f.opts.StatePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state write: "+err.Error())
	}
	if err := os.Rename(tmp, f.opts.StatePath); err != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state rename: "+err.Error())
	}
	return ferr
}

// LastSandboxHostPIDs returns the host PIDs observed during the most recent sandboxed invocation.
func (f *Fake) LastSandboxHostPIDs() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.lastSandboxPIDs...)
}

// SetOverrideBilledMSForTesting overrides BilledMS returned by InvokeFunction under f.mu.
func (f *Fake) SetOverrideBilledMSForTesting(v int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts.OverrideBilledMS = v
}

// SetFaultInvokeAfterDispatchForTesting configures a post-dispatch fault callback on InvokeFunction under f.mu.
func (f *Fake) SetFaultInvokeAfterDispatchForTesting(fn func() error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts.FaultInvokeAfterDispatch = fn
}

// SetFaultMutatorAfterCommitForTesting configures a post-commit fault callback on function mutators under f.mu.
func (f *Fake) SetFaultMutatorAfterCommitForTesting(fn func(op string) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts.FaultMutatorAfterCommit = fn
}

// StagedBundleCount returns the number of retained staged bundles for function name (used by Gate G5).
func (f *Fake) StagedBundleCount(name string) int {
	var n int
	_ = f.doSilent(false, func(s *state) error {
		if fn, ok := s.Functions[name]; ok && fn != nil {
			n = len(fn.Bundles)
		}
		return nil
	})
	return n
}

// PendingGCCount returns the number of pending_gc entries for function name (used by Gate G5).
func (f *Fake) PendingGCCount(name string) int {
	var n int
	_ = f.doSilent(false, func(s *state) error {
		if fn, ok := s.Functions[name]; ok && fn != nil {
			n = len(fn.PendingGC)
		}
		return nil
	})
	return n
}

// InjectUnmarkedFunctionForTesting inserts a function with the given ownerToken directly into state.
func (f *Fake) InjectUnmarkedFunctionForTesting(name, ownerToken string, snap hostkit.FunctionSnapshot) error {
	return f.doSilent(true, func(s *state) error {
		if s.Functions == nil {
			s.Functions = map[string]*functionState{}
		}
		if s.Userpools == nil {
			s.Userpools = map[string]*userpoolState{}
		}
		fn := &functionState{
			State:         hostkit.FunctionStateActive,
			IncarnationID: randomHex16(),
			OpGen:         1,
			OwnerToken:    ownerToken,
			MaxGeneration: 1,
		}
		ensureFunctionMaps(fn)
		if snap.RevisionID == "" {
			snap.RevisionID = nextFunctionRevisionID(fn, name)
		}
		snap.Name = name
		snap.Version = "$LATEST"
		if len(snap.BundleZip) > 0 && snap.CodeSHA256 != "" {
			fn.Bundles[snap.CodeSHA256] = append([]byte(nil), snap.BundleZip...)
		}
		snap.BundleZip = nil
		fn.Latest = snap.Clone()
		s.Functions[name] = fn
		return nil
	})
}

// InjectCandidateForTesting injects an unconfirmed candidate artifact on an existing function (Gate G5c / G6b).
func (f *Fake) InjectCandidateForTesting(name, sha string, bundle []byte, pendingOpID string, terminal bool) error {
	return f.doSilent(true, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", "function not found")
		}
		ensureFunctionMaps(fn)
		if len(bundle) > 0 && sha != "" {
			fn.Bundles[sha] = append([]byte(nil), bundle...)
		}
		fn.Candidate = &functionArtifact{
			CodeSHA256:        sha,
			TargetID:          fmt.Sprintf("lmfn-%s-cand", name),
			PendingOpID:       pendingOpID,
			OpStartedUnixMS:   f.opts.Now().UnixMilli(),
			OperationTerminal: terminal,
		}
		return nil
	})
}

// MarkPendingOperationsTerminalForTesting marks any pending candidate or pending_gc operation on name as terminal.
func (f *Fake) MarkPendingOperationsTerminalForTesting(name string) error {
	return f.doSilent(true, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || fn == nil {
			return nil
		}
		if fn.Candidate != nil {
			fn.Candidate.OperationTerminal = true
		}
		for i := range fn.PendingGC {
			fn.PendingGC[i].OperationTerminal = true
		}
		return nil
	})
}

// FunctionOwnerToken implements hostkit.FunctionOwnershipReader.
func (f *Fake) FunctionOwnerToken(_ context.Context, name string) (string, bool, error) {
	var tok string
	var exists bool
	err := f.doTarget("FunctionOwnerToken", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			exists = false
			return nil
		}
		exists = true
		tok = fn.OwnerToken
		return nil
	})
	return tok, exists, err
}

// AuthoritativeAdapterSelf implements hostkit.AuthoritativeFunctionAdapter.
func (f *Fake) AuthoritativeAdapterSelf() any {
	return f
}

// SetBeforeInvokeLockForTesting sets an optional callback invoked at the start of InvokeFunction
// before acquiring the state lock.
func (f *Fake) SetBeforeInvokeLockForTesting(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts.BeforeInvokeLock = fn
}

// ResolveFunctionTarget implements hostkit.FunctionTargetPinner.
func (f *Fake) ResolveFunctionTarget(_ context.Context, name, qualifier string) (hostkit.FunctionSnapshot, bool) {
	var out hostkit.FunctionSnapshot
	var found bool
	_ = f.doSilent(false, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return nil
		}
		snap, ok := resolveFunctionSnapshot(fn, qualifier)
		if !ok {
			return nil
		}
		out = snap
		found = true
		return nil
	})
	return out, found
}

// PeekDryFunctionState implements hostkit.FunctionTargetPinner.
func (f *Fake) PeekDryFunctionState(_ context.Context, name string) (hostkit.FunctionSnapshot, map[string]hostkit.FunctionSnapshot, []string, map[string]string, bool) {
	var (
		latest       hostkit.FunctionSnapshot
		versions     map[string]hostkit.FunctionSnapshot
		versionOrder []string
		aliases      map[string]string
		found        bool
	)
	_ = f.doSilent(false, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return nil
		}
		ensureFunctionMaps(fn)
		latest = fn.Latest.Clone()
		versions = make(map[string]hostkit.FunctionSnapshot, len(fn.Versions))
		versionOrder = make([]string, 0, len(fn.Versions))
		for k, v := range fn.Versions {
			versions[k] = v.Clone()
			versionOrder = append(versionOrder, k)
		}
		sort.Slice(versionOrder, func(i, j int) bool {
			vi, _ := strconv.Atoi(versionOrder[i])
			vj, _ := strconv.Atoi(versionOrder[j])
			return vi < vj
		})
		aliases = make(map[string]string, len(fn.Aliases))
		for k, v := range fn.Aliases {
			aliases[k] = v
		}
		found = true
		return nil
	})
	return latest, versions, versionOrder, aliases, found
}

// PeekFunctionQuota implements hostkit.FunctionQuotaPeeker.
func (f *Fake) PeekFunctionQuota(_ context.Context, name, qualifier string) (int64, int64, bool) {
	var timeoutSec, memMB int64
	var found bool
	_ = f.doSilent(false, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return nil
		}
		snap, ok := resolveFunctionSnapshot(fn, qualifier)
		if !ok {
			return nil
		}
		timeoutSec = snap.TimeoutSeconds
		memMB = snap.MemoryMB
		found = true
		return nil
	})
	return timeoutSec, memMB, found
}

// PeekFunctionVersionHeadroom implements hostkit.FunctionQuotaPeeker.
func (f *Fake) PeekFunctionVersionHeadroom(_ context.Context, name, expectRevision string) (string, error) {
	var nextVer string
	err := f.doSilent(false, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)
		if expectRevision != "" && fn.Latest.RevisionID != expectRevision {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "PreconditionFailedException",
				fmt.Sprintf("function %q revision_id mismatch: got %q, want %q", name, fn.Latest.RevisionID, expectRevision))
		}
		if len(fn.Versions) >= hostkit.MaxFunctionVersions {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "ResourceLimitExceeded",
				fmt.Sprintf("function %q has reached the maximum of %d published versions", name, hostkit.MaxFunctionVersions))
		}
		nextVer = strconv.Itoa(fn.NextVersion + 1)
		return nil
	})
	return nextVer, err
}

// PeekFunctionAliasHeadroom implements hostkit.FunctionQuotaPeeker.
func (f *Fake) PeekFunctionAliasHeadroom(_ context.Context, name, alias, version string) (bool, error) {
	var isNew bool
	err := f.doSilent(false, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)
		if _, vok := fn.Versions[version]; !vok {
			return f.notFound("", "ResourceNotFoundException",
				fmt.Sprintf("function %q published version %q not found", name, version))
		}
		_, exists := fn.Aliases[alias]
		if !exists && len(fn.Aliases) >= hostkit.MaxFunctionAliases {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "ResourceLimitExceeded",
				fmt.Sprintf("function %q has reached the maximum of %d aliases", name, hostkit.MaxFunctionAliases))
		}
		isNew = !exists
		return nil
	})
	return isNew, err
}

// CreateFunction implements hostkit.Functions.
func (f *Fake) CreateFunction(ctx context.Context, in hostkit.FunctionUpdateInput) (bool, hostkit.FunctionSnapshot, error) {
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["CreateFunction"]++
		f.mu.Unlock()
		return false, hostkit.FunctionSnapshot{}, f.echoToken(ctx, "function")
	}
	var created bool
	var out hostkit.FunctionSnapshot
	name := in.Snapshot.Name
	err := f.doTarget("CreateFunction", name, func(s *state) error {
		if s.Functions == nil {
			s.Functions = map[string]*functionState{}
		}
		if s.Userpools == nil {
			s.Userpools = map[string]*userpoolState{}
		}
		ownerTok := in.OwnerToken
		if ownerTok == "" {
			ownerTok = hostkit.CreateToken(ctx)
		}
		if existing, ok := s.Functions[name]; ok && isFunctionVisible(existing) {
			if !validOwnerToken(existing.OwnerToken) || (ownerTok != "" && existing.OwnerToken != ownerTok) || (in.ExpectedOwnerToken != "" && existing.OwnerToken != in.ExpectedOwnerToken) {
				return hostkit.ProviderError(hostkit.Conflict, 409, "ResourceConflictException",
					fmt.Sprintf("function %q already exists under a different owner", name))
			}
			if in.Generation > 0 && in.Generation < existing.MaxGeneration {
				return hostkit.ProviderError(hostkit.Conflict, 409, "StaleGeneration",
					fmt.Sprintf("stale generation %d < %d for function %q", in.Generation, existing.MaxGeneration, name))
			}
			if !existing.Latest.SameCanonicalConfig(in.Snapshot) {
				return hostkit.ProviderError(hostkit.Conflict, 409, "ResourceConflictException",
					fmt.Sprintf("function %q already exists with a different configuration", name))
			}
			if in.Generation > existing.MaxGeneration {
				existing.MaxGeneration = in.Generation
			}
			created = false
			out = existing.Latest.Clone()
			return nil
		}

		fn := &functionState{
			State:         hostkit.FunctionStateActive,
			IncarnationID: randomHex16(),
			OpGen:         1,
			OwnerToken:    ownerTok,
			MaxGeneration: in.Generation,
		}
		ensureFunctionMaps(fn)
		snap := in.Snapshot.Clone()
		snap.Name = name
		snap.Version = "$LATEST"
		snap.RevisionID = nextFunctionRevisionID(fn, name)
		snap.Generation = in.Generation
		snap.OwnerToken = ownerTok
		snap.IncarnationID = fn.IncarnationID
		if len(snap.BundleZip) > 0 && snap.CodeSHA256 != "" {
			fn.Bundles[snap.CodeSHA256] = append([]byte(nil), snap.BundleZip...)
		}
		snap.BundleZip = nil
		fn.Latest = snap
		s.Functions[name] = fn
		created = true
		out = snap.Clone()
		return nil
	})
	if err == nil {
		f.mu.Lock()
		fault := f.opts.FaultMutatorAfterCommit
		f.mu.Unlock()
		if fault != nil {
			if ferr := fault("CreateFunction"); ferr != nil {
				return false, hostkit.FunctionSnapshot{}, ferr
			}
		}
	}
	return created, out, err
}

// UpdateFunction implements hostkit.Functions.
func (f *Fake) UpdateFunction(ctx context.Context, in hostkit.FunctionUpdateInput) (hostkit.FunctionSnapshot, error) {
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["UpdateFunction"]++
		f.mu.Unlock()
		return hostkit.FunctionSnapshot{}, f.echoToken(ctx, "function")
	}
	var out hostkit.FunctionSnapshot
	name := in.Snapshot.Name
	err := f.doTarget("UpdateFunction", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)

		expOwner := in.ExpectedOwnerToken
		if expOwner == "" {
			expOwner = in.OwnerToken
		}
		if err := verifyFunctionWriteFence(ctx, fn, name, expOwner, in.Generation); err != nil {
			return err
		}
		if in.ExpectRevision != "" && fn.Latest.RevisionID != in.ExpectRevision {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "PreconditionFailedException",
				fmt.Sprintf("function %q revision_id mismatch: got %q, want %q", name, fn.Latest.RevisionID, in.ExpectRevision))
		}

		nowMS := f.opts.Now().UnixMilli()
		// Fold any interrupted candidate into PendingGC and drain unpinned entries (§4.3.3.2).
		if fn.Candidate != nil {
			fn.PendingGC = append(fn.PendingGC, *fn.Candidate)
			fn.Candidate = nil
		}
		drainFunctionPendingGC(fn, nowMS)
		if len(fn.PendingGC) >= 2 {
			return hostkit.ProviderError(hostkit.Conflict, 409, "PendingGCBackpressure",
				fmt.Sprintf("function %q has %d displaced revisions still pinned by active invocations or pending operations", name, len(fn.PendingGC)))
		}

		snap := in.Snapshot.Clone()
		if len(snap.BundleZip) > 0 && snap.CodeSHA256 != "" {
			fn.Bundles[snap.CodeSHA256] = append([]byte(nil), snap.BundleZip...)
		} else if _, hasBundle := fn.Bundles[snap.CodeSHA256]; !hasBundle {
			return hostkit.ProviderError(hostkit.NotFound, 404, "BundleNotFound",
				fmt.Sprintf("staged bundle %q for function %q not found", snap.CodeSHA256, name))
		}
		snap.BundleZip = nil

		oldLatest := fn.Latest
		fn.OpGen++
		if in.Generation > fn.MaxGeneration {
			fn.MaxGeneration = in.Generation
		}
		snap.Name = name
		snap.Version = "$LATEST"
		snap.RevisionID = nextFunctionRevisionID(fn, name)
		snap.Generation = fn.MaxGeneration
		snap.OwnerToken = fn.OwnerToken
		snap.IncarnationID = fn.IncarnationID
		fn.Latest = snap

		// Post-commit synchronous GC of displaced $LATEST (§4.3.3.4).
		oldReferencedByVer := false
		for _, vsnap := range fn.Versions {
			if vsnap.CodeSHA256 == oldLatest.CodeSHA256 {
				oldReferencedByVer = true
				break
			}
		}
		if !oldReferencedByVer && oldLatest.CodeSHA256 != snap.CodeSHA256 {
			oldArt := functionArtifact{
				CodeSHA256:        oldLatest.CodeSHA256,
				TargetID:          oldLatest.RevisionID,
				OperationTerminal: true,
			}
			if isArtifactPinned(fn, oldArt, nowMS) {
				fn.PendingGC = append(fn.PendingGC, oldArt)
			}
		}
		drainFunctionPendingGC(fn, nowMS)

		out = snap.Clone()
		return nil
	})
	if err == nil {
		f.mu.Lock()
		fault := f.opts.FaultMutatorAfterCommit
		f.mu.Unlock()
		if fault != nil {
			if ferr := fault("UpdateFunction"); ferr != nil {
				return hostkit.FunctionSnapshot{}, ferr
			}
		}
	}
	return out, err
}

// DeleteFunction implements hostkit.Functions.
func (f *Fake) DeleteFunction(ctx context.Context, name string) (bool, error) {
	var existed bool
	err := f.doTarget("DeleteFunction", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			existed = false
			return nil
		}
		if err := verifyFunctionWriteFence(ctx, fn, name, "", 0); err != nil {
			return err
		}
		if fn.Candidate != nil && fn.Candidate.PendingOpID != "" && !fn.Candidate.OperationTerminal {
			return hostkit.ProviderError(hostkit.Conflict, 409, "OperationInProgress",
				fmt.Sprintf("function %q has a non-terminal provider operation %q", name, fn.Candidate.PendingOpID))
		}
		for _, art := range fn.PendingGC {
			if art.PendingOpID != "" && !art.OperationTerminal {
				return hostkit.ProviderError(hostkit.Conflict, 409, "OperationInProgress",
					fmt.Sprintf("function %q has a non-terminal pending_gc operation %q", name, art.PendingOpID))
			}
		}
		delete(s.Functions, name)
		deleteTargetPolicies(s, "function:function:"+name)
		existed = true
		return nil
	})
	if err == nil {
		f.mu.Lock()
		fault := f.opts.FaultMutatorAfterCommit
		f.mu.Unlock()
		if fault != nil {
			if ferr := fault("DeleteFunction"); ferr != nil {
				return false, ferr
			}
		}
	}
	return existed, err
}

// FunctionExists implements hostkit.Functions.
func (f *Fake) FunctionExists(_ context.Context, name string) (bool, error) {
	var exists bool
	err := f.doTarget("FunctionExists", name, func(s *state) error {
		fn, ok := s.Functions[name]
		exists = ok && isFunctionVisible(fn)
		return nil
	})
	return exists, err
}

// GetFunction implements hostkit.Functions.
func (f *Fake) GetFunction(_ context.Context, name, qualifier string) (hostkit.FunctionSnapshot, error) {
	var out hostkit.FunctionSnapshot
	err := f.doTarget("GetFunction", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		snap, found := resolveFunctionSnapshot(fn, qualifier)
		if !found {
			return f.notFound("", "ResourceNotFoundException",
				fmt.Sprintf("function %q qualifier %q not found", name, qualifier))
		}
		out = snap
		return nil
	})
	return out, err
}

// ListFunctions implements hostkit.Functions.
func (f *Fake) ListFunctions(_ context.Context) ([]string, error) {
	var names []string
	err := f.do("ListFunctions", func(s *state) error {
		names = make([]string, 0, len(s.Functions))
		for name, fn := range s.Functions {
			if isFunctionVisible(fn) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		return nil
	})
	return names, err
}

// PublishFunctionVersion implements hostkit.Functions.
func (f *Fake) PublishFunctionVersion(ctx context.Context, name, expectRevision string) (string, error) {
	var version string
	err := f.doTarget("PublishFunctionVersion", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)
		if err := verifyFunctionWriteFence(ctx, fn, name, "", 0); err != nil {
			return err
		}
		if expectRevision != "" && fn.Latest.RevisionID != expectRevision {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "PreconditionFailedException",
				fmt.Sprintf("function %q revision_id mismatch: got %q, want %q", name, fn.Latest.RevisionID, expectRevision))
		}
		if len(fn.Versions) >= hostkit.MaxFunctionVersions {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "ResourceLimitExceeded",
				fmt.Sprintf("function %q has reached the maximum of %d published versions", name, hostkit.MaxFunctionVersions))
		}
		fn.NextVersion++
		version = strconv.Itoa(fn.NextVersion)
		vsnap := fn.Latest.Clone()
		vsnap.Version = version
		vsnap.RevisionID = nextFunctionRevisionID(fn, name)
		fn.Versions[version] = vsnap
		fn.VersionOrder = append(fn.VersionOrder, version)
		// Rotate $LATEST's revision_id on version publish (§2.2).
		fn.Latest.RevisionID = nextFunctionRevisionID(fn, name)
		fn.ChildSeq++
		hostkit.ReportFunctionChildMutationSeq(ctx, fn.ChildSeq)
		return nil
	})
	return version, err
}

// ListFunctionVersions implements hostkit.Functions.
func (f *Fake) ListFunctionVersions(_ context.Context, name string) ([]string, error) {
	var out []string
	err := f.doTarget("ListFunctionVersions", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)
		out = make([]string, 0, len(fn.Versions))
		for v := range fn.Versions {
			out = append(out, v)
		}
		sort.Slice(out, func(i, j int) bool {
			vi, _ := strconv.Atoi(out[i])
			vj, _ := strconv.Atoi(out[j])
			return vi < vj
		})
		return nil
	})
	return out, err
}

// SetFunctionAlias implements hostkit.Functions.
func (f *Fake) SetFunctionAlias(ctx context.Context, name, alias, version string) (bool, error) {
	var created bool
	err := f.doTarget("SetFunctionAlias", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)
		if err := verifyFunctionWriteFence(ctx, fn, name, "", 0); err != nil {
			return err
		}
		if _, vok := fn.Versions[version]; !vok {
			return f.notFound("", "ResourceNotFoundException",
				fmt.Sprintf("function %q published version %q not found", name, version))
		}
		_, exists := fn.Aliases[alias]
		if !exists && len(fn.Aliases) >= hostkit.MaxFunctionAliases {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "ResourceLimitExceeded",
				fmt.Sprintf("function %q has reached the maximum of %d aliases", name, hostkit.MaxFunctionAliases))
		}
		fn.Aliases[alias] = version
		created = !exists
		fn.ChildSeq++
		hostkit.ReportFunctionChildMutationSeq(ctx, fn.ChildSeq)
		return nil
	})
	return created, err
}

// GetFunctionAlias implements hostkit.Functions.
func (f *Fake) GetFunctionAlias(_ context.Context, name, alias string) (string, error) {
	var targetVer string
	err := f.doTarget("GetFunctionAlias", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)
		targetVer = fn.Aliases[alias]
		return nil
	})
	return targetVer, err
}

// DeleteFunctionAlias implements hostkit.Functions.
func (f *Fake) DeleteFunctionAlias(ctx context.Context, name, alias string) (bool, error) {
	var existed bool
	err := f.doTarget("DeleteFunctionAlias", name, func(s *state) error {
		fn, ok := s.Functions[name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", name))
		}
		ensureFunctionMaps(fn)
		if err := verifyFunctionWriteFence(ctx, fn, name, "", 0); err != nil {
			return err
		}
		if _, ok := fn.Aliases[alias]; ok {
			delete(fn.Aliases, alias)
			existed = true
		}
		fn.ChildSeq++
		hostkit.ReportFunctionChildMutationSeq(ctx, fn.ChildSeq)
		return nil
	})
	return existed, err
}

// InvokeFunction implements hostkit.Functions.
func (f *Fake) InvokeFunction(ctx context.Context, in hostkit.FunctionInvokeInput) (hostkit.FunctionInvokeOutput, error) {
	f.mu.Lock()
	beforeHook := f.opts.BeforeInvokeLock
	f.mu.Unlock()
	if beforeHook != nil {
		beforeHook()
	}

	var (
		targetSnap hostkit.FunctionSnapshot
		bundleZip  []byte
		invID      = randomHex16()
		slotKey    string
	)

	// Phase 1: Authorize, resolve qualifier, verify pinned target/owner/quota, and acquire concurrency slot / active-invocation pin.
	err := f.doTarget("InvokeFunction", in.Name, func(s *state) error {
		fn, ok := s.Functions[in.Name]
		if !ok || !isFunctionVisible(fn) {
			return f.notFound("", "ResourceNotFoundException", fmt.Sprintf("function %q not found", in.Name))
		}
		ensureFunctionMaps(fn)
		if in.ExpectedOwnerToken != "" {
			if !validOwnerToken(fn.OwnerToken) || fn.OwnerToken != in.ExpectedOwnerToken {
				return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
					fmt.Sprintf("function %q owner token mismatch", in.Name))
			}
		}
		if in.ExpectedIncarnation != "" && fn.IncarnationID != "" && fn.IncarnationID != in.ExpectedIncarnation {
			return hostkit.ProviderError(hostkit.Conflict, 409, "ConcurrentTargetModification",
				fmt.Sprintf("function %q incarnation changed before invocation dispatch", in.Name))
		}
		snap, found := resolveFunctionSnapshot(fn, in.Qualifier)
		if !found {
			return f.notFound("", "ResourceNotFoundException",
				fmt.Sprintf("function %q qualifier %q not found", in.Name, in.Qualifier))
		}
		if in.RejectIfPresent {
			return hostkit.ProviderError(hostkit.Conflict, 409, "ConcurrentTargetModification",
				fmt.Sprintf("function %q qualifier %q appeared after invocation admission", in.Name, in.Qualifier))
		}
		if (in.ExpectedRevisionID != "" && snap.RevisionID != in.ExpectedRevisionID) ||
			(in.ExpectedVersion != "" && snap.Version != in.ExpectedVersion) ||
			(in.ExpectedTimeoutSec > 0 && snap.TimeoutSeconds != in.ExpectedTimeoutSec) ||
			(in.ExpectedMemoryMB > 0 && snap.MemoryMB != in.ExpectedMemoryMB) {
			return hostkit.ProviderError(hostkit.Conflict, 409, "ConcurrentTargetModification",
				fmt.Sprintf("function %q target %q changed between admission and execution dispatch", in.Name, in.Qualifier))
		}

		// Concurrency is enforced across the function (§4.3.5).
		conc := fn.Latest.Concurrency
		if conc == -1 || snap.Concurrency == -1 {
			return hostkit.ProviderError(hostkit.PreconditionFailed, 429, "TooManyRequestsException",
				fmt.Sprintf("function %q has concurrency set to -1 (throttled)", in.Name))
		}

		nowMS := f.opts.Now().UnixMilli()
		cleanExpiredFunctionInvocations(fn, nowMS)
		expiresAt := nowMS + snap.TimeoutSeconds*1000 + 5000

		if conc > 0 {
			acquired := ""
			for i := 1; i <= int(conc); i++ {
				sk := strconv.Itoa(i)
				if cur, busy := fn.Slots[sk]; !busy || cur.ExpiresAtUnixMS <= nowMS {
					acquired = sk
					break
				}
			}
			if acquired == "" {
				return hostkit.ProviderError(hostkit.PreconditionFailed, 429, "TooManyRequestsException",
					fmt.Sprintf("function %q concurrency limit (%d) exceeded", in.Name, conc))
			}
			slotKey = acquired
			fn.Slots[slotKey] = functionSlot{
				InvocationID:    invID,
				CodeSHA256:      snap.CodeSHA256,
				TargetID:        snap.RevisionID,
				ExpiresAtUnixMS: expiresAt,
			}
		} else {
			fn.ActiveInvocations[invID] = functionSlot{
				InvocationID:    invID,
				CodeSHA256:      snap.CodeSHA256,
				TargetID:        snap.RevisionID,
				ExpiresAtUnixMS: expiresAt,
			}
		}

		rawZip, ok := fn.Bundles[snap.CodeSHA256]
		if !ok || len(rawZip) == 0 {
			return hostkit.ProviderError(hostkit.Internal, 0, "BundleMissing",
				fmt.Sprintf("staged bundle %q for function %q is missing", snap.CodeSHA256, in.Name))
		}
		bundleZip = append([]byte(nil), rawZip...)
		targetSnap = snap
		return nil
	})
	if err != nil {
		return hostkit.FunctionInvokeOutput{}, err
	}

	releaseSlot := func() {
		_ = f.doSilent(true, func(s *state) error {
			fn, ok := s.Functions[in.Name]
			if !ok || fn == nil {
				return nil
			}
			ensureFunctionMaps(fn)
			if slotKey != "" {
				if cur, ok := fn.Slots[slotKey]; ok && cur.InvocationID == invID {
					delete(fn.Slots, slotKey)
				}
			}
			if cur, ok := fn.ActiveInvocations[invID]; ok && cur.InvocationID == invID {
				delete(fn.ActiveInvocations, invID)
			}
			return nil
		})
	}

	if cerr := f.ensureSandboxReady(); cerr != nil {
		releaseSlot()
		return hostkit.FunctionInvokeOutput{}, cerr
	}

	// Phase 2: Execute handler inside isolated Linux namespace + Landlock sandbox outside state lock.
	out, pids, execErr := executeInNamespaceJail(ctx, cachedPythonBin, cachedNodeBin, cachedNodeRoot, sandboxExecSpec{
		FunctionName:    in.Name,
		ExecutedVersion: targetSnap.Version,
		Runtime:         targetSnap.Runtime,
		Handler:         targetSnap.Handler,
		BundleZip:       bundleZip,
		TimeoutSeconds:  targetSnap.TimeoutSeconds,
		MemoryMB:        targetSnap.MemoryMB,
		Env:             targetSnap.Env,
		PayloadJSON:     in.PayloadJSON,
	})
	f.mu.Lock()
	f.lastSandboxPIDs = pids
	faultFn := f.opts.FaultInvokeAfterDispatch
	overrideBilled := f.opts.OverrideBilledMS
	f.mu.Unlock()

	if faultFn != nil {
		if ferr := faultFn(); ferr != nil {
			// Do NOT release slot early on lost reply / mid-flight connection drop (§4.3.5).
			return hostkit.FunctionInvokeOutput{}, ferr
		}
	}

	if execErr != nil {
		// If caller context was cancelled mid-flight, keep the slot held until ExpiresAtUnixMS (§4.3.5).
		if ctx.Err() == nil {
			releaseSlot()
		}
		return hostkit.FunctionInvokeOutput{}, execErr
	}

	// Completed 200 response: release concurrency slot / active-invocation pin early (§4.3.5).
	releaseSlot()

	if overrideBilled != 0 {
		out.BilledMS = overrideBilled
	}
	return out, nil
}
