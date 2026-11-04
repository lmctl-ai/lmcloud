// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func missingFunctions() *hostkit.CloudError {
	return hostkit.ProviderError(hostkit.Internal, 0, "FunctionsNotConfigured",
		"host was constructed without a Functions adapter")
}

// FunctionConfig is the mutable builder and readback snapshot for a serverless function.
type FunctionConfig struct {
	h              *Host
	name           string
	exists         bool
	state          string
	runtime        string
	handler        string
	codeSource     string
	inlineCode     string
	packageBucket  string
	packageKey     string
	codeSHA256     string
	timeoutSeconds int64
	memoryMB       int64
	concurrency    int64
	env            map[string]string
	version        string
	revisionID     string
	bundleZip      []byte
	invalid        *hostkit.CloudError
}

func (fc *FunctionConfig) builderFail(op, target string, e *hostkit.CloudError) error {
	if fc != nil {
		fc.invalid = e
	}
	if fc != nil && fc.h != nil {
		return fc.h.fail(op, target, e)
	}
	return e
}

func (fc *FunctionConfig) builderOK() {
	if fc != nil && fc.h != nil {
		fc.h.ok()
	}
}

func (fc *FunctionConfig) clone() *FunctionConfig {
	if fc == nil {
		return nil
	}
	out := *fc
	if fc.env != nil {
		out.env = make(map[string]string, len(fc.env))
		for k, v := range fc.env {
			out.env[k] = v
		}
	}
	if fc.bundleZip != nil {
		out.bundleZip = append([]byte(nil), fc.bundleZip...)
	}
	return &out
}

func (fc *FunctionConfig) writableTarget() *FunctionConfig {
	if fc != nil && fc.exists {
		cp := fc.clone()
		cp.exists = false
		return cp
	}
	return fc
}

func (fc *FunctionConfig) Name() string          { return fc.name }
func (fc *FunctionConfig) Exists() bool          { return fc.exists }
func (fc *FunctionConfig) State() string         { return fc.state }
func (fc *FunctionConfig) Runtime() string       { return fc.runtime }
func (fc *FunctionConfig) Handler() string       { return fc.handler }
func (fc *FunctionConfig) CodeSource() string    { return fc.codeSource }
func (fc *FunctionConfig) InlineCode() string    { return fc.inlineCode }
func (fc *FunctionConfig) PackageBucket() string { return fc.packageBucket }
func (fc *FunctionConfig) PackageKey() string    { return fc.packageKey }
func (fc *FunctionConfig) CodeSHA256() string    { return fc.codeSHA256 }
func (fc *FunctionConfig) TimeoutSeconds() int64 { return fc.timeoutSeconds }
func (fc *FunctionConfig) MemoryMB() int64       { return fc.memoryMB }
func (fc *FunctionConfig) Concurrency() int64    { return fc.concurrency }
func (fc *FunctionConfig) Version() string       { return fc.version }
func (fc *FunctionConfig) RevisionID() string    { return fc.revisionID }

func (fc *FunctionConfig) Env(key string) (string, error) {
	if fc != nil && fc.env != nil {
		if v, ok := fc.env[key]; ok {
			fc.builderOK()
			return v, nil
		}
	}
	ce := hostkit.Preflightf("env key %q is not set on FunctionConfig", key)
	if fc != nil && fc.h != nil {
		return "", fc.h.fail("FunctionConfig.env", key, ce)
	}
	return "", ce
}

func (fc *FunctionConfig) HasEnv(key string) bool {
	if fc == nil || fc.env == nil {
		return false
	}
	_, ok := fc.env[key]
	return ok
}

func (fc *FunctionConfig) EnvNames() []string {
	if fc == nil || len(fc.env) == 0 {
		return []string{}
	}
	names := make([]string, 0, len(fc.env))
	for k := range fc.env {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (fc *FunctionConfig) EnvLen() int64 {
	if fc == nil {
		return 0
	}
	return int64(len(fc.env))
}

func (fc *FunctionConfig) SetRuntime(runtime string) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if ce := hostkit.ValidateFunctionRuntime(runtime); ce != nil {
		return t, t.builderFail("FunctionConfig.set_runtime", runtime, ce)
	}
	if t.codeSource == hostkit.FunctionCodeSourceInline && t.inlineCode != "" {
		zipBytes, sha, ce := hostkit.BuildDeterministicInlineZip(runtime, t.handler, t.inlineCode)
		if ce != nil {
			return t, t.builderFail("FunctionConfig.set_runtime", runtime, ce)
		}
		t.codeSHA256 = sha
		t.bundleZip = zipBytes
	}
	t.runtime = runtime
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) SetHandler(handler string) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if ce := hostkit.ValidateFunctionHandler(handler); ce != nil {
		return t, t.builderFail("FunctionConfig.set_handler", handler, ce)
	}
	if t.codeSource == hostkit.FunctionCodeSourceInline && t.inlineCode != "" {
		zipBytes, sha, ce := hostkit.BuildDeterministicInlineZip(t.runtime, handler, t.inlineCode)
		if ce != nil {
			return t, t.builderFail("FunctionConfig.set_handler", handler, ce)
		}
		t.codeSHA256 = sha
		t.bundleZip = zipBytes
	}
	t.handler = handler
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) SetInlineCode(code string) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if ce := hostkit.ValidateFunctionInlineCode(code); ce != nil {
		return t, t.builderFail("FunctionConfig.set_inline_code", t.name, ce)
	}
	zipBytes, sha, ce := hostkit.BuildDeterministicInlineZip(t.runtime, t.handler, code)
	if ce != nil {
		return t, t.builderFail("FunctionConfig.set_inline_code", t.name, ce)
	}
	t.codeSource = hostkit.FunctionCodeSourceInline
	t.inlineCode = code
	t.packageBucket = ""
	t.packageKey = ""
	t.codeSHA256 = sha
	t.bundleZip = zipBytes
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) SetPackageObject(bucket, key string) (*FunctionConfig, error) {
	t := fc.writableTarget()
	v := hostkit.Validator{}
	if t != nil && t.h != nil && t.h.cfg.Validator != nil {
		v = *t.h.cfg.Validator
	}
	if ce := v.Bucket(bucket); ce != nil {
		return t, t.builderFail("FunctionConfig.set_package_object", bucket, ce)
	}
	if ce := v.Key(key); ce != nil {
		return t, t.builderFail("FunctionConfig.set_package_object", key, ce)
	}
	t.codeSource = hostkit.FunctionCodeSourceObject
	t.packageBucket = bucket
	t.packageKey = key
	t.inlineCode = ""
	t.codeSHA256 = ""
	t.bundleZip = nil
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) SetTimeoutSeconds(sec int64) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if ce := hostkit.ValidateFunctionTimeout(sec); ce != nil {
		return t, t.builderFail("FunctionConfig.set_timeout_seconds", t.name, ce)
	}
	t.timeoutSeconds = sec
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) SetMemoryMB(mb int64) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if ce := hostkit.ValidateFunctionMemoryMB(mb); ce != nil {
		return t, t.builderFail("FunctionConfig.set_memory_mb", t.name, ce)
	}
	t.memoryMB = mb
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) SetConcurrency(c int64) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if ce := hostkit.ValidateFunctionConcurrency(c); ce != nil {
		return t, t.builderFail("FunctionConfig.set_concurrency", t.name, ce)
	}
	t.concurrency = c
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) SetEnv(key, val string) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if t != nil && t.h != nil && val != "" {
		t.h.errs.AddRedaction(val)
	}
	if ce := hostkit.ValidateFunctionEnvKey(key); ce != nil {
		return t, t.builderFail("FunctionConfig.set_env", key, ce)
	}
	if ce := hostkit.ValidateFunctionEnvValue(val); ce != nil {
		return t, t.builderFail("FunctionConfig.set_env", key, ce)
	}
	next := make(map[string]string, len(t.env)+1)
	for k, v := range t.env {
		next[k] = v
	}
	next[key] = val
	if ce := hostkit.ValidateFunctionEnvMap(next); ce != nil {
		return t, t.builderFail("FunctionConfig.set_env", key, ce)
	}
	t.env = next
	t.builderOK()
	return t, nil
}

func (fc *FunctionConfig) RemoveEnv(key string) (*FunctionConfig, error) {
	t := fc.writableTarget()
	if ce := hostkit.ValidateFunctionEnvKey(key); ce != nil {
		return t, t.builderFail("FunctionConfig.remove_env", key, ce)
	}
	if t.env != nil {
		delete(t.env, key)
	}
	t.builderOK()
	return t, nil
}

func (h *Host) snapshotToFunctionConfig(snap hostkit.FunctionSnapshot, exists bool, state string) *FunctionConfig {
	envCopy := make(map[string]string, len(snap.Env))
	for k, v := range snap.Env {
		envCopy[k] = v
		if v != "" {
			h.errs.AddRedaction(v)
		}
	}
	var zipCopy []byte
	if snap.BundleZip != nil {
		zipCopy = append([]byte(nil), snap.BundleZip...)
	}
	return &FunctionConfig{
		h:              h,
		name:           snap.Name,
		exists:         exists,
		state:          state,
		runtime:        snap.Runtime,
		handler:        snap.Handler,
		codeSource:     snap.CodeSource,
		inlineCode:     snap.InlineCode,
		packageBucket:  snap.PackageBucket,
		packageKey:     snap.PackageKey,
		codeSHA256:     snap.CodeSHA256,
		timeoutSeconds: snap.TimeoutSeconds,
		memoryMB:       snap.MemoryMB,
		concurrency:    snap.Concurrency,
		env:            envCopy,
		version:        snap.Version,
		revisionID:     snap.RevisionID,
		bundleZip:      zipCopy,
	}
}

func (h *Host) missingFunctionConfig(name string) *FunctionConfig {
	return &FunctionConfig{
		h:      h,
		name:   name,
		exists: false,
		state:  "",
		env:    map[string]string{},
	}
}

// FunctionInvokeResult is the immutable result of a synchronous function invocation.
type FunctionInvokeResult struct {
	statusCode      int64
	payload         string
	logs            string
	functionError   string
	executedVersion string
	durationMS      float64
	billedMS        int64
	memoryMB        int64
}

func (r *FunctionInvokeResult) StatusCode() int64       { return r.statusCode }
func (r *FunctionInvokeResult) Payload() string         { return r.payload }
func (r *FunctionInvokeResult) Logs() string            { return r.logs }
func (r *FunctionInvokeResult) FunctionError() string   { return r.functionError }
func (r *FunctionInvokeResult) IsError() bool           { return r.functionError != "" }
func (r *FunctionInvokeResult) ExecutedVersion() string { return r.executedVersion }
func (r *FunctionInvokeResult) DurationMS() float64     { return r.durationMS }
func (r *FunctionInvokeResult) BilledMS() int64         { return r.billedMS }
func (r *FunctionInvokeResult) MemoryMB() int64         { return r.memoryMB }

func (h *Host) checkFunctionRouteAllowed(ctx context.Context) *hostkit.CloudError {
	ctx = hostkit.WithForbidLiveRoute(ctx)
	if ep := hostkit.EndpointFrom(ctx); ep != "" && !hostkit.IsLoopbackEndpoint(ep) {
		return hostkit.ProviderError(hostkit.PermissionDenied, 403, "LiveModeUnsupported",
			"live mode refuses function operations: live function slice is not enabled")
	}
	if ce := checkAdapterLiveRouteAllowed(ctx, h.cfg.Functions); ce != nil {
		return ce
	}
	if h.cost != nil {
		if ce := h.cost.checkFunctionAllowed(); ce != nil {
			return ce
		}
	}
	return nil
}

func functionCanonicalDigest(snap hostkit.FunctionSnapshot) string {
	type canonical struct {
		Runtime        string            `json:"runtime"`
		Handler        string            `json:"handler"`
		CodeSource     string            `json:"code_source"`
		CodeSHA256     string            `json:"code_sha256"`
		PackageBucket  string            `json:"package_bucket,omitempty"`
		PackageKey     string            `json:"package_key,omitempty"`
		TimeoutSeconds int64             `json:"timeout_seconds"`
		MemoryMB       int64             `json:"memory_mb"`
		Concurrency    int64             `json:"concurrency"`
		Env            map[string]string `json:"env,omitempty"`
	}
	b, _ := json.Marshal(canonical{
		Runtime:        snap.Runtime,
		Handler:        snap.Handler,
		CodeSource:     snap.CodeSource,
		CodeSHA256:     snap.CodeSHA256,
		PackageBucket:  snap.PackageBucket,
		PackageKey:     snap.PackageKey,
		TimeoutSeconds: snap.TimeoutSeconds,
		MemoryMB:       snap.MemoryMB,
		Concurrency:    snap.Concurrency,
		Env:            snap.Env,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func isDefinitiveFunctionRefusal(ce *hostkit.CloudError) bool {
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

func (h *Host) validateFunctionConfig(cfg *FunctionConfig) *hostkit.CloudError {
	if cfg == nil {
		return hostkit.Preflightf("function config must not be nil")
	}
	if cfg.invalid != nil {
		return cfg.invalid
	}
	if ce := hostkit.ValidateFunctionRuntime(cfg.runtime); ce != nil {
		return ce
	}
	if ce := hostkit.ValidateFunctionHandler(cfg.handler); ce != nil {
		return ce
	}
	switch cfg.codeSource {
	case hostkit.FunctionCodeSourceInline:
		if ce := hostkit.ValidateFunctionInlineCode(cfg.inlineCode); ce != nil {
			return ce
		}
	case hostkit.FunctionCodeSourceObject:
		if ce := h.cfg.Validator.Bucket(cfg.packageBucket); ce != nil {
			return ce
		}
		if ce := h.cfg.Validator.Key(cfg.packageKey); ce != nil {
			return ce
		}
	default:
		return hostkit.Preflightf("function config must specify code via set_inline_code or set_package_object")
	}
	if ce := hostkit.ValidateFunctionTimeout(cfg.timeoutSeconds); ce != nil {
		return ce
	}
	if ce := hostkit.ValidateFunctionMemoryMB(cfg.memoryMB); ce != nil {
		return ce
	}
	if ce := hostkit.ValidateFunctionConcurrency(cfg.concurrency); ce != nil {
		return ce
	}
	for _, v := range cfg.env {
		if v != "" {
			h.errs.AddRedaction(v)
		}
	}
	if ce := hostkit.ValidateFunctionEnvMap(cfg.env); ce != nil {
		return ce
	}
	return nil
}

func (h *Host) stageFunctionBundle(ctx context.Context, dry bool, name string, cfg *FunctionConfig, allowRetained bool) (hostkit.FunctionSnapshot, int64, *hostkit.CloudError) {
	envCopy := make(map[string]string, len(cfg.env))
	for k, v := range cfg.env {
		envCopy[k] = v
	}
	snap := hostkit.FunctionSnapshot{
		Name:           name,
		Runtime:        cfg.runtime,
		Handler:        cfg.handler,
		CodeSource:     cfg.codeSource,
		InlineCode:     cfg.inlineCode,
		PackageBucket:  cfg.packageBucket,
		PackageKey:     cfg.packageKey,
		TimeoutSeconds: cfg.timeoutSeconds,
		MemoryMB:       cfg.memoryMB,
		Concurrency:    cfg.concurrency,
		Env:            envCopy,
		Version:        "$LATEST",
	}

	if cfg.codeSource == hostkit.FunctionCodeSourceInline {
		zipBytes, sha, ce := hostkit.BuildDeterministicInlineZip(cfg.runtime, cfg.handler, cfg.inlineCode)
		if ce != nil {
			return hostkit.FunctionSnapshot{}, 0, ce
		}
		snap.CodeSHA256 = sha
		snap.BundleZip = zipBytes
		return snap, int64(len(cfg.inlineCode)), nil
	}

	// Object package source: if allowRetained is true and cfg already carries a committed
	// codeSHA256 from function_get/function_update without set_package_object having been
	// called again, reuse the retained content-addressed bundle without re-reading the bucket.
	if allowRetained && cfg.codeSHA256 != "" {
		snap.CodeSHA256 = cfg.codeSHA256
		if cfg.bundleZip != nil {
			snap.BundleZip = append([]byte(nil), cfg.bundleZip...)
		}
		return snap, int64(len(snap.BundleZip)), nil
	}

	if dry {
		sum := sha256.Sum256([]byte(cfg.packageBucket + "/" + cfg.packageKey))
		snap.CodeSHA256 = hex.EncodeToString(sum[:])
		return snap, 0, nil
	}

	sctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return hostkit.FunctionSnapshot{}, 0, e
	}
	defer cancel()
	sctx = hostkit.WithForbidLiveRoute(sctx)
	if ce := checkAdapterLiveRouteAllowed(sctx, h.cfg.Store); ce != nil {
		return hostkit.FunctionSnapshot{}, 0, ce
	}
	if h.cfg.Store == nil {
		return hostkit.FunctionSnapshot{}, 0, missingStore()
	}

	mctx, scope, cerr := h.beginAttemptScope(sctx, "object_get", safety.AttemptPricingInput{
		Operation:   "object_get",
		EgressBytes: hostkit.MaxFunctionPackageBytes,
	}, safety.KindObject, target(cfg.packageBucket, cfg.packageKey))
	if cerr != nil {
		return hostkit.FunctionSnapshot{}, 0, cerr
	}
	rawBytes, err := h.cfg.Store.GetObject(mctx, cfg.packageBucket, cfg.packageKey, hostkit.MaxFunctionPackageBytes)
	if err != nil {
		ce := hostkit.AsCloudError(err)
		_, _, abortErr := scope.finish(0, 0, isNotFound(ce), false)
		if abortErr != nil {
			ce = abortErr
		}
		return hostkit.FunctionSnapshot{}, 0, ce
	}
	if len(rawBytes) > hostkit.MaxFunctionPackageBytes {
		_, _, abortErr := scope.finish(int64(len(rawBytes)), int64(len(rawBytes)), true, false)
		ce := hostkit.Preflightf("package object %q size %d exceeds maximum compressed size of %d bytes (16 MiB)",
			cfg.packageKey, len(rawBytes), hostkit.MaxFunctionPackageBytes)
		if abortErr != nil {
			ce = abortErr
		}
		return hostkit.FunctionSnapshot{}, 0, ce
	}
	_, _, abortErr := scope.finish(int64(len(rawBytes)), int64(len(rawBytes)), true, true)
	if abortErr != nil {
		return hostkit.FunctionSnapshot{}, 0, abortErr
	}

	zipBytes, sha, ce := hostkit.ValidateAndCanonicalizePackage(cfg.runtime, cfg.handler, cfg.packageKey, rawBytes)
	if ce != nil {
		return hostkit.FunctionSnapshot{}, 0, ce
	}
	snap.CodeSHA256 = sha
	snap.BundleZip = zipBytes
	return snap, int64(len(zipBytes)), nil
}

func (h *Host) realFunctionExists(ctx context.Context, name string) (bool, *hostkit.CloudError) {
	if h.cfg.Functions == nil {
		return false, missingFunctions()
	}
	ep := hostkit.EndpointFrom(ctx)
	_, _, _, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		return false, cerr
	}
	if hasAmb {
		return false, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation and requires reconciliation", name))
	}
	exists, err := h.cfg.Functions.FunctionExists(ctx, name)
	if err != nil {
		return false, hostkit.AsCloudError(err)
	}
	return exists, nil
}

func (h *Host) meteredFunctionExists(ctx context.Context, name string, isCleanup bool) (bool, *hostkit.CloudError) {
	if h.cfg.Functions == nil {
		return false, missingFunctions()
	}
	ep := hostkit.EndpointFrom(ctx)
	_, _, _, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		return false, cerr
	}
	if hasAmb && !isCleanup {
		return false, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation and requires reconciliation", name))
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "function_exists", safety.AttemptPricingInput{
		Operation: "function_exists",
		IsCleanup: isCleanup,
	}, safety.KindFunction, name)
	if cerr != nil {
		return false, cerr
	}
	exists, err := h.cfg.Functions.FunctionExists(mctx, name)
	ce := hostkit.AsCloudError(err)
	_, _, aerr := scope.finish(0, 0, ce == nil, ce == nil)
	if aerr != nil {
		return false, aerr
	}
	if ce != nil {
		return false, ce
	}
	return exists, nil
}

func (h *Host) meteredFunctionOwnerToken(ctx context.Context, name string) (string, bool, *hostkit.CloudError) {
	if h.cfg.Functions == nil {
		return "", false, missingFunctions()
	}
	rawFn := unwrapGuardAdapter(h.cfg.Functions)
	r, ok := rawFn.(hostkit.FunctionOwnershipReader)
	if !ok {
		return "", false, nil
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "function_read_ownership", safety.AttemptPricingInput{
		Operation: "function_read_ownership",
	}, safety.KindFunction, name)
	if cerr != nil {
		return "", false, cerr
	}
	tok, exists, err := r.FunctionOwnerToken(mctx, name)
	err = hostkit.NilIfTyped(err)
	_, _, aerr := scope.finish(0, 0, err == nil, err == nil)
	if aerr != nil {
		return "", false, aerr
	}
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if ce != nil && ce.Code == hostkit.CostCapExceeded {
			return "", false, ce
		}
		return "", false, ce
	}
	if tok != "" {
		h.errs.AddRedaction(tok)
	}
	return tok, exists, nil
}

func (h *Host) checkOwnershipInScope(mctx context.Context, name, expectedOwnerToken string, hasJournalOwnership bool) (exists bool, ce *hostkit.CloudError) {
	rawFn := unwrapGuardAdapter(h.cfg.Functions)
	r, ok := rawFn.(hostkit.FunctionOwnershipReader)
	if !ok {
		if !hasJournalOwnership {
			return false, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist", name))
		}
		return true, nil
	}
	tok, ex, err := r.FunctionOwnerToken(mctx, name)
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
			fmt.Sprintf("function %q exists but is not owned by this run", name))
	}
	return true, nil
}

func resolveAuthoritativeTargetPinner(ctx context.Context, fn hostkit.Functions) hostkit.FunctionTargetPinner {
	raw := unwrapGuardAdapter(fn)
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
	p, ok := raw.(hostkit.FunctionTargetPinner)
	if !ok {
		return nil
	}
	v, ok := raw.(hostkit.AuthoritativeFunctionAdapter)
	if !ok || v.AuthoritativeAdapterSelf() != raw {
		return nil
	}
	return p
}

func functionFenceCtx(ctx context.Context, ownerToken, generationStr string) context.Context {
	if ownerToken != "" {
		ctx = hostkit.WithCreateToken(ctx, ownerToken)
	}
	genNum, _ := strconv.ParseUint(generationStr, 10, 64)
	if ownerToken != "" || genNum > 0 {
		ctx = hostkit.WithFunctionMutationFence(ctx, hostkit.FunctionMutationFence{
			OwnerToken: ownerToken,
			Generation: genNum,
		})
	}
	return ctx
}

type persistedDryFunctionState struct {
	Snap         hostkit.FunctionSnapshot            `json:"snap"`
	Versions     map[string]hostkit.FunctionSnapshot `json:"versions,omitempty"`
	VersionOrder []string                            `json:"version_order,omitempty"`
	Aliases      map[string]string                   `json:"aliases,omitempty"`
	ChildSeq     uint64                              `json:"child_seq,omitempty"`
	AliasSeq     map[string]uint64                   `json:"alias_seq,omitempty"`
}

func sanitizeSnapshotForJournal(s hostkit.FunctionSnapshot) hostkit.FunctionSnapshot {
	cp := s.Clone()
	cp.BundleZip = nil
	cp.InlineCode = ""
	cp.Env = nil
	if cp.Version == "" {
		cp.Version = "$LATEST"
	}
	return cp
}

func encodePersistedDryFunctionState(st persistedDryFunctionState) string {
	st.Snap = sanitizeSnapshotForJournal(st.Snap)
	if len(st.Versions) > 0 {
		cleanVers := make(map[string]hostkit.FunctionSnapshot, len(st.Versions))
		for k, v := range st.Versions {
			vs := sanitizeSnapshotForJournal(v)
			vs.Version = k
			cleanVers[k] = vs
		}
		st.Versions = cleanVers
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return ""
	}
	return string(raw)
}

func decodePersistedDryFunctionState(raw string) (persistedDryFunctionState, bool) {
	if raw == "" {
		return persistedDryFunctionState{}, false
	}
	var st persistedDryFunctionState
	if err := json.Unmarshal([]byte(raw), &st); err != nil || st.Snap.Name == "" {
		return persistedDryFunctionState{}, false
	}
	if st.Versions == nil {
		st.Versions = map[string]hostkit.FunctionSnapshot{}
	}
	if st.Aliases == nil {
		st.Aliases = map[string]string{}
	}
	if st.AliasSeq == nil {
		st.AliasSeq = map[string]uint64{}
	}
	return st, true
}

func (h *Host) dryResolveFunction(ctx context.Context, name string) (dryFunction, *hostkit.CloudError) {
	return h.dryResolveFunctionInternal(ctx, name, true)
}

func (h *Host) dryResolveFunctionZeroIO(ctx context.Context, name string) (dryFunction, *hostkit.CloudError) {
	return h.dryResolveFunctionInternal(ctx, name, false)
}

func (h *Host) dryResolveFunctionInternal(ctx context.Context, name string, allowAdapterRead bool) (dryFunction, *hostkit.CloudError) {
	if df, ok := h.ov(ctx).function(name); ok {
		return df, nil
	}
	if h.cfg.Functions == nil {
		return dryFunction{}, missingFunctions()
	}
	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, _, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		return dryFunction{}, cerr
	}
	if hasAmb {
		return dryFunction{}, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation and requires reconciliation", name))
	}
	if pinner := resolveAuthoritativeTargetPinner(ctx, h.cfg.Functions); pinner != nil {
		snap, vers, order, aliases, found := pinner.PeekDryFunctionState(ctx, name)
		if !found {
			return dryFunction{exists: false, completeAliases: true}, nil
		}
		df := dryFunction{
			exists:          true,
			completeAliases: true,
			snap:            snap,
			versions:        vers,
			versionOrder:    order,
			aliases:         aliases,
			deletedAliases:  map[string]bool{},
			createdNow:      false,
		}
		h.ov(ctx).setFunction(name, df)
		return df, nil
	}
	if !allowAdapterRead {
		if hasAct && act.StateJSON != "" {
			if st, ok := decodePersistedDryFunctionState(act.StateJSON); ok {
				return dryFunction{
					exists:          true,
					completeAliases: true,
					snap:            st.Snap,
					versions:        st.Versions,
					versionOrder:    st.VersionOrder,
					aliases:         st.Aliases,
					deletedAliases:  map[string]bool{},
					createdNow:      false,
				}, nil
			}
		}
		return dryFunction{exists: false, completeAliases: true}, nil
	}
	snap, err := h.cfg.Functions.GetFunction(ctx, name, "$LATEST")
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if isNotFound(ce) {
			return dryFunction{exists: false}, nil
		}
		return dryFunction{}, ce
	}
	df := dryFunction{
		exists:         true,
		snap:           snap.Clone(),
		versions:       map[string]hostkit.FunctionSnapshot{},
		aliases:        map[string]string{},
		deletedAliases: map[string]bool{},
		createdNow:     false,
	}
	if hasAct && act.StateJSON != "" {
		if st, ok := decodePersistedDryFunctionState(act.StateJSON); ok {
			for k, v := range st.Aliases {
				df.aliases[k] = v
			}
			df.completeAliases = true
		}
	}
	if vers, verr := h.cfg.Functions.ListFunctionVersions(ctx, name); verr == nil {
		df.versionOrder = append([]string(nil), vers...)
		for _, v := range vers {
			if vsnap, gerr := h.cfg.Functions.GetFunction(ctx, name, v); gerr == nil {
				df.versions[v] = vsnap.Clone()
			}
		}
	}
	h.ov(ctx).setFunction(name, df)
	return df, nil
}

func (h *Host) dryResolveAlias(ctx context.Context, name, alias string, df *dryFunction) (string, bool, *hostkit.CloudError) {
	if df.deletedAliases != nil && df.deletedAliases[alias] {
		return "", false, nil
	}
	if df.aliases != nil {
		if targetVer, ok := df.aliases[alias]; ok && targetVer != "" {
			return targetVer, true, nil
		}
	}
	if df.createdNow || df.completeAliases || h.cfg.Functions == nil {
		return "", false, nil
	}
	ver, err := h.cfg.Functions.GetFunctionAlias(ctx, name, alias)
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if isNotFound(ce) {
			return "", false, nil
		}
		return "", false, ce
	}
	if ver == "" {
		return "", false, nil
	}
	if df.aliases == nil {
		df.aliases = map[string]string{}
	}
	df.aliases[alias] = ver
	h.ov(ctx).setFunction(name, *df)
	return ver, true, nil
}

func (h *Host) functionExists(ctx context.Context, dry bool, name string) (bool, *hostkit.CloudError) {
	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			return false, e
		}
		return df.exists, nil
	}
	return h.realFunctionExists(ctx, name)
}

// FunctionConfig creates a new FunctionConfig builder for (runtime, handler).
func (h *Host) FunctionConfig(runtime, handler string) (*FunctionConfig, error) {
	const op = "function_config"
	if ce := hostkit.ValidateFunctionRuntime(runtime); ce != nil {
		return &FunctionConfig{h: h, invalid: ce}, h.fail(op, runtime, ce)
	}
	if ce := hostkit.ValidateFunctionHandler(handler); ce != nil {
		return &FunctionConfig{h: h, invalid: ce}, h.fail(op, handler, ce)
	}
	h.ok()
	return &FunctionConfig{
		h:              h,
		runtime:        runtime,
		handler:        handler,
		timeoutSeconds: hostkit.DefaultFunctionTimeoutSeconds,
		memoryMB:       hostkit.DefaultFunctionMemoryMB,
		concurrency:    hostkit.DefaultFunctionConcurrency,
		env:            map[string]string{},
	}, nil
}

// FunctionCreate implements function_create(name, cfg).
func (h *Host) FunctionCreate(dry bool, name string, cfg *FunctionConfig) (bool, error) {
	const op = "function_create"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}
	if ce := h.validateFunctionConfig(cfg); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	if dry {
		wantSnap, _, ce := h.stageFunctionBundle(ctx, true, name, cfg, false)
		if ce != nil {
			failed = true
			return false, h.fail(op, name, ce)
		}
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		if df.exists {
			if !df.snap.SameCanonicalConfig(wantSnap) {
				failed = true
				return false, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "ResourceConflictException",
					fmt.Sprintf("function %q already exists with a different configuration (dry-run preview)", name)))
			}
			h.ok()
			return false, nil
		}
		wantSnap.RevisionID = "dry-rev-1"
		h.ov(ctx).setFunction(name, dryFunction{
			exists:     true,
			snap:       wantSnap,
			versions:   map[string]hostkit.FunctionSnapshot{},
			aliases:    map[string]string{},
			createdNow: true,
		})
		h.ok()
		return true, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return false, h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if hasAmb && amb.IntentOp != "create" {
		failed = true
		return false, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}
	if !hasAct && !hasAmb {
		if ce := h.cost.checkFunctionCreateHeadroom(ep, name); ce != nil {
			failed = true
			return false, h.fail(op, name, ce)
		}
	}

	wantSnap, stagedBytes, ce := h.stageFunctionBundle(ctx, false, name, cfg, false)
	if ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}
	bytesIn = stagedBytes
	digest := functionCanonicalDigest(wantSnap)

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation:   op,
		PayloadSize: bytesIn,
	}, safety.KindFunction, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}

	entry, cerr := h.cost.beginFunctionIntent(ep, name, "create", digest)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return false, h.fail(op, name, cerr)
	}
	h.errs.AddRedaction(entry.OwnerToken)
	genNum, _ := strconv.ParseUint(entry.Generation, 10, 64)
	wantSnap.OwnerToken = entry.OwnerToken
	wantSnap.Generation = genNum
	expectedOwner := act.OwnerToken
	if expectedOwner == "" && hasAmb {
		expectedOwner = amb.OwnerToken
	}

	mctx = hostkit.WithCreateToken(mctx, entry.OwnerToken)
	created, createdSnap, err := h.cfg.Functions.CreateFunction(mctx, hostkit.FunctionUpdateInput{
		Snapshot:           wantSnap,
		OwnerToken:         entry.OwnerToken,
		ExpectedOwnerToken: expectedOwner,
		Generation:         genNum,
		IntentID:           entry.IntentID,
	})
	ce = hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveFunctionRefusal(ce)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(bytesIn, bytesIn, err == nil || definitiveRefusal, !definitiveRefusal)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, name, abortErr)
	}
	if err != nil {
		if ce.Code == hostkit.Conflict && !hasAct {
			tok, exists, terr := h.meteredFunctionOwnerToken(ctx, name)
			if terr != nil {
				failed = true
				return false, h.fail(op, name, terr)
			}
			if exists && tok != "" && tok == entry.OwnerToken && (!hasAmb || amb.Digest == "" || amb.Digest == digest) {
				entry.StateJSON = encodePersistedDryFunctionState(persistedDryFunctionState{Snap: wantSnap})
				if cerr := h.cost.confirmFunctionIntent(entry); cerr != nil {
					failed = true
					return false, h.fail(op, name, cerr)
				}
				h.cost.lockResourceCleanupIfNeeded(ep, op, safety.KindFunction, name)
				h.ok()
				return true, nil
			}
		}
		failed = true
		if definitiveRefusal {
			_ = h.cost.abortFunctionIntent(entry)
		}
		return false, h.fail(op, name, ce)
	}

	if createdSnap.Name == "" {
		createdSnap = wantSnap
	}
	if hasAct && act.StateJSON != "" {
		entry.StateJSON = act.StateJSON
	} else {
		entry.StateJSON = encodePersistedDryFunctionState(persistedDryFunctionState{Snap: createdSnap})
	}
	if cerr := h.cost.confirmFunctionIntent(entry); cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if !hasAct {
		h.cost.lockResourceCleanupIfNeeded(ep, op, safety.KindFunction, name)
	}
	h.ok()
	return created, nil
}

// FunctionUpdate implements function_update(name, cfg) and function_update(name, cfg, expectRevision).
func (h *Host) FunctionUpdate(dry bool, name string, cfg *FunctionConfig, expectRevision string, hasExpectRevision bool) (*FunctionConfig, error) {
	const op = "function_update"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}
	if hasExpectRevision {
		if expectRevision == "" {
			ce := hostkit.Preflightf("expect_revision on 3-argument function_update must not be empty")
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, ce)
		}
		if ce := hostkit.ValidateFunctionExpectRevision(expectRevision); ce != nil {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, ce)
		}
	}
	if ce := h.validateFunctionConfig(cfg); ce != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, e)
		}
		if !df.exists {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, notFound("FunctionNotFound",
				fmt.Sprintf("function %q does not exist (dry-run preview)", name)))
		}
		if hasExpectRevision && df.snap.RevisionID != "" && df.snap.RevisionID != expectRevision {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, hostkit.ProviderError(hostkit.PreconditionFailed, 412, "PreconditionFailedException",
				fmt.Sprintf("function %q revision mismatch: expected %q, got %q (dry-run preview)", name, expectRevision, df.snap.RevisionID)))
		}
		wantSnap, _, ce := h.stageFunctionBundle(ctx, true, name, cfg, true)
		if ce != nil {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, ce)
		}
		wantSnap.RevisionID = fmt.Sprintf("dry-rev-%d", len(df.versionOrder)+2)
		df.snap = wantSnap
		h.ov(ctx).setFunction(name, df)
		h.ok()
		return h.snapshotToFunctionConfig(wantSnap, true, hostkit.FunctionStateActive), nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, cerr)
	}
	if hasAmb && amb.IntentOp == "delete" {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}
	ownerToken := act.OwnerToken
	if ownerToken == "" && hasAmb {
		ownerToken = amb.OwnerToken
	}

	wantSnap, stagedBytes, ce := h.stageFunctionBundle(ctx, false, name, cfg, true)
	if ce != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}
	bytesIn = stagedBytes
	digest := functionCanonicalDigest(wantSnap)

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation:   op,
		PayloadSize: bytesIn,
	}, safety.KindFunction, name)
	if cerr != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, cerr)
	}

	exists, ownErr := h.checkOwnershipInScope(mctx, name, ownerToken, hasAct || hasAmb)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveFunctionRefusal(ownErr), false)
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, abortErr)
		}
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist", name)))
	}

	entry, cerr := h.cost.beginFunctionIntent(ep, name, "update", digest)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, cerr)
	}
	h.errs.AddRedaction(entry.OwnerToken)
	genNum, _ := strconv.ParseUint(entry.Generation, 10, 64)
	wantSnap.OwnerToken = entry.OwnerToken
	wantSnap.Generation = genNum

	mctx = hostkit.WithCreateToken(mctx, ownerToken)
	updatedSnap, err := h.cfg.Functions.UpdateFunction(mctx, hostkit.FunctionUpdateInput{
		Snapshot:           wantSnap,
		ExpectRevision:     expectRevision,
		OwnerToken:         entry.OwnerToken,
		ExpectedOwnerToken: ownerToken,
		Generation:         genNum,
		IntentID:           entry.IntentID,
	})
	ce = hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveFunctionRefusal(ce)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(bytesIn, bytesIn, err == nil || definitiveRefusal, !definitiveRefusal)
	if abortErr != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, abortErr)
	}
	if err != nil {
		failed = true
		if definitiveRefusal {
			_ = h.cost.abortFunctionIntent(entry)
		}
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}

	prevState, _ := decodePersistedDryFunctionState(act.StateJSON)
	if updatedSnap.Name == "" {
		prevState.Snap = wantSnap
	} else {
		prevState.Snap = updatedSnap
	}
	entry.StateJSON = encodePersistedDryFunctionState(prevState)
	if cerr := h.cost.confirmFunctionIntent(entry); cerr != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, cerr)
	}
	if !hasAct {
		h.cost.lockResourceCleanupIfNeeded(ep, "function_create", safety.KindFunction, name)
	}
	h.ok()
	return h.snapshotToFunctionConfig(updatedSnap, true, hostkit.FunctionStateActive), nil
}

// FunctionDelete implements function_delete(name).
func (h *Host) FunctionDelete(dry bool, name string) (bool, error) {
	const op = "function_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		h.ov(ctx).setFunction(name, dryFunction{exists: false})
		h.ok()
		return df.exists, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return false, h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	ownerToken := act.OwnerToken
	if ownerToken == "" && hasAmb {
		ownerToken = amb.OwnerToken
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
		IsCleanup: true,
	}, safety.KindFunction, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}

	exists, ownErr := h.checkOwnershipInScope(mctx, name, ownerToken, hasAct || hasAmb)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveFunctionRefusal(ownErr), false)
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

	entry, cerr := h.cost.beginFunctionIntent(ep, name, "delete", "")
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if ownerToken != "" {
		h.errs.AddRedaction(ownerToken)
	}
	mctx = functionFenceCtx(mctx, ownerToken, entry.Generation)

	existed, err := h.cfg.Functions.DeleteFunction(mctx, name)
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
		if isDefinitiveFunctionRefusal(ce) {
			_ = h.cost.abortFunctionIntent(entry)
		}
		return false, h.fail(op, name, ce)
	}

	if cerr := h.cost.confirmFunctionDelete(entry); cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	h.ok()
	return existed, nil
}

// FunctionExists implements function_exists(name).
func (h *Host) FunctionExists(dry bool, name string) (bool, error) {
	const op = "function_exists"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	if dry {
		exists, e := h.functionExists(ctx, true, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		h.ok()
		return exists, nil
	}

	exists, ce := h.meteredFunctionExists(ctx, name, false)
	if ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}
	h.ok()
	return exists, nil
}

// FunctionGet implements function_get(name) and function_get(name, qualifier).
func (h *Host) FunctionGet(dry bool, name, qualifier string, hasQualifier bool) (*FunctionConfig, error) {
	const op = "function_get"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}
	if hasQualifier {
		if qualifier == "" {
			ce := hostkit.Preflightf("qualifier on 2-argument function_get must not be empty")
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, ce)
		}
		if ce := hostkit.ValidateFunctionQualifier(qualifier); ce != nil {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, ce)
		}
	} else {
		qualifier = "$LATEST"
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, e)
		}
		if !df.exists {
			h.ok()
			return h.missingFunctionConfig(name), nil
		}
		if qualifier == "" || qualifier == "$LATEST" {
			h.ok()
			return h.snapshotToFunctionConfig(df.snap, true, hostkit.FunctionStateActive), nil
		}
		if vsnap, ok := df.versions[qualifier]; ok {
			h.ok()
			return h.snapshotToFunctionConfig(vsnap, true, hostkit.FunctionStateActive), nil
		}
		targetVer, ok, ce := h.dryResolveAlias(ctx, name, qualifier, &df)
		if ce != nil {
			failed = true
			return h.missingFunctionConfig(name), h.fail(op, name, ce)
		}
		if ok {
			if vsnap, vok := df.versions[targetVer]; vok {
				h.ok()
				return h.snapshotToFunctionConfig(vsnap, true, hostkit.FunctionStateActive), nil
			}
		}
		h.ok()
		return h.missingFunctionConfig(name), nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	_, _, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindFunction, name)
	if cerr != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, cerr)
	}
	snap, err := h.cfg.Functions.GetFunction(mctx, name, qualifier)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isNotFound(ce), ce == nil || isNotFound(ce))
	if abortErr != nil {
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, abortErr)
	}
	if ce != nil {
		if isNotFound(ce) {
			h.ok()
			return h.missingFunctionConfig(name), nil
		}
		failed = true
		return h.missingFunctionConfig(name), h.fail(op, name, ce)
	}
	h.ok()
	return h.snapshotToFunctionConfig(snap, true, hostkit.FunctionStateActive), nil
}

// FunctionList implements function_list().
func (h *Host) FunctionList(dry bool) ([]string, error) {
	const op = "function_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return nil, h.fail(op, "", ce)
	}

	ep := hostkit.EndpointFrom(ctx)
	ambList, cerr := h.cost.listAmbiguousFunctionsForEndpoint(ep)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, "", cerr)
	}
	if len(ambList) > 0 {
		failed = true
		return nil, h.fail(op, ambList[0].Name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", ambList[0].Name, ambList[0].IntentOp)))
	}

	if dry {
		if h.cfg.Functions == nil {
			failed = true
			return nil, h.fail(op, "", missingFunctions())
		}
		names, err := h.cfg.Functions.ListFunctions(ctx)
		if err != nil {
			failed = true
			return nil, h.fail(op, "", hostkit.AsCloudError(err))
		}
		merged := h.ov(ctx).mergeFunctions(names)
		h.ok()
		return merged, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return nil, h.fail(op, "", missingFunctions())
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, "", "")
	if cerr != nil {
		failed = true
		return nil, h.fail(op, "", cerr)
	}
	names, err := h.cfg.Functions.ListFunctions(mctx)
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

// FunctionPublishVersion implements function_publish_version(name) and function_publish_version(name, expectRevision).
func (h *Host) FunctionPublishVersion(dry bool, name, expectRevision string, hasExpectRevision bool) (string, error) {
	const op = "function_publish_version"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return "", h.fail(op, name, ce)
	}
	if hasExpectRevision {
		if expectRevision == "" {
			ce := hostkit.Preflightf("expect_revision on 2-argument function_publish_version must not be empty")
			failed = true
			return "", h.fail(op, name, ce)
		}
		if ce := hostkit.ValidateFunctionExpectRevision(expectRevision); ce != nil {
			failed = true
			return "", h.fail(op, name, ce)
		}
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return "", h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return "", h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return "", h.fail(op, name, e)
		}
		if !df.exists {
			failed = true
			return "", h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist (dry-run preview)", name)))
		}
		if hasExpectRevision && df.snap.RevisionID != "" && df.snap.RevisionID != expectRevision {
			failed = true
			return "", h.fail(op, name, hostkit.ProviderError(hostkit.PreconditionFailed, 412, "PreconditionFailedException",
				fmt.Sprintf("function %q revision mismatch: expected %q, got %q (dry-run preview)", name, expectRevision, df.snap.RevisionID)))
		}
		if len(df.versionOrder) >= hostkit.MaxFunctionVersions {
			failed = true
			return "", h.fail(op, name, hostkit.ProviderError(hostkit.PreconditionFailed, 400, "ResourceLimitExceeded",
				fmt.Sprintf("function %q published version count exceeds maximum (%d)", name, hostkit.MaxFunctionVersions)))
		}
		ver := fmt.Sprintf("%d", len(df.versionOrder)+1)
		vsnap := df.snap.Clone()
		vsnap.Version = ver
		if df.versions == nil {
			df.versions = map[string]hostkit.FunctionSnapshot{}
		}
		df.versions[ver] = vsnap
		df.versionOrder = append(df.versionOrder, ver)
		h.ov(ctx).setFunction(name, df)
		h.ok()
		return ver, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return "", h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return "", h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return "", h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	// Each publish attempt uses a unique durable reservation key under name+"/" so
	// concurrent publishes never deduplicate each other's 30,000 nano-USD cleanup
	// reserve in either campaign_journal or safety_journal, and function_delete
	// releases all name+"/*" reserves on cascade teardown.
	pubReserveKey := name + "/pub-" + safety.NewToken128()[:16]

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindFunctionVersion, pubReserveKey)
	if cerr != nil {
		failed = true
		return "", h.fail(op, name, cerr)
	}

	exists, ownErr := h.checkOwnershipInScope(mctx, name, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveFunctionRefusal(ownErr), false)
		failed = true
		return "", h.fail(op, name, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return "", h.fail(op, name, abortErr)
		}
		failed = true
		return "", h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist", name)))
	}

	var childSeq uint64
	mctx = functionFenceCtx(mctx, act.OwnerToken, act.Generation)
	mctx = hostkit.WithFunctionChildMutationSeqOut(mctx, &childSeq)
	ver, err := h.cfg.Functions.PublishFunctionVersion(mctx, name, expectRevision)
	ce := hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveFunctionRefusal(ce)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, err == nil || definitiveRefusal, !definitiveRefusal)
	if abortErr != nil {
		failed = true
		return "", h.fail(op, name, abortErr)
	}
	if err != nil {
		failed = true
		return "", h.fail(op, name, ce)
	}
	if cerr := h.cost.updateFunctionDryState(ep, name, act.OwnerToken, act.Digest, act.Generation, func(cur string) string {
		st, ok := decodePersistedDryFunctionState(cur)
		if !ok {
			return cur
		}
		vsnap := st.Snap.Clone()
		vsnap.Version = ver
		st.Versions[ver] = vsnap
		found := false
		for _, existingVer := range st.VersionOrder {
			if existingVer == ver {
				found = true
				break
			}
		}
		if !found {
			st.VersionOrder = append(st.VersionOrder, ver)
			sort.Slice(st.VersionOrder, func(i, j int) bool {
				vi, _ := strconv.Atoi(st.VersionOrder[i])
				vj, _ := strconv.Atoi(st.VersionOrder[j])
				return vi < vj
			})
		}
		if childSeq > st.ChildSeq {
			st.ChildSeq = childSeq
		}
		return encodePersistedDryFunctionState(st)
	}); cerr != nil {
		failed = true
		return "", h.fail(op, name, cerr)
	}
	h.ok()
	return ver, nil
}

// FunctionVersions implements function_versions(name).
func (h *Host) FunctionVersions(dry bool, name string) ([]string, error) {
	const op = "function_versions"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return nil, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return nil, h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return nil, h.fail(op, name, e)
		}
		if !df.exists {
			failed = true
			return nil, h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist (dry-run preview)", name)))
		}
		out := append([]string(nil), df.versionOrder...)
		h.ok()
		return out, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return nil, h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	_, _, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return nil, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindFunction, name)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, name, cerr)
	}
	vers, err := h.cfg.Functions.ListFunctionVersions(mctx, name)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil, ce == nil)
	if abortErr != nil {
		failed = true
		return nil, h.fail(op, name, abortErr)
	}
	if ce != nil {
		failed = true
		return nil, h.fail(op, name, ce)
	}
	h.ok()
	return vers, nil
}

// FunctionAliasSet implements function_alias_set(name, alias, version).
func (h *Host) FunctionAliasSet(dry bool, name, alias, version string) error {
	const op = "function_alias_set"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return h.fail(op, name, ce)
	}
	if ce := hostkit.ValidateFunctionAliasName(alias); ce != nil {
		failed = true
		return h.fail(op, alias, ce)
	}
	if ce := hostkit.ValidateFunctionVersionString(version); ce != nil {
		failed = true
		return h.fail(op, version, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return h.fail(op, name, e)
		}
		if !df.exists {
			failed = true
			return h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist (dry-run preview)", name)))
		}
		if _, vok := df.versions[version]; !vok {
			failed = true
			return h.fail(op, name, notFound("VersionNotFound", fmt.Sprintf("function %q version %q does not exist (dry-run preview)", name, version)))
		}
		if df.aliases == nil {
			df.aliases = map[string]string{}
		}
		_, exists, ce := h.dryResolveAlias(ctx, name, alias, &df)
		if ce != nil {
			failed = true
			return h.fail(op, name, ce)
		}
		if !exists && len(df.aliases) >= hostkit.MaxFunctionAliases {
			failed = true
			return h.fail(op, name, hostkit.ProviderError(hostkit.PreconditionFailed, 400, "ResourceLimitExceeded",
				fmt.Sprintf("function %q alias count exceeds maximum (%d)", name, hostkit.MaxFunctionAliases)))
		}
		df.aliases[alias] = version
		if df.deletedAliases != nil {
			delete(df.deletedAliases, alias)
		}
		h.ov(ctx).setFunction(name, df)
		h.ok()
		return nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	isNewAlias := true
	if peeker, ok := h.cfg.Functions.(hostkit.FunctionQuotaPeeker); ok {
		if created, perr := peeker.PeekFunctionAliasHeadroom(ctx, name, alias, version); perr == nil {
			isNewAlias = created
		}
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindFunctionAlias, name+"/"+alias)
	if cerr != nil {
		failed = true
		return h.fail(op, name, cerr)
	}

	exists, ownErr := h.checkOwnershipInScope(mctx, name, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveFunctionRefusal(ownErr), false)
		failed = true
		return h.fail(op, name, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return h.fail(op, name, abortErr)
		}
		failed = true
		return h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist", name)))
	}

	var childSeq uint64
	mctx = functionFenceCtx(mctx, act.OwnerToken, act.Generation)
	mctx = hostkit.WithFunctionChildMutationSeqOut(mctx, &childSeq)
	created, err := h.cfg.Functions.SetFunctionAlias(mctx, name, alias, version)
	ce := hostkit.AsCloudError(err)
	definitiveRefusal := err != nil && isDefinitiveFunctionRefusal(ce)
	lockCleanup := false
	if err == nil {
		lockCleanup = created
	} else if !definitiveRefusal {
		lockCleanup = isNewAlias
	}
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, err == nil || definitiveRefusal, lockCleanup)
	if abortErr != nil {
		failed = true
		return h.fail(op, name, abortErr)
	}
	if err != nil {
		failed = true
		return h.fail(op, name, ce)
	}
	reconciledAliasVer := version
	hasReconciledAlias := false
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupFunctionEntry(ep, name); hasCur && curAct.StateJSON != act.StateJSON {
			if actualVer, gerr := h.cfg.Functions.GetFunctionAlias(ctx, name, alias); gerr == nil {
				reconciledAliasVer = actualVer
				hasReconciledAlias = true
			}
		}
	}
	if cerr := h.cost.updateFunctionDryState(ep, name, act.OwnerToken, act.Digest, act.Generation, func(cur string) string {
		st, ok := decodePersistedDryFunctionState(cur)
		if !ok {
			return cur
		}
		if childSeq > 0 {
			if st.AliasSeq[alias] > childSeq {
				return cur
			}
			st.Aliases[alias] = version
			st.AliasSeq[alias] = childSeq
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedDryFunctionState(st)
		}
		if hasReconciledAlias {
			if reconciledAliasVer == "" {
				delete(st.Aliases, alias)
			} else {
				st.Aliases[alias] = reconciledAliasVer
			}
			return encodePersistedDryFunctionState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		st.Aliases[alias] = version
		return encodePersistedDryFunctionState(st)
	}); cerr != nil {
		failed = true
		return h.fail(op, name, cerr)
	}
	h.ok()
	return nil
}

// FunctionAliasGet implements function_alias_get(name, alias).
func (h *Host) FunctionAliasGet(dry bool, name, alias string) (string, error) {
	const op = "function_alias_get"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return "", h.fail(op, name, ce)
	}
	if ce := hostkit.ValidateFunctionAliasName(alias); ce != nil {
		failed = true
		return "", h.fail(op, alias, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return "", h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return "", h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return "", h.fail(op, name, e)
		}
		if !df.exists {
			failed = true
			return "", h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist (dry-run preview)", name)))
		}
		targetVer, _, ce := h.dryResolveAlias(ctx, name, alias, &df)
		if ce != nil {
			failed = true
			return "", h.fail(op, name, ce)
		}
		h.ok()
		return targetVer, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return "", h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	_, _, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return "", h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return "", h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
	}, safety.KindFunction, name)
	if cerr != nil {
		failed = true
		return "", h.fail(op, name, cerr)
	}
	ver, err := h.cfg.Functions.GetFunctionAlias(mctx, name, alias)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil, ce == nil)
	if abortErr != nil {
		failed = true
		return "", h.fail(op, name, abortErr)
	}
	if ce != nil {
		failed = true
		return "", h.fail(op, name, ce)
	}
	h.ok()
	return ver, nil
}

// FunctionAliasDelete implements function_alias_delete(name, alias).
func (h *Host) FunctionAliasDelete(dry bool, name, alias string) (bool, error) {
	const op = "function_alias_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}
	if ce := hostkit.ValidateFunctionAliasName(alias); ce != nil {
		failed = true
		return false, h.fail(op, alias, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunction(ctx, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		if !df.exists {
			failed = true
			return false, h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist (dry-run preview)", name)))
		}
		_, existed, ce := h.dryResolveAlias(ctx, name, alias, &df)
		if ce != nil {
			failed = true
			return false, h.fail(op, name, ce)
		}
		if existed {
			delete(df.aliases, alias)
			if df.deletedAliases == nil {
				df.deletedAliases = map[string]bool{}
			}
			df.deletedAliases[alias] = true
			h.ov(ctx).setFunction(name, df)
		}
		h.ok()
		return existed, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return false, h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return false, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation: op,
		IsCleanup: true,
	}, safety.KindFunctionAlias, name+"/"+alias)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}

	exists, ownErr := h.checkOwnershipInScope(mctx, name, act.OwnerToken, hasAct)
	if ownErr != nil {
		retries, throttles, _ = scope.finish(0, 0, isDefinitiveFunctionRefusal(ownErr), false)
		failed = true
		return false, h.fail(op, name, ownErr)
	}
	if !exists {
		var abortErr *hostkit.CloudError
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, name, abortErr)
		}
		failed = true
		return false, h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist", name)))
	}

	var childSeq uint64
	mctx = functionFenceCtx(mctx, act.OwnerToken, act.Generation)
	mctx = hostkit.WithFunctionChildMutationSeqOut(mctx, &childSeq)
	existed, err := h.cfg.Functions.DeleteFunctionAlias(mctx, name, alias)
	ce := hostkit.AsCloudError(err)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, ce == nil || isDefinitiveFunctionRefusal(ce), ce == nil)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, name, abortErr)
	}
	if ce != nil {
		failed = true
		return false, h.fail(op, name, ce)
	}
	reconciledAliasVer := ""
	hasReconciledAlias := false
	if childSeq == 0 {
		if curAct, hasCur, _, _, _ := h.cost.lookupFunctionEntry(ep, name); hasCur && curAct.StateJSON != act.StateJSON {
			if actualVer, gerr := h.cfg.Functions.GetFunctionAlias(ctx, name, alias); gerr == nil {
				reconciledAliasVer = actualVer
				hasReconciledAlias = true
			}
		}
	}
	if cerr := h.cost.updateFunctionDryState(ep, name, act.OwnerToken, act.Digest, act.Generation, func(cur string) string {
		st, ok := decodePersistedDryFunctionState(cur)
		if !ok {
			return cur
		}
		if childSeq > 0 {
			if st.AliasSeq[alias] > childSeq {
				return cur
			}
			delete(st.Aliases, alias)
			st.AliasSeq[alias] = childSeq
			if childSeq > st.ChildSeq {
				st.ChildSeq = childSeq
			}
			return encodePersistedDryFunctionState(st)
		}
		if hasReconciledAlias {
			if reconciledAliasVer == "" {
				delete(st.Aliases, alias)
			} else {
				st.Aliases[alias] = reconciledAliasVer
			}
			return encodePersistedDryFunctionState(st)
		}
		if cur != act.StateJSON {
			return cur
		}
		delete(st.Aliases, alias)
		return encodePersistedDryFunctionState(st)
	}); cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	h.ok()
	return existed, nil
}

// FunctionInvoke implements function_invoke(name, payloadJSON) and function_invoke(name, qualifier, payloadJSON).
func (h *Host) FunctionInvoke(dry bool, name, qualifier, payloadJSON string, hasQualifier bool) (*FunctionInvokeResult, error) {
	const op = "function_invoke"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn, bytesOut int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, bytesOut)
		}
	}()

	zeroRes := &FunctionInvokeResult{}
	if ce := hostkit.ValidateFunctionName(name); ce != nil {
		failed = true
		return zeroRes, h.fail(op, name, ce)
	}
	if hasQualifier {
		if qualifier == "" {
			ce := hostkit.Preflightf("qualifier on 3-argument function_invoke must not be empty")
			failed = true
			return zeroRes, h.fail(op, name, ce)
		}
		if ce := hostkit.ValidateFunctionQualifier(qualifier); ce != nil {
			failed = true
			return zeroRes, h.fail(op, name, ce)
		}
	} else {
		qualifier = "$LATEST"
	}
	if ce := hostkit.ValidateFunctionInvokePayload(payloadJSON); ce != nil {
		failed = true
		return zeroRes, h.fail(op, name, ce)
	}

	ctx, cancel, e := h.opCtx("function", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return zeroRes, h.fail(op, name, e)
	}
	defer cancel()

	if ce := h.checkFunctionRouteAllowed(ctx); ce != nil {
		failed = true
		return zeroRes, h.fail(op, name, ce)
	}

	if dry {
		df, e := h.dryResolveFunctionZeroIO(ctx, name)
		if e != nil {
			failed = true
			return zeroRes, h.fail(op, name, e)
		}
		if !df.exists {
			failed = true
			return zeroRes, h.fail(op, name, notFound("FunctionNotFound", fmt.Sprintf("function %q does not exist (dry-run preview)", name)))
		}
		targetSnap := df.snap
		execVer := "$LATEST"
		if qualifier != "" && qualifier != "$LATEST" {
			if vsnap, ok := df.versions[qualifier]; ok {
				targetSnap = vsnap
				execVer = qualifier
			} else {
				targetVer, ok, ce := h.dryResolveAlias(ctx, name, qualifier, &df)
				if ce != nil {
					failed = true
					return zeroRes, h.fail(op, name, ce)
				}
				if ok {
					if vsnap, vok := df.versions[targetVer]; vok {
						targetSnap = vsnap
						execVer = targetVer
					} else {
						failed = true
						return zeroRes, h.fail(op, name, notFound("VersionNotFound", fmt.Sprintf("function %q version %q does not exist (dry-run preview)", name, targetVer)))
					}
				} else {
					failed = true
					return zeroRes, h.fail(op, name, notFound("QualifierNotFound", fmt.Sprintf("function %q qualifier %q does not exist (dry-run preview)", name, qualifier)))
				}
			}
		}
		if targetSnap.Concurrency == -1 {
			failed = true
			return zeroRes, h.fail(op, name, hostkit.ProviderError(hostkit.PreconditionFailed, 429, "TooManyRequestsException",
				fmt.Sprintf("function %q has concurrency set to -1 (throttled)", name)))
		}
		h.ok()
		return &FunctionInvokeResult{
			statusCode:      200,
			payload:         "{}",
			logs:            "",
			functionError:   "",
			executedVersion: execVer,
			durationMS:      0.0,
			billedMS:        1,
			memoryMB:        targetSnap.MemoryMB,
		}, nil
	}

	if h.cfg.Functions == nil {
		failed = true
		return zeroRes, h.fail(op, name, missingFunctions())
	}

	ep := hostkit.EndpointFrom(ctx)
	act, hasAct, amb, hasAmb, cerr := h.cost.lookupFunctionEntry(ep, name)
	if cerr != nil {
		failed = true
		return zeroRes, h.fail(op, name, cerr)
	}
	if hasAmb {
		failed = true
		return zeroRes, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousFunctionState",
			fmt.Sprintf("function %q has an unresolved ambiguous operation (%s) and requires reconciliation", name, amb.IntentOp)))
	}

	invokeIn := hostkit.FunctionInvokeInput{
		Name:        name,
		Qualifier:   qualifier,
		PayloadJSON: payloadJSON,
	}
	timeoutSec := int64(hostkit.MaxFunctionTimeoutSeconds)
	memMB := int64(hostkit.MaxFunctionMemoryMB)
	if pinner := resolveAuthoritativeTargetPinner(ctx, h.cfg.Functions); pinner != nil {
		if snap, found := pinner.ResolveFunctionTarget(ctx, name, qualifier); found && snap.TimeoutSeconds > 0 && snap.MemoryMB >= 128 {
			timeoutSec = snap.TimeoutSeconds
			memMB = snap.MemoryMB
			expOwner := snap.OwnerToken
			if hasAct && act.OwnerToken != "" {
				expOwner = act.OwnerToken
			}
			invokeIn.ExpectedOwnerToken = expOwner
			invokeIn.ExpectedIncarnation = snap.IncarnationID
			invokeIn.ExpectedRevisionID = snap.RevisionID
			invokeIn.ExpectedVersion = snap.Version
			invokeIn.ExpectedTimeoutSec = snap.TimeoutSeconds
			invokeIn.ExpectedMemoryMB = snap.MemoryMB
		} else {
			timeoutSec = int64(hostkit.DefaultFunctionTimeoutSeconds)
			memMB = int64(hostkit.DefaultFunctionMemoryMB)
			invokeIn.RejectIfPresent = true
		}
	} else if hasAct && act.OwnerToken != "" {
		invokeIn.ExpectedOwnerToken = act.OwnerToken
	}

	memShares := memMB / 128
	if memShares < 1 {
		memShares = 1
	}
	maxUnits := int64(100) + (timeoutSec*1000)*memShares
	reqBytes := int64(len(payloadJSON))
	maxWireBytes := reqBytes + hostkit.MaxFunctionWireBytes

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation:    op,
		BillingUnits: maxUnits,
		EgressBytes:  maxWireBytes,
	}, safety.KindFunction, name)
	if cerr != nil {
		failed = true
		return zeroRes, h.fail(op, name, cerr)
	}

	invStart := h.cfg.Now()
	out, err := h.cfg.Functions.InvokeFunction(mctx, invokeIn)
	invDur := h.cfg.Now().Sub(invStart)
	if invDur < 0 {
		invDur = 0
	}
	durMS := float64(invDur.Nanoseconds()) / 1e6

	if err != nil {
		ce := hostkit.AsCloudError(err)
		definitiveRefusal := isDefinitiveFunctionRefusal(ce)
		if ce != nil && ce.HTTPStatus == 429 {
			throttles++
		}
		var abortErr *hostkit.CloudError
		if definitiveRefusal {
			bytesOut = reqBytes
			_, _, abortErr = scope.finishWithUnits(reqBytes, reqBytes, 100, true, false)
		} else {
			// Ambiguous / lost reply on non-idempotent invoke: retain full worst-case reservation!
			bytesOut = reqBytes
			_, _, abortErr = scope.finishWithUnits(maxWireBytes, maxWireBytes, maxUnits, false, false)
		}
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return zeroRes, h.fail(op, name, ce)
	}

	effTimeout := out.TimeoutSeconds
	if effTimeout <= 0 {
		effTimeout = timeoutSec
	}
	maxBilledMS := effTimeout * 1000
	effMemMB := out.MemoryMB
	if effMemMB < 128 {
		effMemMB = memMB
	}
	effMemShares := effMemMB / 128
	if effMemShares < 1 {
		effMemShares = 1
	}

	var settledBilledMS int64
	if out.BilledMS < 1 || out.BilledMS > maxBilledMS {
		settledBilledMS = maxBilledMS
	} else {
		hostCeilMS := int64(math.Ceil(durMS))
		if hostCeilMS < 1 {
			hostCeilMS = 1
		}
		if hostCeilMS > maxBilledMS {
			hostCeilMS = maxBilledMS
		}
		settledBilledMS = out.BilledMS
		if out.FunctionError == "Timeout" {
			settledBilledMS = maxBilledMS
		} else if hostCeilMS > settledBilledMS && out.BilledMS == 0 {
			settledBilledMS = hostCeilMS
		}
	}

	settledUnits := int64(100) + settledBilledMS*effMemShares
	bytesOut = reqBytes
	bytesIn = int64(len(out.Payload))
	totalLogicalBytes := bytesOut + bytesIn

	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finishWithUnits(totalLogicalBytes, totalLogicalBytes, settledUnits, true, true)
	if abortErr != nil {
		failed = true
		return zeroRes, h.fail(op, name, abortErr)
	}

	h.ok()
	return &FunctionInvokeResult{
		statusCode:      out.StatusCode,
		payload:         out.Payload,
		logs:            hostkit.TruncateUTF8LogTail(out.Logs, hostkit.MaxFunctionLogBytes),
		functionError:   out.FunctionError,
		executedVersion: out.ExecutedVersion,
		durationMS:      durMS,
		billedMS:        settledBilledMS,
		memoryMB:        effMemMB,
	}, nil
}
