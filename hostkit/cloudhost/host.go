// SPDX-License-Identifier: MIT

// Package cloudhost implements the shared lmcloud schema once, on top of the
// hostkit adapter interfaces. A provider port supplies an ObjectStore, a Queue
// and an EndpointResolver; everything a script can observe (validation,
// idempotency, error precedence, abort format, codec, pagination, dry previews)
// is decided here so all hosts behave identically.
package cloudhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

// Config wires a provider into the shared host.
type Config struct {
	// Provider is the identifier returned by cloud.provider().
	Provider    string
	Store       hostkit.ObjectStore
	Queue       hostkit.Queue
	Tables      hostkit.Tables
	Permissions hostkit.Permissions
	Functions   hostkit.Functions
	Endpoints   *hostkit.EndpointResolver
	Validator   *hostkit.Validator
	// OpTimeout bounds one operation (default 2m); ListTimeout bounds exhaustive lists (default 10m).
	OpTimeout   time.Duration
	ListTimeout time.Duration
	MaxPages    int
	// PollInterval/Now/Sleep drive the client-side wait loop for adapters without long polling.
	PollInterval time.Duration
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
	// Optional cost metering configuration (defaults to SyntheticSimPriceTable and DefaultCostCapUSD).
	Meter             *safety.CostMeter
	PriceTable        *safety.PriceTable
	Journal           *safety.Journal
	CampaignStatePath string
	OnSetWorkCap      func(workCapNanoUSD int64) error
}

// Host is the state behind the `cloud` context object.
type Host struct {
	cfg     Config
	errs    *hostkit.ErrorState
	dry     *dryScopes
	cost    *costTracker
	metrics *metricsTracker
}

// New returns a host for cfg. Missing optional fields get defaults.
func New(cfg Config) *Host {
	if cfg.Endpoints == nil {
		cfg.Endpoints = &hostkit.EndpointResolver{}
	}
	if cfg.Validator == nil {
		cfg.Validator = &hostkit.Validator{}
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = 2 * time.Minute
	}
	if cfg.ListTimeout <= 0 {
		cfg.ListTimeout = 10 * time.Minute
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = hostkit.DefaultMaxPages
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 250 * time.Millisecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = hostkit.SleepContext
	}
	// Every adapter error passes through hostkit.NilIfTyped (typed-nil trap).
	if cfg.Store != nil {
		cfg.Store = guardStore{cfg.Store}
	}
	if cfg.Queue != nil {
		cfg.Queue = guardQueue{cfg.Queue}
	}
	if cfg.Tables != nil {
		cfg.Tables = guardTables{cfg.Tables}
	}
	if cfg.Permissions != nil {
		cfg.Permissions = guardPermissions{cfg.Permissions}
	}
	if cfg.Functions != nil {
		cfg.Functions = guardFunctions{cfg.Functions}
	}
	errs := hostkit.NewErrorState()
	ct := newCostTracker(cfg)
	ct.mu.Lock()
	ct.onToken = errs.AddRedaction
	for _, pa := range ct.activePolicies {
		if pa.OwnerToken != "" {
			errs.AddRedaction(pa.OwnerToken)
		}
	}
	for _, pa := range ct.ambiguousPolicies {
		if pa.OwnerToken != "" {
			errs.AddRedaction(pa.OwnerToken)
		}
	}
	for _, fe := range ct.activeFunctionEntries {
		if fe.OwnerToken != "" {
			errs.AddRedaction(fe.OwnerToken)
		}
	}
	for _, fe := range ct.ambiguousFunctions {
		if fe.OwnerToken != "" {
			errs.AddRedaction(fe.OwnerToken)
		}
	}
	ct.mu.Unlock()
	return &Host{
		cfg:     cfg,
		errs:    errs,
		dry:     &dryScopes{m: map[string]*overlay{}},
		cost:    ct,
		metrics: newMetricsTracker(cfg.Now),
	}
}

// ---- small helpers ----

func (h *Host) fail(op, target string, e *hostkit.CloudError) error {
	if e != nil && e.ProviderCode == "LiveCostCapExceeded" {
		e = hostkit.ProviderError(hostkit.CostCapExceeded, 0, "CostCapExceeded", e.Message)
	}
	return h.errs.Fail(op, target, e)
}

func (h *Host) ok() { h.errs.Succeed() }

func (h *Host) opCtx(service string, timeout time.Duration) (context.Context, context.CancelFunc, *hostkit.CloudError) {
	ep, _, e := h.cfg.Endpoints.Resolve(service)
	if e != nil {
		return nil, nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return hostkit.WithEndpoint(ctx, ep), cancel, nil
}

func isNotFound(e *hostkit.CloudError) bool { return e != nil && e.Code == hostkit.NotFound }

func notFound(what hostkit.Absence, msg string) *hostkit.CloudError {
	return hostkit.ProviderError(hostkit.NotFound, 0, "", msg).WithAbsent(what)
}

func target(b, k string) string { return b + "/" + k }

func missingStore() *hostkit.CloudError {
	return hostkit.ProviderError(hostkit.Internal, 0, "", "this host has no object storage adapter")
}

func missingQueue() *hostkit.CloudError {
	return hostkit.ProviderError(hostkit.Internal, 0, "", "this host has no queue adapter")
}

// NormalizeETag strips a weak prefix and surrounding double quotes.
func NormalizeETag(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "W/") || strings.HasPrefix(s, "w/") {
		s = strings.TrimSpace(s[2:])
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}

func dryETag(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "dry-" + hex.EncodeToString(sum[:8])
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- configuration ----

// Provider returns the provider identifier. It does not touch last_error.
func (h *Host) Provider() string { return h.cfg.Provider }

// AbortOnError reports the flag. It does not touch last_error.
func (h *Host) AbortOnError() bool { return h.errs.Abort() }

// SetAbortOnError sets the flag and resets last_error.
func (h *Host) SetAbortOnError(abort bool) { h.errs.SetAbort(abort) }

// LastError returns the last_error snapshot.
func (h *Host) LastError() hostkit.CloudError { return h.errs.Last() }

// Endpoint returns the redacted effective endpoint for service.
func (h *Host) Endpoint(service string) (string, error) {
	ep, e := h.cfg.Endpoints.Display(service)
	if e != nil {
		return "", h.fail("endpoint", service, e)
	}
	h.ok()
	return ep, nil
}

// SetEndpoint validates and stores an explicit endpoint override (also in dry runs: it is local state).
func (h *Host) SetEndpoint(service, raw string) error {
	if e := h.cfg.Endpoints.Set(service, raw); e != nil {
		return h.fail("set_endpoint", service, e)
	}
	h.ok()
	return nil
}

// ---- probes shared by real and dry paths (read-only) ----

func isDefinitiveNonStreamError(err error) bool {
	if err == nil {
		return false
	}
	var ce *hostkit.CloudError
	if !errors.As(err, &ce) || ce == nil {
		return false
	}
	if ce.HTTPStatus >= 400 {
		return true
	}
	switch ce.Code {
	case hostkit.NotFound, hostkit.Conflict, hostkit.PreconditionFailed, hostkit.PermissionDenied, hostkit.InvalidArgument, hostkit.CostCapExceeded:
		return true
	}
	return false
}

func (h *Host) realBucketExists(ctx context.Context, b string) (bool, *hostkit.CloudError) {
	if h.cfg.Store == nil {
		return false, missingStore()
	}
	e := hostkit.AsCloudError(h.cfg.Store.HeadBucket(ctx, b))
	switch {
	case e == nil:
		return true, nil
	case isNotFound(e):
		return false, nil
	default:
		return false, e
	}
}

func (h *Host) meteredBucketExists(ctx context.Context, b string, isCleanup bool) (bool, *hostkit.CloudError) {
	if h.cfg.Store == nil {
		return false, missingStore()
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "bucket_exists", safety.AttemptPricingInput{Operation: "bucket_exists", IsCleanup: isCleanup}, safety.KindBucket, b)
	if cerr != nil {
		return false, cerr
	}
	exists, e := h.realBucketExists(mctx, b)
	_, _, aerr := scope.finish(0, 0, true, e == nil)
	if aerr != nil {
		e = aerr
	}
	return exists, e
}

func (h *Host) meteredBucketCreateToken(ctx context.Context, b, token string) (bool, *hostkit.CloudError) {
	if token == "" || h.cfg.Store == nil {
		return false, nil
	}
	rawStore := h.cfg.Store
	if gs, ok := rawStore.(guardStore); ok {
		rawStore = gs.s
	}
	r, ok := rawStore.(hostkit.BucketCreateTokenReader)
	if !ok {
		return false, nil
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "bucket_read_ownership", safety.AttemptPricingInput{Operation: "bucket_read_ownership"}, safety.KindBucket, b)
	if cerr != nil {
		return false, cerr
	}
	got, err := r.BucketCreateToken(mctx, b)
	err = hostkit.NilIfTyped(err)
	_, _, aerr := scope.finish(0, 0, true, err == nil)
	if aerr != nil {
		return false, aerr
	}
	if err != nil {
		if ce := hostkit.AsCloudError(err); ce != nil && ce.Code == hostkit.CostCapExceeded {
			return false, ce
		}
		return false, nil
	}
	return got == token, nil
}

func (h *Host) bucketExists(ctx context.Context, dry bool, b string) (bool, *hostkit.CloudError) {
	if dry {
		if v, ok := h.ov(ctx).bucket(b); ok {
			return v, nil
		}
	}
	return h.realBucketExists(ctx, b)
}

func (h *Host) realQueueExists(ctx context.Context, q string) (bool, *hostkit.CloudError) {
	if h.cfg.Queue == nil {
		return false, missingQueue()
	}
	e := hostkit.AsCloudError(h.cfg.Queue.LookupQueue(ctx, q))
	switch {
	case e == nil:
		return true, nil
	case isNotFound(e):
		return false, nil
	default:
		return false, e
	}
}

func (h *Host) meteredQueueExists(ctx context.Context, q string) (bool, *hostkit.CloudError) {
	if h.cfg.Queue == nil {
		return false, missingQueue()
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "queue_exists", safety.AttemptPricingInput{Operation: "queue_exists"}, safety.KindQueue, q)
	if cerr != nil {
		return false, cerr
	}
	exists, e := h.realQueueExists(mctx, q)
	_, _, aerr := scope.finish(0, 0, true, e == nil)
	if aerr != nil {
		e = aerr
	}
	return exists, e
}

func (h *Host) meteredQueueCreateToken(ctx context.Context, q, token string) (bool, *hostkit.CloudError) {
	if token == "" || h.cfg.Queue == nil {
		return false, nil
	}
	rawQueue := h.cfg.Queue
	if gq, ok := rawQueue.(guardQueue); ok {
		rawQueue = gq.q
	}
	r, ok := rawQueue.(hostkit.QueueCreateTokenReader)
	if !ok {
		return false, nil
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "queue_read_ownership", safety.AttemptPricingInput{Operation: "queue_read_ownership"}, safety.KindQueue, q)
	if cerr != nil {
		return false, cerr
	}
	got, err := r.QueueCreateToken(mctx, q)
	err = hostkit.NilIfTyped(err)
	_, _, aerr := scope.finish(0, 0, true, err == nil)
	if aerr != nil {
		return false, aerr
	}
	if err != nil {
		if ce := hostkit.AsCloudError(err); ce != nil && ce.Code == hostkit.CostCapExceeded {
			return false, ce
		}
		return false, nil
	}
	return got == token, nil
}

func (h *Host) queueExists(ctx context.Context, dry bool, q string) (bool, *hostkit.CloudError) {
	if dry {
		if v, ok := h.ov(ctx).queue(q); ok {
			return v, nil
		}
	}
	return h.realQueueExists(ctx, q)
}

// ---- buckets ----

// BucketCreate implements bucket_create.
func (h *Host) BucketCreate(dry bool, b string) (bool, error) {
	const op = "bucket_create"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Bucket(b); e != nil {
		failed = true
		return false, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, b, e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			failed = true
			return false, h.fail(op, b, e)
		}
		h.ov(ctx).setBucket(b, true, !exists)
		h.ok()
		return !exists, nil
	}
	if h.cfg.Store == nil {
		failed = true
		return false, h.fail(op, b, missingStore())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindBucket, b)
	if cerr != nil {
		failed = true
		return false, h.fail(op, b, cerr)
	}
	token := newCreateToken()
	h.errs.AddRedaction(token) // v4: never echoed into last_error/aborts
	mctx = hostkit.WithCreateToken(mctx, token)
	created, err := h.cfg.Store.CreateBucket(mctx, b)
	var abortErr *hostkit.CloudError
	if err == nil {
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, b, abortErr)
		}
		h.ok()
		return created, nil
	}
	ce := hostkit.AsCloudError(err)
	if ce.Code == hostkit.Conflict {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, b, abortErr)
		}
		// Design 02 §6.1: 409 is idempotent success only if the bucket is accessible in our scope.
		exists, perr := h.meteredBucketExists(ctx, b, false)
		if perr == nil && exists {
			proven, terr := h.meteredBucketCreateToken(ctx, b, token)
			if terr != nil {
				failed = true
				return false, h.fail(op, b, terr)
			}
			if proven {
				h.cost.lockResourceCleanupIfNeeded(hostkit.EndpointFrom(ctx), op, safety.KindBucket, b)
			}
			h.ok()
			return proven, nil
		}
		if perr != nil && perr.Code == hostkit.CostCapExceeded {
			failed = true
			return false, h.fail(op, b, perr)
		}
		failed = true
		return false, h.fail(op, b, ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, false)
	if abortErr != nil {
		ce = abortErr
	}
	failed = true
	return false, h.fail(op, b, ce)
}

// BucketDelete implements bucket_delete.
func (h *Host) BucketDelete(dry bool, b string) (bool, error) {
	const op = "bucket_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Bucket(b); e != nil {
		failed = true
		return false, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, b, e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			failed = true
			return false, h.fail(op, b, e)
		}
		if !exists {
			h.ok()
			return false, nil
		}
		keys, e := h.dryKeys(ctx, b, "")
		if e != nil {
			failed = true
			return false, h.fail(op, b, e)
		}
		if len(keys) > 0 {
			failed = true
			return false, h.fail(op, b, hostkit.ProviderError(hostkit.Conflict, 409, "BucketNotEmpty", "bucket is not empty (dry-run preview)"))
		}
		h.ov(ctx).setBucket(b, false, false)
		h.ok()
		return true, nil
	}
	if h.cfg.Store == nil {
		failed = true
		return false, h.fail(op, b, missingStore())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: true}, safety.KindBucket, b)
	if cerr != nil {
		failed = true
		return false, h.fail(op, b, cerr)
	}
	ce := hostkit.AsCloudError(h.cfg.Store.DeleteBucket(mctx, b))
	var abortErr *hostkit.CloudError
	switch {
	case ce == nil:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, b, abortErr)
		}
		h.ok()
		return true, nil
	case isNotFound(ce) && ce.Absent != hostkit.AbsentObject:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, b, abortErr)
		}
		h.ok()
		return false, nil
	default:
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return false, h.fail(op, b, ce)
	}
}

// BucketExists implements bucket_exists. Only a genuine NOT_FOUND yields false/OK.
func (h *Host) BucketExists(dry bool, b string) (bool, error) {
	const op = "bucket_exists"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Bucket(b); e != nil {
		failed = true
		return false, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, b, e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			failed = true
			return false, h.fail(op, b, e)
		}
		h.ok()
		return exists, nil
	}
	if h.cfg.Store == nil {
		failed = true
		return false, h.fail(op, b, missingStore())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindBucket, b)
	if cerr != nil {
		failed = true
		return false, h.fail(op, b, cerr)
	}
	exists, e := h.realBucketExists(mctx, b)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, e == nil)
	if abortErr != nil {
		e = abortErr
	}
	if e != nil {
		failed = true
		return false, h.fail(op, b, e)
	}
	h.ok()
	return exists, nil
}

// BucketList implements bucket_list: every page, sorted, de-duplicated.
func (h *Host) BucketList(dry bool) ([]string, error) {
	const op = "bucket_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	ctx, cancel, e := h.opCtx("storage", h.cfg.ListTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	defer cancel()
	if h.cfg.Store == nil {
		failed = true
		return nil, h.fail(op, "", missingStore())
	}
	names, e := hostkit.ListAll(ctx, h.cfg.MaxPages, func(ctx context.Context, token string) ([]string, string, error) {
		if dry {
			return h.cfg.Store.ListBuckets(ctx, token)
		}
		mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindBucket, "")
		if cerr != nil {
			return nil, "", cerr
		}
		items, next, err := h.cfg.Store.ListBuckets(mctx, token)
		r, t, abortErr := scope.finish(0, 0, true, err == nil)
		retries += r
		throttles += t
		if abortErr != nil {
			return nil, "", abortErr
		}
		return items, next, err
	})
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	if dry {
		names = h.ov(ctx).mergeBuckets(names)
	}
	h.ok()
	return hostkit.SortedUnique(names), nil
}

// ---- objects ----

// ObjectPut implements both object_put overloads.
func (h *Host) ObjectPut(dry bool, b, k, body, ct string, meta map[string]string) (*hostkit.ObjectMeta, error) {
	const op = "object_put"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesOut int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, bytesOut)
		}
	}()
	none := &hostkit.ObjectMeta{Bucket: b, Key: k, Metadata: map[string]string{}}
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k), hostkit.ObjectSize(len(body)), hostkit.ContentType(ct), hostkit.Metadata(meta)} {
		if e != nil {
			failed = true
			return none, h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return none, h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			failed = true
			return none, h.fail(op, target(b, k), e)
		}
		if !exists {
			failed = true
			return none, h.fail(op, target(b, k), notFound(hostkit.AbsentBucket, "bucket does not exist (dry-run preview)"))
		}
		m := &hostkit.ObjectMeta{Exists: true, Bucket: b, Key: k, Size: int64(len(body)), ETag: dryETag(body), ContentType: ct, Metadata: copyMap(meta)}
		h.ov(ctx).putObject(b, k, body, m)
		h.ok()
		return m, nil
	}
	if h.cfg.Store == nil {
		failed = true
		return none, h.fail(op, target(b, k), missingStore())
	}
	sz := int64(len(body))
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, PayloadSize: sz}, safety.KindObject, target(b, k))
	if cerr != nil {
		failed = true
		return none, h.fail(op, target(b, k), cerr)
	}
	m, err := h.cfg.Store.PutObject(mctx, b, k, []byte(body), ct, copyMap(meta))
	var abortErr *hostkit.CloudError
	if err != nil {
		retries, throttles, abortErr = scope.finish(sz, sz, false, false)
		ce := hostkit.AsCloudError(err)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return none, h.fail(op, target(b, k), ce)
	}
	retries, throttles, abortErr = scope.finish(sz, sz, true, true)
	if abortErr != nil {
		failed = true
		return none, h.fail(op, target(b, k), abortErr)
	}
	bytesOut = sz
	m.Exists, m.Bucket, m.Key, m.Size = true, b, k, sz
	m.ETag = NormalizeETag(m.ETag)
	if m.ContentType == "" {
		m.ContentType = ct
	}
	if m.Metadata == nil {
		m.Metadata = copyMap(meta)
	}
	h.ok()
	return &m, nil
}

// ObjectGet implements object_get. Oversized bodies fail; they are never truncated.
func (h *Host) ObjectGet(dry bool, b, k string) (string, error) {
	const op = "object_get"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k)} {
		if e != nil {
			failed = true
			return "", h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return "", h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		if state, body, _ := h.ov(ctx).object(b, k); state != dryUnknown {
			if state == dryPresent {
				h.ok()
				return body, nil
			}
			failed = true
			return "", h.fail(op, target(b, k), h.dryMissing(state))
		}
	}
	if h.cfg.Store == nil {
		failed = true
		return "", h.fail(op, target(b, k), missingStore())
	}
	var scope *attemptScope
	mctx := ctx
	if !dry {
		var cerr *hostkit.CloudError
		mctx, scope, cerr = h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, EgressBytes: hostkit.MaxObjectBytes}, safety.KindObject, target(b, k))
		if cerr != nil {
			failed = true
			return "", h.fail(op, target(b, k), cerr)
		}
	}
	data, err := h.cfg.Store.GetObject(mctx, b, k, hostkit.MaxObjectBytes)
	var abortErr *hostkit.CloudError
	if err != nil {
		headerStarted := scope != nil && scope.hasLastAttempt && scope.lastAttempt.Status >= 200 && scope.lastAttempt.Status < 400
		if len(data) == 0 && !headerStarted && isDefinitiveNonStreamError(err) {
			retries, throttles, abortErr = scope.finish(0, 0, true, false)
		} else {
			retries, throttles, abortErr = scope.finish(hostkit.MaxObjectBytes, hostkit.MaxObjectBytes, false, false)
		}
		ce := hostkit.AsCloudError(err)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return "", h.fail(op, target(b, k), ce)
	}
	if len(data) > hostkit.MaxObjectBytes {
		retries, throttles, abortErr = scope.finish(hostkit.MaxObjectBytes, hostkit.MaxObjectBytes, false, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "object body exceeds the 16 MiB limit; refusing to truncate")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return "", h.fail(op, target(b, k), ce)
	}
	actualBytes := int64(len(data))
	retries, throttles, abortErr = scope.finish(actualBytes, actualBytes, true, true)
	if abortErr != nil {
		failed = true
		return "", h.fail(op, target(b, k), abortErr)
	}
	bytesIn = actualBytes
	h.ok()
	return string(data), nil
}

func (h *Host) dryMissing(state dryState) *hostkit.CloudError {
	if state == dryBucketGone {
		return notFound(hostkit.AbsentBucket, "bucket does not exist (dry-run preview)")
	}
	return notFound(hostkit.AbsentObject, "object does not exist (dry-run preview)")
}

// ObjectHead implements object_head: missing key in an existing bucket is exists()==false/OK.
func (h *Host) ObjectHead(dry bool, b, k string) (*hostkit.ObjectMeta, error) {
	const op = "object_head"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	absent := &hostkit.ObjectMeta{Bucket: b, Key: k, Metadata: map[string]string{}}
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k)} {
		if e != nil {
			failed = true
			return absent, h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return absent, h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		if state, _, m := h.ov(ctx).object(b, k); state != dryUnknown {
			switch state {
			case dryPresent:
				h.ok()
				c := *m
				c.Metadata = copyMap(m.Metadata)
				return &c, nil
			case dryBucketGone:
				failed = true
				return absent, h.fail(op, target(b, k), h.dryMissing(state))
			default:
				h.ok()
				return absent, nil
			}
		}
	}
	if h.cfg.Store == nil {
		failed = true
		return absent, h.fail(op, target(b, k), missingStore())
	}
	var scope *attemptScope
	mctx := ctx
	if !dry {
		var cerr *hostkit.CloudError
		mctx, scope, cerr = h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindObject, target(b, k))
		if cerr != nil {
			failed = true
			return absent, h.fail(op, target(b, k), cerr)
		}
	}
	m, err := h.cfg.Store.HeadObject(mctx, b, k)
	var abortErr *hostkit.CloudError
	if err == nil {
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return absent, h.fail(op, target(b, k), abortErr)
		}
		m.Exists, m.Bucket, m.Key = true, b, k
		m.ETag = NormalizeETag(m.ETag)
		if m.ContentType == "" {
			m.ContentType = "application/octet-stream"
		}
		if m.Metadata == nil {
			m.Metadata = map[string]string{}
		}
		h.ok()
		return &m, nil
	}
	ce := hostkit.AsCloudError(err)
	if !isNotFound(ce) {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return absent, h.fail(op, target(b, k), ce)
	}
	switch ce.Absent {
	case hostkit.AbsentObject:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return absent, h.fail(op, target(b, k), abortErr)
		}
		h.ok()
		return absent, nil
	case hostkit.AbsentBucket:
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return absent, h.fail(op, target(b, k), ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return absent, h.fail(op, target(b, k), abortErr)
	}
	var exists bool
	var perr *hostkit.CloudError
	if dry {
		exists, perr = h.realBucketExists(ctx, b)
	} else {
		exists, perr = h.meteredBucketExists(ctx, b, false)
	}
	if perr != nil {
		failed = true
		return absent, h.fail(op, target(b, k), perr)
	}
	if !exists {
		failed = true
		return absent, h.fail(op, target(b, k), ce.WithAbsent(hostkit.AbsentBucket))
	}
	h.ok()
	return absent, nil
}

// ObjectDelete implements object_delete: idempotent within an existing bucket.
func (h *Host) ObjectDelete(dry bool, b, k string) error {
	const op = "object_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k)} {
		if e != nil {
			failed = true
			return h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			failed = true
			return h.fail(op, target(b, k), e)
		}
		if !exists {
			failed = true
			return h.fail(op, target(b, k), notFound(hostkit.AbsentBucket, "bucket does not exist (dry-run preview)"))
		}
		h.ov(ctx).deleteObject(b, k)
		h.ok()
		return nil
	}
	if h.cfg.Store == nil {
		failed = true
		return h.fail(op, target(b, k), missingStore())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: true}, safety.KindObject, target(b, k))
	if cerr != nil {
		failed = true
		return h.fail(op, target(b, k), cerr)
	}
	ce := hostkit.AsCloudError(h.cfg.Store.DeleteObject(mctx, b, k))
	var abortErr *hostkit.CloudError
	if ce == nil {
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return h.fail(op, target(b, k), abortErr)
		}
		h.ok()
		return nil
	}
	if !isNotFound(ce) {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return h.fail(op, target(b, k), ce)
	}
	switch ce.Absent {
	case hostkit.AbsentObject:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return h.fail(op, target(b, k), abortErr)
		}
		h.ok()
		return nil
	case hostkit.AbsentBucket:
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return h.fail(op, target(b, k), ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return h.fail(op, target(b, k), abortErr)
	}
	exists, perr := h.meteredBucketExists(ctx, b, true)
	if perr != nil {
		failed = true
		return h.fail(op, target(b, k), perr)
	}
	if !exists {
		failed = true
		return h.fail(op, target(b, k), ce.WithAbsent(hostkit.AbsentBucket))
	}
	h.ok()
	return nil
}

// Page is the ObjectListPage snapshot.
type Page struct {
	Items     []hostkit.ObjectSummary
	NextToken string
}

// ObjectList implements both object_list overloads.
func (h *Host) ObjectList(dry bool, b, prefix string, maxKeys int64, token string) (*Page, error) {
	const op = "object_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	empty := &Page{}
	if e := h.cfg.Validator.Bucket(b); e != nil {
		failed = true
		return empty, h.fail(op, b, e)
	}
	max, e := hostkit.ListMax(maxKeys)
	if e != nil {
		failed = true
		return empty, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return empty, h.fail(op, b, e)
	}
	defer cancel()
	if dry && h.ov(ctx).touchesBucket(b) {
		keys, e := h.dryKeys(ctx, b, prefix)
		if e != nil {
			failed = true
			return empty, h.fail(op, b, e)
		}
		p := &Page{}
		for _, k := range keys {
			if token != "" && k <= token {
				continue
			}
			if len(p.Items) == max {
				p.NextToken = p.Items[len(p.Items)-1].Key
				break
			}
			_, body, m := h.ov(ctx).object(b, k)
			s := hostkit.ObjectSummary{Key: k}
			if m != nil {
				s.Size, s.ETag = int64(len(body)), m.ETag
			}
			p.Items = append(p.Items, s)
		}
		h.ok()
		return p, nil
	}
	if h.cfg.Store == nil {
		failed = true
		return empty, h.fail(op, b, missingStore())
	}
	var scope *attemptScope
	mctx := ctx
	if !dry {
		var cerr *hostkit.CloudError
		mctx, scope, cerr = h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindBucket, b)
		if cerr != nil {
			failed = true
			return empty, h.fail(op, b, cerr)
		}
	}
	page, err := h.cfg.Store.ListObjects(mctx, b, prefix, max, token)
	var abortErr *hostkit.CloudError
	if err != nil {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		ce := hostkit.AsCloudError(err)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return empty, h.fail(op, b, ce)
	}
	if len(page.Items) > max {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned more items than max_keys")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return empty, h.fail(op, b, ce)
	}
	if token != "" && page.NextToken == token {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "pagination stalled: continuation token repeated")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return empty, h.fail(op, b, ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return empty, h.fail(op, b, abortErr)
	}
	items := append([]hostkit.ObjectSummary(nil), page.Items...)
	sort.SliceStable(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	for i := range items {
		items[i].ETag = NormalizeETag(items[i].ETag)
	}
	h.ok()
	return &Page{Items: items, NextToken: page.NextToken}, nil
}

func (h *Host) realKeys(ctx context.Context, b, prefix string) ([]string, *hostkit.CloudError) {
	if h.cfg.Store == nil {
		return nil, missingStore()
	}
	return hostkit.ListAll(ctx, h.cfg.MaxPages, func(ctx context.Context, token string) ([]string, string, error) {
		page, err := h.cfg.Store.ListObjects(ctx, b, prefix, hostkit.MaxListMax, token)
		if err != nil {
			return nil, "", err
		}
		keys := make([]string, len(page.Items))
		for i, it := range page.Items {
			keys[i] = it.Key
		}
		return keys, page.NextToken, nil
	})
}

// dryKeys merges the real listing with the dry overlay for bucket b.
func (h *Host) dryKeys(ctx context.Context, b, prefix string) ([]string, *hostkit.CloudError) {
	var real []string
	if !h.ov(ctx).bucketCreatedInDry(b) {
		keys, e := h.realKeys(ctx, b, prefix)
		if e != nil {
			return nil, e
		}
		real = keys
	}
	return h.ov(ctx).mergeKeys(b, prefix, real), nil
}

// ObjectListAll implements object_list_all: all pages or an error, never partial.
func (h *Host) ObjectListAll(dry bool, b, prefix string) ([]string, error) {
	const op = "object_list_all"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Bucket(b); e != nil {
		failed = true
		return nil, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.ListTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, b, e)
	}
	defer cancel()
	var keys []string
	if dry {
		if h.ov(ctx).touchesBucket(b) {
			keys, e = h.dryKeys(ctx, b, prefix)
		} else {
			keys, e = h.realKeys(ctx, b, prefix)
		}
	} else {
		if h.cfg.Store == nil {
			failed = true
			return nil, h.fail(op, b, missingStore())
		}
		keys, e = hostkit.ListAll(ctx, h.cfg.MaxPages, func(ctx context.Context, token string) ([]string, string, error) {
			mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindBucket, b)
			if cerr != nil {
				return nil, "", cerr
			}
			page, err := h.cfg.Store.ListObjects(mctx, b, prefix, hostkit.MaxListMax, token)
			r, t, abortErr := scope.finish(0, 0, true, err == nil)
			retries += r
			throttles += t
			if abortErr != nil {
				return nil, "", abortErr
			}
			if err != nil {
				return nil, "", err
			}
			out := make([]string, len(page.Items))
			for i, it := range page.Items {
				out[i] = it.Key
			}
			return out, page.NextToken, nil
		})
	}
	if e != nil {
		failed = true
		return nil, h.fail(op, b, e)
	}
	h.ok()
	return hostkit.SortedUnique(keys), nil
}

// ---- queues ----

// QueueCreate implements queue_create.
func (h *Host) QueueCreate(dry bool, q string) (bool, error) {
	const op = "queue_create"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Queue(q); e != nil {
		failed = true
		return false, h.fail(op, q, e)
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		exists, e := h.queueExists(ctx, true, q)
		if e != nil {
			failed = true
			return false, h.fail(op, q, e)
		}
		h.ov(ctx).setQueue(q, true)
		h.ok()
		return !exists, nil
	}
	if h.cfg.Queue == nil {
		failed = true
		return false, h.fail(op, q, missingQueue())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindQueue, q)
	if cerr != nil {
		failed = true
		return false, h.fail(op, q, cerr)
	}
	token := newCreateToken()
	h.errs.AddRedaction(token) // v4: never echoed into last_error/aborts
	mctx = hostkit.WithCreateToken(mctx, token)
	created, err := h.cfg.Queue.CreateQueue(mctx, q)
	var abortErr *hostkit.CloudError
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if ce.Code == hostkit.Conflict {
			retries, throttles, abortErr = scope.finish(0, 0, true, false)
			if abortErr != nil {
				failed = true
				return false, h.fail(op, q, abortErr)
			}
			exists, perr := h.meteredQueueExists(ctx, q)
			if perr == nil && exists {
				proven, terr := h.meteredQueueCreateToken(ctx, q, token)
				if terr != nil {
					failed = true
					return false, h.fail(op, q, terr)
				}
				if proven {
					h.cost.lockResourceCleanupIfNeeded(hostkit.EndpointFrom(ctx), op, safety.KindQueue, q)
				}
				h.ok()
				return proven, nil
			}
			if perr != nil && perr.Code == hostkit.CostCapExceeded {
				failed = true
				return false, h.fail(op, q, perr)
			}
			failed = true
			return false, h.fail(op, q, ce)
		}
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return false, h.fail(op, q, ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, q, abortErr)
	}
	h.ok()
	return created, nil
}

// QueueDelete implements queue_delete.
func (h *Host) QueueDelete(dry bool, q string) (bool, error) {
	const op = "queue_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Queue(q); e != nil {
		failed = true
		return false, h.fail(op, q, e)
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		exists, e := h.queueExists(ctx, true, q)
		if e != nil {
			failed = true
			return false, h.fail(op, q, e)
		}
		h.ov(ctx).setQueue(q, false)
		h.ok()
		return exists, nil
	}
	if h.cfg.Queue == nil {
		failed = true
		return false, h.fail(op, q, missingQueue())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: true}, safety.KindQueue, q)
	if cerr != nil {
		failed = true
		return false, h.fail(op, q, cerr)
	}
	ce := hostkit.AsCloudError(h.cfg.Queue.DeleteQueue(mctx, q))
	var abortErr *hostkit.CloudError
	switch {
	case ce == nil:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, q, abortErr)
		}
		h.ok()
		return true, nil
	case isNotFound(ce):
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, q, abortErr)
		}
		h.ok()
		return false, nil
	default:
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return false, h.fail(op, q, ce)
	}
}

// QueueExists implements queue_exists.
func (h *Host) QueueExists(dry bool, q string) (bool, error) {
	const op = "queue_exists"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Queue(q); e != nil {
		failed = true
		return false, h.fail(op, q, e)
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		exists, e := h.queueExists(ctx, true, q)
		if e != nil {
			failed = true
			return false, h.fail(op, q, e)
		}
		h.ok()
		return exists, nil
	}
	if h.cfg.Queue == nil {
		failed = true
		return false, h.fail(op, q, missingQueue())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindQueue, q)
	if cerr != nil {
		failed = true
		return false, h.fail(op, q, cerr)
	}
	exists, e := h.realQueueExists(mctx, q)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, e == nil)
	if abortErr != nil {
		e = abortErr
	}
	if e != nil {
		failed = true
		return false, h.fail(op, q, e)
	}
	h.ok()
	return exists, nil
}

// QueueList implements queue_list: every page, sorted, de-duplicated.
func (h *Host) QueueList(dry bool) ([]string, error) {
	const op = "queue_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	ctx, cancel, e := h.opCtx("queue", h.cfg.ListTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	defer cancel()
	if h.cfg.Queue == nil {
		failed = true
		return nil, h.fail(op, "", missingQueue())
	}
	names, e := hostkit.ListAll(ctx, h.cfg.MaxPages, func(ctx context.Context, token string) ([]string, string, error) {
		if dry {
			return h.cfg.Queue.ListQueues(ctx, token)
		}
		mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindQueue, "")
		if cerr != nil {
			return nil, "", cerr
		}
		items, next, err := h.cfg.Queue.ListQueues(mctx, token)
		r, t, abortErr := scope.finish(0, 0, true, err == nil)
		retries += r
		throttles += t
		if abortErr != nil {
			return nil, "", abortErr
		}
		return items, next, err
	})
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	if dry {
		names = h.ov(ctx).mergeQueues(names)
	}
	h.ok()
	return hostkit.SortedUnique(names), nil
}

func (h *Host) requireQueue(ctx context.Context, dry bool, q string) *hostkit.CloudError {
	exists, e := h.queueExists(ctx, dry, q)
	if e != nil {
		return e
	}
	if !exists {
		return notFound(hostkit.AbsentQueue, "queue does not exist (dry-run preview)")
	}
	return nil
}

// QueueSend implements queue_send.
func (h *Host) QueueSend(dry bool, q, body string) (string, error) {
	const op = "queue_send"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesOut int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, bytesOut)
		}
	}()
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.QueueBodySize(len(body))} {
		if e != nil {
			failed = true
			return "", h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return "", h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		if e := h.requireQueue(ctx, true, q); e != nil {
			failed = true
			return "", h.fail(op, q, e)
		}
		h.ok()
		return "dry-run-message-id", nil
	}
	if h.cfg.Queue == nil {
		failed = true
		return "", h.fail(op, q, missingQueue())
	}
	sz := int64(len(body))
	wire := hostkit.EncodeQueueBody(body, hostkit.CapsFor(ctx, h.cfg.Queue, q).TextOnlyWire)
	chargeBytes := sz
	if int64(len(wire)) > chargeBytes {
		chargeBytes = int64(len(wire))
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, PayloadSize: chargeBytes}, safety.KindQueue, q)
	if cerr != nil {
		failed = true
		return "", h.fail(op, q, cerr)
	}
	id, err := h.cfg.Queue.Send(mctx, q, wire)
	var abortErr *hostkit.CloudError
	if err != nil {
		retries, throttles, abortErr = scope.finish(chargeBytes, sz, false, false)
		ce := hostkit.AsCloudError(err)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return "", h.fail(op, q, ce)
	}
	if id == "" {
		retries, throttles, abortErr = scope.finish(chargeBytes, sz, false, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "provider accepted the message but returned no message id")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return "", h.fail(op, q, ce)
	}
	retries, throttles, abortErr = scope.finish(chargeBytes, sz, true, true)
	if abortErr != nil {
		failed = true
		return "", h.fail(op, q, abortErr)
	}
	bytesOut = sz
	h.ok()
	return id, nil
}

// Message is the QueueMessage snapshot.
type Message struct {
	ID, Body, Receipt string
}

// QueueReceive implements both queue_receive overloads.
func (h *Host) QueueReceive(dry bool, q string, max, wait, vis int64) ([]Message, error) {
	const op = "queue_receive"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.ReceiveArgs(max, wait, vis)} {
		if e != nil {
			failed = true
			return nil, h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout+time.Duration(wait)*time.Second)
	if e != nil {
		failed = true
		return nil, h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		// Receiving consumes (hides) messages: the preview never calls Receive.
		if e := h.requireQueue(ctx, true, q); e != nil {
			failed = true
			return nil, h.fail(op, q, e)
		}
		h.ok()
		return nil, nil
	}
	if h.cfg.Queue == nil {
		failed = true
		return nil, h.fail(op, q, missingQueue())
	}
	caps := hostkit.CapsFor(ctx, h.cfg.Queue, q)
	maxWire, cerr := hostkit.ProviderMaxQueueReceiveWireBytes(h.cost.provider, int(max), caps)
	if cerr != nil {
		failed = true
		return nil, h.fail(op, q, cerr)
	}
	perMsgWireLimit := int64(65_536)
	if caps.TextOnlyWire {
		perMsgWireLimit = 2 * 65_536
	}
	maxBatchWireLimit := int64(max) * perMsgWireLimit
	pricingIn := safety.AttemptPricingInput{Operation: op, PayloadSize: maxWire}

	parseRawMessages := func(raw []hostkit.RawMessage) ([]Message, int64, int64, *hostkit.CloudError) {
		var rawWireTotal int64
		for _, m := range raw {
			rawWireTotal += int64(len(m.Wire))
		}
		errWire := rawWireTotal
		if errWire <= 0 {
			errWire = maxWire
		}
		if len(raw) > int(max) {
			return nil, errWire, errWire, hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned more messages than max_messages")
		}
		out := make([]Message, 0, len(raw))
		var totalDecoded, totalCharge int64
		for _, m := range raw {
			if m.ID == "" || m.Receipt == "" {
				return nil, errWire, errWire, hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned a message without id or receipt")
			}
			wireSz := int64(len(m.Wire))
			if wireSz > perMsgWireLimit {
				return nil, errWire, errWire, hostkit.ProviderError(hostkit.Internal, 0, "OversizedQueueMessage", "provider returned a message exceeding the per-message wire bound")
			}
			body, e := hostkit.DecodeQueueBody(m.Wire)
			if e != nil {
				return nil, errWire, errWire, e
			}
			decSz := int64(len(body))
			if decSz > hostkit.MaxQueueBodyBytes {
				return nil, errWire, errWire, hostkit.ProviderError(hostkit.Internal, 0, "OversizedQueueMessage", "provider returned a message body exceeding the 48 KiB limit")
			}
			if decSz > wireSz {
				wireSz = decSz
			}
			totalDecoded += decSz
			totalCharge += wireSz
			if totalCharge > maxBatchWireLimit {
				return nil, errWire, errWire, hostkit.ProviderError(hostkit.Internal, 0, "OversizedQueueMessage", "provider returned a batch exceeding the quoted wire bound")
			}
			out = append(out, Message{ID: m.ID, Body: body, Receipt: m.Receipt})
		}
		return out, totalCharge, totalDecoded, nil
	}

	if caps.LongPoll {
		mctx, scope, cerr := h.beginAttemptScope(ctx, op, pricingIn, safety.KindQueue, q)
		if cerr != nil {
			failed = true
			return nil, h.fail(op, q, cerr)
		}
		raw, rerr := h.cfg.Queue.Receive(mctx, q, int(max), int(wait), int(vis))
		var abortErr *hostkit.CloudError
		if rerr != nil {
			headerStarted := scope != nil && scope.hasLastAttempt && scope.lastAttempt.Status >= 200 && scope.lastAttempt.Status < 400
			if len(raw) == 0 && !headerStarted && isDefinitiveNonStreamError(rerr) {
				retries, throttles, abortErr = scope.finish(0, 0, true, false)
			} else {
				retries, throttles, abortErr = scope.finish(maxWire, maxWire, false, false)
			}
			ce := hostkit.AsCloudError(rerr)
			if abortErr != nil {
				ce = abortErr
			}
			failed = true
			return nil, h.fail(op, q, ce)
		}
		out, totalCharge, totalDecoded, perr := parseRawMessages(raw)
		if perr != nil {
			retries, throttles, abortErr = scope.finish(totalCharge, totalDecoded, true, false)
			if abortErr != nil {
				perr = abortErr
			}
			failed = true
			return nil, h.fail(op, q, perr)
		}
		retries, throttles, abortErr = scope.finish(totalCharge, totalDecoded, true, true)
		if abortErr != nil {
			failed = true
			return nil, h.fail(op, q, abortErr)
		}
		bytesIn = totalDecoded
		h.ok()
		return out, nil
	}

	var out []Message
	rerr := hostkit.WaitLoop(ctx, time.Duration(wait)*time.Second, h.cfg.PollInterval, h.cfg.Now, h.cfg.Sleep, func(pollCtx context.Context) (int, error) {
		mctx, scope, cerr := h.beginAttemptScope(pollCtx, op, pricingIn, safety.KindQueue, q)
		if cerr != nil {
			return 0, cerr
		}
		raw, err := h.cfg.Queue.Receive(mctx, q, int(max), 0, int(vis))
		if err != nil {
			var r, t int64
			var abortErr *hostkit.CloudError
			headerStarted := scope != nil && scope.hasLastAttempt && scope.lastAttempt.Status >= 200 && scope.lastAttempt.Status < 400
			if len(raw) == 0 && !headerStarted && isDefinitiveNonStreamError(err) {
				r, t, abortErr = scope.finish(0, 0, true, false)
			} else {
				r, t, abortErr = scope.finish(maxWire, maxWire, false, false)
			}
			retries += r
			throttles += t
			if abortErr != nil {
				return 0, abortErr
			}
			return 0, err
		}
		parsed, totalCharge, totalDecoded, perr := parseRawMessages(raw)
		if perr != nil {
			r, t, abortErr := scope.finish(totalCharge, totalDecoded, true, false)
			retries += r
			throttles += t
			if abortErr != nil {
				return 0, abortErr
			}
			return 0, perr
		}
		r, t, abortErr := scope.finish(totalCharge, totalDecoded, true, true)
		retries += r
		throttles += t
		if abortErr != nil {
			return 0, abortErr
		}
		out = parsed
		bytesIn += totalDecoded
		return len(parsed), nil
	})
	if rerr != nil {
		failed = true
		return nil, h.fail(op, q, hostkit.AsCloudError(rerr))
	}
	h.ok()
	return out, nil
}

// QueueAck implements queue_ack with missing-queue precedence and idempotent re-ack.
func (h *Host) QueueAck(dry bool, q, receipt string) error {
	const op = "queue_ack"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.Receipt(receipt)} {
		if e != nil {
			failed = true
			return h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		if e := h.requireQueue(ctx, true, q); e != nil {
			failed = true
			return h.fail(op, q, e)
		}
		h.ok()
		return nil
	}
	if h.cfg.Queue == nil {
		failed = true
		return h.fail(op, q, missingQueue())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: false}, safety.KindQueue, q)
	if cerr != nil {
		failed = true
		return h.fail(op, q, cerr)
	}
	ce := hostkit.AsCloudError(h.cfg.Queue.Ack(mctx, q, receipt))
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, ce == nil)
	if abortErr != nil {
		failed = true
		return h.fail(op, q, abortErr)
	}
	ce = hostkit.ReceiptPrecedence(ce, true, func() (bool, *hostkit.CloudError) { return h.meteredQueueExists(ctx, q) })
	if ce != nil {
		failed = true
		return h.fail(op, q, ce)
	}
	h.ok()
	return nil
}

// QueueNack implements queue_nack and returns the receipt valid from now on.
func (h *Host) QueueNack(dry bool, q, receipt string, vis int64) (string, error) {
	const op = "queue_nack"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.Visibility(vis), hostkit.Receipt(receipt)} {
		if e != nil {
			failed = true
			return "", h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return "", h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		if e := h.requireQueue(ctx, true, q); e != nil {
			failed = true
			return "", h.fail(op, q, e)
		}
		h.ok()
		return receipt, nil
	}
	if h.cfg.Queue == nil {
		failed = true
		return "", h.fail(op, q, missingQueue())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindQueue, q)
	if cerr != nil {
		failed = true
		return "", h.fail(op, q, cerr)
	}
	nr, err := h.cfg.Queue.Nack(mctx, q, receipt, int(vis))
	var abortErr *hostkit.CloudError
	if err != nil {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			failed = true
			return "", h.fail(op, q, abortErr)
		}
		ce := hostkit.ReceiptPrecedence(hostkit.AsCloudError(err), false, func() (bool, *hostkit.CloudError) { return h.meteredQueueExists(ctx, q) })
		if ce == nil {
			ce = hostkit.ProviderError(hostkit.Internal, 0, "", "nack failed")
		}
		failed = true
		return "", h.fail(op, q, ce)
	}
	if nr == "" {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned no receipt after visibility change")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return "", h.fail(op, q, ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return "", h.fail(op, q, abortErr)
	}
	h.ok()
	return nr, nil
}

// ---- dry overlay ----

type dryState int

const (
	dryUnknown dryState = iota
	dryPresent
	dryObjectGone
	dryBucketGone
)

type dryObject struct {
	body string
	meta *hostkit.ObjectMeta // nil = deleted in this dry run
}

type dryTable struct {
	exists     bool
	sorted     bool
	hasSorted  bool
	createdNow bool
}

type dryTableItem struct {
	item *hostkit.Item // nil = deleted in this dry run
}

type dryFunction struct {
	exists          bool
	createdNow      bool
	completeAliases bool
	snap            hostkit.FunctionSnapshot
	versions        map[string]hostkit.FunctionSnapshot
	versionOrder    []string
	aliases         map[string]string
	deletedAliases  map[string]bool
}

// overlay records what a dry run would have changed, so later reads in the
// same dry run see the previewed state instead of aborting. It never reaches
// the provider.
type overlay struct {
	mu        sync.Mutex
	buckets   map[string]bool // true created, false deleted
	created   map[string]bool // bucket did not exist before this dry run
	objects   map[string]map[string]dryObject
	queues    map[string]bool
	tables    map[string]dryTable
	items     map[string]map[string]dryTableItem
	policies  map[string]*hostkit.PolicyAttachment // nil = detached in this dry run
	functions map[string]dryFunction
	drySeq    int64
}

func newOverlay() *overlay {
	return &overlay{
		buckets:   map[string]bool{},
		created:   map[string]bool{},
		objects:   map[string]map[string]dryObject{},
		queues:    map[string]bool{},
		tables:    map[string]dryTable{},
		items:     map[string]map[string]dryTableItem{},
		policies:  map[string]*hostkit.PolicyAttachment{},
		functions: map[string]dryFunction{},
	}
}

func (o *overlay) bucket(b string) (bool, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.buckets[b]
	return v, ok
}

// setBucket records a previewed bucket state; createdNow marks a bucket that
// did not exist before this dry run (so its real listing is known to be empty).
func (o *overlay) setBucket(b string, exists, createdNow bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buckets[b] = exists
	if createdNow {
		o.created[b] = true
	}
	if !exists {
		delete(o.created, b)
		o.objects[b] = map[string]dryObject{}
	}
}

func (o *overlay) bucketCreatedInDry(b string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.created[b] || (o.buckets[b] == false && hasKey(o.buckets, b))
}

func hasKey(m map[string]bool, k string) bool { _, ok := m[k]; return ok }

func (o *overlay) touchesBucket(b string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, a := o.buckets[b]
	_, c := o.objects[b]
	return a || c
}

func (o *overlay) putObject(b, k, body string, m *hostkit.ObjectMeta) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.objects[b] == nil {
		o.objects[b] = map[string]dryObject{}
	}
	o.objects[b][k] = dryObject{body: body, meta: m}
}

func (o *overlay) deleteObject(b, k string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.objects[b] == nil {
		o.objects[b] = map[string]dryObject{}
	}
	o.objects[b][k] = dryObject{}
}

func (o *overlay) object(b, k string) (dryState, string, *hostkit.ObjectMeta) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if v, ok := o.buckets[b]; ok && !v {
		return dryBucketGone, "", nil
	}
	if d, ok := o.objects[b][k]; ok {
		if d.meta == nil {
			return dryObjectGone, "", nil
		}
		return dryPresent, d.body, d.meta
	}
	if o.created[b] {
		return dryObjectGone, "", nil
	}
	return dryUnknown, "", nil
}

func (o *overlay) mergeKeys(b, prefix string, real []string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	set := map[string]bool{}
	for _, k := range real {
		set[k] = true
	}
	for k, d := range o.objects[b] {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		set[k] = d.meta != nil
	}
	var out []string
	for k, live := range set {
		if live {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func mergeSet(names []string, overlay map[string]bool) []string {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for n, v := range overlay {
		set[n] = v
	}
	var out []string
	for n, live := range set {
		if live {
			out = append(out, n)
		}
	}
	return out
}

func (o *overlay) mergeBuckets(names []string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return mergeSet(names, o.buckets)
}

func (o *overlay) queue(q string) (bool, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.queues[q]
	return v, ok
}

func (o *overlay) setQueue(q string, exists bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.queues[q] = exists
}

func (o *overlay) mergeQueues(names []string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return mergeSet(names, o.queues)
}

func (o *overlay) table(t string) (dryTable, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.tables[t]
	return v, ok
}

func (o *overlay) setTable(t string, exists, sorted, hasSorted, createdNow bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tables[t] = dryTable{exists: exists, sorted: sorted, hasSorted: hasSorted, createdNow: createdNow}
	if !exists {
		o.items[t] = map[string]dryTableItem{}
	}
}

func (o *overlay) mergeTables(names []string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for n, dt := range o.tables {
		set[n] = dt.exists
	}
	var out []string
	for n, live := range set {
		if live {
			out = append(out, n)
		}
	}
	return out
}

func (o *overlay) nextDryVersion(table, pk, sk string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.drySeq++
	sum := sha256.Sum256([]byte(table + "\x00" + pk + "\x00" + sk + "\x00" + hostkit.EscapeSegment(string(rune(o.drySeq)))))
	return "dry-" + hex.EncodeToString(sum[:8])
}

func (o *overlay) putTableItem(t, key string, it hostkit.Item) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.items[t] == nil {
		o.items[t] = map[string]dryTableItem{}
	}
	cp := it.Clone()
	o.items[t][key] = dryTableItem{item: &cp}
}

func (o *overlay) deleteTableItem(t, key string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.items[t] == nil {
		o.items[t] = map[string]dryTableItem{}
	}
	o.items[t][key] = dryTableItem{item: nil}
}

func (o *overlay) tableItem(t, key string) (dryState, hostkit.Item) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if dt, ok := o.tables[t]; ok && !dt.exists {
		return dryBucketGone, hostkit.Item{}
	}
	if di, ok := o.items[t][key]; ok {
		if di.item == nil {
			return dryObjectGone, hostkit.Item{}
		}
		return dryPresent, di.item.Clone()
	}
	if dt, ok := o.tables[t]; ok && dt.createdNow {
		return dryObjectGone, hostkit.Item{}
	}
	return dryUnknown, hostkit.Item{}
}

func (o *overlay) mergeTableItems(t string, real []hostkit.Item, match func(hostkit.Item) bool) []hostkit.Item {
	o.mu.Lock()
	defer o.mu.Unlock()
	byKey := map[string]hostkit.Item{}
	for _, it := range real {
		if match == nil || match(it) {
			byKey[it.PK+"\x00"+it.SK] = it.Clone()
		}
	}
	for k, di := range o.items[t] {
		if di.item == nil {
			delete(byKey, k)
			continue
		}
		if match == nil || match(*di.item) {
			byKey[k] = di.item.Clone()
		} else {
			delete(byKey, k)
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]hostkit.Item, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

func (o *overlay) attachPolicy(att hostkit.PolicyAttachment) {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := att.Clone()
	key := hostkit.AttachmentKey(att.Kind, att.Target, att.Principal)
	cp.Key = key
	o.policies[key] = &cp
}

func (o *overlay) detachPolicy(kind hostkit.AttachmentKind, target, principal string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := hostkit.AttachmentKey(kind, target, principal)
	o.policies[key] = nil
}

func (o *overlay) mergePolicies(real []hostkit.PolicyAttachment) []hostkit.PolicyAttachment {
	o.mu.Lock()
	defer o.mu.Unlock()
	byKey := make(map[string]hostkit.PolicyAttachment, len(real))
	for _, att := range real {
		key := hostkit.AttachmentKey(att.Kind, att.Target, att.Principal)
		byKey[key] = att.Clone()
	}
	for k, p := range o.policies {
		if p == nil {
			delete(byKey, k)
		} else {
			byKey[k] = p.Clone()
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]hostkit.PolicyAttachment, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

func copyBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (o *overlay) function(name string) (dryFunction, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	df, ok := o.functions[name]
	if !ok {
		return dryFunction{}, false
	}
	cp := dryFunction{
		exists:          df.exists,
		createdNow:      df.createdNow,
		completeAliases: df.completeAliases,
		snap:            df.snap.Clone(),
		versions:        make(map[string]hostkit.FunctionSnapshot, len(df.versions)),
		versionOrder:    append([]string(nil), df.versionOrder...),
		aliases:         copyMap(df.aliases),
		deletedAliases:  copyBoolMap(df.deletedAliases),
	}
	for k, v := range df.versions {
		cp.versions[k] = v.Clone()
	}
	return cp, true
}

func (o *overlay) setFunction(name string, df dryFunction) {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := dryFunction{
		exists:          df.exists,
		createdNow:      df.createdNow,
		completeAliases: df.completeAliases,
		snap:            df.snap.Clone(),
		versions:        make(map[string]hostkit.FunctionSnapshot, len(df.versions)),
		versionOrder:    append([]string(nil), df.versionOrder...),
		aliases:         copyMap(df.aliases),
		deletedAliases:  copyBoolMap(df.deletedAliases),
	}
	for k, v := range df.versions {
		cp.versions[k] = v.Clone()
	}
	o.functions[name] = cp
}

func (o *overlay) mergeFunctions(names []string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for n, df := range o.functions {
		set[n] = df.exists
	}
	var out []string
	for n, live := range set {
		if live {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// errIndex is returned by list accessors for out-of-range indices.
var errIndex = errors.New("index out of range")

// newCreateToken returns a random per-call create token (128 bits, hex).
func newCreateToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// provenByToken resolves "CONFLICT, but the resource is accessible" (design
// decision, durable-memory/09-hostkit.md v3): created=true only when the
// adapter reads back the exact create token of this call, which it stored
// atomically in the create request. No reader, a read error, a missing or a
// different token all mean false ("already existed"): the host never claims a
// create it cannot prove. Creation timestamps are deliberately not used.
func provenByToken[R any](adapter any, token string, read func(R) (string, error)) bool {
	r, ok := adapter.(R)
	if !ok || token == "" {
		return false
	}
	got, err := read(r)
	return hostkit.NilIfTyped(err) == nil && got == token
}

// dryScopes keeps one dry overlay per resolved endpoint, so a preview made
// against endpoint A (or the offline route "") never appears at endpoint B.
// The endpoint is the per-service resolution attached to ctx; provider scope
// (account/project) that is not part of the endpoint is out of reach here.
type dryScopes struct {
	mu sync.Mutex
	m  map[string]*overlay
}

func (h *Host) ov(ctx context.Context) *overlay {
	key := hostkit.EndpointFrom(ctx)
	h.dry.mu.Lock()
	defer h.dry.mu.Unlock()
	o, ok := h.dry.m[key]
	if !ok {
		o = newOverlay()
		h.dry.m[key] = o
	}
	return o
}
