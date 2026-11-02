// SPDX-License-Identifier: MIT

// Package cloudhost implements the shared lmcloud schema once, on top of the
// hostkit adapter interfaces. A provider port supplies an ObjectStore, a Queue
// and an EndpointResolver; everything a script can observe (validation,
// idempotency, error precedence, abort format, codec, pagination, dry previews)
// is decided here so all hosts behave identically.
package cloudhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// Config wires a provider into the shared host.
type Config struct {
	// Provider is the identifier returned by cloud.provider().
	Provider  string
	Store     hostkit.ObjectStore
	Queue     hostkit.Queue
	Endpoints *hostkit.EndpointResolver
	Validator *hostkit.Validator
	// OpTimeout bounds one operation (default 2m); ListTimeout bounds exhaustive lists (default 10m).
	OpTimeout   time.Duration
	ListTimeout time.Duration
	MaxPages    int
	// PollInterval/Now/Sleep drive the client-side wait loop for adapters without long polling.
	PollInterval time.Duration
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
}

// Host is the state behind the `cloud` context object.
type Host struct {
	cfg  Config
	errs *hostkit.ErrorState
	dry  *overlay
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
	return &Host{cfg: cfg, errs: hostkit.NewErrorState(), dry: newOverlay()}
}

// ---- small helpers ----

func (h *Host) fail(op, target string, e *hostkit.CloudError) error {
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

func (h *Host) bucketExists(ctx context.Context, dry bool, b string) (bool, *hostkit.CloudError) {
	if dry {
		if v, ok := h.dry.bucket(b); ok {
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

func (h *Host) queueExists(ctx context.Context, dry bool, q string) (bool, *hostkit.CloudError) {
	if dry {
		if v, ok := h.dry.queue(q); ok {
			return v, nil
		}
	}
	return h.realQueueExists(ctx, q)
}

// ---- buckets ----

// BucketCreate implements bucket_create.
func (h *Host) BucketCreate(dry bool, b string) (bool, error) {
	const op = "bucket_create"
	if e := h.cfg.Validator.Bucket(b); e != nil {
		return false, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return false, h.fail(op, b, e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			return false, h.fail(op, b, e)
		}
		h.dry.setBucket(b, true, !exists)
		h.ok()
		return !exists, nil
	}
	if h.cfg.Store == nil {
		return false, h.fail(op, b, missingStore())
	}
	start := h.cfg.Now()
	created, err := h.cfg.Store.CreateBucket(ctx, b)
	if err == nil {
		h.ok()
		return created, nil
	}
	ce := hostkit.AsCloudError(err)
	if ce.Code == hostkit.Conflict {
		// Design 02 §6.1: 409 is idempotent success only if the bucket is accessible in our scope.
		if exists, perr := h.realBucketExists(ctx, b); perr == nil && exists {
			h.ok()
			return createdDuringCall(h.cfg.Store, start, func(t hostkit.BucketCreationTimer) (time.Time, error) {
				return t.BucketCreatedAt(ctx, b)
			}), nil
		}
	}
	return false, h.fail(op, b, ce)
}

// BucketDelete implements bucket_delete.
func (h *Host) BucketDelete(dry bool, b string) (bool, error) {
	const op = "bucket_delete"
	if e := h.cfg.Validator.Bucket(b); e != nil {
		return false, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return false, h.fail(op, b, e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			return false, h.fail(op, b, e)
		}
		if !exists {
			h.ok()
			return false, nil
		}
		keys, e := h.dryKeys(ctx, b, "")
		if e != nil {
			return false, h.fail(op, b, e)
		}
		if len(keys) > 0 {
			return false, h.fail(op, b, hostkit.ProviderError(hostkit.Conflict, 409, "BucketNotEmpty", "bucket is not empty (dry-run preview)"))
		}
		h.dry.setBucket(b, false, false)
		h.ok()
		return true, nil
	}
	if h.cfg.Store == nil {
		return false, h.fail(op, b, missingStore())
	}
	ce := hostkit.AsCloudError(h.cfg.Store.DeleteBucket(ctx, b))
	switch {
	case ce == nil:
		h.ok()
		return true, nil
	case isNotFound(ce) && ce.Absent != hostkit.AbsentObject:
		h.ok()
		return false, nil
	default:
		return false, h.fail(op, b, ce)
	}
}

// BucketExists implements bucket_exists. Only a genuine NOT_FOUND yields false/OK.
func (h *Host) BucketExists(dry bool, b string) (bool, error) {
	const op = "bucket_exists"
	if e := h.cfg.Validator.Bucket(b); e != nil {
		return false, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return false, h.fail(op, b, e)
	}
	defer cancel()
	exists, e := h.bucketExists(ctx, dry, b)
	if e != nil {
		return false, h.fail(op, b, e)
	}
	h.ok()
	return exists, nil
}

// BucketList implements bucket_list: every page, sorted, de-duplicated.
func (h *Host) BucketList(dry bool) ([]string, error) {
	const op = "bucket_list"
	ctx, cancel, e := h.opCtx("storage", h.cfg.ListTimeout)
	if e != nil {
		return nil, h.fail(op, "", e)
	}
	defer cancel()
	if h.cfg.Store == nil {
		return nil, h.fail(op, "", missingStore())
	}
	names, e := hostkit.ListAll(ctx, h.cfg.MaxPages, h.cfg.Store.ListBuckets)
	if e != nil {
		return nil, h.fail(op, "", e)
	}
	if dry {
		names = h.dry.mergeBuckets(names)
	}
	h.ok()
	return hostkit.SortedUnique(names), nil
}

// ---- objects ----

// ObjectPut implements both object_put overloads.
func (h *Host) ObjectPut(dry bool, b, k, body, ct string, meta map[string]string) (*hostkit.ObjectMeta, error) {
	const op = "object_put"
	none := &hostkit.ObjectMeta{Bucket: b, Key: k, Metadata: map[string]string{}}
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k), hostkit.ObjectSize(len(body)), hostkit.ContentType(ct), hostkit.Metadata(meta)} {
		if e != nil {
			return none, h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return none, h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			return none, h.fail(op, target(b, k), e)
		}
		if !exists {
			return none, h.fail(op, target(b, k), notFound(hostkit.AbsentBucket, "bucket does not exist (dry-run preview)"))
		}
		m := &hostkit.ObjectMeta{Exists: true, Bucket: b, Key: k, Size: int64(len(body)), ETag: dryETag(body), ContentType: ct, Metadata: copyMap(meta)}
		h.dry.putObject(b, k, body, m)
		h.ok()
		return m, nil
	}
	if h.cfg.Store == nil {
		return none, h.fail(op, target(b, k), missingStore())
	}
	m, err := h.cfg.Store.PutObject(ctx, b, k, []byte(body), ct, copyMap(meta))
	if err != nil {
		return none, h.fail(op, target(b, k), hostkit.AsCloudError(err))
	}
	m.Exists, m.Bucket, m.Key, m.Size = true, b, k, int64(len(body))
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
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k)} {
		if e != nil {
			return "", h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return "", h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		if state, body, _ := h.dry.object(b, k); state != dryUnknown {
			if state == dryPresent {
				h.ok()
				return body, nil
			}
			return "", h.fail(op, target(b, k), h.dryMissing(state))
		}
	}
	if h.cfg.Store == nil {
		return "", h.fail(op, target(b, k), missingStore())
	}
	data, err := h.cfg.Store.GetObject(ctx, b, k, hostkit.MaxObjectBytes)
	if err != nil {
		return "", h.fail(op, target(b, k), hostkit.AsCloudError(err))
	}
	if len(data) > hostkit.MaxObjectBytes {
		return "", h.fail(op, target(b, k), hostkit.ProviderError(hostkit.Internal, 0, "", "object body exceeds the 16 MiB limit; refusing to truncate"))
	}
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
	absent := &hostkit.ObjectMeta{Bucket: b, Key: k, Metadata: map[string]string{}}
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k)} {
		if e != nil {
			return absent, h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return absent, h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		if state, _, m := h.dry.object(b, k); state != dryUnknown {
			switch state {
			case dryPresent:
				h.ok()
				c := *m
				c.Metadata = copyMap(m.Metadata)
				return &c, nil
			case dryBucketGone:
				return absent, h.fail(op, target(b, k), h.dryMissing(state))
			default:
				h.ok()
				return absent, nil
			}
		}
	}
	if h.cfg.Store == nil {
		return absent, h.fail(op, target(b, k), missingStore())
	}
	m, err := h.cfg.Store.HeadObject(ctx, b, k)
	if err == nil {
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
		return absent, h.fail(op, target(b, k), ce)
	}
	switch ce.Absent {
	case hostkit.AbsentObject:
		h.ok()
		return absent, nil
	case hostkit.AbsentBucket:
		return absent, h.fail(op, target(b, k), ce)
	}
	exists, perr := h.realBucketExists(ctx, b)
	if perr != nil {
		return absent, h.fail(op, target(b, k), perr)
	}
	if !exists {
		return absent, h.fail(op, target(b, k), ce.WithAbsent(hostkit.AbsentBucket))
	}
	h.ok()
	return absent, nil
}

// ObjectDelete implements object_delete: idempotent within an existing bucket.
func (h *Host) ObjectDelete(dry bool, b, k string) error {
	const op = "object_delete"
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Bucket(b), h.cfg.Validator.Key(k)} {
		if e != nil {
			return h.fail(op, target(b, k), e)
		}
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return h.fail(op, target(b, k), e)
	}
	defer cancel()
	if dry {
		exists, e := h.bucketExists(ctx, true, b)
		if e != nil {
			return h.fail(op, target(b, k), e)
		}
		if !exists {
			return h.fail(op, target(b, k), notFound(hostkit.AbsentBucket, "bucket does not exist (dry-run preview)"))
		}
		h.dry.deleteObject(b, k)
		h.ok()
		return nil
	}
	if h.cfg.Store == nil {
		return h.fail(op, target(b, k), missingStore())
	}
	ce := hostkit.AsCloudError(h.cfg.Store.DeleteObject(ctx, b, k))
	if ce == nil {
		h.ok()
		return nil
	}
	if !isNotFound(ce) {
		return h.fail(op, target(b, k), ce)
	}
	switch ce.Absent {
	case hostkit.AbsentObject:
		h.ok()
		return nil
	case hostkit.AbsentBucket:
		return h.fail(op, target(b, k), ce)
	}
	exists, perr := h.realBucketExists(ctx, b)
	if perr != nil {
		return h.fail(op, target(b, k), perr)
	}
	if !exists {
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
	empty := &Page{}
	if e := h.cfg.Validator.Bucket(b); e != nil {
		return empty, h.fail(op, b, e)
	}
	max, e := hostkit.ListMax(maxKeys)
	if e != nil {
		return empty, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
	if e != nil {
		return empty, h.fail(op, b, e)
	}
	defer cancel()
	if dry && h.dry.touchesBucket(b) {
		keys, e := h.dryKeys(ctx, b, prefix)
		if e != nil {
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
			_, body, m := h.dry.object(b, k)
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
		return empty, h.fail(op, b, missingStore())
	}
	page, err := h.cfg.Store.ListObjects(ctx, b, prefix, max, token)
	if err != nil {
		return empty, h.fail(op, b, hostkit.AsCloudError(err))
	}
	if len(page.Items) > max {
		return empty, h.fail(op, b, hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned more items than max_keys"))
	}
	if token != "" && page.NextToken == token {
		return empty, h.fail(op, b, hostkit.ProviderError(hostkit.Internal, 0, "", "pagination stalled: continuation token repeated"))
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
	if !h.dry.bucketCreatedInDry(b) {
		keys, e := h.realKeys(ctx, b, prefix)
		if e != nil {
			return nil, e
		}
		real = keys
	}
	return h.dry.mergeKeys(b, prefix, real), nil
}

// ObjectListAll implements object_list_all: all pages or an error, never partial.
func (h *Host) ObjectListAll(dry bool, b, prefix string) ([]string, error) {
	const op = "object_list_all"
	if e := h.cfg.Validator.Bucket(b); e != nil {
		return nil, h.fail(op, b, e)
	}
	ctx, cancel, e := h.opCtx("storage", h.cfg.ListTimeout)
	if e != nil {
		return nil, h.fail(op, b, e)
	}
	defer cancel()
	var keys []string
	if dry && h.dry.touchesBucket(b) {
		keys, e = h.dryKeys(ctx, b, prefix)
	} else {
		keys, e = h.realKeys(ctx, b, prefix)
	}
	if e != nil {
		return nil, h.fail(op, b, e)
	}
	h.ok()
	return hostkit.SortedUnique(keys), nil
}

// ---- queues ----

// QueueCreate implements queue_create.
func (h *Host) QueueCreate(dry bool, q string) (bool, error) {
	const op = "queue_create"
	if e := h.cfg.Validator.Queue(q); e != nil {
		return false, h.fail(op, q, e)
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		return false, h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		exists, e := h.queueExists(ctx, true, q)
		if e != nil {
			return false, h.fail(op, q, e)
		}
		h.dry.setQueue(q, true)
		h.ok()
		return !exists, nil
	}
	if h.cfg.Queue == nil {
		return false, h.fail(op, q, missingQueue())
	}
	start := h.cfg.Now()
	created, err := h.cfg.Queue.CreateQueue(ctx, q)
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if ce.Code == hostkit.Conflict {
			if exists, perr := h.realQueueExists(ctx, q); perr == nil && exists {
				h.ok()
				return createdDuringCall(h.cfg.Queue, start, func(t hostkit.QueueCreationTimer) (time.Time, error) {
					return t.QueueCreatedAt(ctx, q)
				}), nil
			}
		}
		return false, h.fail(op, q, ce)
	}
	h.ok()
	return created, nil
}

// QueueDelete implements queue_delete.
func (h *Host) QueueDelete(dry bool, q string) (bool, error) {
	const op = "queue_delete"
	if e := h.cfg.Validator.Queue(q); e != nil {
		return false, h.fail(op, q, e)
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		return false, h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		exists, e := h.queueExists(ctx, true, q)
		if e != nil {
			return false, h.fail(op, q, e)
		}
		h.dry.setQueue(q, false)
		h.ok()
		return exists, nil
	}
	if h.cfg.Queue == nil {
		return false, h.fail(op, q, missingQueue())
	}
	ce := hostkit.AsCloudError(h.cfg.Queue.DeleteQueue(ctx, q))
	switch {
	case ce == nil:
		h.ok()
		return true, nil
	case isNotFound(ce):
		h.ok()
		return false, nil
	default:
		return false, h.fail(op, q, ce)
	}
}

// QueueExists implements queue_exists.
func (h *Host) QueueExists(dry bool, q string) (bool, error) {
	const op = "queue_exists"
	if e := h.cfg.Validator.Queue(q); e != nil {
		return false, h.fail(op, q, e)
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		return false, h.fail(op, q, e)
	}
	defer cancel()
	exists, e := h.queueExists(ctx, dry, q)
	if e != nil {
		return false, h.fail(op, q, e)
	}
	h.ok()
	return exists, nil
}

// QueueList implements queue_list: every page, sorted, de-duplicated.
func (h *Host) QueueList(dry bool) ([]string, error) {
	const op = "queue_list"
	ctx, cancel, e := h.opCtx("queue", h.cfg.ListTimeout)
	if e != nil {
		return nil, h.fail(op, "", e)
	}
	defer cancel()
	if h.cfg.Queue == nil {
		return nil, h.fail(op, "", missingQueue())
	}
	names, e := hostkit.ListAll(ctx, h.cfg.MaxPages, h.cfg.Queue.ListQueues)
	if e != nil {
		return nil, h.fail(op, "", e)
	}
	if dry {
		names = h.dry.mergeQueues(names)
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
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.QueueBodySize(len(body))} {
		if e != nil {
			return "", h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		return "", h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		if e := h.requireQueue(ctx, true, q); e != nil {
			return "", h.fail(op, q, e)
		}
		h.ok()
		return "dry-run-message-id", nil
	}
	if h.cfg.Queue == nil {
		return "", h.fail(op, q, missingQueue())
	}
	wire := hostkit.EncodeQueueBody(body, hostkit.CapsFor(ctx, h.cfg.Queue, q).TextOnlyWire)
	id, err := h.cfg.Queue.Send(ctx, q, wire)
	if err != nil {
		return "", h.fail(op, q, hostkit.AsCloudError(err))
	}
	if id == "" {
		return "", h.fail(op, q, hostkit.ProviderError(hostkit.Internal, 0, "", "provider accepted the message but returned no message id"))
	}
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
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.ReceiveArgs(max, wait, vis)} {
		if e != nil {
			return nil, h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout+time.Duration(wait)*time.Second)
	if e != nil {
		return nil, h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		// Receiving consumes (hides) messages: the preview never calls Receive.
		if e := h.requireQueue(ctx, true, q); e != nil {
			return nil, h.fail(op, q, e)
		}
		h.ok()
		return nil, nil
	}
	if h.cfg.Queue == nil {
		return nil, h.fail(op, q, missingQueue())
	}
	caps := hostkit.CapsFor(ctx, h.cfg.Queue, q)
	var raw []hostkit.RawMessage
	var rerr error
	if caps.LongPoll {
		raw, rerr = h.cfg.Queue.Receive(ctx, q, int(max), int(wait), int(vis))
	} else {
		rerr = hostkit.WaitLoop(ctx, time.Duration(wait)*time.Second, h.cfg.PollInterval, h.cfg.Now, h.cfg.Sleep, func(ctx context.Context) (int, error) {
			msgs, err := h.cfg.Queue.Receive(ctx, q, int(max), 0, int(vis))
			raw = msgs
			return len(msgs), err
		})
	}
	if rerr != nil {
		return nil, h.fail(op, q, hostkit.AsCloudError(rerr))
	}
	if len(raw) > int(max) {
		return nil, h.fail(op, q, hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned more messages than max_messages"))
	}
	out := make([]Message, 0, len(raw))
	for _, m := range raw {
		if m.ID == "" || m.Receipt == "" {
			return nil, h.fail(op, q, hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned a message without id or receipt"))
		}
		body, e := hostkit.DecodeQueueBody(m.Wire)
		if e != nil {
			return nil, h.fail(op, q, e)
		}
		out = append(out, Message{ID: m.ID, Body: body, Receipt: m.Receipt})
	}
	h.ok()
	return out, nil
}

// QueueAck implements queue_ack with missing-queue precedence and idempotent re-ack.
func (h *Host) QueueAck(dry bool, q, receipt string) error {
	const op = "queue_ack"
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.Receipt(receipt)} {
		if e != nil {
			return h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		return h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		if e := h.requireQueue(ctx, true, q); e != nil {
			return h.fail(op, q, e)
		}
		h.ok()
		return nil
	}
	if h.cfg.Queue == nil {
		return h.fail(op, q, missingQueue())
	}
	ce := hostkit.AsCloudError(h.cfg.Queue.Ack(ctx, q, receipt))
	ce = hostkit.ReceiptPrecedence(ce, true, func() (bool, *hostkit.CloudError) { return h.realQueueExists(ctx, q) })
	if ce != nil {
		return h.fail(op, q, ce)
	}
	h.ok()
	return nil
}

// QueueNack implements queue_nack and returns the receipt valid from now on.
func (h *Host) QueueNack(dry bool, q, receipt string, vis int64) (string, error) {
	const op = "queue_nack"
	for _, e := range []*hostkit.CloudError{h.cfg.Validator.Queue(q), hostkit.Visibility(vis), hostkit.Receipt(receipt)} {
		if e != nil {
			return "", h.fail(op, q, e)
		}
	}
	ctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
	if e != nil {
		return "", h.fail(op, q, e)
	}
	defer cancel()
	if dry {
		if e := h.requireQueue(ctx, true, q); e != nil {
			return "", h.fail(op, q, e)
		}
		h.ok()
		return receipt, nil
	}
	if h.cfg.Queue == nil {
		return "", h.fail(op, q, missingQueue())
	}
	nr, err := h.cfg.Queue.Nack(ctx, q, receipt, int(vis))
	if err != nil {
		ce := hostkit.ReceiptPrecedence(hostkit.AsCloudError(err), false, func() (bool, *hostkit.CloudError) { return h.realQueueExists(ctx, q) })
		if ce == nil {
			ce = hostkit.ProviderError(hostkit.Internal, 0, "", "nack failed")
		}
		return "", h.fail(op, q, ce)
	}
	if nr == "" {
		return "", h.fail(op, q, hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned no receipt after visibility change"))
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

// overlay records what a dry run would have changed, so later reads in the
// same dry run see the previewed state instead of aborting. It never reaches
// the provider.
type overlay struct {
	mu      sync.Mutex
	buckets map[string]bool // true created, false deleted
	created map[string]bool // bucket did not exist before this dry run
	objects map[string]map[string]dryObject
	queues  map[string]bool
}

func newOverlay() *overlay {
	return &overlay{buckets: map[string]bool{}, created: map[string]bool{}, objects: map[string]map[string]dryObject{}, queues: map[string]bool{}}
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

// errIndex is returned by list accessors for out-of-range indices.
var errIndex = errors.New("index out of range")

// createdDuringCall resolves "CONFLICT, but the resource is accessible" (see
// durable-memory/09-hostkit.md, create idempotency): it returns true only when
// the adapter reports a server-side creation time at or after the start of
// this call, i.e. an earlier attempt of the same call (a retry, or a reply
// lost after the server committed) created it. Without a timer, or when the
// timer fails, the answer is false ("already existed"): the host never claims
// a create it cannot prove. Clock skew can only turn a true into a false.
func createdDuringCall[T any](adapter any, start time.Time, at func(T) (time.Time, error)) bool {
	t, ok := adapter.(T)
	if !ok {
		return false
	}
	created, err := at(t)
	return hostkit.NilIfTyped(err) == nil && !created.IsZero() && !created.Before(start)
}
