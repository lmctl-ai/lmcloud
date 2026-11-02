// SPDX-License-Identifier: MIT

// Package fakeadapter is a conformance-style in-memory implementation of the
// hostkit ObjectStore and Queue adapters. State can be persisted to a JSON file
// (guarded by a file lock) so several host processes in one conformance
// scenario observe the same cloud. It is a test double, not a simulator: it
// models the documented shared semantics and nothing provider specific.
package fakeadapter

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// Auth configures enforce mode. In open mode every call is allowed.
type Auth struct {
	Enforce bool
	// Credential returns the caller's credential for each call.
	Credential func() string
	// Allow is the authorized credential; Deny is a valid but policy-denied one.
	Allow, Deny string
}

func (a Auth) check() error {
	if !a.Enforce {
		return nil
	}
	c := ""
	if a.Credential != nil {
		c = a.Credential()
	}
	switch {
	case c != "" && c == a.Allow:
		return nil
	case c != "" && c == a.Deny:
		return hostkit.ProviderError(hostkit.PermissionDenied, 403, "AccessDenied", "principal is not authorized for this operation")
	default:
		return hostkit.ProviderError(hostkit.Unauthenticated, 401, "NotAuthenticated", "credential was not accepted")
	}
}

// Options configures a Fake.
type Options struct {
	// StatePath persists state to a JSON file shared across processes ("" = memory only).
	StatePath string
	Auth      Auth
	// PageSize caps list pages (default 1000) to exercise pagination.
	PageSize int
	// VagueNotFound omits Absent hints so the host must disambiguate by probing.
	VagueNotFound bool
	Now           func() time.Time
	// LongPoll makes Receive honour waitSeconds itself (polling the state until
	// a message is visible or the wait passes) and report LongPoll=true, so an
	// offline route can simulate a long-polling provider route. Default false:
	// the host runs its client-side wait loop. Added in hostkit v3.
	LongPoll bool
	// BinaryWire reports TextOnlyWire=false (the fake then accepts any bytes).
	BinaryWire bool
	// PollInterval is the LongPoll re-check interval (default 50ms).
	PollInterval time.Duration
}

// Fake implements hostkit.ObjectStore and hostkit.Queue.
type Fake struct {
	opts  Options
	mu    sync.Mutex
	mem   *state
	calls map[string]int
}

type object struct {
	Body        []byte
	ContentType string
	Metadata    map[string]string
	ETag        string
}

type message struct {
	ID        string
	Wire      string
	Receipt   string
	VisibleAt int64
}

type state struct {
	Seq     int64
	Buckets map[string]map[string]*object
	Queues  map[string][]*message
	// Create tokens stored atomically with each create (hostkit.CreateToken).
	BucketTokens map[string]string `json:",omitempty"`
	QueueTokens  map[string]string `json:",omitempty"`
}

func newState() *state {
	return &state{Buckets: map[string]map[string]*object{}, Queues: map[string][]*message{}}
}

// New returns a fake adapter.
func New(opts Options) *Fake {
	if opts.PageSize <= 0 || opts.PageSize > hostkit.MaxListMax {
		opts.PageSize = hostkit.MaxListMax
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Fake{opts: opts, mem: newState(), calls: map[string]int{}}
}

// Mutators are the adapter methods that change state; a dry run must call none of them.
var Mutators = []string{"CreateBucket", "DeleteBucket", "PutObject", "DeleteObject", "CreateQueue", "DeleteQueue", "Send", "Receive", "Ack", "Nack"}

// Calls returns a copy of the per-method call counters.
func (f *Fake) Calls() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.calls {
		out[k] = v
	}
	return out
}

// MutatorCalls sums the counters of Mutators.
func (f *Fake) MutatorCalls() int {
	c := f.Calls()
	n := 0
	for _, m := range Mutators {
		n += c[m]
	}
	return n
}

// do runs fn against the current state under the process mutex and the file lock.
func (f *Fake) do(name string, fn func(s *state) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[name]++
	if err := f.opts.Auth.check(); err != nil {
		return err
	}
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
		if err := json.Unmarshal(raw, s); err != nil {
			return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state is corrupt: "+err.Error())
		}
		if s.Buckets == nil {
			s.Buckets = map[string]map[string]*object{}
		}
		if s.Queues == nil {
			s.Queues = map[string][]*message{}
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state read: "+err.Error())
	}
	ferr := fn(s)
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

func (f *Fake) notFound(absent hostkit.Absence, providerCode, msg string) *hostkit.CloudError {
	e := hostkit.ProviderError(hostkit.NotFound, 404, providerCode, msg)
	if f.opts.VagueNotFound {
		return e
	}
	return e.WithAbsent(absent)
}

func etag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func pageToken(last string) string { return base64.RawURLEncoding.EncodeToString([]byte(last)) }

func afterToken(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", hostkit.ProviderError(hostkit.InvalidArgument, 400, "InvalidToken", "malformed continuation token")
	}
	return string(raw), nil
}

func page(names []string, token string, max int) ([]string, string, error) {
	sort.Strings(names)
	after, err := afterToken(token)
	if err != nil {
		return nil, "", err
	}
	var out []string
	for _, n := range names {
		if token != "" && n <= after {
			continue
		}
		if len(out) == max {
			return out, pageToken(out[len(out)-1]), nil
		}
		out = append(out, n)
	}
	return out, "", nil
}

// ---- ObjectStore ----

func (f *Fake) CreateBucket(ctx context.Context, b string) (bool, error) {
	created := false
	err := f.do("CreateBucket", func(s *state) error {
		if _, ok := s.Buckets[b]; ok {
			return hostkit.ProviderError(hostkit.Conflict, 409, "BucketAlreadyExists", "bucket already exists")
		}
		s.Buckets[b] = map[string]*object{}
		setToken(&s.BucketTokens, b, hostkit.CreateToken(ctx))
		created = true
		return nil
	})
	return created, err
}

func (f *Fake) DeleteBucket(_ context.Context, b string) error {
	return f.do("DeleteBucket", func(s *state) error {
		objs, ok := s.Buckets[b]
		if !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		if len(objs) > 0 {
			return hostkit.ProviderError(hostkit.Conflict, 409, "BucketNotEmpty", "bucket is not empty")
		}
		delete(s.Buckets, b)
		delete(s.BucketTokens, b)
		return nil
	})
}

func (f *Fake) HeadBucket(_ context.Context, b string) error {
	return f.do("HeadBucket", func(s *state) error {
		if _, ok := s.Buckets[b]; !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		return nil
	})
}

func (f *Fake) ListBuckets(_ context.Context, token string) ([]string, string, error) {
	var names []string
	var next string
	err := f.do("ListBuckets", func(s *state) error {
		all := make([]string, 0, len(s.Buckets))
		for b := range s.Buckets {
			all = append(all, b)
		}
		var err error
		names, next, err = page(all, token, f.opts.PageSize)
		return err
	})
	return names, next, err
}

func (f *Fake) PutObject(_ context.Context, b, k string, body []byte, ct string, meta map[string]string) (hostkit.ObjectMeta, error) {
	var out hostkit.ObjectMeta
	err := f.do("PutObject", func(s *state) error {
		objs, ok := s.Buckets[b]
		if !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		o := &object{Body: append([]byte(nil), body...), ContentType: ct, Metadata: meta, ETag: etag(body)}
		objs[k] = o
		out = hostkit.ObjectMeta{Exists: true, Bucket: b, Key: k, Size: int64(len(body)), ETag: o.ETag, ContentType: ct, Metadata: meta}
		return nil
	})
	return out, err
}

func (f *Fake) GetObject(_ context.Context, b, k string, limit int64) ([]byte, error) {
	var out []byte
	err := f.do("GetObject", func(s *state) error {
		objs, ok := s.Buckets[b]
		if !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		o, ok := objs[k]
		if !ok {
			return f.notFound(hostkit.AbsentObject, "NoSuchKey", "object not found")
		}
		if int64(len(o.Body)) > limit {
			return hostkit.ProviderError(hostkit.Internal, 200, "", "object exceeds the read limit; refusing to truncate")
		}
		out = append([]byte(nil), o.Body...)
		return nil
	})
	return out, err
}

func (f *Fake) HeadObject(_ context.Context, b, k string) (hostkit.ObjectMeta, error) {
	var out hostkit.ObjectMeta
	err := f.do("HeadObject", func(s *state) error {
		objs, ok := s.Buckets[b]
		if !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		o, ok := objs[k]
		if !ok {
			return f.notFound(hostkit.AbsentObject, "NoSuchKey", "object not found")
		}
		meta := map[string]string{}
		for mk, mv := range o.Metadata {
			meta[mk] = mv
		}
		out = hostkit.ObjectMeta{Exists: true, Bucket: b, Key: k, Size: int64(len(o.Body)), ETag: o.ETag, ContentType: o.ContentType, Metadata: meta}
		return nil
	})
	return out, err
}

func (f *Fake) DeleteObject(_ context.Context, b, k string) error {
	return f.do("DeleteObject", func(s *state) error {
		objs, ok := s.Buckets[b]
		if !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		if _, ok := objs[k]; !ok {
			return f.notFound(hostkit.AbsentObject, "NoSuchKey", "object not found")
		}
		delete(objs, k)
		return nil
	})
}

func (f *Fake) ListObjects(_ context.Context, b, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	var out hostkit.ObjectPage
	err := f.do("ListObjects", func(s *state) error {
		objs, ok := s.Buckets[b]
		if !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		var keys []string
		for k := range objs {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, k)
			}
		}
		names, next, err := page(keys, token, min(max, f.opts.PageSize))
		if err != nil {
			return err
		}
		for _, k := range names {
			o := objs[k]
			out.Items = append(out.Items, hostkit.ObjectSummary{Key: k, Size: int64(len(o.Body)), ETag: o.ETag})
		}
		out.NextToken = next
		return nil
	})
	return out, err
}

// ---- Queue ----

// QueueCaps: no long polling (the host runs the wait loop) and a text-only
// wire (the host applies the base64 envelope to unsafe bytes).
func (f *Fake) QueueCaps() hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: f.opts.LongPoll, TextOnlyWire: !f.opts.BinaryWire}
}

// QueueCapsFor reports the same caps per call (hostkit.QueueCapsProvider).
func (f *Fake) QueueCapsFor(context.Context, string) hostkit.QueueCaps { return f.QueueCaps() }

func setToken(m *map[string]string, name, token string) {
	if token == "" {
		return
	}
	if *m == nil {
		*m = map[string]string{}
	}
	(*m)[name] = token
}

// BucketCreateToken returns the create token stored with the bucket.
func (f *Fake) BucketCreateToken(_ context.Context, b string) (string, error) {
	var tok string
	err := f.do("BucketCreateToken", func(s *state) error {
		if _, ok := s.Buckets[b]; !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		tok = s.BucketTokens[b]
		return nil
	})
	return tok, err
}

// QueueCreateToken returns the create token stored with the queue.
func (f *Fake) QueueCreateToken(_ context.Context, q string) (string, error) {
	var tok string
	err := f.do("QueueCreateToken", func(s *state) error {
		if _, ok := s.Queues[q]; !ok {
			return f.notFound(hostkit.AbsentQueue, "QueueNotFound", "queue not found")
		}
		tok = s.QueueTokens[q]
		return nil
	})
	return tok, err
}

func (f *Fake) CreateQueue(ctx context.Context, q string) (bool, error) {
	created := false
	err := f.do("CreateQueue", func(s *state) error {
		if _, ok := s.Queues[q]; ok {
			return nil
		}
		s.Queues[q] = []*message{}
		setToken(&s.QueueTokens, q, hostkit.CreateToken(ctx))
		created = true
		return nil
	})
	return created, err
}

func (f *Fake) DeleteQueue(_ context.Context, q string) error {
	return f.do("DeleteQueue", func(s *state) error {
		if _, ok := s.Queues[q]; !ok {
			return f.notFound(hostkit.AbsentQueue, "QueueNotFound", "queue not found")
		}
		delete(s.Queues, q)
		delete(s.QueueTokens, q)
		return nil
	})
}

func (f *Fake) LookupQueue(_ context.Context, q string) error {
	return f.do("LookupQueue", func(s *state) error {
		if _, ok := s.Queues[q]; !ok {
			return f.notFound(hostkit.AbsentQueue, "QueueNotFound", "queue not found")
		}
		return nil
	})
}

func (f *Fake) ListQueues(_ context.Context, token string) ([]string, string, error) {
	var names []string
	var next string
	err := f.do("ListQueues", func(s *state) error {
		all := make([]string, 0, len(s.Queues))
		for q := range s.Queues {
			all = append(all, q)
		}
		var err error
		names, next, err = page(all, token, f.opts.PageSize)
		return err
	})
	return names, next, err
}

func (f *Fake) Send(_ context.Context, q, wire string) (string, error) {
	var id string
	err := f.do("Send", func(s *state) error {
		msgs, ok := s.Queues[q]
		if !ok {
			return f.notFound(hostkit.AbsentQueue, "QueueNotFound", "queue not found")
		}
		if wire == "" || (!f.opts.BinaryWire && !hostkit.TextSafe(wire)) {
			return hostkit.ProviderError(hostkit.InvalidArgument, 400, "InvalidMessageContents", "message body must be non-empty text")
		}
		s.Seq++
		id = "m" + strconv.FormatInt(s.Seq, 10)
		s.Queues[q] = append(msgs, &message{ID: id, Wire: wire})
		return nil
	})
	return id, err
}

func (f *Fake) Receive(ctx context.Context, q string, max, wait int, visibility int) ([]hostkit.RawMessage, error) {
	if !f.opts.LongPoll || wait <= 0 {
		return f.receiveOnce(q, max, visibility)
	}
	interval := f.opts.PollInterval
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}
	var out []hostkit.RawMessage
	err := hostkit.WaitLoop(ctx, time.Duration(wait)*time.Second, interval, f.opts.Now, nil, func(context.Context) (int, error) {
		msgs, err := f.receiveOnce(q, max, visibility)
		out = msgs
		return len(msgs), err
	})
	return out, err
}

func (f *Fake) receiveOnce(q string, max, visibility int) ([]hostkit.RawMessage, error) {
	var out []hostkit.RawMessage
	err := f.do("Receive", func(s *state) error {
		msgs, ok := s.Queues[q]
		if !ok {
			return f.notFound(hostkit.AbsentQueue, "QueueNotFound", "queue not found")
		}
		now := f.opts.Now().UnixNano()
		for _, m := range msgs {
			if len(out) == max {
				break
			}
			if m.VisibleAt > now {
				continue
			}
			s.Seq++
			m.Receipt = m.ID + ":" + strconv.FormatInt(s.Seq, 10)
			m.VisibleAt = now + int64(visibility)*int64(time.Second)
			out = append(out, hostkit.RawMessage{ID: m.ID, Wire: m.Wire, Receipt: m.Receipt})
		}
		return nil
	})
	return out, err
}

// receipts are "<id>:<generation>"; anything else is malformed. The fake
// judges the receipt before the queue, like providers that parse the receipt
// first, so the host's missing-queue precedence is exercised.
func malformedReceipt(r string) bool {
	i := strings.LastIndexByte(r, ':')
	if i <= 0 || i == len(r)-1 {
		return true
	}
	_, err := strconv.ParseInt(r[i+1:], 10, 64)
	return err != nil
}

func (f *Fake) Ack(_ context.Context, q, receipt string) error {
	return f.do("Ack", func(s *state) error {
		if malformedReceipt(receipt) {
			return hostkit.ProviderError(hostkit.InvalidArgument, 400, "InvalidReceipt", "receipt is malformed")
		}
		msgs, ok := s.Queues[q]
		if !ok {
			return f.notFound(hostkit.AbsentQueue, "QueueNotFound", "queue not found")
		}
		for i, m := range msgs {
			if m.Receipt == receipt {
				s.Queues[q] = append(msgs[:i], msgs[i+1:]...)
				return nil
			}
		}
		return f.notFound(hostkit.AbsentMessage, "MessageNotFound", "no in-flight message for receipt")
	})
}

func (f *Fake) Nack(_ context.Context, q, receipt string, visibility int) (string, error) {
	var next string
	err := f.do("Nack", func(s *state) error {
		if malformedReceipt(receipt) {
			return hostkit.ProviderError(hostkit.InvalidArgument, 400, "InvalidReceipt", "receipt is malformed")
		}
		msgs, ok := s.Queues[q]
		if !ok {
			return f.notFound(hostkit.AbsentQueue, "QueueNotFound", "queue not found")
		}
		for _, m := range msgs {
			if m.Receipt == receipt {
				// Rotate the receipt on every visibility change (the strictest provider behaviour).
				s.Seq++
				m.Receipt = m.ID + ":" + strconv.FormatInt(s.Seq, 10)
				m.VisibleAt = f.opts.Now().UnixNano() + int64(visibility)*int64(time.Second)
				next = m.Receipt
				return nil
			}
		}
		return f.notFound(hostkit.AbsentMessage, "MessageNotFound", "no in-flight message for receipt")
	})
	return next, err
}
