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
	return a.checkTarget("", "")
}

func (a Auth) checkTarget(op, target string) error {
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
		if op == "CurrentPrincipal" {
			return nil
		}
		if strings.HasSuffix(target, "-targetok") && (op == "CreateBucket" || op == "HeadBucket" || op == "DeleteBucket" || op == "BucketCreateToken") {
			return nil
		}
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
	// EchoCreateToken makes CreateBucket/CreateQueue fail with 403 and echo
	// the call's create token in the message and provider code, the way some
	// providers echo request markers (tests the host's token redaction).
	// The error is built as a struct literal, bypassing hostkit's constructors.
	// Added in hostkit v4.
	EchoCreateToken bool
	// DisableNamespaceSandbox simulates an environment where Linux user/PID/mount/net
	// namespaces are unavailable so InvokeFunction fails closed with Internal.
	DisableNamespaceSandbox bool
	// OverrideBilledMS, if non-zero, overrides the BilledMS returned by InvokeFunction
	// (used to test host settlement of malformed/out-of-range provider billing metadata).
	OverrideBilledMS int64
	// FaultInvokeAfterDispatch, if non-nil, is called after InvokeFunction dispatches
	// execution and if it returns an error, InvokeFunction returns that error (simulating
	// a lost reply / mid-flight connection drop).
	FaultInvokeAfterDispatch func() error
	// FaultMutatorAfterCommit, if non-nil, is called after a function control-plane
	// mutator (CreateFunction, UpdateFunction, DeleteFunction) commits its state mutation;
	// if it returns a non-nil error, the mutator returns that error (simulating a lost reply).
	FaultMutatorAfterCommit func(op string) error
	// BeforeInvokeLock is an optional test hook called at the start of InvokeFunction
	// before acquiring the state lock (used to test concurrent updates/alias retargets at dispatch).
	BeforeInvokeLock func()
}

func (f *Fake) echoToken(ctx context.Context, kind string) error {
	tok := hostkit.CreateToken(ctx)
	return &hostkit.CloudError{
		Code:         hostkit.PermissionDenied,
		HTTPStatus:   403,
		ProviderCode: "CreateDenied." + tok,
		Message:      kind + " create rejected for client request token " + tok + " (lmcloud-create-token=" + tok + ")",
	}
}

// Fake implements hostkit.ObjectStore and hostkit.Queue.
type Fake struct {
	opts            Options
	mu              sync.Mutex
	mem             *state
	calls           map[string]int
	lastSandboxPIDs []int
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

type tableItem struct {
	PK      string                  `json:"pk"`
	SK      string                  `json:"sk,omitempty"`
	Version string                  `json:"version"`
	Attrs   map[string]hostkit.Attr `json:"attrs,omitempty"`
}

func (ti *tableItem) toHostkit() hostkit.Item {
	attrs := make(map[string]hostkit.Attr, len(ti.Attrs))
	for k, v := range ti.Attrs {
		attrs[k] = v.Clone()
	}
	return hostkit.Item{
		PK:      ti.PK,
		SK:      ti.SK,
		Version: ti.Version,
		Exists:  true,
		Attrs:   attrs,
	}
}

type tableState struct {
	Sorted bool                  `json:"sorted"`
	Items  map[string]*tableItem `json:"items"`
}

type state struct {
	Seq       int64
	Buckets   map[string]map[string]*object
	Queues    map[string][]*message
	Tables    map[string]*tableState              `json:",omitempty"`
	Policies  map[string]hostkit.PolicyAttachment `json:",omitempty"`
	Functions map[string]*functionState           `json:",omitempty"`
	// Create tokens stored atomically with each create (hostkit.CreateToken).
	BucketTokens      map[string]string `json:",omitempty"`
	QueueTokens       map[string]string `json:",omitempty"`
	TableTokens       map[string]string `json:",omitempty"`
	PolicyGenerations map[string]uint64 `json:",omitempty"`
	PolicyOwners      map[string]string `json:",omitempty"`
}

func newState() *state {
	return &state{
		Buckets:           map[string]map[string]*object{},
		Queues:            map[string][]*message{},
		Tables:            map[string]*tableState{},
		Policies:          map[string]hostkit.PolicyAttachment{},
		Functions:         map[string]*functionState{},
		PolicyGenerations: map[string]uint64{},
		PolicyOwners:      map[string]string{},
	}
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
var Mutators = []string{
	"CreateBucket", "DeleteBucket", "PutObject", "DeleteObject",
	"CreateQueue", "DeleteQueue", "Send", "Receive", "Ack", "Nack",
	"CreateTable", "DeleteTable", "PutItem", "DeleteItem", "UpdateItem",
	"AttachPolicy", "DetachPolicy",
	"CreateFunction", "UpdateFunction", "DeleteFunction",
	"PublishFunctionVersion", "SetFunctionAlias", "DeleteFunctionAlias", "InvokeFunction",
}

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
	return f.doTarget(name, "", fn)
}

func (f *Fake) doTarget(name, target string, fn func(s *state) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[name]++
	if err := f.opts.Auth.checkTarget(name, target); err != nil {
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
	if info, statErr := os.Stat(f.opts.StatePath); statErr == nil && info.Size() > 64<<20 {
		return hostkit.ProviderError(hostkit.Internal, 0, "", "fake state exceeds 64 MiB limit")
	}
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
		if s.PolicyGenerations == nil {
			s.PolicyGenerations = map[string]uint64{}
		}
		if s.PolicyOwners == nil {
			s.PolicyOwners = map[string]string{}
		}
		if s.Functions == nil {
			s.Functions = map[string]*functionState{}
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
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["CreateBucket"]++
		f.mu.Unlock()
		return false, f.echoToken(ctx, "bucket")
	}
	created := false
	err := f.doTarget("CreateBucket", b, func(s *state) error {
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
	return f.doTarget("DeleteBucket", b, func(s *state) error {
		objs, ok := s.Buckets[b]
		if !ok {
			return f.notFound(hostkit.AbsentBucket, "NoSuchBucket", "bucket not found")
		}
		if len(objs) > 0 {
			return hostkit.ProviderError(hostkit.Conflict, 409, "BucketNotEmpty", "bucket is not empty")
		}
		delete(s.Buckets, b)
		delete(s.BucketTokens, b)
		deleteTargetPolicies(s, "storage:bucket:"+b)
		return nil
	})
}

func (f *Fake) HeadBucket(_ context.Context, b string) error {
	return f.doTarget("HeadBucket", b, func(s *state) error {
		if fb := strings.TrimSpace(os.Getenv("LMCLOUD_FOREIGN_BUCKET")); fb != "" && b == fb {
			return nil
		}
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
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["CreateQueue"]++
		f.mu.Unlock()
		return false, f.echoToken(ctx, "queue")
	}
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
		deleteTargetPolicies(s, "queue:queue:"+q)
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

// ---- Tables ----

func tableItemKey(pk, sk string) string {
	if sk == "" {
		return pk
	}
	return pk + "\x00" + sk
}

func checkTableLayout(tbl *tableState, name, sk string) *hostkit.CloudError {
	if tbl.Sorted && sk == "" {
		return hostkit.Preflightf("table %q has a composite key and requires a sort key (sk)", name)
	}
	if !tbl.Sorted && sk != "" {
		return hostkit.Preflightf("table %q is partition-key-only and does not accept a sort key (sk)", name)
	}
	return nil
}

func nextItemVersion(s *state, table, pk, sk string) string {
	s.Seq++
	sum := sha256.Sum256([]byte(table + "\x00" + pk + "\x00" + sk + "\x00" + strconv.FormatInt(s.Seq, 10)))
	return hex.EncodeToString(sum[:16])
}

// TableCreateToken returns the create token stored with the table.
func (f *Fake) TableCreateToken(_ context.Context, name string) (string, error) {
	var tok string
	err := f.do("TableCreateToken", func(s *state) error {
		if _, ok := s.Tables[name]; !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		tok = s.TableTokens[name]
		return nil
	})
	return tok, err
}

// DescribeTable returns the key layout and creation token of an existing table.
func (f *Fake) DescribeTable(_ context.Context, name string) (hostkit.TableInfo, error) {
	var info hostkit.TableInfo
	err := f.do("DescribeTable", func(s *state) error {
		tbl, ok := s.Tables[name]
		if !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		info = hostkit.TableInfo{
			Sorted:      tbl.Sorted,
			CreateToken: s.TableTokens[name],
		}
		return nil
	})
	return info, err
}

func (f *Fake) CreateTable(ctx context.Context, name string, sorted bool) (bool, error) {
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["CreateTable"]++
		f.mu.Unlock()
		return false, f.echoToken(ctx, "table")
	}
	created := false
	err := f.do("CreateTable", func(s *state) error {
		if existing, ok := s.Tables[name]; ok {
			if existing.Sorted != sorted {
				return hostkit.ProviderError(hostkit.Conflict, 409, "ResourceInUseException", "table already exists with a different key layout")
			}
			if tok := hostkit.CreateToken(ctx); tok != "" && s.TableTokens[name] == tok {
				created = true
			}
			return nil
		}
		s.Tables[name] = &tableState{Sorted: sorted, Items: map[string]*tableItem{}}
		setToken(&s.TableTokens, name, hostkit.CreateToken(ctx))
		created = true
		return nil
	})
	return created, err
}

func (f *Fake) DeleteTable(_ context.Context, name string) error {
	return f.do("DeleteTable", func(s *state) error {
		if _, ok := s.Tables[name]; !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		delete(s.Tables, name)
		delete(s.TableTokens, name)
		deleteTargetPolicies(s, "tables:table:"+name)
		return nil
	})
}

func (f *Fake) HeadTable(_ context.Context, name string) error {
	return f.do("HeadTable", func(s *state) error {
		if _, ok := s.Tables[name]; !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		return nil
	})
}

func (f *Fake) ListTables(_ context.Context, token string) ([]string, string, error) {
	var names []string
	var next string
	err := f.do("ListTables", func(s *state) error {
		all := make([]string, 0, len(s.Tables))
		for t := range s.Tables {
			if t == "lmcloudmeta" {
				continue
			}
			all = append(all, t)
		}
		var err error
		names, next, err = page(all, token, f.opts.PageSize)
		return err
	})
	return names, next, err
}

func (f *Fake) PutItem(ctx context.Context, table string, item hostkit.Item, mode hostkit.PutMode, expectVersion string) (hostkit.Item, error) {
	var out hostkit.Item
	err := f.do("PutItem", func(s *state) error {
		tbl, ok := s.Tables[table]
		if !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		if e := checkTableLayout(tbl, table, item.SK); e != nil {
			return e
		}
		if tbl.Items == nil {
			tbl.Items = map[string]*tableItem{}
		}
		ik := tableItemKey(item.PK, item.SK)
		existing, exists := tbl.Items[ik]
		var priorBytes int64
		if exists {
			priorBytes = hostkit.NativeItemBillableBytes(existing.toHostkit())
		}
		switch mode {
		case hostkit.PutUnconditional:
		case hostkit.PutIfAbsent:
			if exists {
				hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
					PriorExists:   true,
					PriorBytes:    priorBytes,
					NewBytes:      hostkit.NativeItemBillableBytes(item),
					Authoritative: true,
				})
				return hostkit.ProviderError(hostkit.Conflict, 409, "ConditionalCheckFailedException", "item already exists")
			}
		case hostkit.PutIfVersion:
			if !exists {
				hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
					PriorExists:   false,
					NewBytes:      hostkit.NativeItemBillableBytes(item),
					Authoritative: true,
				})
				return f.notFound(hostkit.AbsentItem, "ConditionalCheckFailedException", "item not found")
			}
			if existing.Version != expectVersion {
				hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
					PriorExists:   true,
					PriorBytes:    priorBytes,
					NewBytes:      hostkit.NativeItemBillableBytes(item),
					Authoritative: true,
				})
				return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "ConditionalCheckFailedException", "item version mismatch")
			}
		default:
			return hostkit.ProviderError(hostkit.Internal, 0, "", "unknown PutMode")
		}
		attrs := make(map[string]hostkit.Attr, len(item.Attrs))
		for k, v := range item.Attrs {
			attrs[k] = v.Clone()
		}
		stored := &tableItem{
			PK:      item.PK,
			SK:      item.SK,
			Version: nextItemVersion(s, table, item.PK, item.SK),
			Attrs:   attrs,
		}
		tbl.Items[ik] = stored
		out = stored.toHostkit()
		hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
			PriorExists:   exists,
			PriorBytes:    priorBytes,
			NewBytes:      hostkit.NativeItemBillableBytes(out),
			Authoritative: true,
		})
		return nil
	})
	return out, err
}

func (f *Fake) GetItem(_ context.Context, table, pk, sk string) (hostkit.Item, error) {
	var out hostkit.Item
	err := f.do("GetItem", func(s *state) error {
		tbl, ok := s.Tables[table]
		if !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		if e := checkTableLayout(tbl, table, sk); e != nil {
			return e
		}
		it, ok := tbl.Items[tableItemKey(pk, sk)]
		if !ok {
			return f.notFound(hostkit.AbsentItem, "ItemNotFound", "item not found")
		}
		out = it.toHostkit()
		return nil
	})
	return out, err
}

func (f *Fake) DeleteItem(ctx context.Context, table, pk, sk string) error {
	return f.do("DeleteItem", func(s *state) error {
		tbl, ok := s.Tables[table]
		if !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		if e := checkTableLayout(tbl, table, sk); e != nil {
			return e
		}
		ik := tableItemKey(pk, sk)
		existing, ok := tbl.Items[ik]
		if !ok {
			hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
				PriorExists:   false,
				Authoritative: true,
			})
			return f.notFound(hostkit.AbsentItem, "ItemNotFound", "item not found")
		}
		priorBytes := hostkit.NativeItemBillableBytes(existing.toHostkit())
		delete(tbl.Items, ik)
		hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
			PriorExists:   true,
			PriorBytes:    priorBytes,
			Authoritative: true,
		})
		return nil
	})
}

func (f *Fake) UpdateItem(ctx context.Context, table, pk, sk string, changes hostkit.Item) (hostkit.Item, error) {
	var out hostkit.Item
	err := f.do("UpdateItem", func(s *state) error {
		tbl, ok := s.Tables[table]
		if !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		if e := checkTableLayout(tbl, table, sk); e != nil {
			return e
		}
		ik := tableItemKey(pk, sk)
		existing, ok := tbl.Items[ik]
		if !ok {
			hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
				PriorExists:   false,
				Authoritative: true,
			})
			return f.notFound(hostkit.AbsentItem, "ResourceNotFoundException", "item not found")
		}
		priorBytes := hostkit.NativeItemBillableBytes(existing.toHostkit())
		merged := make(map[string]hostkit.Attr, len(existing.Attrs)+len(changes.Attrs))
		for k, v := range existing.Attrs {
			merged[k] = v.Clone()
		}
		for k, v := range changes.Attrs {
			merged[k] = v.Clone()
		}
		if _, cerr := hostkit.CanonicalItemBytes(merged); cerr != nil {
			return cerr
		}
		existing.Attrs = merged
		existing.Version = nextItemVersion(s, table, pk, sk)
		out = existing.toHostkit()
		hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
			PriorExists:   true,
			PriorBytes:    priorBytes,
			NewBytes:      hostkit.NativeItemBillableBytes(out),
			Authoritative: true,
		})
		return nil
	})
	return out, err
}

func (f *Fake) Query(_ context.Context, table, pk, skFrom, skTo string, max int, token string) (hostkit.TablePage, error) {
	var out hostkit.TablePage
	err := f.do("Query", func(s *state) error {
		tbl, ok := s.Tables[table]
		if !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		if !tbl.Sorted && (skFrom != "" || skTo != "") {
			return hostkit.Preflightf("sort key range [sk_from, sk_to) is not valid on partition-key-only table %q", table)
		}
		var keys []string
		for k, it := range tbl.Items {
			if it.PK != pk {
				continue
			}
			if tbl.Sorted {
				if skFrom != "" && it.SK < skFrom {
					continue
				}
				if skTo != "" && it.SK >= skTo {
					continue
				}
			}
			keys = append(keys, k)
		}
		names, next, err := page(keys, token, min(max, f.opts.PageSize))
		if err != nil {
			return err
		}
		for _, k := range names {
			out.Items = append(out.Items, tbl.Items[k].toHostkit())
		}
		out.NextToken = next
		return nil
	})
	return out, err
}

func (f *Fake) Scan(_ context.Context, table string, max int, token string) (hostkit.TablePage, error) {
	var out hostkit.TablePage
	err := f.do("Scan", func(s *state) error {
		tbl, ok := s.Tables[table]
		if !ok {
			return f.notFound(hostkit.AbsentTable, "ResourceNotFoundException", "table not found")
		}
		keys := make([]string, 0, len(tbl.Items))
		for k := range tbl.Items {
			keys = append(keys, k)
		}
		names, next, err := page(keys, token, min(max, f.opts.PageSize))
		if err != nil {
			return err
		}
		for _, k := range names {
			out.Items = append(out.Items, tbl.Items[k].toHostkit())
		}
		out.NextToken = next
		return nil
	})
	return out, err
}

// ---- Permissions ----

func (f *Fake) CurrentPrincipal(_ context.Context) (string, error) {
	var out string
	err := f.do("CurrentPrincipal", func(_ *state) error {
		if p := strings.TrimSpace(os.Getenv("LMCLOUD_REF_PRINCIPAL")); p != "" {
			if strings.HasPrefix(p, "principal:") {
				out = p
			} else {
				out = "principal:" + p
			}
			return nil
		}
		out = "principal:ref-default"
		return nil
	})
	return out, err
}

func validOwnerToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func deleteTargetPolicies(s *state, target string) {
	if s == nil || len(s.Policies) == 0 {
		return
	}
	for k, pa := range s.Policies {
		if pa.Kind == hostkit.AttachmentResource && pa.Target == target {
			delete(s.Policies, k)
		}
	}
}

func (f *Fake) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	if f.opts.EchoCreateToken {
		f.mu.Lock()
		f.calls["AttachPolicy"]++
		f.mu.Unlock()
		return f.echoToken(ctx, "policy")
	}
	return f.do("AttachPolicy", func(s *state) error {
		if s.Policies == nil {
			s.Policies = map[string]hostkit.PolicyAttachment{}
		}
		if s.PolicyGenerations == nil {
			s.PolicyGenerations = map[string]uint64{}
		}
		if s.PolicyOwners == nil {
			s.PolicyOwners = map[string]string{}
		}
		key := hostkit.AttachmentKey(att.Kind, att.Target, att.Principal)
		attGen, _ := strconv.ParseUint(att.Generation, 10, 64)
		if cur, exists := s.Policies[key]; exists {
			if !validOwnerToken(cur.OwnerToken) || cur.OwnerToken != att.OwnerToken {
				return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "OwnershipMismatch", "foreign policy attachment already exists for target and principal")
			}
			if exp, hasExp := hostkit.ExpectedAttachmentFrom(ctx); hasExp {
				if exp.ExpectedOwnerToken != "" && cur.OwnerToken != exp.ExpectedOwnerToken {
					return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "OwnershipMismatch", "policy attachment owner token mismatch")
				}
			}
			if curGen, err := strconv.ParseUint(cur.Generation, 10, 64); err == nil && attGen > 0 && attGen < curGen {
				return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "StaleGeneration", "stale policy attachment generation")
			}
		}
		if att.OwnerToken != "" && s.PolicyOwners[key] == att.OwnerToken {
			if attGen > 0 && attGen < s.PolicyGenerations[key] {
				return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "StaleGeneration", "stale policy attachment generation")
			}
		}
		if att.OwnerToken != "" {
			s.PolicyOwners[key] = att.OwnerToken
		}
		if attGen > 0 {
			s.PolicyGenerations[key] = attGen
		}
		s.Policies[key] = att.Clone()
		return nil
	})
}

func (f *Fake) DetachPolicy(ctx context.Context, kind hostkit.AttachmentKind, target, principal string) error {
	return f.do("DetachPolicy", func(s *state) error {
		if s.Policies == nil {
			return nil
		}
		if s.PolicyGenerations == nil {
			s.PolicyGenerations = map[string]uint64{}
		}
		if s.PolicyOwners == nil {
			s.PolicyOwners = map[string]string{}
		}
		key := hostkit.AttachmentKey(kind, target, principal)
		cur, exists := s.Policies[key]
		if exp, hasExp := hostkit.ExpectedAttachmentFrom(ctx); hasExp {
			if exists {
				if !validOwnerToken(cur.OwnerToken) || (exp.ExpectedOwnerToken != "" && cur.OwnerToken != exp.ExpectedOwnerToken) || (exp.OwnerToken != "" && cur.OwnerToken != exp.OwnerToken) {
					return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "OwnershipMismatch", "policy attachment owner token mismatch")
				}
				if exp.ExpectedGeneration != "" {
					curGen, _ := strconv.ParseUint(cur.Generation, 10, 64)
					expGen, _ := strconv.ParseUint(exp.ExpectedGeneration, 10, 64)
					if curGen > 0 && expGen > 0 && curGen > expGen {
						return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "GenerationMismatch", "policy attachment generation mismatch")
					}
				}
			}
			if genNum, err := strconv.ParseUint(exp.Generation, 10, 64); err == nil && genNum > 0 {
				if genNum < s.PolicyGenerations[key] {
					return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "StaleGeneration", "stale policy detach generation")
				}
				s.PolicyGenerations[key] = genNum
			}
			if exp.OwnerToken != "" {
				s.PolicyOwners[key] = exp.OwnerToken
			}
		} else if exists {
			if tok := hostkit.CreateToken(ctx); tok != "" && (!validOwnerToken(cur.OwnerToken) || cur.OwnerToken != tok) {
				return hostkit.ProviderError(hostkit.PreconditionFailed, 412, "OwnershipMismatch", "policy attachment owner token mismatch")
			}
		}
		delete(s.Policies, key)
		return nil
	})
}

func (f *Fake) CheckPolicy(_ context.Context, _, _, _ string) error {
	return f.do("CheckPolicy", func(_ *state) error {
		return nil
	})
}
