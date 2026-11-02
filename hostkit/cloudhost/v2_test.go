// SPDX-License-Identifier: MIT

package cloudhost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

// typedNilAdapter wraps the fake and returns a typed-nil *CloudError through
// error on every success path (the exact bug lmoci hit in deleteQueue).
type typedNilAdapter struct{ *fakeadapter.Fake }

func tn(err error) error {
	if err != nil {
		return err
	}
	var ce *hostkit.CloudError
	return ce
}

func (a typedNilAdapter) CreateBucket(ctx context.Context, b string) (bool, error) {
	v, err := a.Fake.CreateBucket(ctx, b)
	return v, tn(err)
}
func (a typedNilAdapter) DeleteBucket(ctx context.Context, b string) error {
	return tn(a.Fake.DeleteBucket(ctx, b))
}
func (a typedNilAdapter) HeadBucket(ctx context.Context, b string) error {
	return tn(a.Fake.HeadBucket(ctx, b))
}
func (a typedNilAdapter) PutObject(ctx context.Context, b, k string, body []byte, ct string, m map[string]string) (hostkit.ObjectMeta, error) {
	v, err := a.Fake.PutObject(ctx, b, k, body, ct, m)
	return v, tn(err)
}
func (a typedNilAdapter) CreateQueue(ctx context.Context, q string) (bool, error) {
	v, err := a.Fake.CreateQueue(ctx, q)
	return v, tn(err)
}
func (a typedNilAdapter) DeleteQueue(ctx context.Context, q string) error {
	return tn(a.Fake.DeleteQueue(ctx, q))
}
func (a typedNilAdapter) Send(ctx context.Context, q, w string) (string, error) {
	v, err := a.Fake.Send(ctx, q, w)
	return v, tn(err)
}

func TestTypedNilAdapterErrorsAreSuccess(t *testing.T) {
	a := typedNilAdapter{fakeadapter.New(fakeadapter.Options{})}
	h := New(Config{Store: a, Queue: a, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	if c, err := h.BucketCreate(false, "tn-bkt"); err != nil || !c {
		t.Fatalf("create: %v %+v", err, h.LastError())
	}
	if ex, err := h.BucketExists(false, "tn-bkt"); err != nil || !ex {
		t.Fatalf("exists: %v", err)
	}
	if m, err := h.ObjectPut(false, "tn-bkt", "k", "v", "text/plain", nil); err != nil || !m.Exists {
		t.Fatalf("put: %v", err)
	}
	if c, err := h.QueueCreate(false, "tn-q"); err != nil || !c {
		t.Fatalf("queue create: %v", err)
	}
	if id, err := h.QueueSend(false, "tn-q", "x"); err != nil || id == "" {
		t.Fatalf("send: %v", err)
	}
	if d, err := h.QueueDelete(false, "tn-q"); err != nil || !d || h.LastError().Code != hostkit.OK {
		t.Fatalf("queue delete: %v %+v", err, h.LastError())
	}
}

// conflictAfterCommit models a create whose first attempt committed server-side
// (storing the call's create token) but whose reply was lost: it reports CONFLICT.
// It also exposes a creation timer claiming "just now" to prove timers are ignored.
type conflictAfterCommit struct {
	*fakeadapter.Fake
	commit bool // false: the resource pre-exists, created by someone else
}

func (c conflictAfterCommit) CreateBucket(ctx context.Context, b string) (bool, error) {
	if c.commit {
		_, _ = c.Fake.CreateBucket(ctx, b)
	}
	return false, hostkit.ProviderError(hostkit.Conflict, 409, "BucketAlreadyExists", "exists")
}
func (c conflictAfterCommit) CreateQueue(ctx context.Context, q string) (bool, error) {
	if c.commit {
		_, _ = c.Fake.CreateQueue(ctx, q)
	}
	return false, hostkit.ProviderError(hostkit.Conflict, 409, "QueueAlreadyExists", "exists")
}
func (c conflictAfterCommit) BucketCreatedAt(context.Context, string) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}
func (c conflictAfterCommit) QueueCreatedAt(context.Context, string) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

// hostkit v3 decision (09-hostkit.md): CONFLICT + accessible resource is
// created=true only when the adapter reads back this call's create token.
func TestCreateConflictResolvedByToken(t *testing.T) {
	env := &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}
	// 1. Our earlier attempt committed with this call's token -> true.
	a := conflictAfterCommit{fakeadapter.New(fakeadapter.Options{}), true}
	h := New(Config{Store: a, Queue: a, Endpoints: env})
	h.SetAbortOnError(false)
	if got, _ := h.BucketCreate(false, "own-bkt"); !got || h.LastError().Code != hostkit.OK {
		t.Fatalf("own bucket: %v %+v", got, h.LastError())
	}
	if got, _ := h.QueueCreate(false, "own-q"); !got || h.LastError().Code != hostkit.OK {
		t.Fatalf("own queue: %v %+v", got, h.LastError())
	}
	// 2. Pre-existing (another call's token, or none) -> false even though the
	//    deprecated creation timer claims a recent time (a skewed server clock).
	pre := fakeadapter.New(fakeadapter.Options{})
	ctx := hostkit.WithCreateToken(context.Background(), "someone-elses-token")
	_, _ = pre.CreateBucket(ctx, "pre-bkt")
	_, _ = pre.CreateQueue(context.Background(), "pre-q")
	b := conflictAfterCommit{pre, false}
	h = New(Config{Store: b, Queue: b, Endpoints: env})
	h.SetAbortOnError(false)
	if got, _ := h.BucketCreate(false, "pre-bkt"); got || h.LastError().Code != hostkit.OK {
		t.Fatalf("pre-existing bucket: %v %+v", got, h.LastError())
	}
	if got, _ := h.QueueCreate(false, "pre-q"); got || h.LastError().Code != hostkit.OK {
		t.Fatalf("pre-existing queue: %v %+v", got, h.LastError())
	}
	// 3. No token reader -> false.
	f := noTokenStore{fakeadapter.New(fakeadapter.Options{})}
	_, _ = f.Fake.CreateBucket(context.Background(), "nt-bkt")
	h = New(Config{Store: f, Queue: f.Fake, Endpoints: env})
	if got, _ := h.BucketCreate(false, "nt-bkt"); got {
		t.Fatal("no reader: must be false")
	}
	// 4. A queue CONFLICT for a queue we cannot see stays CONFLICT.
	h = New(Config{Store: f.Fake, Queue: conflictOnly{fakeadapter.New(fakeadapter.Options{})}, Endpoints: env})
	h.SetAbortOnError(false)
	if _, _ = h.QueueCreate(false, "foreign-q"); h.LastError().Code != hostkit.Conflict {
		t.Fatalf("foreign queue: %+v", h.LastError())
	}
}

// noTokenStore hides the fake's token reader.
type noTokenStore struct{ *fakeadapter.Fake }

func (noTokenStore) BucketCreateToken() {}

type conflictOnly struct{ *fakeadapter.Fake }

func (c conflictOnly) CreateQueue(context.Context, string) (bool, error) {
	return false, hostkit.ProviderError(hostkit.Conflict, 409, "QueueAlreadyExists", "someone else's")
}

// perQueueCaps long-polls only on queues whose name starts with "lp-".
type perQueueCaps struct {
	*fakeadapter.Fake
	waits []int
}

func (p *perQueueCaps) QueueCapsFor(_ context.Context, q string) hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: strings.HasPrefix(q, "lp-"), TextOnlyWire: true}
}
func (p *perQueueCaps) Receive(ctx context.Context, q string, max, wait, vis int) ([]hostkit.RawMessage, error) {
	p.waits = append(p.waits, wait)
	return p.Fake.Receive(ctx, q, max, wait, vis)
}

func TestQueueCapsPerCall(t *testing.T) {
	p := &perQueueCaps{Fake: fakeadapter.New(fakeadapter.Options{})}
	h := New(Config{Store: p.Fake, Queue: p, PollInterval: time.Millisecond, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	for _, q := range []string{"lp-queue", "sp-queue"} {
		if _, err := h.QueueCreate(false, q); err != nil {
			t.Fatal(err)
		}
	}
	p.waits = nil
	_, _ = h.QueueReceive(false, "lp-queue", 1, 1, 30)
	if len(p.waits) != 1 || p.waits[0] != 1 {
		t.Fatalf("long-poll queue: waits=%v (adapter must receive wait_seconds once)", p.waits)
	}
	p.waits = nil
	_, _ = h.QueueReceive(false, "sp-queue", 1, 1, 30)
	if len(p.waits) < 2 || p.waits[0] != 0 {
		t.Fatalf("short-poll queue: waits=%v (host must loop with wait 0)", p.waits)
	}
}

func TestProgramCLI(t *testing.T) {
	var initCalls int
	p := Program{
		Name: "lmx", Version: "9.9", Schema: []byte(`{"x":1}`), Help: "HELP TEXT\n", Notices: "NOTICES",
		Init:     func() error { initCalls++; return errors.New("bad LMX_MAX_MEMORY_MB") },
		Commands: map[string]func([]string, io.Writer) int{"--sweep": func(a []string, w io.Writer) int { w.Write([]byte("swept " + strings.Join(a[1:], ","))); return 7 }},
	}
	run := func(args ...string) (int, string) {
		var out bytes.Buffer
		p.Out = &out
		return p.Main(args), out.String()
	}
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 0, "HELP TEXT"},
		{[]string{"-h"}, 0, "HELP TEXT"},
		{[]string{"cloud", "--help"}, 0, "HELP TEXT"},
		{[]string{"cloud", "-V"}, 0, "lmx 9.9"},
		{[]string{"--notices"}, 0, "NOTICES\n"},
		{[]string{"cloud", "--lmcode-schema"}, 0, `{"x":1}`},
		{[]string{"--lmcode-signatures", "--without-std"}, 0, "method Cloud.queue_nack(string, string, int) -> string"},
		{[]string{"cloud", "--sweep", "a", "b"}, 7, "swept a,b"},
	} {
		code, out := run(c.args...)
		if code != c.code || !strings.Contains(out, c.want) {
			t.Errorf("%v: code=%d out=%q", c.args, code, out)
		}
	}
	if code, out := run("--lmcode-signatures", "--without-std"); code != 0 || strings.Contains(out, "fn str_len") {
		t.Fatal("--without-std must omit std signatures")
	}
	if code, _ := run("--lmcode", "/nonexistent.dslb"); code != 2 || initCalls != 1 {
		t.Fatalf("Init failure must be a CLI_USAGE exit 2 (code=%d init=%d)", code, initCalls)
	}
	p.Notices = ""
	if code, _ := run("--notices"); code != 2 {
		t.Fatal("--notices without text must be a usage error")
	}
}
