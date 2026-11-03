// SPDX-License-Identifier: MIT

package cloudhost

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

func newTestHost(t *testing.T, opts fakeadapter.Options) (*Host, *fakeadapter.Fake) {
	t.Helper()
	f := fakeadapter.New(opts)
	h := New(Config{Provider: "ref", Store: f, Queue: f, Tables: f, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}, PollInterval: time.Millisecond})
	h.SetAbortOnError(false)
	return h, f
}

func code(h *Host) hostkit.Code { return h.LastError().Code }

// Sol finding 1: a dry run performs zero provider mutator calls, yet previews
// coherently (later reads in the same dry run see earlier previews).
func TestDryRunMakesZeroMutatorCalls(t *testing.T) {
	h, f := newTestHost(t, fakeadapter.Options{})
	// Real setup: an existing bucket with one object and an existing queue.
	mustB(t)(h.BucketCreate(false, "existing-b"))
	if _, err := h.ObjectPut(false, "existing-b", "k0", "v0", "text/plain", nil); err != nil {
		t.Fatal(err)
	}
	mustB(t)(h.QueueCreate(false, "existing-q"))
	before := f.MutatorCalls()

	created, _ := h.BucketCreate(true, "dry-b")
	if !created || code(h) != hostkit.OK {
		t.Fatal("dry bucket_create preview")
	}
	if ex, _ := h.BucketExists(true, "dry-b"); !ex {
		t.Fatal("dry overlay must make the previewed bucket visible")
	}
	if again, _ := h.BucketCreate(true, "existing-b"); again {
		t.Fatal("dry create of an existing bucket must preview false")
	}
	m, _ := h.ObjectPut(true, "dry-b", "a/b.txt", "hello", "text/plain", map[string]string{"env": "dev"})
	if !m.Exists || m.Size != 5 || m.ETag == "" {
		t.Fatalf("dry put preview %+v", m)
	}
	if body, _ := h.ObjectGet(true, "dry-b", "a/b.txt"); body != "hello" {
		t.Fatalf("dry get of previewed object = %q", body)
	}
	if keys, _ := h.ObjectListAll(true, "existing-b", ""); strings.Join(keys, ",") != "k0" {
		t.Fatalf("dry list_all = %v", keys)
	}
	_ = h.ObjectDelete(true, "existing-b", "k0")
	if hm, _ := h.ObjectHead(true, "existing-b", "k0"); hm.Exists || code(h) != hostkit.OK {
		t.Fatal("dry delete preview must hide the object")
	}
	if del, _ := h.BucketDelete(true, "existing-b"); !del {
		t.Fatalf("dry delete of now-empty bucket: %v", h.LastError())
	}
	if _, err := h.ObjectPut(true, "no-such-bucket", "k", "v", "text/plain", nil); err != nil || code(h) != hostkit.NotFound {
		t.Fatal("dry put into a missing bucket must preview NOT_FOUND")
	}
	if _, err := h.ObjectPut(true, "dry-b", "k", strings.Repeat("x", hostkit.MaxObjectBytes+1), "text/plain", nil); err != nil || code(h) != hostkit.InvalidArgument {
		t.Fatal("dry put must enforce the body bound")
	}
	mustB(t)(h.QueueCreate(true, "dry-q"))
	if id, _ := h.QueueSend(true, "dry-q", "x"); id == "" {
		t.Fatal("dry send preview id")
	}
	if msgs, _ := h.QueueReceive(true, "existing-q", 1, 0, 30); len(msgs) != 0 || code(h) != hostkit.OK {
		t.Fatal("dry receive preview")
	}
	if _, _ = h.QueueReceive(true, "missing-q", 1, 0, 30); code(h) != hostkit.NotFound {
		t.Fatal("dry receive on missing queue must preview NOT_FOUND")
	}
	_ = h.QueueAck(true, "existing-q", "m1:1")
	if r, _ := h.QueueNack(true, "existing-q", "m1:1", 0); r != "m1:1" {
		t.Fatal("dry nack returns the receipt")
	}
	if del, _ := h.QueueDelete(true, "existing-q"); !del {
		t.Fatal("dry queue delete")
	}
	if names, _ := h.QueueList(true); strings.Join(names, ",") != "dry-q" {
		t.Fatalf("dry queue_list = %v", names)
	}
	mustB(t)(h.TableCreate(true, "dryt", true))
	dryIt, _ := h.ItemNew("p1", "s1", true)
	_, _ = dryIt.SetString("msg", "hello")
	putRes, _ := h.ItemPut(true, "dryt", dryIt, hostkit.PutUnconditional, "")
	if !putRes.Exists() || putRes.Version() == "" {
		t.Fatal("dry item_put preview")
	}
	if gotIt, _ := h.ItemGet(true, "dryt", "p1", "s1", true); !gotIt.Exists() {
		t.Fatal("dry item_get of previewed item")
	}
	if tnames, _ := h.TableList(true); strings.Join(tnames, ",") != "dryt" {
		t.Fatalf("dry table_list = %v", tnames)
	}
	if got := f.MutatorCalls(); got != before {
		t.Fatalf("dry run made %d provider mutator calls: %v", got-before, f.Calls())
	}
	// Real state untouched.
	if ex, _ := h.BucketExists(false, "dry-b"); ex {
		t.Fatal("dry run leaked into real state")
	}
	if ex, _ := h.QueueExists(false, "existing-q"); !ex {
		t.Fatal("dry delete leaked into real state")
	}
}

func mustB(t *testing.T) func(bool, error) {
	return func(_ bool, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
}

// stub overrides individual adapter calls on top of the fake.
type stub struct {
	*fakeadapter.Fake
	headObject  func() (hostkit.ObjectMeta, error)
	getObject   func(limit int64) ([]byte, error)
	listObjects func(token string) (hostkit.ObjectPage, error)
	listBuckets func(token string) ([]string, string, error)
	create      func() (bool, error)
	headBucket  func() error
}

func (s *stub) HeadObject(ctx context.Context, b, k string) (hostkit.ObjectMeta, error) {
	if s.headObject != nil {
		return s.headObject()
	}
	return s.Fake.HeadObject(ctx, b, k)
}
func (s *stub) GetObject(ctx context.Context, b, k string, limit int64) ([]byte, error) {
	if s.getObject != nil {
		return s.getObject(limit)
	}
	return s.Fake.GetObject(ctx, b, k, limit)
}
func (s *stub) ListObjects(ctx context.Context, b, p string, max int, token string) (hostkit.ObjectPage, error) {
	if s.listObjects != nil {
		return s.listObjects(token)
	}
	return s.Fake.ListObjects(ctx, b, p, max, token)
}
func (s *stub) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	if s.listBuckets != nil {
		return s.listBuckets(token)
	}
	return s.Fake.ListBuckets(ctx, token)
}
func (s *stub) CreateBucket(ctx context.Context, b string) (bool, error) {
	if s.create != nil {
		return s.create()
	}
	return s.Fake.CreateBucket(ctx, b)
}
func (s *stub) HeadBucket(ctx context.Context, b string) error {
	if s.headBucket != nil {
		return s.headBucket()
	}
	return s.Fake.HeadBucket(ctx, b)
}

func stubHost(t *testing.T, s *stub) *Host {
	h := New(Config{Provider: "ref", Store: s, Queue: s.Fake, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	h.SetAbortOnError(false)
	if _, err := s.Fake.CreateBucket(context.Background(), "bkt"); err != nil {
		t.Fatal(err)
	}
	return h
}

// Sol finding 5: an object HEAD 404 NotAuthorizedOrNotFound (classified by the
// adapter as PERMISSION_DENIED) never becomes exists()==false, even though the
// bucket itself is accessible.
func TestHeadDenialNeverBecomesAbsent(t *testing.T) {
	s := &stub{Fake: fakeadapter.New(fakeadapter.Options{})}
	s.headObject = func() (hostkit.ObjectMeta, error) {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.PermissionDenied, 404, "NotAuthorizedOrNotFound", "not authorized or not found")
	}
	h := stubHost(t, s)
	m, err := h.ObjectHead(false, "bkt", "secret.txt")
	if err != nil || m.Exists || code(h) != hostkit.PermissionDenied || h.LastError().HTTPStatus != 404 {
		t.Fatalf("exists=%v last=%+v", m.Exists, h.LastError())
	}
	// Vague NOT_FOUND (no Absent hint): the host disambiguates by probing the bucket.
	s.headObject = func() (hostkit.ObjectMeta, error) {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.NotFound, 404, "", "not found")
	}
	if m, _ := h.ObjectHead(false, "bkt", "nope"); m.Exists || code(h) != hostkit.OK {
		t.Fatalf("vague 404 + bucket exists must be absent/OK: %+v", h.LastError())
	}
	if _, _ = h.ObjectHead(false, "other-bkt", "nope"); code(h) != hostkit.NotFound {
		t.Fatalf("vague 404 + missing bucket must be NOT_FOUND: %+v", h.LastError())
	}
	s.headBucket = func() error { return hostkit.ProviderError(hostkit.PermissionDenied, 403, "AccessDenied", "no") }
	if _, _ = h.ObjectHead(false, "bkt", "nope"); code(h) != hostkit.PermissionDenied {
		t.Fatalf("probe denial must surface: %+v", h.LastError())
	}
	if ex, _ := h.BucketExists(false, "bkt"); ex || code(h) != hostkit.PermissionDenied {
		t.Fatal("bucket_exists denial must not be false/OK")
	}
}

// Sol finding 4: an adapter that ignores the limit still cannot hand back more than 16 MiB.
func TestOversizedGetIsRejected(t *testing.T) {
	s := &stub{Fake: fakeadapter.New(fakeadapter.Options{})}
	s.getObject = func(limit int64) ([]byte, error) {
		if limit != hostkit.MaxObjectBytes {
			t.Fatalf("limit passed = %d", limit)
		}
		return hostkit.ReadBounded(bytes.NewReader(make([]byte, 33_562_624)), limit)
	}
	h := stubHost(t, s)
	if body, _ := h.ObjectGet(false, "bkt", "big"); body != "" || code(h) != hostkit.Internal {
		t.Fatalf("len=%d last=%+v", len(body), h.LastError())
	}
	s.getObject = func(int64) ([]byte, error) { return make([]byte, hostkit.MaxObjectBytes+1), nil }
	if body, _ := h.ObjectGet(false, "bkt", "big"); body != "" || code(h) != hostkit.Internal {
		t.Fatal("host-side defence must reject an adapter that over-reads")
	}
}

// Sol finding 6: stalled tokens and page limits fail; bucket_list follows every page.
func TestPaginationFailsInsteadOfPartial(t *testing.T) {
	s := &stub{Fake: fakeadapter.New(fakeadapter.Options{})}
	s.listObjects = func(token string) (hostkit.ObjectPage, error) {
		return hostkit.ObjectPage{Items: []hostkit.ObjectSummary{{Key: "a" + token}}, NextToken: "same"}, nil
	}
	s.listBuckets = func(token string) ([]string, string, error) {
		switch token {
		case "":
			return []string{"b2", "b1"}, "p2", nil
		case "p2":
			return []string{"b3"}, "", nil
		}
		return nil, "", hostkit.ProviderError(hostkit.Internal, 500, "", "bad token")
	}
	h := stubHost(t, s)
	if keys, _ := h.ObjectListAll(false, "bkt", ""); keys != nil || code(h) != hostkit.Internal {
		t.Fatalf("stalled list_all: %v %+v", keys, h.LastError())
	}
	if p, _ := h.ObjectList(false, "bkt", "", 10, "same"); len(p.Items) != 0 || code(h) != hostkit.Internal {
		t.Fatal("single page that repeats the request token must fail")
	}
	if names, _ := h.BucketList(false); strings.Join(names, ",") != "b1,b2,b3" || code(h) != hostkit.OK {
		t.Fatalf("bucket_list = %v %+v", names, h.LastError())
	}
	h2 := New(Config{Store: s, Queue: s.Fake, MaxPages: 3, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	h2.SetAbortOnError(false)
	s.listBuckets = func(token string) ([]string, string, error) { return []string{"x" + token}, token + "n", nil }
	if names, _ := h2.BucketList(false); names != nil || code(h2) != hostkit.Internal {
		t.Fatal("page limit must fail, not return partial results")
	}
}

// Design 02 §6.1 / Sol finding 11: 409 is idempotent only if the bucket is accessible.
func TestBucketCreateConflict(t *testing.T) {
	s := &stub{Fake: fakeadapter.New(fakeadapter.Options{})}
	s.create = func() (bool, error) {
		return false, hostkit.ProviderError(hostkit.Conflict, 409, "BucketAlreadyExists", "taken")
	}
	h := stubHost(t, s)
	if created, _ := h.BucketCreate(false, "bkt"); created || code(h) != hostkit.OK {
		t.Fatal("owned bucket: false/OK")
	}
	if _, _ = h.BucketCreate(false, "foreign-bkt"); code(h) != hostkit.Conflict {
		t.Fatalf("foreign bucket must be CONFLICT: %+v", h.LastError())
	}
}

// Sol finding 2 at host level: an unsafe env endpoint fails before any adapter call.
func TestUnsafeEnvEndpointBlocksCalls(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	env := map[string]string{"LMCLOUD_STORAGE_ENDPOINT": "http://0.0.0.0:4599"}
	h := New(Config{Store: f, Queue: f, Endpoints: &hostkit.EndpointResolver{Getenv: func(k string) string { return env[k] }}})
	h.SetAbortOnError(false)
	if _, _ = h.BucketCreate(false, "abc"); code(h) != hostkit.InvalidArgument || len(f.Calls()) != 0 {
		t.Fatalf("last=%+v calls=%v", h.LastError(), f.Calls())
	}
	if _, err := h.Endpoint("storage"); err != nil || code(h) != hostkit.InvalidArgument {
		t.Fatal("endpoint() must report the invalid env source")
	}
	env["LMCLOUD_STORAGE_ENDPOINT"] = "http://127.0.0.1:4599"
	if ep, _ := h.Endpoint("storage"); ep != "http://127.0.0.1:4599" {
		t.Fatal(ep)
	}
	h.SetAbortOnError(true)
	err := h.SetEndpoint("storage", "http://user:secret@127.0.0.1:1")
	if err == nil || strings.Contains(err.Error(), "secret") || !strings.HasPrefix(err.Error(), "[INVALID_ARGUMENT] set_endpoint: ") {
		t.Fatalf("abort message = %v", err)
	}
}

// Design 07 §5.4 end to end: missing queue + odd receipt => NOT_FOUND; existing
// queue + malformed receipt => INVALID_ARGUMENT; re-ack => OK; nack returns a new receipt.
func TestQueueReceiptFlow(t *testing.T) {
	h, _ := newTestHost(t, fakeadapter.Options{})
	_ = h.QueueAck(false, "missing-q", "\n")
	if code(h) != hostkit.NotFound {
		t.Fatalf("ack missing queue: %+v", h.LastError())
	}
	_, _ = h.QueueNack(false, "missing-q", "garbage", 10)
	if code(h) != hostkit.NotFound {
		t.Fatalf("nack missing queue: %+v", h.LastError())
	}
	mustB(t)(h.QueueCreate(false, "q-one"))
	_, _ = h.QueueNack(false, "q-one", "garbage", 10)
	if code(h) != hostkit.InvalidArgument {
		t.Fatalf("nack malformed: %+v", h.LastError())
	}
	if _, err := h.QueueSend(false, "q-one", ""); err != nil {
		t.Fatal(err)
	}
	msgs, _ := h.QueueReceive(false, "q-one", 1, 1, 30)
	if len(msgs) != 1 || msgs[0].Body != "" {
		t.Fatalf("receive %+v %+v", msgs, h.LastError())
	}
	r2, _ := h.QueueNack(false, "q-one", msgs[0].Receipt, 30)
	if r2 == "" || r2 == msgs[0].Receipt {
		t.Fatal("nack must return the rotated receipt")
	}
	_ = h.QueueAck(false, "q-one", r2)
	_ = h.QueueAck(false, "q-one", r2)
	if code(h) != hostkit.OK {
		t.Fatalf("re-ack must be idempotent: %+v", h.LastError())
	}
	_, _ = h.QueueNack(false, "q-one", r2, 0)
	if code(h) != hostkit.InvalidArgument {
		t.Fatalf("nack of an acked receipt: %+v", h.LastError())
	}
	_, _ = h.QueueSend(false, "q-one", strings.Repeat("x", 49153))
	if code(h) != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatal("48 KiB preflight")
	}
}

func TestVagueAdapterStillMeetsSemantics(t *testing.T) {
	h, _ := newTestHost(t, fakeadapter.Options{VagueNotFound: true})
	mustB(t)(h.BucketCreate(false, "vb1"))
	if err := h.ObjectDelete(false, "vb1", "missing"); err != nil || code(h) != hostkit.OK {
		t.Fatal("delete missing key in existing bucket is OK")
	}
	if _ = h.ObjectDelete(false, "vb-missing", "k"); code(h) != hostkit.NotFound {
		t.Fatal("delete in missing bucket is NOT_FOUND")
	}
	if m, _ := h.ObjectHead(false, "vb1", "missing"); m.Exists || code(h) != hostkit.OK {
		t.Fatal("head missing key is absent/OK")
	}
}

func TestAbortOnErrorDefault(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Store: f, Queue: f, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	_, err := h.ObjectGet(false, "nobkt", "k")
	if err == nil || !strings.HasPrefix(err.Error(), "[NOT_FOUND] object_get (nobkt/k): ") || !strings.Contains(err.Error(), "provider_code=NoSuchBucket") {
		t.Fatalf("abort = %v", err)
	}
	if _, err := h.BucketCreate(false, "Bad_Bucket"); err == nil || !strings.HasPrefix(err.Error(), "[INVALID_ARGUMENT] bucket_create: ") {
		t.Fatalf("preflight abort = %v", err)
	}
	if h.LastError().ProviderCode != "" || h.LastError().HTTPStatus != 0 {
		t.Fatal("preflight last_error shape")
	}
}

func TestHostIsSafeForConcurrentUse(t *testing.T) {
	h, _ := newTestHost(t, fakeadapter.Options{})
	mustB(t)(h.BucketCreate(false, "conc"))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "k" + string(rune('a'+i))
			_, _ = h.ObjectPut(i%2 == 0, "conc", key, "v", "text/plain", nil)
			_, _ = h.ObjectHead(i%2 == 0, "conc", key)
			_ = h.LastError()
		}(i)
	}
	wg.Wait()
}

type tableStub struct {
	*fakeadapter.Fake
	getItem    func() (hostkit.Item, error)
	queryItems func(token string) (hostkit.TablePage, error)
}

func (s *tableStub) GetItem(ctx context.Context, table, pk, sk string) (hostkit.Item, error) {
	if s.getItem != nil {
		return s.getItem()
	}
	return s.Fake.GetItem(ctx, table, pk, sk)
}

func (s *tableStub) Query(ctx context.Context, table, pk, skFrom, skTo string, maxItems int, token string) (hostkit.TablePage, error) {
	if s.queryItems != nil {
		return s.queryItems(token)
	}
	return s.Fake.Query(ctx, table, pk, skFrom, skTo, maxItems, token)
}

func TestTablesTokenBindingAndOversizedProviderItem(t *testing.T) {
	s := &tableStub{Fake: fakeadapter.New(fakeadapter.Options{})}
	h := New(Config{Provider: "ref", Store: s.Fake, Queue: s.Fake, Tables: s, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	h.SetAbortOnError(false)

	mustB(t)(h.TableCreate(false, "tba", true))
	mustB(t)(h.TableCreate(false, "tbb", true))
	for _, sk := range []string{"s1", "s2", "s3"} {
		it, _ := h.ItemNew("p1", sk, true)
		_, _ = it.SetString("v", sk)
		_, _ = h.ItemPut(false, "tba", it, hostkit.PutUnconditional, "")
	}

	p1, _ := h.ItemQuery(false, "tba", "p1", "s1", "s9", 1, "")
	if p1.NextToken == "" || code(h) != hostkit.OK {
		t.Fatalf("expected page 1 token, got %+v err=%+v", p1, h.LastError())
	}
	tok := p1.NextToken

	// Replay query token against different table, pk, range, or item_scan must fail pre-flight INVALID_ARGUMENT.
	if _, _ = h.ItemQuery(false, "tbb", "p1", "s1", "s9", 1, tok); code(h) != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("cross-table query token replay must fail preflight: %+v", h.LastError())
	}
	if _, _ = h.ItemQuery(false, "tba", "p2", "s1", "s9", 1, tok); code(h) != hostkit.InvalidArgument {
		t.Fatalf("cross-pk query token replay must fail preflight: %+v", h.LastError())
	}
	if _, _ = h.ItemQuery(false, "tba", "p1", "s2", "s9", 1, tok); code(h) != hostkit.InvalidArgument {
		t.Fatalf("changed sk_from query token replay must fail preflight: %+v", h.LastError())
	}
	if _, _ = h.ItemScan(false, "tba", 1, tok); code(h) != hostkit.InvalidArgument {
		t.Fatalf("query token replayed on item_scan must fail preflight: %+v", h.LastError())
	}

	// Stalled provider token fails closed with INTERNAL.
	s.queryItems = func(token string) (hostkit.TablePage, error) {
		return hostkit.TablePage{Items: []hostkit.Item{{PK: "p1", SK: "s1", Version: "e1", Attrs: map[string]hostkit.Attr{}}}, NextToken: token}, nil
	}
	if _, _ = h.ItemQuery(false, "tba", "p1", "s1", "s9", 1, tok); code(h) != hostkit.Internal {
		t.Fatalf("stalled query token must fail INTERNAL: %+v", h.LastError())
	}
	s.queryItems = nil

	// Oversized item returned by a buggy provider fails closed with INTERNAL (OversizedTableItem).
	s.getItem = func() (hostkit.Item, error) {
		big := strings.Repeat("x", hostkit.MaxAttrStringUTF16Units+1)
		return hostkit.Item{
			PK:      "p1",
			SK:      "s1",
			Version: "e1",
			Attrs:   map[string]hostkit.Attr{"big": hostkit.StringAttr(big)},
		}, nil
	}
	if got, _ := h.ItemGet(false, "tba", "p1", "s1", true); got.Exists() || code(h) != hostkit.Internal || h.LastError().ProviderCode != "OversizedTableItem" {
		t.Fatalf("oversized provider item must fail closed INTERNAL/OversizedTableItem: exists=%v err=%+v", got.Exists(), h.LastError())
	}
}
