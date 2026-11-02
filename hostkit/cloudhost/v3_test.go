// SPDX-License-Identifier: MIT

package cloudhost

import (
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

// Risk 9: a dry preview made at endpoint A never appears at endpoint B (or
// at the offline route), and switching back to A still sees it.
func TestDryPreviewsAreScopedPerEndpoint(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Store: f, Queue: f, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	h.SetAbortOnError(false)
	set := func(ep string) {
		t.Helper()
		if err := h.SetEndpoint("all", ep); err != nil {
			t.Fatal(err)
		}
	}
	set("http://127.0.0.1:4001")
	if c, _ := h.BucketCreate(true, "scoped-bkt"); !c {
		t.Fatal("dry create")
	}
	if c, _ := h.QueueCreate(true, "scoped-q"); !c {
		t.Fatal("dry queue create")
	}
	if ex, _ := h.BucketExists(true, "scoped-bkt"); !ex {
		t.Fatal("preview must be visible at the same endpoint")
	}
	set("http://127.0.0.1:4002")
	if ex, _ := h.BucketExists(true, "scoped-bkt"); ex {
		t.Fatal("preview leaked to another endpoint")
	}
	if ex, _ := h.QueueExists(true, "scoped-q"); ex {
		t.Fatal("queue preview leaked to another endpoint")
	}
	if names, _ := h.BucketList(true); len(names) != 0 {
		t.Fatalf("bucket_list at B = %v", names)
	}
	set("http://127.0.0.1:4001")
	if ex, _ := h.BucketExists(true, "scoped-bkt"); !ex {
		t.Fatal("switching back must keep A's previews")
	}
	if f.MutatorCalls() != 0 {
		t.Fatalf("dry run mutated the backend: %v", f.Calls())
	}
}

// Risk 8: the offline route follows its own caps. A short-polling fake behind
// a Router whose sim route long-polls must still wait wait_seconds offline.
func TestOfflineReceiveFollowsRouteCaps(t *testing.T) {
	offline := fakeadapter.New(fakeadapter.Options{})
	simulated := fakeadapter.New(fakeadapter.Options{LongPoll: true, PollInterval: 10 * time.Millisecond})
	router := hostkit.Router{Pick: hostkit.EndpointRoutes{Offline: offline, Sim: simulated}.Pick}
	h := New(Config{Store: router, Queue: router, PollInterval: 50 * time.Millisecond, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	for name, setup := range map[string]func(){
		"offline (host wait loop)": func() {},
		"sim (adapter long poll)":  func() { _ = h.SetEndpoint("queue", "http://127.0.0.1:4599") },
	} {
		setup()
		if _, err := h.QueueCreate(false, "wait-q"); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		msgs, err := h.QueueReceive(false, "wait-q", 1, 1, 30)
		elapsed := time.Since(start)
		if err != nil || len(msgs) != 0 {
			t.Fatalf("%s: %v %v", name, msgs, err)
		}
		if elapsed < 900*time.Millisecond || elapsed > 3*time.Second {
			t.Fatalf("%s: empty receive with wait=1 took %v, want ~1s", name, elapsed)
		}
	}
}
