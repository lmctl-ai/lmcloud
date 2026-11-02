// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

func TestStateIsSharedAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	ctx := context.Background()
	a := New(Options{StatePath: path})
	if _, err := a.CreateBucket(ctx, "shared"); err != nil {
		t.Fatal(err)
	}
	b := New(Options{StatePath: path})
	if err := b.HeadBucket(ctx, "shared"); err != nil {
		t.Fatalf("second instance cannot see bucket: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f := New(Options{StatePath: path})
			if _, err := f.PutObject(ctx, "shared", string(rune('a'+i)), []byte("v"), "text/plain", nil); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	page, err := New(Options{StatePath: path, PageSize: 3}).ListObjects(ctx, "shared", "", 1000, "")
	if err != nil || len(page.Items) != 3 || page.NextToken == "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestAuthModes(t *testing.T) {
	cred := ""
	f := New(Options{Auth: Auth{Enforce: true, Credential: func() string { return cred }, Allow: "good", Deny: "denied"}})
	ctx := context.Background()
	check := func(want hostkit.Code) {
		t.Helper()
		_, err := f.CreateQueue(ctx, "q1")
		got := hostkit.OK
		if err != nil {
			got = hostkit.AsCloudError(err).Code
		}
		if got != want {
			t.Fatalf("cred %q: got %s want %s", cred, got, want)
		}
	}
	check(hostkit.Unauthenticated)
	cred = "bogus"
	check(hostkit.Unauthenticated)
	cred = "denied"
	check(hostkit.PermissionDenied)
	cred = "good"
	check(hostkit.OK)
}

func TestReceiptRotationAndVisibility(t *testing.T) {
	f := New(Options{})
	ctx := context.Background()
	_, _ = f.CreateQueue(ctx, "q1")
	_, _ = f.Send(ctx, "q1", "hello")
	got, _ := f.Receive(ctx, "q1", 1, 0, 30)
	if len(got) != 1 {
		t.Fatal("receive")
	}
	if again, _ := f.Receive(ctx, "q1", 1, 0, 30); len(again) != 0 {
		t.Fatal("message must be hidden while in flight")
	}
	r2, err := f.Nack(ctx, "q1", got[0].Receipt, 0)
	if err != nil || r2 == got[0].Receipt {
		t.Fatalf("nack must rotate: %q %v", r2, err)
	}
	if err := f.Ack(ctx, "q1", got[0].Receipt); hostkit.AsCloudError(err).Absent != hostkit.AbsentMessage {
		t.Fatalf("stale receipt must be message-scoped NOT_FOUND: %v", err)
	}
	if _, err := f.Send(ctx, "q1", "bin\x00"); err == nil {
		t.Fatal("text-only fake transport must reject unsafe bytes")
	}
}
