// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// typedNil returns a nil *CloudError through the error interface: the trap.
func typedNil() error {
	var ce *CloudError
	return ce
}

func TestTypedNilIsSuccess(t *testing.T) {
	err := typedNil()
	if err == nil {
		t.Fatal("precondition: typed nil must be a non-nil interface")
	}
	if NilIfTyped(err) != nil || AsCloudError(err) != nil {
		t.Fatal("typed-nil *CloudError must be treated as success")
	}
	real := ProviderError(NotFound, 404, "x", "y")
	if NilIfTyped(real) == nil || AsCloudError(real).Code != NotFound {
		t.Fatal("a real CloudError must survive")
	}
	if NilIfTyped(errors.New("boom")) == nil {
		t.Fatal("other errors must survive")
	}
}

func TestReadBoundedResponseCarriesStatus(t *testing.T) {
	resp := &http.Response{StatusCode: 206, Body: io.NopCloser(strings.NewReader("too long"))}
	if _, e := ReadBoundedResponse(resp, 3); e == nil || e.HTTPStatus != 206 || e.Code != Internal {
		t.Fatalf("got %+v", e)
	}
	resp = &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}
	if b, e := ReadBoundedResponse(resp, 3); e != nil || string(b) != "ok" {
		t.Fatalf("%q %v", b, e)
	}
}

// stubBackend records which route served a call.
type stubBackend struct {
	name string
	caps QueueCaps
	Backend
}

func (s stubBackend) HeadBucket(context.Context, string) error {
	return ProviderError(NotFound, 404, s.name, "from "+s.name)
}
func (s stubBackend) QueueCaps() QueueCaps { return s.caps }

func TestRouterEndpointRoutes(t *testing.T) {
	off, sim, live := stubBackend{name: "offline"}, stubBackend{name: "sim", caps: QueueCaps{LongPoll: true}}, stubBackend{name: "live"}
	useLive := false
	r := Router{Pick: EndpointRoutes{Offline: off, Sim: sim, Live: live, UseLive: func() bool { return useLive }}.Pick}
	route := func(ep string) string {
		ctx := WithEndpoint(context.Background(), ep)
		e := AsCloudError(r.HeadBucket(ctx, "b"))
		if e == nil {
			return "<nil>"
		}
		return e.ProviderCode
	}
	cases := map[string]string{"": "offline", "http://127.0.0.1:4599": "sim", "http://[::1]:1": "sim", "http://localhost:1": "sim", "https://objectstorage.example.com": "live"}
	for ep, want := range cases {
		if got := route(ep); got != want {
			t.Errorf("endpoint %q routed to %s, want %s", ep, got, want)
		}
	}
	useLive = true
	if got := route(""); got != "live" {
		t.Fatalf("UseLive: %s", got)
	}
	if !r.QueueCapsFor(WithEndpoint(context.Background(), "http://127.0.0.1:1"), "q").LongPoll {
		t.Fatal("caps must come from the routed backend")
	}
	if r.QueueCapsFor(context.Background(), "q").LongPoll {
		t.Fatal("offline backend caps")
	}
	noLive := Router{Pick: EndpointRoutes{Offline: off, Unavailable: func(route string) error {
		return ProviderError(Unauthenticated, 0, "LiveNotImplemented", route)
	}}.Pick}
	if e := AsCloudError(noLive.HeadBucket(WithEndpoint(context.Background(), "https://x.example"), "b")); e == nil || e.ProviderCode != "LiveNotImplemented" {
		t.Fatalf("unavailable route: %+v", e)
	}
	typed := Router{Pick: func(context.Context) (Backend, error) { return off, typedNil() }}
	if e := AsCloudError(typed.HeadBucket(context.Background(), "b")); e == nil || e.ProviderCode != "offline" {
		t.Fatalf("typed-nil pick error must be ignored: %+v", e)
	}
	if e := AsCloudError((Router{}).HeadBucket(context.Background(), "b")); e == nil || e.Code != Internal {
		t.Fatal("router without Pick must fail")
	}
	var _ ObjectStore = Router{}
	var _ Queue = Router{}
	var _ QueueCapsProvider = Router{}
	var _ BucketCreationTimer = Router{}
	var _ QueueCreationTimer = Router{}
}
