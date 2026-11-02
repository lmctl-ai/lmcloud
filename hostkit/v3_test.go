// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"testing"
	"time"
)

type nilBackend struct{ Backend }

func TestRouterRejectsTypedNilBackend(t *testing.T) {
	var p *nilBackend
	r := Router{Pick: func(context.Context) (Backend, error) { return p, nil }}
	if e := AsCloudError(r.HeadBucket(context.Background(), "b")); e == nil || e.Code != Internal {
		t.Fatalf("typed-nil backend must be an error, not a panic: %+v", e)
	}
}

// Additional Sol finding: a cancelled wait is a failure, not an empty receive.
func TestWaitLoopCancellationIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := WaitLoop(ctx, time.Second, 10*time.Millisecond, nil, nil, func(context.Context) (int, error) { return 0, nil })
	if AsCloudError(err) == nil || AsCloudError(err).Code != Internal {
		t.Fatalf("cancelled wait returned %v", err)
	}
	if err := WaitLoop(context.Background(), 0, time.Millisecond, nil, nil, func(context.Context) (int, error) { return 0, nil }); err != nil {
		t.Fatalf("exhausting the requested wait is success: %v", err)
	}
}

func TestCreateTokenContext(t *testing.T) {
	if CreateToken(context.Background()) != "" {
		t.Fatal("no token by default")
	}
	if CreateToken(WithCreateToken(context.Background(), "abc")) != "abc" {
		t.Fatal("token round trip")
	}
	var _ BucketCreateTokenReader = Router{}
	var _ QueueCreateTokenReader = Router{}
}
