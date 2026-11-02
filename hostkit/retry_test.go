// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type sleepRecorder struct{ slept []time.Duration }

func (s *sleepRecorder) sleep(ctx context.Context, d time.Duration) error {
	s.slept = append(s.slept, d)
	return ctx.Err()
}

func testPolicy(rec *sleepRecorder) RetryPolicy {
	p := DefaultRetryPolicy()
	p.Jitter = func(max time.Duration) time.Duration { return max }
	p.Sleep = rec.sleep
	p.Now = func() time.Time { return time.Unix(1_000_000, 0) }
	return p
}

func TestRetryAttemptsAndBackoff(t *testing.T) {
	cases := []struct {
		name       string
		statuses   []int
		transport  bool
		retryTrans bool // idempotent
		wantN      int
		wantSleeps []time.Duration
		wantFinal  int
	}{
		{"503 exhausted (idempotent)", []int{503, 503, 503, 503}, false, true, 3, []time.Duration{100 * time.Millisecond, 250 * time.Millisecond}, 503},
		{"503 not retried for non-idempotent POST", []int{503, 200}, false, false, 1, nil, 503},
		{"429 then ok (always retried)", []int{429, 200}, false, false, 2, []time.Duration{100 * time.Millisecond}, 200},
		{"500 502 504 retried (idempotent)", []int{500, 502, 504}, false, true, 3, []time.Duration{100 * time.Millisecond, 250 * time.Millisecond}, 504},
		{"500 not retried for non-idempotent", []int{500, 200}, false, false, 1, nil, 500},
		{"404 not retried", []int{404, 200}, false, true, 1, nil, 404},
		{"501 not retried", []int{501, 200}, false, true, 1, nil, 501},
		{"transport not retried (non-idempotent)", nil, true, false, 1, nil, 0},
		{"transport retried when idempotent", nil, true, true, 3, []time.Duration{100 * time.Millisecond, 250 * time.Millisecond}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &sleepRecorder{}
			p := testPolicy(rec)
			last, n := p.Do(context.Background(), c.retryTrans, func(_ context.Context, i int) Attempt {
				if c.transport {
					return Attempt{Err: errors.New("connection reset")}
				}
				return Attempt{Status: c.statuses[i]}
			})
			if n != c.wantN || last.Status != c.wantFinal {
				t.Fatalf("attempts=%d status=%d, want %d/%d", n, last.Status, c.wantN, c.wantFinal)
			}
			if len(rec.slept) != len(c.wantSleeps) {
				t.Fatalf("sleeps = %v, want %v", rec.slept, c.wantSleeps)
			}
			for i := range rec.slept {
				if rec.slept[i] != c.wantSleeps[i] {
					t.Fatalf("sleeps = %v, want %v", rec.slept, c.wantSleeps)
				}
			}
		})
	}
}

func TestRetryAfterHonouredAndCapped(t *testing.T) {
	rec := &sleepRecorder{}
	p := testPolicy(rec)
	p.Jitter = func(time.Duration) time.Duration { return 0 }
	statuses := []Attempt{{Status: 429, RetryAfter: "1"}, {Status: 503, RetryAfter: "120"}, {Status: 200}}
	_, n := p.Do(context.Background(), true, func(_ context.Context, i int) Attempt { return statuses[i] })
	if n != 3 || rec.slept[0] != time.Second || rec.slept[1] != 2*time.Second {
		t.Fatalf("n=%d slept=%v; want 1s then the 2s cap", n, rec.slept)
	}
	date := time.Unix(1_000_000, 0).Add(1500 * time.Millisecond).UTC().Format(http.TimeFormat)
	if d, ok := ParseRetryAfter(date, time.Unix(1_000_000, 0)); !ok || d < time.Second || d > 2*time.Second {
		t.Fatalf("http-date Retry-After = %v %v", d, ok)
	}
	if _, ok := ParseRetryAfter("soon", time.Now()); ok {
		t.Fatal("garbage Retry-After accepted")
	}
}

func TestJitterIsBounded(t *testing.T) {
	p := DefaultRetryPolicy()
	for i := 0; i < 1000; i++ {
		for attempt, base := range p.Backoff {
			if d := p.Delay(attempt, ""); d < 0 || d > base {
				t.Fatalf("delay %v outside [0,%v]", d, base)
			}
		}
	}
}

func TestRetryStopsAtDeadline(t *testing.T) {
	rec := &sleepRecorder{}
	p := testPolicy(rec)
	now := time.Unix(1_000_000, 0)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(50*time.Millisecond))
	defer cancel()
	_, n := p.Do(ctx, false, func(context.Context, int) Attempt { return Attempt{Status: 503} })
	if n != 1 || len(rec.slept) != 0 {
		t.Fatalf("must not sleep past the deadline: n=%d slept=%v", n, rec.slept)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	_, n = p.Do(cctx, true, func(context.Context, int) Attempt { return Attempt{Err: errors.New("x")} })
	if n != 1 {
		t.Fatalf("cancelled ctx: attempts = %d", n)
	}
}

// Sol finding 3: a mock 503 must be retried 3 times and end as INTERNAL with http=503.
func TestDoHTTP503MapsToInternalAfterThreeAttempts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"code":"ServiceUnavailable"}`))
	}))
	defer srv.Close()
	rec := &sleepRecorder{}
	p := testPolicy(rec)
	resp, n, err := p.DoHTTP(context.Background(), NewHTTPClient(5*time.Second), true, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if n != 3 || hits.Load() != 3 || resp.StatusCode != 503 {
		t.Fatalf("attempts=%d hits=%d status=%d", n, hits.Load(), resp.StatusCode)
	}
	e := FinalStatusError(resp.StatusCode, "ServiceUnavailable", "service unavailable")
	if e.Code != Internal || e.HTTPStatus != 503 || e.ProviderCode != "ServiceUnavailable" {
		t.Fatalf("final error = %+v", e)
	}
}

// v2: a non-idempotent request is retried after a transport error only when
// the request provably never left the client (dial/DNS failure).
func TestNotSentIsRetriedForNonIdempotent(t *testing.T) {
	rec := &sleepRecorder{}
	p := testPolicy(rec)
	_, n := p.Do(context.Background(), false, func(_ context.Context, i int) Attempt {
		if i < 2 {
			return Attempt{Err: errors.New("dial tcp: connection refused"), NotSent: true}
		}
		return Attempt{Status: 200}
	})
	if n != 3 {
		t.Fatalf("attempts = %d, want 3", n)
	}
	// Real dial failure against a closed port is classified as not sent.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()
	_, err := http.Get(addr)
	if err == nil || !RequestNotSent(err) {
		t.Fatalf("closed port error %v not classified as not-sent", err)
	}
	if RequestNotSent(errors.New("read: connection reset by peer")) {
		t.Fatal("an in-flight failure must not be classified as not sent")
	}
	for m, want := range map[string]bool{"GET": true, "head": true, "PUT": true, "DELETE": true, "POST": false, "PATCH": false} {
		if IdempotentMethod(m) != want {
			t.Fatalf("IdempotentMethod(%s) != %v", m, want)
		}
	}
}

func TestDoHTTPPostNotRetriedOn500(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()
	rec := &sleepRecorder{}
	resp, n, err := testPolicy(rec).DoHTTP(context.Background(), NewHTTPClient(5*time.Second), IdempotentMethod("POST"), func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n != 1 || hits.Load() != 1 {
		t.Fatalf("POST attempts=%d hits=%d, want 1", n, hits.Load())
	}
}
