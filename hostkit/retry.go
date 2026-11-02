// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RetryPolicy is the single bounded retry policy (design 02 §5.2): at most
// Attempts tries for 429, 503 and transient 500/502/504, exponential backoff
// with full jitter, Retry-After honoured up to RetryAfterCap. Adapters must
// disable any provider SDK retries so attempts never multiply.
type RetryPolicy struct {
	Attempts      int
	Backoff       []time.Duration
	RetryAfterCap time.Duration
	// Jitter returns a duration in [0, max]; defaults to uniform full jitter.
	Jitter func(max time.Duration) time.Duration
	// Sleep waits for d or until ctx ends; injectable for tests.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is used for Retry-After HTTP dates and deadline checks.
	Now func() time.Time
}

// DefaultRetryPolicy returns the spec policy: 3 attempts, 100/250/500ms, Retry-After <= 2s.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		Attempts:      3,
		Backoff:       []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond},
		RetryAfterCap: 2 * time.Second,
	}
}

// RetryableStatus reports whether status is retried by the shared policy.
func RetryableStatus(status int) bool {
	switch status {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}

// Attempt is the outcome of one try. Err is a transport error (no response).
// NotSent marks a transport error that happened before any byte of the
// request reached the server (dial/DNS/TLS-handshake failure); such attempts
// are safe to retry even for non-idempotent requests.
type Attempt struct {
	Status     int
	RetryAfter string
	Err        error
	NotSent    bool
}

// IdempotentMethod is the default retry safety by HTTP method: GET, HEAD,
// PUT, DELETE and OPTIONS are idempotent; POST and PATCH are not. An adapter
// may still pass idempotent=true for a POST that carries a client token
// (e.g. an idempotency key or client request id the provider de-duplicates).
func IdempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "PUT", "DELETE", "OPTIONS":
		return true
	}
	return false
}

// RequestNotSent reports whether err from http.Client.Do happened before the
// request could have reached the server.
func RequestNotSent(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	var dns *net.DNSError
	return errors.As(err, &dns)
}

// retryable decides whether attempt a may be repeated (design 02 §5.2 plus
// the idempotency rule): 429 always (the server refused before processing);
// 500/502/503/504 and in-flight transport errors only for idempotent
// requests; transport errors that provably happened before sending, always.
func retryable(a Attempt, idempotent bool) bool {
	if a.Err != nil {
		return a.NotSent || idempotent
	}
	if a.Status == 429 {
		return true
	}
	return idempotent && RetryableStatus(a.Status)
}

func (p RetryPolicy) normalized() RetryPolicy {
	d := DefaultRetryPolicy()
	if p.Attempts <= 0 {
		p.Attempts = d.Attempts
	}
	if len(p.Backoff) == 0 {
		p.Backoff = d.Backoff
	}
	if p.RetryAfterCap <= 0 {
		p.RetryAfterCap = d.RetryAfterCap
	}
	if p.Jitter == nil {
		p.Jitter = func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(max) + 1))
		}
	}
	if p.Sleep == nil {
		p.Sleep = SleepContext
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	return p
}

// SleepContext sleeps for d or returns ctx.Err() early.
func SleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ParseRetryAfter parses delta-seconds or an HTTP date relative to now.
func ParseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		if secs > 86400 {
			secs = 86400
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// Delay returns the wait before retry number i (0-based), honouring Retry-After.
func (p RetryPolicy) Delay(i int, retryAfter string) time.Duration {
	p = p.normalized()
	base := p.Backoff[min(i, len(p.Backoff)-1)]
	d := p.Jitter(base)
	if ra, ok := ParseRetryAfter(retryAfter, p.Now()); ok {
		ra = min(ra, p.RetryAfterCap)
		d = max(d, ra)
	}
	return d
}

// Do runs fn up to Attempts times. idempotent says whether repeating the
// request is safe after it may have been processed (see IdempotentMethod):
// non-idempotent requests are retried only on 429 or when Attempt.NotSent.
// It stops early when ctx ends or the next delay would pass ctx's deadline,
// returning the last attempt and the number of attempts made.
//
// v2 change: before hostkit v2 a non-idempotent request was also retried on
// 5xx, which could turn a create that succeeded server-side into a 409.
func (p RetryPolicy) Do(ctx context.Context, idempotent bool, fn func(ctx context.Context, attempt int) Attempt) (Attempt, int) {
	p = p.normalized()
	var last Attempt
	n := 0
	for i := 0; i < p.Attempts; i++ {
		if ctx.Err() != nil && n > 0 {
			break
		}
		last = fn(ctx, i)
		n++
		retry := retryable(last, idempotent) && (last.Err == nil || ctx.Err() == nil)
		if !retry || i == p.Attempts-1 {
			break
		}
		d := p.Delay(i, last.RetryAfter)
		if dl, ok := ctx.Deadline(); ok && p.Now().Add(d).After(dl) {
			break
		}
		if p.Sleep(ctx, d) != nil {
			break
		}
	}
	return last, n
}

// DoHTTP sends a request built by build with the shared retry policy over
// EnforceClient(client) (same-origin redirects, timeout, no env proxy);
// idempotent follows Do (use IdempotentMethod(req.Method) unless the request
// carries a provider-honoured client token). Bodies
// of discarded responses are drained (bounded) and closed. The caller owns the
// returned response body. Requests must be rebuilt per attempt so bodies replay.
func (p RetryPolicy) DoHTTP(ctx context.Context, client *http.Client, idempotent bool, build func(ctx context.Context) (*http.Request, error)) (*http.Response, int, error) {
	client = EnforceClient(client)
	var resp *http.Response
	var buildErr error
	last, n := p.Do(ctx, idempotent, func(ctx context.Context, _ int) Attempt {
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			resp = nil
		}
		req, err := build(ctx)
		if err != nil {
			buildErr = err
			return Attempt{}
		}
		r, err := client.Do(req)
		if err != nil {
			return Attempt{Err: err, NotSent: RequestNotSent(err)}
		}
		resp = r
		return Attempt{Status: r.StatusCode, RetryAfter: r.Header.Get("Retry-After")}
	})
	if buildErr != nil {
		return nil, n, buildErr
	}
	if last.Err != nil {
		return nil, n, last.Err
	}
	return resp, n, nil
}

// FinalStatusError classifies the final response of an exhausted retry:
// retryable statuses become INTERNAL with the final HTTP and provider code.
func FinalStatusError(status int, providerCode, message string) *CloudError {
	return ProviderError(CodeForStatus(status), status, providerCode, message)
}
