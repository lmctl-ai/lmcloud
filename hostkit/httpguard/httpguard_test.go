// SPDX-License-Identifier: MIT

package httpguard_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/httpguard"
)

// These tests drive hostkit's own HTTP path (DoHTTP + ReadBoundedResponseErr)
// through httpguard; adapters should run the same checks on their code path.

func fastPolicy() hostkit.RetryPolicy {
	p := hostkit.DefaultRetryPolicy()
	p.Jitter = func(time.Duration) time.Duration { return 0 }
	return p
}

func call(t *testing.T, client *http.Client, method, url string, idempotent bool, auth string) (*http.Response, int, error) {
	t.Helper()
	return fastPolicy().DoHTTP(context.Background(), client, idempotent, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader([]byte("payload")))
		if err == nil && auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return req, err
	})
}

func TestGET503RetriedThreeTimes(t *testing.T) {
	srv := httpguard.New(t)
	srv.Script(httpguard.Status(503, `{"code":"ServiceUnavailable"}`))
	resp, n, err := call(t, hostkit.NewHTTPClient(0), "GET", srv.URL+"/x", true, "")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n != 3 || resp.StatusCode != 503 {
		t.Fatalf("attempts=%d status=%d", n, resp.StatusCode)
	}
	httpguard.AssertCount(t, srv, "GET", 3)
}

func TestPOST429RetriedPOST5xxAndHangUpNot(t *testing.T) {
	srv := httpguard.New(t)
	srv.Script(httpguard.RetryAfter(429, "0"), httpguard.Status(200, "{}"))
	resp, _, err := call(t, hostkit.NewHTTPClient(0), "POST", srv.URL, hostkit.IdempotentMethod("POST"), "")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	httpguard.AssertCount(t, srv, "POST", 2)

	srv.Script(httpguard.Status(500, ""))
	resp, _, err = call(t, hostkit.NewHTTPClient(0), "POST", srv.URL, false, "")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	httpguard.AssertCount(t, srv, "POST", 1)

	// The server received the whole request and hung up: possibly committed.
	srv.Script(httpguard.HangUp())
	if _, _, err := call(t, hostkit.NewHTTPClient(0), "POST", srv.URL, false, ""); err == nil {
		t.Fatal("hang-up must surface as a transport error")
	}
	httpguard.AssertCount(t, srv, "POST", 1)
	// The same failure on an idempotent PUT is retried.
	srv.Script(httpguard.HangUp())
	_, _, _ = call(t, hostkit.NewHTTPClient(0), "PUT", srv.URL, true, "")
	httpguard.AssertCount(t, srv, "PUT", 3)
}

func TestDeadlineIsHonoured(t *testing.T) {
	srv := httpguard.New(t)
	srv.Script(httpguard.Delay(5*time.Second, httpguard.Status(200, "{}")))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := fastPolicy().DoHTTP(ctx, hostkit.NewHTTPClient(0), true, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("deadline not honoured: err=%v after %v", err, time.Since(start))
	}
}

func TestOversizeRejectedWithStatus(t *testing.T) {
	srv := httpguard.New(t)
	srv.Script(httpguard.Oversize(hostkit.MaxObjectBytes + 1))
	resp, _, err := call(t, hostkit.NewHTTPClient(0), "GET", srv.URL, true, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, rerr := hostkit.ReadBoundedResponseErr(resp, hostkit.MaxObjectBytes)
	ce := hostkit.AsCloudError(rerr)
	if data != nil || ce == nil || ce.Code != hostkit.Internal || ce.HTTPStatus != 200 {
		t.Fatalf("len=%d err=%+v", len(data), ce)
	}
	// Success returns a nil error interface, never a typed nil.
	srv.Script(httpguard.Status(200, "ok"))
	resp2, _, _ := call(t, hostkit.NewHTTPClient(0), "GET", srv.URL, true, "")
	defer resp2.Body.Close()
	if b, err := hostkit.ReadBoundedResponseErr(resp2, 10); err != nil || string(b) != "ok" {
		t.Fatalf("%q %v", b, err)
	}
}

// v3: DoHTTP hardens any client it is given, so a hand-built client cannot
// forward credentials across origins by accident.
func TestRedirectPolicyEnforcedEvenForPlainClients(t *testing.T) {
	foreign := httpguard.New(t)
	origin := httpguard.New(t)
	origin.Script(httpguard.RedirectTo(foreign.URL + "/steal"))
	for name, client := range map[string]*http.Client{"hostkit": hostkit.NewHTTPClient(0), "plain": {}, "nil": nil} {
		foreign.Script()
		_, _, err := call(t, client, "GET", origin.URL, true, "Bearer super-secret-token")
		if err == nil || !strings.Contains(err.Error(), hostkit.ErrCrossOriginRedirect.Error()) {
			t.Fatalf("%s client followed a cross-origin redirect: %v", name, err)
		}
		httpguard.AssertCount(t, foreign, "", 0)
		httpguard.AssertNoCredentials(t, foreign)
	}
	same := httpguard.New(t)
	same.Script(httpguard.RedirectTo("/final"), httpguard.Status(200, "{}"))
	resp, _, err := call(t, &http.Client{}, "GET", same.URL, true, "")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("same-origin redirect: %v", err)
	}
	resp.Body.Close()
}

func TestEnforceClient(t *testing.T) {
	c := hostkit.EnforceClient(&http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}})
	if c.Timeout != hostkit.DefaultHTTPTimeout || c.CheckRedirect == nil || c.Transport.(*http.Transport).Proxy != nil {
		t.Fatalf("not hardened: %+v", c)
	}
	keep := &http.Client{Timeout: 5 * time.Second}
	if hostkit.EnforceClient(keep).Timeout != 5*time.Second || keep.CheckRedirect != nil {
		t.Fatal("must keep an explicit timeout and never mutate the input")
	}
}

// EnforceClient keeps an adapter's stricter redirect hook (lmazure strips
// Authorization on every redirect; v3 first replaced the hook, a regression).
func TestEnforceClientKeepsStricterRedirectHook(t *testing.T) {
	srv := httpguard.New(t)
	srv.Script(httpguard.RedirectTo("/next"), httpguard.Status(200, "{}"))
	strict := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		req.Header.Del("Authorization")
		return nil
	}}
	resp, _, err := call(t, strict, "GET", srv.URL, true, "SharedKey acct:sig")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	reqs := srv.Requests()
	if len(reqs) != 2 || reqs[0].Authorization == "" || reqs[1].Authorization != "" {
		t.Fatalf("adapter hook lost: %+v", reqs)
	}
	foreign := httpguard.New(t)
	srv.Script(httpguard.RedirectTo(foreign.URL))
	if _, _, err := call(t, strict, "GET", srv.URL, true, "x"); err == nil {
		t.Fatal("same-origin check must still run before the adapter hook")
	}
	httpguard.AssertCount(t, foreign, "", 0)
}
