// SPDX-License-Identifier: MIT

// Package httpguard is a fault-injecting loopback HTTP server for adapter
// tests. It lets every provider adapter prove, with the same fixtures, that
// its HTTP path honours the hostkit bounds: retry attempt counts (503, 429,
// POST after a committed request), deadlines, oversized bodies and redirect
// policy (no credentials sent to another origin).
//
//	srv := httpguard.New(t)
//	srv.Script(httpguard.Status(503, ""))           // every request -> 503
//	... point the adapter at srv.URL, call it ...
//	httpguard.AssertCount(t, srv, "GET", 3)          // retried exactly 3 times
package httpguard

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Request is one recorded request.
type Request struct {
	Method        string
	Path          string
	Authorization string
	Body          []byte
}

// Step answers one request.
type Step func(w http.ResponseWriter, r *http.Request)

// Server is a scripted loopback server. Steps are consumed in order; once the
// script is exhausted the last step repeats. With no script it answers 200 {}.
type Server struct {
	URL string

	srv   *httptest.Server
	mu    sync.Mutex
	steps []Step
	next  int
	reqs  []Request
}

// New starts a server that closes when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	s.URL = s.srv.URL
	t.Cleanup(s.srv.Close)
	return s
}

// Script replaces the response script and clears the request log.
func (s *Server) Script(steps ...Step) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps, s.next, s.reqs = steps, 0, nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.mu.Lock()
	s.reqs = append(s.reqs, Request{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"), Body: body})
	var step Step
	if len(s.steps) > 0 {
		i := s.next
		if i >= len(s.steps) {
			i = len(s.steps) - 1
		}
		step = s.steps[i]
		s.next++
	}
	s.mu.Unlock()
	if step == nil {
		step = Status(200, "{}")
	}
	step(w, r)
}

// Requests returns a copy of the request log.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Count returns the number of requests with method ("" = all).
func (s *Server) Count(method string) int {
	n := 0
	for _, r := range s.Requests() {
		if method == "" || strings.EqualFold(r.Method, method) {
			n++
		}
	}
	return n
}

// Status answers code with body; headers are "Name: value" strings.
func Status(code int, body string, headers ...string) Step {
	return func(w http.ResponseWriter, _ *http.Request) {
		for _, h := range headers {
			if k, v, ok := strings.Cut(h, ":"); ok {
				w.Header().Set(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
		if body != "" && w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

// RetryAfter answers code with a Retry-After header.
func RetryAfter(code int, seconds string) Step {
	return Status(code, "", "Retry-After: "+seconds)
}

// Oversize answers 200 with n bytes of 'x' (streamed, never buffered).
func Oversize(n int64) Step {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(n))
		w.WriteHeader(200)
		buf := []byte(strings.Repeat("x", 32<<10))
		for n > 0 {
			k := int64(len(buf))
			if k > n {
				k = n
			}
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	}
}

// Delay sleeps d (or until the client goes away) and then runs next.
func Delay(d time.Duration, next Step) Step {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
		next(w, r)
	}
}

// RedirectTo answers 307 to url (use another Server's URL for a cross-origin redirect).
func RedirectTo(url string) Step {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// HangUp closes the connection after the request (and its body) was fully
// received, without any response: the server may have committed the request,
// so a non-idempotent call must not be retried.
func HangUp() Step {
	return func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			panic("httpguard: response writer cannot hijack")
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}
}

// AssertCount fails the test unless srv received exactly n requests with method.
func AssertCount(t testing.TB, srv *Server, method string, n int) {
	t.Helper()
	if got := srv.Count(method); got != n {
		t.Fatalf("httpguard: %d %s requests, want %d: %+v", got, method, n, srv.Requests())
	}
}

// AssertNoCredentials fails the test if any request reached srv with an
// Authorization header (use on the foreign server of a redirect test).
func AssertNoCredentials(t testing.TB, srv *Server) {
	t.Helper()
	for _, r := range srv.Requests() {
		if r.Authorization != "" {
			t.Fatalf("httpguard: credentials reached %s %s", r.Method, r.Path)
		}
	}
}
