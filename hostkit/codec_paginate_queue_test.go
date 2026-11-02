// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

func TestQueueCodecExamples(t *testing.T) {
	cases := []struct {
		body     string
		textOnly bool
		wire     string
	}{
		{"", true, EmptySentinel},
		{"", false, EmptySentinel},
		{"hello", true, "hello"},
		{EmptySentinel, true, EscapePrefix + EmptySentinel},
		{"__lmcloud_future__:text", true, EscapePrefix + "__lmcloud_future__:text"}, // Sol finding 10
		{"__lmcloud_", false, EscapePrefix + "__lmcloud_"},
		{"bin\x00\xff", false, "bin\x00\xff"},
		{"bin\x00", true, Base64Prefix + "YmluAA=="},
		{"tab\tnl\ncr\r", true, "tab\tnl\ncr\r"},
	}
	for _, c := range cases {
		w := EncodeQueueBody(c.body, c.textOnly)
		if w != c.wire {
			t.Errorf("Encode(%q,%v) = %q want %q", c.body, c.textOnly, w, c.wire)
		}
		back, e := DecodeQueueBody(w)
		if e != nil || back != c.body {
			t.Errorf("Decode(%q) = %q, %v", w, back, e)
		}
	}
	if s, e := DecodeQueueBody("__lmcloud_unknown_form"); e != nil || s != "__lmcloud_unknown_form" {
		t.Fatal("foreign reserved-prefix wire must pass through")
	}
	if _, e := DecodeQueueBody(Base64Prefix + "!!!"); e == nil {
		t.Fatal("malformed base64 envelope accepted")
	}
}

func randomBody(r *rand.Rand) string {
	pieces := []string{"", "__lmcloud_", EmptySentinel, EscapePrefix, Base64Prefix, "\x00", "\xff", "雪", "🚀", "a", "\n", "￾"}
	var b strings.Builder
	for n := r.IntN(6); n > 0; n-- {
		if r.IntN(2) == 0 {
			b.WriteString(pieces[r.IntN(len(pieces))])
		} else {
			buf := make([]byte, r.IntN(8))
			for i := range buf {
				buf[i] = byte(r.IntN(256))
			}
			b.Write(buf)
		}
	}
	return b.String()
}

func TestQueueCodecRoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		body := randomBody(r)
		for _, textOnly := range []bool{true, false} {
			w := EncodeQueueBody(body, textOnly)
			if w == "" {
				t.Fatalf("empty wire for %q", body)
			}
			if textOnly && !TextSafe(w) {
				t.Fatalf("text-only wire not text-safe for %q: %q", body, w)
			}
			if strings.HasPrefix(body, ReservedPrefix) && !strings.HasPrefix(w, EscapePrefix) && !strings.HasPrefix(w, Base64Prefix) {
				t.Fatalf("reserved body %q not escaped: %q", body, w)
			}
			got, e := DecodeQueueBody(w)
			if e != nil || got != body {
				t.Fatalf("round trip %q (textOnly=%v): wire %q -> %q, %v", body, textOnly, w, got, e)
			}
		}
	}
}

func pages(m map[string][2]any) PageFetch[string] {
	return func(_ context.Context, token string) ([]string, string, error) {
		p, ok := m[token]
		if !ok {
			return nil, "", errors.New("unexpected token " + token)
		}
		return p[0].([]string), p[1].(string), nil
	}
}

func TestListAll(t *testing.T) {
	ctx := context.Background()
	all, e := ListAll(ctx, 10, pages(map[string][2]any{"": {[]string{"a"}, "t1"}, "t1": {[]string{"b"}, "t2"}, "t2": {[]string{"c"}, ""}}))
	if e != nil || strings.Join(all, ",") != "a,b,c" {
		t.Fatalf("%v %v", all, e)
	}
	// Sol finding 6: stalled (same token) and cyclic tokens fail instead of returning partial data.
	for name, m := range map[string]map[string][2]any{
		"stalled": {"": {[]string{"a"}, "t1"}, "t1": {[]string{"b"}, "t1"}},
		"cycle":   {"": {[]string{"a"}, "t1"}, "t1": {[]string{"b"}, "t2"}, "t2": {[]string{"c"}, "t1"}},
	} {
		got, e := ListAll(ctx, 10, pages(m))
		if e == nil || e.Code != Internal || got != nil {
			t.Fatalf("%s: got %v %v", name, got, e)
		}
	}
	endless := func(_ context.Context, token string) ([]string, string, error) {
		return []string{token}, token + "x", nil
	}
	if got, e := ListAll(ctx, 5, endless); e == nil || got != nil || !strings.Contains(e.Message, "5 pages") {
		t.Fatalf("page limit: %v %v", got, e)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := ListAll(cctx, 5, endless); e == nil {
		t.Fatal("cancelled listing succeeded")
	}
	failing := func(context.Context, string) ([]string, string, error) {
		return nil, "", ProviderError(PermissionDenied, 403, "AccessDenied", "no")
	}
	if _, e := ListAll(ctx, 5, failing); e == nil || e.Code != PermissionDenied {
		t.Fatalf("page error: %v", e)
	}
	if got := SortedUnique([]string{"b", "a", "b", "c", "a"}); strings.Join(got, ",") != "a,b,c" {
		t.Fatal(got)
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.t = c.t.Add(d)
	return nil
}

func TestWaitLoop(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	polls := 0
	err := WaitLoop(context.Background(), 2*time.Second, 250*time.Millisecond, clk.now, clk.sleep, func(context.Context) (int, error) {
		polls++
		return 0, nil
	})
	if err != nil || polls != 9 || clk.t.Sub(time.Unix(0, 0)) != 2*time.Second {
		t.Fatalf("polls=%d elapsed=%v err=%v", polls, clk.t.Sub(time.Unix(0, 0)), err)
	}
	clk = &fakeClock{t: time.Unix(0, 0)}
	polls = 0
	_ = WaitLoop(context.Background(), 0, 250*time.Millisecond, clk.now, clk.sleep, func(context.Context) (int, error) { polls++; return 0, nil })
	if polls != 1 {
		t.Fatalf("wait 0 must poll exactly once, polled %d", polls)
	}
	polls = 0
	_ = WaitLoop(context.Background(), 20*time.Second, time.Second, clk.now, clk.sleep, func(context.Context) (int, error) {
		polls++
		if polls == 3 {
			return 1, nil
		}
		return 0, nil
	})
	if polls != 3 {
		t.Fatalf("must stop at first message, polled %d", polls)
	}
	boom := errors.New("boom")
	if err := WaitLoop(context.Background(), time.Second, time.Millisecond, clk.now, clk.sleep, func(context.Context) (int, error) { return 0, boom }); !errors.Is(err, boom) {
		t.Fatal("errors must stop the loop")
	}
}

// Sol finding 9 / design 07 §5.4: missing queue beats malformed receipt; only a
// message-scoped NOT_FOUND on an existing queue is an idempotent ack.
func TestReceiptPrecedence(t *testing.T) {
	malformed := ProviderError(InvalidArgument, 400, "InvalidReceipt", "bad")
	gone := ProviderError(NotFound, 404, "MessageNotFound", "gone").WithAbsent(AbsentMessage)
	qgone := ProviderError(NotFound, 404, "QueueNotFound", "q").WithAbsent(AbsentQueue)
	denied := ProviderError(PermissionDenied, 403, "AccessDenied", "no")
	vague := ProviderError(NotFound, 404, "", "?")
	exists := func(v bool) func() (bool, *CloudError) { return func() (bool, *CloudError) { return v, nil } }
	probeFails := func() (bool, *CloudError) { return false, denied }
	cases := []struct {
		name  string
		e     *CloudError
		ack   bool
		probe func() (bool, *CloudError)
		want  Code // OK means nil
	}{
		{"malformed+missing queue", malformed, true, exists(false), NotFound},
		{"malformed+queue exists", malformed, true, exists(true), InvalidArgument},
		{"queue gone", qgone, true, exists(true), NotFound},
		{"re-ack gone message", gone, true, exists(true), OK},
		{"nack gone message", gone, false, exists(true), InvalidArgument},
		{"message gone but queue missing", gone, true, exists(false), NotFound},
		{"denied passes through", denied, true, exists(true), PermissionDenied},
		{"vague 404 existing queue stays NOT_FOUND", vague, true, exists(true), NotFound},
		{"probe denial wins", malformed, false, probeFails, PermissionDenied},
		{"success", nil, true, exists(true), OK},
	}
	for _, c := range cases {
		got := ReceiptPrecedence(c.e, c.ack, c.probe)
		code := OK
		if got != nil {
			code = got.Code
		}
		if code != c.want {
			t.Errorf("%s: got %s want %s", c.name, code, c.want)
		}
	}
}
