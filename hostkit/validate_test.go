// SPDX-License-Identifier: MIT

package hostkit

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestBucketNames(t *testing.T) {
	v := &Validator{}
	good := []string{"abc", "lmcloud-c01-r0-alpha", "a1b", strings.Repeat("a", 63), "0ab"}
	bad := []string{"ab", strings.Repeat("a", 64), "Bad_Bucket", "a--b", "-ab", "ab-", "a.b", "xn--abc", "sthree-x", "sthree-configurator", "amzn-s3-demo-x", "abc-s3alias", "googx", "my-google-b", "g00gle-b", "ab c", "é12"}
	for _, n := range good {
		if e := v.Bucket(n); e != nil {
			t.Errorf("%q rejected: %v", n, e)
		}
	}
	for _, n := range bad {
		if e := v.Bucket(n); e == nil || e.Code != InvalidArgument || e.HTTPStatus != 0 || e.ProviderCode != "" {
			t.Errorf("%q accepted or mis-shaped: %+v", n, e)
		}
	}
	extra := &Validator{BucketRules: []Rule{func(n string) string {
		if strings.HasPrefix(n, "tmp") {
			return "reserved by this deployment"
		}
		return ""
	}}}
	if extra.Bucket("tmp-1") == nil || extra.Bucket("abc") != nil {
		t.Fatal("pluggable bucket rule")
	}
}

// Sol finding 8: aws-/amz-/azure- are valid portable queue names.
func TestQueueNames(t *testing.T) {
	v := &Validator{}
	good := []string{"abc", "aws-queue", "amz-queue", "azure-q1", "lmcloud-q01-r0-a", "a" + strings.Repeat("b", 62)}
	bad := []string{"ab", "1starts-with-digit", "Bad_Queue", "my--queue", "google-queue", "goog1", "x-g00gle", "q-", strings.Repeat("a", 64)}
	for _, n := range good {
		if e := v.Queue(n); e != nil {
			t.Errorf("%q rejected: %v", n, e)
		}
	}
	for _, n := range bad {
		if v.Queue(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestObjectKeys(t *testing.T) {
	v := &Validator{}
	good := []string{"a", "logs/2026/a.txt", "key with space+plus%pct?q#h", "雪/🚀.txt", strings.Repeat("k", 1024), strings.Repeat("a/", 300) + "z"}
	bad := []string{"", strings.Repeat("k", 1025), "/leading", "trailing/", "a//b", `a\b`, "a/./b", "a/../b", "..", "end.", "seg./x", "a\x00b", "a\nb", "a\x7fb", "\xff\xfe"}
	for _, k := range good {
		if e := v.Key(k); e != nil {
			t.Errorf("%q rejected: %v", k, e)
		}
	}
	for _, k := range bad {
		if v.Key(k) == nil {
			t.Errorf("%q accepted", k)
		}
	}
}

// Sol finding 8: content_type 255/256 boundary.
func TestContentType(t *testing.T) {
	base := "application/"
	ok255 := base + strings.Repeat("x", 255-len(base))
	cases := map[string]bool{
		"application/json": true, "text/plain; charset=utf-8": true, ok255: true,
		ok255 + "x": false, "": false, "json": false, "/json": false, "text/": false, "text/pl\nain": false, "text/plain\x00": false, "téxt/plain": false,
	}
	for ct, want := range cases {
		if got := ContentType(ct) == nil; got != want {
			t.Errorf("ContentType(%q) ok=%v want %v", ct, got, want)
		}
	}
}

// Sol finding 8: metadata 32/33 entries, padded values, 2048 bytes.
func TestMetadata(t *testing.T) {
	many := func(n int) map[string]string {
		m := map[string]string{}
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("k%02d", i)] = "v"
		}
		return m
	}
	cases := []struct {
		name string
		m    map[string]string
		ok   bool
	}{
		{"32 entries", many(32), true},
		{"33 entries", many(33), false},
		{"good", map[string]string{"env": "staging", "build_id": "42"}, true},
		{"empty value", map[string]string{"env": ""}, true},
		{"leading space", map[string]string{"env": " x"}, false},
		{"trailing space", map[string]string{"env": "x "}, false},
		{"tab", map[string]string{"env": "a\tb"}, false},
		{"non-ascii", map[string]string{"env": "é"}, false},
		{"hyphen key", map[string]string{"bad-hyphen": "v"}, false},
		{"digit key", map[string]string{"1digit": "v"}, false},
		{"upper key", map[string]string{"Env": "v"}, false},
		{"2048 bytes", map[string]string{"k": strings.Repeat("v", 2047)}, true},
		{"2049 bytes", map[string]string{"k": strings.Repeat("v", 2048)}, false},
	}
	for _, c := range cases {
		if got := Metadata(c.m) == nil; got != c.ok {
			t.Errorf("%s: ok=%v want %v", c.name, got, c.ok)
		}
	}
}

func TestBoundsAndReceipt(t *testing.T) {
	if n, e := ListMax(0); e != nil || n != 1000 {
		t.Fatal("0 -> 1000")
	}
	for _, bad := range []int64{-1, 1001} {
		if _, e := ListMax(bad); e == nil {
			t.Fatalf("max_keys %d accepted", bad)
		}
	}
	type rc struct{ max, wait, vis int64 }
	for _, c := range []rc{{1, 0, 0}, {10, 20, 600}} {
		if ReceiveArgs(c.max, c.wait, c.vis) != nil {
			t.Fatalf("%v rejected", c)
		}
	}
	for _, c := range []rc{{0, 0, 0}, {11, 0, 0}, {1, -1, 0}, {1, 21, 0}, {1, 0, -1}, {1, 0, 601}} {
		if ReceiveArgs(c.max, c.wait, c.vis) == nil {
			t.Fatalf("%v accepted", c)
		}
	}
	if Receipt("") == nil {
		t.Fatal("empty receipt must fail preflight")
	}
	// Sol finding 9: only the empty receipt is preflighted; the provider judges the rest.
	for _, r := range []string{" ", "\n", "x\x00y"} {
		if Receipt(r) != nil {
			t.Fatalf("non-empty receipt %q must not fail preflight", r)
		}
	}
	if ObjectSize(MaxObjectBytes) != nil || ObjectSize(MaxObjectBytes+1) == nil {
		t.Fatal("16 MiB boundary")
	}
	if QueueBodySize(49152) != nil || QueueBodySize(49153) == nil {
		t.Fatal("48 KiB boundary")
	}
}

func TestEscapeKey(t *testing.T) {
	cases := map[string][2]string{
		"a b+c%d?e#f": {"a%20b%2Bc%25d%3Fe%23f", "a%20b%2Bc%25d%3Fe%23f"},
		"dir/雪.txt":   {"dir/%E9%9B%AA.txt", "dir%2F%E9%9B%AA.txt"},
		"A-Z_a.z~0":   {"A-Z_a.z~0", "A-Z_a.z~0"},
	}
	for in, want := range cases {
		if got := EscapeKeyPath(in); got != want[0] {
			t.Errorf("EscapeKeyPath(%q) = %q want %q", in, got, want[0])
		}
		if got := EscapeKeyWhole(in); got != want[1] {
			t.Errorf("EscapeKeyWhole(%q) = %q want %q", in, got, want[1])
		}
	}
}

// Sol finding 4: a 33,562,624-byte response is rejected, never truncated.
func TestReadBoundedRejectsOversize(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, 33_562_624)
	data, e := ReadBounded(bytes.NewReader(body), MaxObjectBytes)
	if e == nil || data != nil || e.Code != Internal {
		t.Fatalf("oversized body accepted: len=%d err=%v", len(data), e)
	}
	exact := bytes.Repeat([]byte{'y'}, MaxObjectBytes)
	data, e = ReadBounded(bytes.NewReader(exact), MaxObjectBytes)
	if e != nil || len(data) != MaxObjectBytes {
		t.Fatalf("exact limit: len=%d err=%v", len(data), e)
	}
	if _, e := ReadBounded(bytes.NewReader(append(exact, 'z')), MaxObjectBytes); e == nil {
		t.Fatal("limit+1 accepted")
	}
}
