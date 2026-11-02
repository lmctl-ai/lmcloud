// SPDX-License-Identifier: MIT

package hostkit

import (
	"regexp"
	"strings"
	"testing"
)

var hex32 = regexp.MustCompile(`(?i)[0-9a-f]{32}`)

const tok = "0123456789abcdef0123456789abcdef"

func TestRedactCreateTokensInText(t *testing.T) {
	cases := map[string]string{
		"bucket already exists for token " + tok:               "bucket already exists for token [create-token]",
		"tag lmcloud-create-token=" + tok + " rejected":        "tag lmcloud-create-token=<redacted> rejected",
		"code CreateDenied." + strings.ToUpper(tok):            "code CreateDenied.[create-token]",
		"see https://h.example/b/" + tok + "/x?sig=1":          "see https://h.example/b/[create-token]/x?redacted",
		"no token here: bucket lmcloud-c01-r0-alpha (etag 3f)": "no token here: bucket lmcloud-c01-r0-alpha (etag 3f)",
	}
	for in, want := range cases {
		if got := RedactText(in); got != want {
			t.Errorf("RedactText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := RedactTarget("https://h.example/" + tok); hex32.MatchString(got) {
		t.Fatalf("target leaked token: %s", got)
	}
}

func TestErrorStateRedactsExactSecretsEverywhere(t *testing.T) {
	s := NewErrorState()
	secret := "op-marker-Zz9-not-hex" // a non-hex exact secret: only AddRedaction can catch it
	s.AddRedaction(secret)
	s.AddRedaction("short") // ignored (<8 bytes)
	// Struct literal: bypasses the constructors' redaction on purpose.
	e := &CloudError{Code: PermissionDenied, HTTPStatus: 403, ProviderCode: "Denied." + secret + "." + tok, Message: "echo " + secret + " and " + tok}
	err := s.Fail("bucket_create", "bkt-"+secret, e)
	last := s.Last()
	for _, field := range []string{last.Message, last.ProviderCode, err.Error()} {
		if strings.Contains(field, secret) || hex32.MatchString(field) {
			t.Fatalf("secret leaked: %q", field)
		}
		if !strings.Contains(field, CreateTokenMarker) {
			t.Fatalf("marker missing: %q", field)
		}
	}
	if !strings.Contains(err.Error(), "(bkt-[create-token])") {
		t.Fatalf("target not redacted: %s", err.Error())
	}
	if !strings.Contains(s.scrubLocked("a short b"), "short") {
		t.Fatal("strings under 8 bytes must not be registered")
	}
	for i := 0; i < maxRedactions+10; i++ {
		s.AddRedaction(strings.Repeat("x", 8) + string(rune('a'+i%26)) + strings.Repeat("y", i))
	}
	if len(s.secrets) != maxRedactions {
		t.Fatalf("redaction list unbounded: %d", len(s.secrets))
	}
}

func TestConstructorsRedactTokens(t *testing.T) {
	e := ProviderError(Conflict, 409, "Taken."+tok, "exists with token "+tok)
	if hex32.MatchString(e.Message) || hex32.MatchString(e.ProviderCode) {
		t.Fatalf("ProviderError kept a token: %+v", e)
	}
	if p := Preflightf("bad %s", tok); hex32.MatchString(p.Message) {
		t.Fatalf("Preflightf kept a token: %s", p.Message)
	}
}
