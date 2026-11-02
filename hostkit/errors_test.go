// SPDX-License-Identifier: MIT

package hostkit

import (
	"errors"
	"strings"
	"testing"
)

func TestCodesAreExactlyTheSchemaEnum(t *testing.T) {
	want := []string{"OK", "INVALID_ARGUMENT", "NOT_FOUND", "CONFLICT", "PRECONDITION_FAILED", "UNAUTHENTICATED", "PERMISSION_DENIED", "INTERNAL"}
	if len(Codes) != len(want) {
		t.Fatalf("codes = %v", Codes)
	}
	for i, c := range Codes {
		if string(c) != want[i] || !c.Valid() {
			t.Fatalf("code %d = %q", i, c)
		}
	}
	for _, bad := range []Code{"UNAVAILABLE", "RATE_LIMITED", "ALREADY_EXISTS", ""} {
		if bad.Valid() {
			t.Fatalf("%q must not be a schema code", bad)
		}
		if got := ProviderError(bad, 503, "x", "m").Code; got != Internal {
			t.Fatalf("ProviderError(%q) code = %q, want INTERNAL", bad, got)
		}
	}
}

func TestCodeForStatus(t *testing.T) {
	cases := map[int]Code{200: OK, 204: OK, 400: InvalidArgument, 401: Unauthenticated, 403: PermissionDenied, 404: NotFound, 409: Conflict, 412: PreconditionFailed, 429: Internal, 500: Internal, 502: Internal, 503: Internal, 504: Internal, 418: Internal}
	for status, want := range cases {
		if got := CodeForStatus(status); got != want {
			t.Errorf("CodeForStatus(%d) = %s, want %s", status, got, want)
		}
	}
}

func TestFormatAbort(t *testing.T) {
	cases := []struct {
		name, op, target string
		err              *CloudError
		want             string
	}{
		{"preflight", "bucket_create", "Bad_Bucket", Preflightf("invalid bucket name %q", "Bad_Bucket"), `[INVALID_ARGUMENT] bucket_create: invalid bucket name "Bad_Bucket"`},
		{"provider", "object_get", "my-bucket/missing.txt", ProviderError(NotFound, 404, "NoSuchKey", "object not found"), "[NOT_FOUND] object_get (my-bucket/missing.txt): object not found (http=404, provider_code=NoSuchKey)"},
		{"no provider code", "queue_send", "q1", ProviderError(Internal, 503, "", "service unavailable"), "[INTERNAL] queue_send (q1): service unavailable (http=503, provider_code=none)"},
		{"url target redacted", "set_endpoint", "http://user:hunter2@127.0.0.1:1/?sig=abc", ProviderError(Internal, 0, "", "boom"), "[INTERNAL] set_endpoint (http://127.0.0.1:1/?redacted): boom (http=0, provider_code=none)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FormatAbort(c.op, c.target, c.err); got != c.want {
				t.Fatalf("got  %s\nwant %s", got, c.want)
			}
			if strings.Contains(FormatAbort(c.op, c.target, c.err), "hunter2") {
				t.Fatal("secret leaked")
			}
		})
	}
	if e := Preflightf("x"); e.HTTPStatus != 0 || e.ProviderCode != "" {
		t.Fatalf("preflight must have http=0 and no provider code: %+v", e)
	}
}

func TestErrorStateAbortSemantics(t *testing.T) {
	s := NewErrorState()
	if !s.Abort() || s.Last().Code != OK {
		t.Fatal("default must be abort=true, last=OK")
	}
	err := s.Fail("bucket_exists", "b", ProviderError(PermissionDenied, 403, "AccessDenied", "denied"))
	var ae *AbortError
	if !errors.As(err, &ae) || !strings.HasPrefix(ae.Error(), "[PERMISSION_DENIED] bucket_exists (b): ") {
		t.Fatalf("abort error = %v", err)
	}
	if s.Last().Code != PermissionDenied {
		t.Fatal("last_error must be recorded")
	}
	s.SetAbort(false)
	if s.Last().Code != OK {
		t.Fatal("set_abort_on_error resets last_error")
	}
	if err := s.Fail("x", "y", ProviderError(NotFound, 404, "", "gone")); err != nil {
		t.Fatalf("non-abort mode must not return an error: %v", err)
	}
	if s.Last().Code != NotFound || s.Last().Absent != AbsentUnknown {
		t.Fatalf("last = %+v", s.Last())
	}
	s.Succeed()
	if s.Last().Code != OK {
		t.Fatal("succeed resets")
	}
}

func TestAsCloudError(t *testing.T) {
	if AsCloudError(nil) != nil {
		t.Fatal("nil stays nil")
	}
	e := AsCloudError(errors.New("dial tcp 10.0.0.1: token=abcdef secret"))
	if e.Code != Internal || strings.Contains(e.Message, "abcdef") {
		t.Fatalf("transport error = %+v", e)
	}
	wrapped := errors.Join(errors.New("ctx"), ProviderError(Conflict, 409, "X", "y"))
	if AsCloudError(wrapped).Code != Conflict {
		t.Fatal("wrapped CloudError must be preserved")
	}
	if AsCloudError(&CloudError{Code: "UNAVAILABLE"}).Code != Internal {
		t.Fatal("out-of-enum code must become INTERNAL")
	}
}
