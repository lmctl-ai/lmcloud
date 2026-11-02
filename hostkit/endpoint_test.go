// SPDX-License-Identifier: MIT

package hostkit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateEndpoint(t *testing.T) {
	cases := []struct {
		raw  string
		want string // "" = rejected
	}{
		{"http://127.0.0.1:4566", "http://127.0.0.1:4566"},
		{"http://127.0.0.1:4566/", "http://127.0.0.1:4566"},
		{"http://127.9.8.7:1", "http://127.9.8.7:1"},
		{"http://localhost:4577", "http://localhost:4577"},
		{"http://LOCALHOST:4577", "http://LOCALHOST:4577"},
		{"http://[::1]:4588", "http://[::1]:4588"},
		{"HTTPS://storage.example.com", "https://storage.example.com"},
		{"https://objectstorage.example.com/n/ns", "https://objectstorage.example.com/n/ns"},
		{"http://0.0.0.0:4599", ""},  // Sol finding 2
		{"https://0.0.0.0:4599", ""}, // unspecified is never a destination
		{"http://[::]:4599", ""},
		{"http://127.0.0.1.evil.example:4566", ""},
		{"http://localhost.evil.example", ""},
		{"http://10.0.0.5:4566", ""},
		{"http://example.com", ""},
		{"http://user:secret@127.0.0.1:4566", ""},
		{"https://user@example.com", ""},
		{"https://example.com/?sig=abc", ""},
		{"https://example.com/#frag", ""},
		{"https://example.com?", ""},
		{"ftp://example.com", ""},
		{"127.0.0.1:4566", ""},
		{"", ""},
		{" http://127.0.0.1:1", ""},
		{"http://127.0.0.1:99999", ""},
		{"http:///path", ""},
	}
	for _, c := range cases {
		got, e := ValidateEndpoint(c.raw)
		if c.want == "" {
			if e == nil || e.Code != InvalidArgument || e.HTTPStatus != 0 {
				t.Errorf("ValidateEndpoint(%q) = %q, %v; want INVALID_ARGUMENT", c.raw, got, e)
			}
			if e != nil && strings.Contains(e.Message, "secret") {
				t.Errorf("message leaks secret: %s", e.Message)
			}
			continue
		}
		if e != nil || got != c.want {
			t.Errorf("ValidateEndpoint(%q) = %q, %v; want %q", c.raw, got, e, c.want)
		}
	}
}

func TestValidateService(t *testing.T) {
	for _, s := range Services {
		if ValidateService(s, false) != nil {
			t.Fatalf("%s rejected", s)
		}
	}
	if ValidateService("all", true) != nil || ValidateService("all", false) == nil {
		t.Fatal("all only valid for set_endpoint")
	}
	for _, bad := range []string{"", "s3", "STORAGE", "objectstorage", "unknown_service"} {
		if ValidateService(bad, true) == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestEndpointPrecedence(t *testing.T) {
	native := map[string][]NativeEnv{
		"storage": {{Name: "NATIVE_STORAGE_URL"}, {Name: "NATIVE_URL"}},
		"queue":   {{Name: "NATIVE_QUEUE_HOST", BareHostPort: true}},
	}
	full := map[string]string{
		"LMCLOUD_STORAGE_ENDPOINT": "http://127.0.0.1:1",
		"LMX_STORAGE_ENDPOINT":     "http://127.0.0.1:2",
		"LMCLOUD_ENDPOINT":         "http://127.0.0.1:3",
		"LMX_ENDPOINT":             "http://127.0.0.1:4",
		"NATIVE_STORAGE_URL":       "http://127.0.0.1:5",
		"NATIVE_URL":               "http://127.0.0.1:6",
	}
	order := []string{"LMCLOUD_STORAGE_ENDPOINT", "LMX_STORAGE_ENDPOINT", "LMCLOUD_ENDPOINT", "LMX_ENDPOINT", "NATIVE_STORAGE_URL", "NATIVE_URL"}
	env := map[string]string{}
	for k, v := range full {
		env[k] = v
	}
	r := &EndpointResolver{Prefix: "LMX", Native: native, Default: map[string]string{"storage": "https://default.example"}, Getenv: envMap(env)}
	for _, name := range order {
		got, src, e := r.Resolve("storage")
		if e != nil || src != name || got != full[name] {
			t.Fatalf("want %s=%s, got %s=%s (%v)", name, full[name], src, got, e)
		}
		delete(env, name)
	}
	if got, src, _ := r.Resolve("storage"); got != "https://default.example" || src != "default" {
		t.Fatalf("default: %s %s", src, got)
	}
	if e := r.Set("all", "http://127.0.0.1:7"); e != nil {
		t.Fatal(e)
	}
	if got, src, _ := r.Resolve("storage"); got != "http://127.0.0.1:7" || src != "set_endpoint(all)" {
		t.Fatalf("all: %s %s", src, got)
	}
	if e := r.Set("storage", "http://127.0.0.1:8"); e != nil {
		t.Fatal(e)
	}
	if got, _, _ := r.Resolve("storage"); got != "http://127.0.0.1:8" {
		t.Fatalf("explicit service beats all: %s", got)
	}
	if got, _, _ := r.Resolve("queue"); got != "http://127.0.0.1:7" {
		t.Fatalf("queue falls back to all: %s", got)
	}
	r2 := &EndpointResolver{Native: native, Getenv: envMap(map[string]string{"NATIVE_QUEUE_HOST": "localhost:8085"})}
	if got, _, e := r2.Resolve("queue"); e != nil || got != "http://localhost:8085" {
		t.Fatalf("bare host:port: %q %v", got, e)
	}
}

// Sol finding 2: env/default sources are validated, not only set_endpoint.
func TestEndpointEnvSourcesAreValidated(t *testing.T) {
	for _, bad := range []string{"http://0.0.0.0:4599", "http://example.com", "http://u:pw@127.0.0.1:1", "https://h.example/?token=abc"} {
		r := &EndpointResolver{Prefix: "LMX", Getenv: envMap(map[string]string{"LMX_ENDPOINT": bad})}
		_, src, e := r.Resolve("storage")
		if e == nil || e.Code != InvalidArgument || src != "LMX_ENDPOINT" {
			t.Fatalf("%q from env: src=%s err=%v", bad, src, e)
		}
		if strings.Contains(e.Message, "pw") || strings.Contains(e.Message, "abc") {
			t.Fatalf("error leaks the value: %s", e.Message)
		}
	}
	r := &EndpointResolver{Default: map[string]string{"storage": "http://0.0.0.0:1"}, Getenv: envMap(nil)}
	if _, _, e := r.Resolve("storage"); e == nil {
		t.Fatal("unsafe default accepted")
	}
	if e := r.Set("storage", "http://0.0.0.0:1"); e == nil {
		t.Fatal("unsafe explicit endpoint accepted")
	}
	if e := r.Set("bogus", "http://127.0.0.1:1"); e == nil {
		t.Fatal("unknown service accepted")
	}
}

func TestRedaction(t *testing.T) {
	cases := map[string]string{
		"http://user:pw@127.0.0.1:1/p?sig=x#f":                    "http://127.0.0.1:1/p?redacted",
		"failed GET https://h.example/b?X-Amz-Signature=deadbeef": "failed GET https://h.example/b?redacted",
		"Authorization: Bearer abcdefghijklmnop":                  "Authorization: <redacted>",
		"token=abc123 and password=hunter2":                       "token=<redacted> and password=<redacted>",
		"bucket lmcloud-c01 not found":                            "bucket lmcloud-c01 not found",
	}
	for in, want := range cases {
		if got := RedactText(in); got != want {
			t.Errorf("RedactText(%q) = %q, want %q", in, got, want)
		}
	}
	if RedactURL("::not a url") != "<redacted-url>" {
		t.Fatal("unparseable URL must be fully redacted")
	}
	r := &EndpointResolver{Getenv: envMap(nil)}
	if e := r.Set("storage", "https://store.example/base"); e != nil {
		t.Fatal(e)
	}
	if got, _ := r.Display("storage"); got != "https://store.example/base" {
		t.Fatalf("display = %s", got)
	}
}

func TestSameOriginRedirects(t *testing.T) {
	var sawAuth string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cross":
			http.Redirect(w, r, other.URL+"/x", http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		default:
			w.WriteHeader(200)
		}
	}))
	defer origin.Close()
	client := NewHTTPClient(0)
	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/cross", nil)
	req.Header.Set("Authorization", "Signature secret")
	if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), ErrCrossOriginRedirect.Error()) {
		t.Fatalf("cross-origin redirect followed: %v", err)
	}
	if sawAuth != "" {
		t.Fatal("credentials reached another origin")
	}
	resp, err := client.Get(origin.URL + "/same")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("same-origin redirect: %v", err)
	}
	resp.Body.Close()
}
