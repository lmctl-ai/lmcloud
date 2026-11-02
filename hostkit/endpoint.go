// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Services are the per-service endpoint selectors of design 02 §2.1.
var Services = []string{"storage", "queue", "tables", "vm", "container", "lambda", "valkey", "userpool", "permissions", "cost"}

// AllServices is the wildcard selector accepted by set_endpoint.
const AllServices = "all"

// ValidateService accepts a known service; "all" only when allowAll is set.
func ValidateService(service string, allowAll bool) *CloudError {
	if allowAll && service == AllServices {
		return nil
	}
	for _, s := range Services {
		if service == s {
			return nil
		}
	}
	return Preflightf("unknown service %q", service)
}

// IsLoopbackHost reports whether host (no port) is loopback: localhost, 127.0.0.0/8 or ::1.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ValidateEndpoint enforces the endpoint policy for every source (explicit
// call, environment, CLI or built-in default) and returns the normalized URL.
// http is allowed only for loopback hosts; unspecified addresses (0.0.0.0, ::)
// are always rejected; userinfo, query and fragment are rejected.
func ValidateEndpoint(raw string) (string, *CloudError) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return "", Preflightf("endpoint must be a non-empty URL without surrounding whitespace")
	}
	if strings.ContainsAny(raw, "\x00\r\n\t ") {
		return "", Preflightf("endpoint contains control characters or spaces")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", Preflightf("endpoint is not a valid URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", Preflightf("endpoint scheme must be http or https")
	}
	if u.User != nil {
		return "", Preflightf("endpoint must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.Contains(raw, "#") {
		return "", Preflightf("endpoint must not contain a query or fragment")
	}
	host := u.Hostname()
	if host == "" || u.Opaque != "" {
		return "", Preflightf("endpoint must include a host")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return "", Preflightf("endpoint host %s is an unspecified address", host)
	}
	if port := u.Port(); port != "" {
		var p int
		if _, err := fmt.Sscanf(port, "%d", &p); err != nil || p <= 0 || p > 65535 {
			return "", Preflightf("endpoint port is invalid")
		}
	}
	if scheme == "http" && !IsLoopbackHost(host) {
		return "", Preflightf("plain http endpoint is allowed only for loopback hosts (got %s)", host)
	}
	u.Scheme = scheme
	out := u.String()
	return strings.TrimRight(out, "/"), nil
}

// NativeEnv names one provider-native environment variable. BareHostPort marks
// variables that hold "host:port" without a scheme; they are read as http://.
type NativeEnv struct {
	Name         string
	BareHostPort bool
}

// EndpointResolver implements the canonical precedence of design 02 §3.3:
//  1. set_endpoint(service) then set_endpoint("all")
//  2. LMCLOUD_<SERVICE>_ENDPOINT then <PREFIX>_<SERVICE>_ENDPOINT
//  3. LMCLOUD_ENDPOINT then <PREFIX>_ENDPOINT
//  4. provider-native service then global variables (Native)
//  5. Default (live endpoint; "" lets the adapter use its regional default)
//
// Every source is validated with ValidateEndpoint; an invalid environment value
// is an INVALID_ARGUMENT error naming the variable, never silently skipped.
type EndpointResolver struct {
	// Prefix is the host environment prefix, e.g. "LMXYZ" (no trailing underscore).
	Prefix string
	// Native lists provider-native variables per service, most specific first.
	Native map[string][]NativeEnv
	// Default is the built-in endpoint per service (validated too).
	Default map[string]string
	// Getenv defaults to os.Getenv.
	Getenv func(string) string

	mu       sync.Mutex
	explicit map[string]string
}

// Set validates and stores an explicit override for service or "all".
func (r *EndpointResolver) Set(service, raw string) *CloudError {
	if e := ValidateService(service, true); e != nil {
		return e
	}
	norm, e := ValidateEndpoint(raw)
	if e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.explicit == nil {
		r.explicit = map[string]string{}
	}
	r.explicit[service] = norm
	return nil
}

// Resolve returns the effective endpoint for service and the name of its source.
func (r *EndpointResolver) Resolve(service string) (string, string, *CloudError) {
	if e := ValidateService(service, false); e != nil {
		return "", "", e
	}
	r.mu.Lock()
	explicitSvc, explicitAll := r.explicit[service], r.explicit[AllServices]
	r.mu.Unlock()
	if explicitSvc != "" {
		return explicitSvc, "set_endpoint(" + service + ")", nil
	}
	if explicitAll != "" {
		return explicitAll, "set_endpoint(all)", nil
	}
	getenv := r.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	svc := strings.ToUpper(service)
	candidates := []NativeEnv{{Name: "LMCLOUD_" + svc + "_ENDPOINT"}}
	if r.Prefix != "" {
		candidates = append(candidates, NativeEnv{Name: r.Prefix + "_" + svc + "_ENDPOINT"})
	}
	candidates = append(candidates, NativeEnv{Name: "LMCLOUD_ENDPOINT"})
	if r.Prefix != "" {
		candidates = append(candidates, NativeEnv{Name: r.Prefix + "_ENDPOINT"})
	}
	candidates = append(candidates, r.Native[service]...)
	for _, c := range candidates {
		v := getenv(c.Name)
		if v == "" {
			continue
		}
		if c.BareHostPort && !strings.Contains(v, "://") {
			v = "http://" + v
		}
		norm, e := ValidateEndpoint(v)
		if e != nil {
			return "", c.Name, Preflightf("environment variable %s: %s", c.Name, e.Message)
		}
		return norm, c.Name, nil
	}
	if d := r.Default[service]; d != "" {
		norm, e := ValidateEndpoint(d)
		if e != nil {
			return "", "default", Preflightf("built-in default endpoint for %s: %s", service, e.Message)
		}
		return norm, "default", nil
	}
	return "", "default", nil
}

// Display returns the redacted effective endpoint for cloud.endpoint(service).
func (r *EndpointResolver) Display(service string) (string, *CloudError) {
	ep, _, e := r.Resolve(service)
	if e != nil {
		return "", e
	}
	return RedactURL(ep), nil
}

type endpointKey struct{}

// WithEndpoint attaches the resolved endpoint ("" = live default) to ctx for adapters.
func WithEndpoint(ctx context.Context, endpoint string) context.Context {
	return context.WithValue(ctx, endpointKey{}, endpoint)
}

// EndpointFrom returns the endpoint attached by the host ("" = live default).
func EndpointFrom(ctx context.Context) string {
	v, _ := ctx.Value(endpointKey{}).(string)
	return v
}

// ErrCrossOriginRedirect is returned by SameOriginRedirects.
var ErrCrossOriginRedirect = errors.New("redirect to a different origin refused")

// SameOriginRedirects allows at most maxHops redirects and only to the same
// scheme://host:port; cross-origin and https->http redirects are refused, so
// credentials are never forwarded to another origin.
func SameOriginRedirects(maxHops int) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if len(via) > maxHops {
			return fmt.Errorf("stopped after %d redirects", maxHops)
		}
		first := via[0].URL
		if !strings.EqualFold(req.URL.Scheme, first.Scheme) || !strings.EqualFold(req.URL.Host, first.Host) {
			return ErrCrossOriginRedirect
		}
		return nil
	}
}

// NewHTTPClient returns a client with no proxy from the environment, a total
// timeout and the same-origin redirect policy.
func NewHTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: SameOriginRedirects(3)}
}
