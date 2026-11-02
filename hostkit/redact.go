// SPDX-License-Identifier: MIT

package hostkit

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	urlPattern    = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>()]+`)
	headerPattern = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization)(\s*[=:]\s*)[^\r\n,;&]*`)
	secretPattern = regexp.MustCompile(`(?i)\b(x-amz-signature|x-amz-credential|x-amz-security-token|x-ms-sas|sas|sig|signature|access_token|token|secret|password|passwd|credential|private_key|api_key|apikey)(\s*[=:]\s*)("[^"]*"|[^\s,&;]+)`)
	bearerPattern = regexp.MustCompile(`(?i)\b(bearer|basic|signature)\s+[A-Za-z0-9._~+/=:,"-]{8,}`)
)

// RedactURL removes userinfo, query and fragment from a URL. Unparseable
// input is replaced entirely, so a malformed secret-bearing value never leaks.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "<redacted-url>"
	}
	u.User = nil
	if u.RawQuery != "" || u.ForceQuery {
		u.RawQuery = "redacted"
		u.ForceQuery = false
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// RedactText redacts URLs, credential assignments and auth header values in free text.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	s = urlPattern.ReplaceAllStringFunc(s, RedactURL)
	s = headerPattern.ReplaceAllString(s, "${1}${2}<redacted>")
	s = secretPattern.ReplaceAllString(s, "${1}${2}<redacted>")
	s = bearerPattern.ReplaceAllString(s, "${1} <redacted>")
	return s
}

// RedactTarget redacts an operation target (bucket/key, queue name, or URL).
func RedactTarget(target string) string {
	if strings.Contains(target, "://") {
		return RedactURL(target)
	}
	return RedactText(target)
}
