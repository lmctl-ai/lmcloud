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
	// tokenPattern matches the create-token format (128 bits as 32 hex digits,
	// see cloudhost newCreateToken). Any such string in diagnostic text is
	// replaced, because providers echo creation markers in error messages.
	// Side effect: other 32-hex values in error text (e.g. an MD5-style ETag or
	// a request id of that shape) are also replaced; that text is diagnostic only.
	tokenPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{32}\b`)
)

// CreateTokenMarker replaces create tokens in every diagnostic string.
const CreateTokenMarker = "[create-token]"

// RedactCreateTokens replaces every create-token-shaped string in s.
func RedactCreateTokens(s string) string {
	if s == "" {
		return s
	}
	return tokenPattern.ReplaceAllString(s, CreateTokenMarker)
}

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
	return RedactCreateTokens(u.String())
}

// RedactText redacts URLs, credential assignments, auth header values and
// create tokens (v4) in free text. Every CloudError constructor, FormatAbort
// and ErrorState.Fail run it, so it is the central redaction point.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	s = urlPattern.ReplaceAllStringFunc(s, RedactURL)
	s = headerPattern.ReplaceAllString(s, "${1}${2}<redacted>")
	s = secretPattern.ReplaceAllString(s, "${1}${2}<redacted>")
	s = bearerPattern.ReplaceAllString(s, "${1} <redacted>")
	return RedactCreateTokens(s)
}

// RedactTarget redacts an operation target (bucket/key, queue name, or URL).
func RedactTarget(target string) string {
	if strings.Contains(target, "://") {
		return RedactURL(target)
	}
	return RedactText(target)
}
