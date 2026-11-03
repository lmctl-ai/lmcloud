// SPDX-License-Identifier: MIT

package hostkit

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Portable limits (design 02 §4/§7, 07 §4).
const (
	MaxObjectBytes               = 16 << 20 // 16,777,216
	MaxQueueBodyBytes            = 49152
	MaxProviderQueueMessageBytes = 1 << 20 // 1,048,576 (conservative provider per-message wire ceiling, e.g. AWS SQS 1 MiB = 16 x 64 KiB chunks)
	MaxKeyBytes                  = 1024
	MaxContentTypeBytes   = 255
	MaxMetadataEntries    = 32
	MaxMetadataBytes      = 2048
	DefaultListMax        = 1000
	MaxListMax            = 1000
	MaxReceiveMessages    = 10
	MaxWaitSeconds        = 20
	MaxVisibilitySeconds  = 600
	DefaultReceiveMax     = 1
	DefaultReceiveWait    = 0
	DefaultReceiveVisible = 30
)

var (
	bucketPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	queuePattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,61}[a-z0-9]$`)
	metaKeyPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	bucketBadPrefix = []string{"xn--", "sthree-", "amzn-s3-demo-", "goog"}
	bucketBadSuffix = []string{"-s3alias", "--ol-s3"}
	reservedInfix   = []string{"google", "g00gle"}
)

// Rule is a pluggable name rule; it returns a rejection reason or "".
type Rule func(name string) string

// Validator applies the portable rules plus optional extra rule sets (for
// example names a specific provider additionally reserves). Extra rules can
// only narrow the portable set, never widen it.
type Validator struct {
	BucketRules []Rule
	QueueRules  []Rule
	KeyRules    []Rule
}

func applyRules(kind, name string, rules []Rule) *CloudError {
	for _, r := range rules {
		if reason := r(name); reason != "" {
			return Preflightf("invalid %s name %q: %s", kind, name, reason)
		}
	}
	return nil
}

// Bucket validates a bucket name.
func (v *Validator) Bucket(name string) *CloudError {
	if !bucketPattern.MatchString(name) {
		return Preflightf("invalid bucket name %q: must be 3-63 chars of [a-z0-9-], starting and ending with [a-z0-9]", name)
	}
	if strings.Contains(name, "--") {
		return Preflightf("invalid bucket name %q: consecutive hyphens", name)
	}
	for _, p := range bucketBadPrefix {
		if strings.HasPrefix(name, p) {
			return Preflightf("invalid bucket name %q: reserved prefix %q", name, p)
		}
	}
	for _, s := range bucketBadSuffix {
		if strings.HasSuffix(name, s) {
			return Preflightf("invalid bucket name %q: reserved suffix %q", name, s)
		}
	}
	for _, s := range reservedInfix {
		if strings.Contains(name, s) {
			return Preflightf("invalid bucket name %q: reserved string %q", name, s)
		}
	}
	if v != nil {
		return applyRules("bucket", name, v.BucketRules)
	}
	return nil
}

// Queue validates a queue name.
func (v *Validator) Queue(name string) *CloudError {
	if !queuePattern.MatchString(name) {
		return Preflightf("invalid queue name %q: must be 3-63 chars of [a-z0-9-], start with [a-z] and end with [a-z0-9]", name)
	}
	if strings.Contains(name, "--") {
		return Preflightf("invalid queue name %q: consecutive hyphens", name)
	}
	if strings.HasPrefix(name, "goog") {
		return Preflightf("invalid queue name %q: reserved prefix \"goog\"", name)
	}
	for _, s := range reservedInfix {
		if strings.Contains(name, s) {
			return Preflightf("invalid queue name %q: reserved string %q", name, s)
		}
	}
	if v != nil {
		return applyRules("queue", name, v.QueueRules)
	}
	return nil
}

// Key validates an object key.
func (v *Validator) Key(key string) *CloudError {
	switch {
	case len(key) == 0 || len(key) > MaxKeyBytes:
		return Preflightf("object key must be 1..%d bytes", MaxKeyBytes)
	case !utf8.ValidString(key):
		return Preflightf("object key must be valid UTF-8")
	case strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/"):
		return Preflightf("object key must not start or end with '/'")
	case strings.Contains(key, "//"):
		return Preflightf("object key must not contain empty segments")
	case strings.Contains(key, `\`):
		return Preflightf("object key must not contain backslash")
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c < 0x20 || c == 0x7f {
			return Preflightf("object key must not contain control characters")
		}
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "." || seg == ".." || strings.HasSuffix(seg, ".") {
			return Preflightf("object key segments must not be '.' or '..' or end with '.'")
		}
	}
	if v != nil {
		return applyRules("object key", key, v.KeyRules)
	}
	return nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ContentType validates a content type: 1..255 printable ASCII bytes with non-empty type/subtype.
func ContentType(ct string) *CloudError {
	if len(ct) == 0 || len(ct) > MaxContentTypeBytes {
		return Preflightf("content_type must be 1..%d bytes", MaxContentTypeBytes)
	}
	if !printableASCII(ct) {
		return Preflightf("content_type must be printable ASCII")
	}
	slash := strings.IndexByte(ct, '/')
	if slash <= 0 || strings.TrimSpace(ct[:slash]) == "" || strings.TrimSpace(ct[slash+1:]) == "" {
		return Preflightf("content_type must have the form type/subtype")
	}
	return nil
}

// Metadata validates user metadata: <=32 entries, key pattern, printable ASCII
// values without leading/trailing whitespace, sum(len(k)+len(v)) <= 2048.
func Metadata(m map[string]string) *CloudError {
	if len(m) > MaxMetadataEntries {
		return Preflightf("metadata has %d entries; at most %d allowed", len(m), MaxMetadataEntries)
	}
	total := 0
	for k, v := range m {
		if !metaKeyPattern.MatchString(k) {
			return Preflightf("invalid metadata key %q: must match ^[a-z][a-z0-9_]{0,62}$", k)
		}
		if !printableASCII(v) {
			return Preflightf("metadata value for %q must be printable ASCII", k)
		}
		if strings.TrimSpace(v) != v {
			return Preflightf("metadata value for %q must not have leading or trailing whitespace", k)
		}
		total += len(k) + len(v)
	}
	if total > MaxMetadataBytes {
		return Preflightf("metadata is %d bytes; at most %d allowed", total, MaxMetadataBytes)
	}
	return nil
}

// ObjectSize enforces the 16 MiB object ceiling.
func ObjectSize(n int) *CloudError {
	if n > MaxObjectBytes {
		return Preflightf("object body is %d bytes; at most %d allowed", n, MaxObjectBytes)
	}
	return nil
}

// QueueBodySize enforces the 48 KiB raw queue payload ceiling.
func QueueBodySize(n int) *CloudError {
	if n > MaxQueueBodyBytes {
		return Preflightf("queue message body is %d bytes; at most %d allowed", n, MaxQueueBodyBytes)
	}
	return nil
}

// ListMax normalizes max_keys: 0 means the default 1000; 1..1000 allowed.
func ListMax(maxKeys int64) (int, *CloudError) {
	if maxKeys == 0 {
		return DefaultListMax, nil
	}
	if maxKeys < 0 || maxKeys > MaxListMax {
		return 0, Preflightf("max_keys must be 0..%d", MaxListMax)
	}
	return int(maxKeys), nil
}

// ReceiveArgs validates queue_receive bounds.
func ReceiveArgs(maxMessages, waitSeconds, visibility int64) *CloudError {
	if maxMessages < 1 || maxMessages > MaxReceiveMessages {
		return Preflightf("max_messages must be 1..%d", MaxReceiveMessages)
	}
	if waitSeconds < 0 || waitSeconds > MaxWaitSeconds {
		return Preflightf("wait_seconds must be 0..%d", MaxWaitSeconds)
	}
	return Visibility(visibility)
}

// Visibility validates a visibility timeout.
func Visibility(v int64) *CloudError {
	if v < 0 || v > MaxVisibilitySeconds {
		return Preflightf("visibility_timeout must be 0..%d", MaxVisibilitySeconds)
	}
	return nil
}

// Receipt preflights only the empty receipt; every other receipt is judged by
// the provider after the queue is resolved (missing queue wins, design 07 §5.4).
func Receipt(r string) *CloudError {
	if r == "" {
		return Preflightf("receipt must not be empty")
	}
	return nil
}

const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// EscapeSegment percent-encodes every byte outside RFC 3986 unreserved as %XX (uppercase).
func EscapeSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte("0123456789ABCDEF"[c>>4])
		b.WriteByte("0123456789ABCDEF"[c&15])
	}
	return b.String()
}

// EscapeKeyPath encodes each '/'-separated segment and keeps the separators.
func EscapeKeyPath(key string) string {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = EscapeSegment(s)
	}
	return strings.Join(segs, "/")
}

// EscapeKeyWhole encodes the whole key as one segment ('/' becomes %2F).
func EscapeKeyWhole(key string) string { return EscapeSegment(key) }

// ReadBounded reads at most limit bytes and fails (never truncates) when the
// stream holds more. The returned error is INTERNAL with the observed bound.
//
// Typed-nil footgun: the result is *CloudError. In a function that returns
// error, `data, e := ReadBounded(...); return data, e` returns a NON-nil error
// on success. Use ReadBoundedErr there, or `if e != nil { return nil, e }`.
func ReadBounded(r io.Reader, limit int64) ([]byte, *CloudError) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, ProviderError(Internal, 0, "", "reading response body: "+err.Error())
	}
	if int64(len(data)) > limit {
		return nil, ProviderError(Internal, 0, "", "response body exceeds the "+itoa(limit)+"-byte limit; refusing to truncate")
	}
	return data, nil
}

// ReadBoundedResponse is ReadBounded for an HTTP response: any error carries
// resp.StatusCode as its http_status. It does not close the body.
func ReadBoundedResponse(resp *http.Response, limit int64) ([]byte, *CloudError) {
	data, e := ReadBounded(resp.Body, limit)
	if e != nil {
		e.HTTPStatus = resp.StatusCode
	}
	return data, e
}

// ReadBoundedErr is ReadBounded with a plain error result: nil on success,
// never a typed-nil *CloudError. Prefer it in adapter methods that return
// error, so `return data, err` cannot hit the typed-nil trap (v3).
func ReadBoundedErr(r io.Reader, limit int64) ([]byte, error) {
	data, e := ReadBounded(r, limit)
	if e != nil {
		return nil, e
	}
	return data, nil
}

// ReadBoundedResponseErr is ReadBoundedResponse with a plain error result.
func ReadBoundedResponseErr(resp *http.Response, limit int64) ([]byte, error) {
	data, e := ReadBoundedResponse(resp, limit)
	if e != nil {
		return nil, e
	}
	return data, nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
