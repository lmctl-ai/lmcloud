// SPDX-License-Identifier: MIT

package hostkit

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// Canonical queue wire encoding (design 07 §4.2).
const (
	ReservedPrefix = "__lmcloud_"
	EmptySentinel  = "__lmcloud_empty__"
	EscapePrefix   = "__lmcloud_esc__:"
	Base64Prefix   = "__lmcloud_b64__:"
)

// TextSafe reports whether s can travel as a JSON/XML text value: valid UTF-8
// without control bytes other than tab, LF and CR, and without U+FFFE/U+FFFF.
func TextSafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
		case r < 0x20 || r == 0x7f:
			return false
		case r == 0xFFFE || r == 0xFFFF:
			return false
		}
	}
	return true
}

// EncodeQueueBody maps a raw body to its wire form:
//  1. "" becomes EmptySentinel;
//  2. any body starting with "__lmcloud_" becomes EscapePrefix+body;
//  3. when textOnly is set (the transport carries text, not bytes) and the
//     result is not TextSafe, it becomes Base64Prefix+base64(result).
//
// The wire form is never empty. Transports that base64 the whole message
// themselves pass textOnly=false.
func EncodeQueueBody(body string, textOnly bool) string {
	if body == "" {
		return EmptySentinel
	}
	w := body
	if strings.HasPrefix(body, ReservedPrefix) {
		w = EscapePrefix + body
	}
	if textOnly && !TextSafe(w) {
		return Base64Prefix + base64.StdEncoding.EncodeToString([]byte(w))
	}
	return w
}

// DecodeQueueBody inverts EncodeQueueBody. A wire value that starts with the
// reserved prefix but none of the known forms was not produced by an lmcloud
// host and is returned unchanged.
func DecodeQueueBody(wire string) (string, *CloudError) {
	if strings.HasPrefix(wire, Base64Prefix) {
		raw, err := base64.StdEncoding.DecodeString(wire[len(Base64Prefix):])
		if err != nil {
			return "", ProviderError(Internal, 0, "", "queue message has a malformed base64 envelope")
		}
		inner := string(raw)
		if strings.HasPrefix(inner, EscapePrefix) {
			return inner[len(EscapePrefix):], nil
		}
		return inner, nil
	}
	if wire == EmptySentinel {
		return "", nil
	}
	if strings.HasPrefix(wire, EscapePrefix) {
		return wire[len(EscapePrefix):], nil
	}
	return wire, nil
}
