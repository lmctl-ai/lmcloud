// SPDX-License-Identifier: MIT

// Package hostkit holds the provider-neutral logic shared by every lmcloud
// host: the error model, retry policy, endpoint policy, validation, payload
// codec, pagination and queue helpers, and the provider adapter interfaces.
// It imports no provider SDK and names no provider.
package hostkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// Code is the shared schema enum ErrorCode. Only these nine values exist;
// adapters must map every provider outcome onto one of them.
type Code string

const (
	OK                 Code = "OK"
	InvalidArgument    Code = "INVALID_ARGUMENT"
	NotFound           Code = "NOT_FOUND"
	Conflict           Code = "CONFLICT"
	PreconditionFailed Code = "PRECONDITION_FAILED"
	Unauthenticated    Code = "UNAUTHENTICATED"
	PermissionDenied   Code = "PERMISSION_DENIED"
	CostCapExceeded    Code = "COST_CAP_EXCEEDED"
	Internal           Code = "INTERNAL"
)

// Codes lists the schema enum in declaration order.
var Codes = []Code{OK, InvalidArgument, NotFound, Conflict, PreconditionFailed, Unauthenticated, PermissionDenied, CostCapExceeded, Internal}

// Valid reports whether c is a member of the shared enum.
func (c Code) Valid() bool {
	for _, k := range Codes {
		if c == k {
			return true
		}
	}
	return false
}

// Absence tells the host what a NOT_FOUND refers to. Adapters set it when the
// provider response identifies the missing resource; it is never shown to scripts.
type Absence string

const (
	AbsentUnknown  Absence = ""
	AbsentBucket   Absence = "bucket"
	AbsentObject   Absence = "object"
	AbsentQueue    Absence = "queue"
	AbsentMessage  Absence = "message"
	AbsentTable    Absence = "table"
	AbsentItem     Absence = "item"
	AbsentUserpool Absence = "userpool"
	AbsentUser     Absence = "user"
	AbsentGroup    Absence = "group"
)

// CloudError is the structured last_error value.
type CloudError struct {
	Code         Code
	HTTPStatus   int
	ProviderCode string
	Message      string
	// Absent qualifies NOT_FOUND for host-side disambiguation.
	Absent Absence
	// Preflight marks client-side validation failures (http=0, provider_code="").
	Preflight bool
}

func (e *CloudError) Error() string {
	if e == nil {
		return string(OK)
	}
	return string(e.Code) + ": " + e.Message
}

// OK reports whether the error represents success.
func (e *CloudError) OK() bool { return e == nil || e.Code == OK }

// Success returns the OK value.
func Success() *CloudError { return &CloudError{Code: OK} }

// Preflightf builds an INVALID_ARGUMENT validation error with http=0 and no provider code.
func Preflightf(format string, args ...any) *CloudError {
	return &CloudError{Code: InvalidArgument, Message: RedactText(fmt.Sprintf(format, args...)), Preflight: true}
}

// ProviderError builds a classified provider error. Codes outside the shared
// enum (or OK) become INTERNAL so scripts can always name the result.
func ProviderError(code Code, httpStatus int, providerCode, message string) *CloudError {
	if !code.Valid() || code == OK {
		code = Internal
	}
	return &CloudError{Code: code, HTTPStatus: httpStatus, ProviderCode: RedactText(providerCode), Message: RedactText(message)}
}

// WithAbsent returns a copy of e qualified with a NOT_FOUND target.
func (e *CloudError) WithAbsent(a Absence) *CloudError {
	c := *e
	c.Absent = a
	return &c
}

// CodeForStatus is the default HTTP status classification. Adapters refine it
// with provider error codes (for example a 403/404 that means authentication
// failure or policy denial). 429, 5xx and unknown statuses are INTERNAL.
func CodeForStatus(status int) Code {
	switch {
	case status >= 200 && status < 300:
		return OK
	case status == 400 || status == 405 || status == 411 || status == 413 || status == 414 || status == 416 || status == 422:
		return InvalidArgument
	case status == 401:
		return Unauthenticated
	case status == 403:
		return PermissionDenied
	case status == 404 || status == 410:
		return NotFound
	case status == 409:
		return Conflict
	case status == 412:
		return PreconditionFailed
	default:
		return Internal
	}
}

// NilIfTyped returns nil for a nil error and for a typed-nil *CloudError
// wrapped in a non-nil error interface (the classic Go trap: a function
// declared to return error that returns a nil *CloudError variable). Every
// place hostkit receives an adapter error goes through it, so a typed nil is
// success, never "[INTERNAL] … OK".
//
// Adapter authors: still prefer `if cerr != nil { return cerr }; return nil`.
func NilIfTyped(err error) error {
	if err == nil {
		return nil
	}
	if ce, ok := err.(*CloudError); ok && ce == nil {
		return nil
	}
	return err
}

// AsCloudError converts any adapter error into a CloudError. Unclassified
// errors (transport failures, decode failures) become redacted INTERNAL. A
// nil or typed-nil error returns nil.
func AsCloudError(err error) *CloudError {
	if NilIfTyped(err) == nil {
		return nil
	}
	var ce *CloudError
	if errors.As(err, &ce) && ce != nil {
		if !ce.Code.Valid() || ce.Code == OK {
			c := *ce
			c.Code = Internal
			return &c
		}
		return ce
	}
	return &CloudError{Code: Internal, Message: RedactText(err.Error())}
}

// FormatAbort renders the located RUN_HOST abort message (design 02 §5.2).
func FormatAbort(op, target string, e *CloudError) string {
	if e.Preflight {
		return fmt.Sprintf("[%s] %s: %s", e.Code, op, RedactText(e.Message))
	}
	pc := e.ProviderCode
	if pc == "" {
		pc = "none"
	}
	return fmt.Sprintf("[%s] %s (%s): %s (http=%d, provider_code=%s)", e.Code, op, RedactTarget(target), RedactText(e.Message), e.HTTPStatus, RedactText(pc))
}

// AbortError is returned to the lmcode VM when abort_on_error is true.
type AbortError struct {
	Message string
	Err     *CloudError
}

func (a *AbortError) Error() string { return a.Message }

// ErrorState holds last_error and the abort_on_error flag for one host.
type ErrorState struct {
	mu    sync.Mutex
	last  CloudError
	abort bool
	// secrets are exact strings (this host's create tokens) replaced by
	// CreateTokenMarker before last_error is stored or an abort is formatted.
	secrets         []string
	retainedSecrets []string
	retainedSet     map[string]struct{}
	retainedBytes   int
	pinnedSecrets   map[string][]string
	pinnedOrder     []string
	pinnedBytes     int
}

// maxRedactions bounds the primary secrets slice (oldest dropped first).
const maxRedactions = 256

// maxRetainedRedactions and maxRetainedRedactionBytes bound the transient
// redaction FIFO (including JSON-escaped and URL-encoded forms).
const (
	maxRetainedRedactions     = 4096
	maxRetainedRedactionBytes = 1 << 20
	maxSingleRedactionBytes   = 8192
	maxPinnedRedactionKeys    = 16384
	maxPinnedRedactionBytes   = 4 << 20
)

func expandSecretVariants(secret string) []string {
	if len(secret) < 8 || len(secret) > maxSingleRedactionBytes {
		return nil
	}
	out := make([]string, 0, 4)
	out = append(out, secret)
	if jb, err := json.Marshal(secret); err == nil && len(jb) >= 2 {
		jEsc := string(jb[1 : len(jb)-1])
		if len(jEsc) >= 8 && jEsc != secret {
			out = append(out, jEsc)
		}
	}
	if uEsc := url.QueryEscape(secret); len(uEsc) >= 8 && uEsc != secret {
		out = append(out, uEsc)
	}
	if pEsc := url.PathEscape(secret); len(pEsc) >= 8 && pEsc != secret {
		out = append(out, pEsc)
	}
	return out
}

func (s *ErrorState) addRetainedLocked(sec string) {
	if len(sec) < 8 || len(sec) > maxSingleRedactionBytes*4 {
		return
	}
	if s.retainedSet == nil {
		s.retainedSet = make(map[string]struct{}, 64)
	}
	if _, exists := s.retainedSet[sec]; exists {
		return
	}
	for len(s.retainedSecrets) >= maxRetainedRedactions || (s.retainedBytes+len(sec) > maxRetainedRedactionBytes && len(s.retainedSecrets) > 0) {
		dropped := s.retainedSecrets[0]
		delete(s.retainedSet, dropped)
		s.retainedBytes -= len(dropped)
		if s.retainedBytes < 0 {
			s.retainedBytes = 0
		}
		s.retainedSecrets = s.retainedSecrets[1:]
	}
	s.retainedSet[sec] = struct{}{}
	s.retainedSecrets = append(s.retainedSecrets, sec)
	s.retainedBytes += len(sec)
}

// AddRedaction registers an exact string (a create token, password, or session
// token) that must never appear in last_error, its provider_code, the abort
// message or its target. Strings shorter than 8 bytes or larger than 8192 bytes
// are ignored. Added in v4.
func (s *ErrorState) AddRedaction(secret string) {
	if len(secret) < 8 || len(secret) > maxSingleRedactionBytes {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = append(s.secrets, secret)
	if len(s.secrets) > maxRedactions {
		s.secrets = s.secrets[len(s.secrets)-maxRedactions:]
	}
	for _, v := range expandSecretVariants(secret) {
		s.addRetainedLocked(v)
	}
}

// PinActiveSecret pins an active credential (such as a user's current password
// or an active session token) under lifecycle key so transient AddRedaction
// churn cannot evict it while the credential remains active.
func (s *ErrorState) PinActiveSecret(key, secret string) {
	if key == "" || len(secret) < 8 || len(secret) > maxSingleRedactionBytes {
		return
	}
	variants := expandSecretVariants(secret)
	if len(variants) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = append(s.secrets, secret)
	if len(s.secrets) > maxRedactions {
		s.secrets = s.secrets[len(s.secrets)-maxRedactions:]
	}
	for _, v := range variants {
		s.addRetainedLocked(v)
	}
	if s.pinnedSecrets == nil {
		s.pinnedSecrets = make(map[string][]string, 64)
	}
	var addedBytes int
	for _, v := range variants {
		addedBytes += len(v)
	}
	if prev, exists := s.pinnedSecrets[key]; exists {
		for _, pv := range prev {
			s.pinnedBytes -= len(pv)
		}
		if s.pinnedBytes < 0 {
			s.pinnedBytes = 0
		}
	} else {
		for (len(s.pinnedSecrets) >= maxPinnedRedactionKeys || (s.pinnedBytes+addedBytes > maxPinnedRedactionBytes && len(s.pinnedSecrets) > 0)) && len(s.pinnedOrder) > 0 {
			evictKey := s.pinnedOrder[0]
			s.pinnedOrder = s.pinnedOrder[1:]
			if old, ok := s.pinnedSecrets[evictKey]; ok {
				for _, ov := range old {
					s.pinnedBytes -= len(ov)
				}
				delete(s.pinnedSecrets, evictKey)
			}
		}
		s.pinnedOrder = append(s.pinnedOrder, key)
	}
	s.pinnedSecrets[key] = variants
	s.pinnedBytes += addedBytes
}

// UnpinActiveSecret unpins an active credential when it is deleted or superseded.
func (s *ErrorState) UnpinActiveSecret(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.pinnedSecrets[key]; ok {
		for _, pv := range prev {
			s.pinnedBytes -= len(pv)
		}
		if s.pinnedBytes < 0 {
			s.pinnedBytes = 0
		}
		delete(s.pinnedSecrets, key)
	}
}

// UnpinActiveSecretPrefix unpins all active credentials whose key starts with prefix.
func (s *ErrorState) UnpinActiveSecretPrefix(prefix string) {
	if prefix == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, prev := range s.pinnedSecrets {
		if strings.HasPrefix(k, prefix) {
			for _, pv := range prev {
				s.pinnedBytes -= len(pv)
			}
			delete(s.pinnedSecrets, k)
		}
	}
	if s.pinnedBytes < 0 {
		s.pinnedBytes = 0
	}
}

// scrubLocked replaces the registered exact strings, then applies RedactText.
func (s *ErrorState) scrubLocked(text string) string {
	for _, variants := range s.pinnedSecrets {
		for _, sec := range variants {
			text = strings.ReplaceAll(text, sec, CreateTokenMarker)
		}
	}
	for _, sec := range s.secrets {
		text = strings.ReplaceAll(text, sec, CreateTokenMarker)
	}
	for _, sec := range s.retainedSecrets {
		text = strings.ReplaceAll(text, sec, CreateTokenMarker)
	}
	return RedactText(text)
}

// NewErrorState starts with OK and abort_on_error == true.
func NewErrorState() *ErrorState { return &ErrorState{last: CloudError{Code: OK}, abort: true} }

// Abort reports the abort_on_error flag.
func (s *ErrorState) Abort() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.abort
}

// SetAbort updates abort_on_error and resets last_error to OK.
func (s *ErrorState) SetAbort(abort bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abort = abort
	s.last = CloudError{Code: OK}
}

// Last returns a copy of last_error.
func (s *ErrorState) Last() CloudError {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// Succeed records OK.
func (s *ErrorState) Succeed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = CloudError{Code: OK}
}

// Fail records e and returns an *AbortError when abort_on_error is true, else nil.
func (s *ErrorState) Fail(op, target string, e *CloudError) error {
	if e == nil || e.Code == OK {
		s.Succeed()
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *e
	c.Message = s.scrubLocked(c.Message)
	c.ProviderCode = s.scrubLocked(c.ProviderCode)
	c.Absent = AbsentUnknown
	s.last = c
	if !s.abort {
		return nil
	}
	msg := FormatAbort(s.scrubLocked(op), s.scrubLocked(target), &c)
	return &AbortError{Message: s.scrubLocked(msg), Err: &c}
}
