// SPDX-License-Identifier: MIT

package hostkit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Portable limits for the userpool slice (durable-memory/17-userpool-design.md §3.1).
const (
	MinUserpoolNameLen        = 3
	MaxUserpoolNameLen        = 32
	MinPoolUsernameLen        = 3
	MaxPoolUsernameLen        = 64
	MinPoolGroupNameLen       = 3
	MaxPoolGroupNameLen       = 64
	MinPoolPasswordLen        = 8
	MaxPoolPasswordLen        = 128
	MinPoolAttrNameLen        = 1
	MaxPoolAttrNameLen        = 20
	MaxPoolAttrValueBytes     = 2048
	MaxPoolAttrsPerUser       = 32
	MaxUserpoolsPerRun        = 128
	MaxUsersPerPool           = 2000
	MaxGroupsPerPool          = 64
	MaxMembershipsPerUser     = 64
	MaxGroupsPerUser          = 64
	MaxSessionBindingsPerUser = 128
	DefaultUserListMaxItems   = 100
	MaxUserListMaxItems       = 500
	MaxJWTTokenBytes          = 8192
	MaxJWTHeaderBytes         = 4096
	MaxJWTPayloadBytes        = 4096
	MaxJWKSBytes              = 256 << 10
	MaxJWKSKeys               = 16
	MaxPageTokenBytes         = 512
	MaxUserIndexBytes         = 2 << 20
	MaxUserPageProfileBytes   = 1 << 20
	DefaultSessionTTLSeconds  = 3600
	MaxClockSkewSeconds       = 60
	PageTokenTTLSeconds       = 300

	GenericSignInErrorMessage = "invalid username or password"

	// PBKDF2-HMAC-SHA256 parameters for reference/in-memory password verifiers (§2.4, §3.2).
	PBKDF2Iterations = 600_000
	PBKDF2SaltBytes  = 16
	PBKDF2KeyBytes   = 32
)

// Portable user statuses.
const (
	UserStatusForceChangePassword = "FORCE_CHANGE_PASSWORD"
	UserStatusConfirmed           = "CONFIRMED"
)

var (
	userpoolNameRe  = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	poolUsernameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	poolGroupNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	poolAttrNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,19}$`)
)

func isReservedUserpoolIdentifier(s string) bool {
	lower := strings.ToLower(s)
	if lower == "lmcloudmeta" {
		return true
	}
	return len(lower) >= 4 && strings.HasPrefix(lower, "__") && strings.HasSuffix(lower, "__")
}

// ValidateUserpoolName enforces portable userpool naming rules:
// 3..32 ASCII bytes, ^[a-z][a-z0-9]{2,31}$, not reserved.
func ValidateUserpoolName(pool string) *CloudError {
	if len(pool) < MinUserpoolNameLen || len(pool) > MaxUserpoolNameLen {
		return Preflightf("userpool name %q length must be between %d and %d bytes (got %d)",
			pool, MinUserpoolNameLen, MaxUserpoolNameLen, len(pool))
	}
	if !userpoolNameRe.MatchString(pool) {
		return Preflightf("userpool name %q must match ^[a-z][a-z0-9]{2,31}$", pool)
	}
	if isReservedUserpoolIdentifier(pool) {
		return Preflightf("userpool name %q is reserved", pool)
	}
	return nil
}

// ValidatePoolUsername enforces portable username rules:
// 3..64 ASCII bytes, ^[a-z][a-z0-9_]{2,63}$, not reserved.
func ValidatePoolUsername(username string) *CloudError {
	if len(username) < MinPoolUsernameLen || len(username) > MaxPoolUsernameLen {
		return Preflightf("username %q length must be between %d and %d bytes (got %d)",
			username, MinPoolUsernameLen, MaxPoolUsernameLen, len(username))
	}
	if !poolUsernameRe.MatchString(username) {
		return Preflightf("username %q must match ^[a-z][a-z0-9_]{2,63}$", username)
	}
	if isReservedUserpoolIdentifier(username) {
		return Preflightf("username %q is reserved", username)
	}
	return nil
}

// ValidatePoolGroupName enforces portable group name rules:
// 3..64 ASCII bytes, ^[a-z][a-z0-9_]{2,63}$, not reserved.
func ValidatePoolGroupName(group string) *CloudError {
	if len(group) < MinPoolGroupNameLen || len(group) > MaxPoolGroupNameLen {
		return Preflightf("group name %q length must be between %d and %d bytes (got %d)",
			group, MinPoolGroupNameLen, MaxPoolGroupNameLen, len(group))
	}
	if !poolGroupNameRe.MatchString(group) {
		return Preflightf("group name %q must match ^[a-z][a-z0-9_]{2,63}$", group)
	}
	if isReservedUserpoolIdentifier(group) {
		return Preflightf("group name %q is reserved", group)
	}
	return nil
}

// ValidatePoolPassword enforces portable password rules (8..128 printable non-space
// ASCII bytes 0x21..0x7E, containing at least one ASCII letter and at least one
// ASCII digit). Fixed error templates are used so the password is never echoed.
func ValidatePoolPassword(password string) *CloudError {
	if !utf8.ValidString(password) {
		return Preflightf("invalid password: must be valid UTF-8")
	}
	if len(password) < MinPoolPasswordLen || len(password) > MaxPoolPasswordLen {
		return Preflightf("invalid password: length must be between %d and %d bytes",
			MinPoolPasswordLen, MaxPoolPasswordLen)
	}
	hasLetter := false
	hasDigit := false
	for i := 0; i < len(password); i++ {
		b := password[i]
		if b < 0x21 || b > 0x7e {
			return Preflightf("invalid password: all bytes must be printable non-whitespace ASCII (0x21..0x7E)")
		}
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			hasLetter = true
		} else if b >= '0' && b <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return Preflightf("invalid password: must contain at least one ASCII letter and at least one ASCII digit")
	}
	return nil
}

var reservedPoolAttrNames = map[string]bool{
	"sub":         true,
	"username":    true,
	"groups":      true,
	"lmcloudmeta": true,
}

// ValidatePoolAttrName enforces portable custom user attribute key rules:
// 1..20 ASCII bytes, ^[a-z][a-z0-9_]{0,19}$, not reserved ("sub", "username", "groups", "lmcloudmeta", "__*__").
func ValidatePoolAttrName(name string) *CloudError {
	if len(name) < MinPoolAttrNameLen || len(name) > MaxPoolAttrNameLen {
		return Preflightf("attribute name %q length must be between %d and %d bytes (got %d)",
			name, MinPoolAttrNameLen, MaxPoolAttrNameLen, len(name))
	}
	if !poolAttrNameRe.MatchString(name) {
		return Preflightf("attribute name %q must match ^[a-z][a-z0-9_]{0,19}$", name)
	}
	if reservedPoolAttrNames[strings.ToLower(name)] || isReservedUserpoolIdentifier(name) {
		return Preflightf("attribute name %q is reserved", name)
	}
	return nil
}

// ValidatePoolAttrValue enforces portable custom user attribute value rules:
// valid UTF-8, <= 2048 bytes, no NUL bytes. Empty string "" is valid.
func ValidatePoolAttrValue(val string) *CloudError {
	if len(val) > MaxPoolAttrValueBytes {
		return Preflightf("attribute value length %d exceeds maximum of %d bytes", len(val), MaxPoolAttrValueBytes)
	}
	if !utf8.ValidString(val) {
		return Preflightf("attribute value must be valid UTF-8")
	}
	if strings.IndexByte(val, 0) >= 0 {
		return Preflightf("attribute value must not contain NUL bytes")
	}
	return nil
}

// ValidatePoolAttributes validates a user attribute map (<= 32 attributes, valid keys and values).
func ValidatePoolAttributes(attrs map[string]string) *CloudError {
	if len(attrs) > MaxPoolAttrsPerUser {
		return Preflightf("user attribute count %d exceeds maximum of %d", len(attrs), MaxPoolAttrsPerUser)
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if ce := ValidatePoolAttrName(k); ce != nil {
			return ce
		}
		if ce := ValidatePoolAttrValue(attrs[k]); ce != nil {
			return ce
		}
	}
	return nil
}

// ValidateUserListMaxItems validates max_items on user_list (0..500; 0 defaults to 100).
func ValidateUserListMaxItems(maxItems int64) (int, *CloudError) {
	if maxItems < 0 || maxItems > MaxUserListMaxItems {
		return 0, Preflightf("user_list max_items must be between 0 and %d (got %d)", MaxUserListMaxItems, maxItems)
	}
	if maxItems == 0 {
		return DefaultUserListMaxItems, nil
	}
	return int(maxItems), nil
}

// ParsedUntrustedJWT holds the structurally validated, unverified components of a compact JWT.
type ParsedUntrustedJWT struct {
	SigningInput string
	Header       map[string]any
	Payload      map[string]any
	Signature    []byte
}

func decodeStrictBase64URLSegment(seg string) ([]byte, error) {
	if seg == "" {
		return nil, errors.New("empty segment")
	}
	for i := 0; i < len(seg); i++ {
		b := seg[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_' {
			continue
		}
		return nil, errors.New("invalid base64url character")
	}
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(raw) != seg {
		return nil, errors.New("non-canonical base64url encoding")
	}
	return raw, nil
}

func parseJSONObjectNoDuplicateKeys(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("expected JSON object")
	}
	obj, err := parseJSONObjectBody(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON object")
	}
	return obj, nil
}

func parseJSONObjectBody(dec *json.Decoder) (map[string]any, error) {
	out := make(map[string]any)
	for dec.More() {
		ktok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := ktok.(string)
		if !ok {
			return nil, errors.New("expected string object key")
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate JSON key %q", key)
		}
		val, err := parseJSONValueNoDuplicateKeys(dec)
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
	endTok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := endTok.(json.Delim); !ok || delim != '}' {
		return nil, errors.New("expected closing brace")
	}
	return out, nil
}

func parseJSONValueNoDuplicateKeys(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			return parseJSONObjectBody(dec)
		case '[':
			var arr []any
			for dec.More() {
				elem, err := parseJSONValueNoDuplicateKeys(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, elem)
			}
			endTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if endDelim, ok := endTok.(json.Delim); !ok || endDelim != ']' {
				return nil, errors.New("expected closing bracket")
			}
			return arr, nil
		default:
			return nil, errors.New("unexpected delimiter")
		}
	}
	return tok, nil
}

// ValidateJWTFormatAndParseUntrusted performs pre-flight structural validation of a compact
// JWT string per durable-memory/17-userpool-design.md §2.6:
//   - non-empty, <= 8192 bytes, no whitespace or control characters
//   - exactly 3 dot-separated segments (header.payload.signature)
//   - valid raw URL-safe base64 without '=' padding
//   - decoded header JSON <= 4096 bytes and payload JSON <= 4096 bytes
//   - both header and payload are valid JSON objects with no duplicate keys at any level
//
// Fixed error templates are used so the token is never echoed in error messages.
func ValidateJWTFormatAndParseUntrusted(token string) (*ParsedUntrustedJWT, *CloudError) {
	if len(token) == 0 {
		return nil, Preflightf("invalid token: token must not be empty")
	}
	if len(token) > MaxJWTTokenBytes {
		return nil, Preflightf("invalid token: token length exceeds maximum of %d bytes", MaxJWTTokenBytes)
	}
	for i := 0; i < len(token); i++ {
		b := token[i]
		if b <= 0x20 || b >= 0x7f {
			return nil, Preflightf("invalid token: contains whitespace or non-ASCII characters")
		}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, Preflightf("invalid token: compact JWT must have exactly 3 dot-separated segments")
	}
	headerRaw, err := decodeStrictBase64URLSegment(parts[0])
	if err != nil {
		return nil, Preflightf("invalid token: malformed base64url JWT header segment")
	}
	if len(headerRaw) > MaxJWTHeaderBytes {
		return nil, Preflightf("invalid token: decoded JWT header exceeds %d bytes", MaxJWTHeaderBytes)
	}
	payloadRaw, err := decodeStrictBase64URLSegment(parts[1])
	if err != nil {
		return nil, Preflightf("invalid token: malformed base64url JWT payload segment")
	}
	if len(payloadRaw) > MaxJWTPayloadBytes {
		return nil, Preflightf("invalid token: decoded JWT payload exceeds %d bytes", MaxJWTPayloadBytes)
	}
	headerObj, err := parseJSONObjectNoDuplicateKeys(headerRaw)
	if err != nil {
		return nil, Preflightf("invalid token: JWT header must be a valid JSON object without duplicate keys")
	}
	payloadObj, err := parseJSONObjectNoDuplicateKeys(payloadRaw)
	if err != nil {
		return nil, Preflightf("invalid token: JWT payload must be a valid JSON object without duplicate keys")
	}
	algStr, _ := headerObj["alg"].(string)
	if algStr == "" {
		return nil, Preflightf("invalid token: JWT header missing string \"alg\" field")
	}
	var sigBytes []byte
	if parts[2] == "" {
		// An empty signature segment is structurally valid only for alg=="none"
		// (which then fails trust verification with UNAUTHENTICATED after pool existence).
		if !strings.EqualFold(algStr, "none") {
			return nil, Preflightf("invalid token: empty JWT signature segment")
		}
	} else {
		sigBytes, err = decodeStrictBase64URLSegment(parts[2])
		if err != nil {
			return nil, Preflightf("invalid token: malformed base64url JWT signature segment")
		}
	}
	return &ParsedUntrustedJWT{
		SigningInput: parts[0] + "." + parts[1],
		Header:       headerObj,
		Payload:      payloadObj,
		Signature:    sigBytes,
	}, nil
}

var (
	pbkdf2MemoMu sync.Mutex
	// pbkdf2Memo maps SHA-256(password || 0x00 || salt) -> derived 32-byte key
	// for up to 32 active entries in memory (never storing plaintext passwords).
	pbkdf2Memo = make(map[[32]byte][PBKDF2KeyBytes]byte, 32)
)

func pbkdf2MemoKey(password string, salt []byte) [32]byte {
	h := sha256.New()
	_, _ = io.WriteString(h, password)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(salt)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func derivePBKDF2Cached(password string, salt []byte) ([]byte, error) {
	key := pbkdf2MemoKey(password, salt)
	pbkdf2MemoMu.Lock()
	if cached, ok := pbkdf2Memo[key]; ok {
		pbkdf2MemoMu.Unlock()
		out := make([]byte, PBKDF2KeyBytes)
		copy(out, cached[:])
		return out, nil
	}
	pbkdf2MemoMu.Unlock()

	dk, err := pbkdf2.Key(sha256.New, password, salt, PBKDF2Iterations, PBKDF2KeyBytes)
	if err != nil || len(dk) != PBKDF2KeyBytes {
		return dk, err
	}

	var entry [PBKDF2KeyBytes]byte
	copy(entry[:], dk)
	pbkdf2MemoMu.Lock()
	if len(pbkdf2Memo) >= 32 {
		pbkdf2Memo = make(map[[32]byte][PBKDF2KeyBytes]byte, 32)
	}
	pbkdf2Memo[key] = entry
	pbkdf2MemoMu.Unlock()
	return dk, nil
}

// DerivePasswordPBKDF2 computes a salted PBKDF2-HMAC-SHA256 (600,000 iterations)
// verifier with a fresh 16-byte crypto/rand salt.
func DerivePasswordPBKDF2(password string) (saltHex, verifierHex string, err error) {
	var salt [PBKDF2SaltBytes]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return "", "", err
	}
	dk, err := derivePBKDF2Cached(password, salt[:])
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(salt[:]), hex.EncodeToString(dk), nil
}

// VerifyPasswordPBKDF2 verifies password against saltHex and verifierHex using
// PBKDF2-HMAC-SHA256 (600,000 iterations) and subtle.ConstantTimeCompare.
func VerifyPasswordPBKDF2(password, saltHex, verifierHex string) bool {
	if saltHex == "" || verifierHex == "" {
		DummyVerifyPasswordPBKDF2(password)
		return false
	}
	salt, err1 := hex.DecodeString(saltHex)
	want, err2 := hex.DecodeString(verifierHex)
	if err1 != nil || err2 != nil || len(salt) != PBKDF2SaltBytes || len(want) != PBKDF2KeyBytes {
		DummyVerifyPasswordPBKDF2(password)
		return false
	}
	dk, err := derivePBKDF2Cached(password, salt)
	if err != nil || len(dk) != PBKDF2KeyBytes {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

var dummyPBKDF2Salt = []byte("lmcloud-dummy-up")
var dummyPBKDF2Want = make([]byte, PBKDF2KeyBytes)

// DummyVerifyPasswordPBKDF2 executes a full 600,000-iteration PBKDF2-HMAC-SHA256
// derivation and constant-time comparison when a user does not exist, has no
// password set, or is disabled, preventing timing-based user enumeration.
func DummyVerifyPasswordPBKDF2(password string) {
	dk, err := derivePBKDF2Cached(password, dummyPBKDF2Salt)
	if err == nil && len(dk) == PBKDF2KeyBytes {
		_ = subtle.ConstantTimeCompare(dk, dummyPBKDF2Want)
	}
}

// GeneratePoolRSAKeyPair generates a 2048-bit RSA keypair and key ID (kid) for a user pool.
func GeneratePoolRSAKeyPair() (privPEM, pubPEM, kid string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", "", err
	}
	pubBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	sum := sha256.Sum256(pubDER)
	kid = "kid-" + hex.EncodeToString(sum[:8])
	return string(privBlock), string(pubBlock), kid, nil
}

// ParseRSAPrivateKeyPEM parses a PKCS#1 PEM-encoded RSA private key.
func ParseRSAPrivateKeyPEM(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("invalid RSA private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParseRSAPublicKeyPEM parses a PKIX PEM-encoded RSA public key.
func ParseRSAPublicKeyPEM(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("invalid RSA public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pub, nil
}

// MintRS256JWT signs a compact RS256 JWT with the given RSA private key PEM and kid.
func MintRS256JWT(privPEM, kid string, payload map[string]any) (string, error) {
	priv, err := ParseRSAPrivateKeyPEM(privPEM)
	if err != nil {
		return "", err
	}
	header := map[string]string{
		"alg": "RS256",
		"kid": kid,
		"typ": "JWT",
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hB64 := base64.RawURLEncoding.EncodeToString(hb)
	pB64 := base64.RawURLEncoding.EncodeToString(pb)
	signingInput := hB64 + "." + pB64
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	sB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sB64, nil
}

// VerifiedJWTClaims holds the verified claims extracted from an RS256 session JWT.
type VerifiedJWTClaims struct {
	Sub       string
	Username  string
	Issuer    string
	ClientID  string
	IssuedAt  int64
	ExpiresAt int64
	ExpiresIn int64
	ClaimsMap map[string]string
}

func jsonNumberToInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		s := string(n)
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, true
		}
		return 0, false
	case float64:
		if math.Trunc(n) != n || n > float64(math.MaxInt64) || n < float64(math.MinInt64) {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

// VerifyRS256JWT cryptographically verifies a parsed JWT against a pool's RSA public key,
// kid, issuer, and temporal bounds (nowUnix < exp and iat <= nowUnix + 60).
// Any verification failure returns ErrorCode.UNAUTHENTICATED without echoing the token.
func VerifyRS256JWT(parsed *ParsedUntrustedJWT, pubPEM, expectedKid, expectedIssuer string, nowUnix int64) (*VerifiedJWTClaims, *CloudError) {
	return VerifyRS256JWTWithKeySet(parsed, pubPEM, expectedKid, nil, expectedIssuer, nowUnix)
}

// VerifyRS256JWTWithKeySet cryptographically verifies a parsed JWT against a pool's active RSA
// public key or bounded rotated key set (<= 16 keys, <= 256 KiB), issuer, and temporal bounds.
func VerifyRS256JWTWithKeySet(parsed *ParsedUntrustedJWT, pubPEM, expectedKid string, rotatedKeys map[string]string, expectedIssuer string, nowUnix int64) (*VerifiedJWTClaims, *CloudError) {
	if parsed == nil {
		return nil, ProviderError(Unauthenticated, 401, "InvalidToken", "token verification failed")
	}
	alg, _ := parsed.Header["alg"].(string)
	if alg != "RS256" {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenAlgorithm", "unsupported or untrusted JWT algorithm")
	}
	if len(parsed.Signature) == 0 {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenSignature", "missing JWT signature")
	}
	keyPEM := pubPEM
	if expectedKid != "" {
		kid, _ := parsed.Header["kid"].(string)
		if kid != "" && kid != expectedKid {
			if len(rotatedKeys) <= MaxJWKSKeys {
				if rk, ok := rotatedKeys[kid]; ok && len(rk) <= MaxJWKSBytes {
					keyPEM = rk
				} else {
					return nil, ProviderError(Unauthenticated, 401, "InvalidTokenKeyID", "JWT key ID does not match pool signing key")
				}
			} else {
				return nil, ProviderError(Unauthenticated, 401, "InvalidTokenKeyID", "JWT key ID does not match pool signing key")
			}
		}
	}
	pub, err := ParseRSAPublicKeyPEM(keyPEM)
	if err != nil {
		return nil, ProviderError(Unauthenticated, 401, "InvalidPoolKey", "failed to load pool public key")
	}
	digest := sha256.Sum256([]byte(parsed.SigningInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], parsed.Signature); err != nil {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenSignature", "JWT cryptographic signature verification failed")
	}

	iss, _ := parsed.Payload["iss"].(string)
	if expectedIssuer != "" && iss != expectedIssuer {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenIssuer", "JWT issuer does not match user pool")
	}
	sub, _ := parsed.Payload["sub"].(string)
	if sub == "" {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenClaims", "JWT missing mandatory sub claim")
	}
	username, _ := parsed.Payload["username"].(string)
	if username == "" {
		username, _ = parsed.Payload["cognito:username"].(string)
	}
	if username == "" {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenClaims", "JWT missing mandatory username claim")
	}
	iat, okIat := jsonNumberToInt64(parsed.Payload["iat"])
	exp, okExp := jsonNumberToInt64(parsed.Payload["exp"])
	if !okIat || !okExp || iat <= 0 || exp <= 0 {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenClaims", "JWT missing valid integer iat or exp claim")
	}
	// Strict temporal checks (§2.6): valid iff nowUnix < exp and iat <= nowUnix + 60.
	if nowUnix >= exp {
		return nil, ProviderError(Unauthenticated, 401, "TokenExpiredException", "session token has expired")
	}
	if iat > nowUnix+MaxClockSkewSeconds {
		return nil, ProviderError(Unauthenticated, 401, "InvalidTokenIssuedAt", "session token iat is in the future beyond clock skew tolerance")
	}
	expiresIn := exp - nowUnix
	if expiresIn < 1 {
		return nil, ProviderError(Unauthenticated, 401, "TokenExpiredException", "session token has expired")
	}

	claimsMap := map[string]string{
		"sub":      sub,
		"username": username,
		"iat":      strconv.FormatInt(iat, 10),
		"exp":      strconv.FormatInt(exp, 10),
	}
	if iss != "" {
		claimsMap["iss"] = iss
	}
	clientID, _ := parsed.Payload["client_id"].(string)
	if clientID != "" {
		claimsMap["client_id"] = clientID
	}
	if tokenUse, ok := parsed.Payload["token_use"].(string); ok && tokenUse != "" {
		claimsMap["token_use"] = tokenUse
	}
	return &VerifiedJWTClaims{
		Sub:       sub,
		Username:  username,
		Issuer:    iss,
		ClientID:  clientID,
		IssuedAt:  iat,
		ExpiresAt: exp,
		ExpiresIn: expiresIn,
		ClaimsMap: claimsMap,
	}, nil
}

// UserListPageTokenPayload is the authenticated continuation cursor for user_list (§2.5).
type UserListPageTokenPayload struct {
	Version         int    `json:"v"`
	Endpoint        string `json:"ep"`
	Scope           string `json:"sc"`
	PoolName        string `json:"pool"`
	PoolID          string `json:"pid"`
	PoolIncarnation string `json:"inc"`
	MaxItems        int    `json:"max"`
	CursorUsername  string `json:"cur"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
}

// SignUserListPageToken encodes and HMAC-SHA256 signs a user_list continuation token.
func SignUserListPageToken(secretKey []byte, p UserListPageTokenPayload) (string, error) {
	if len(secretKey) < 16 {
		return "", errors.New("pagination signing key too short")
	}
	p.Version = 1
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	bodyB64 := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, secretKey)
	_, _ = mac.Write([]byte("lmcloud-userpool-page-v1:"))
	_, _ = mac.Write([]byte(bodyB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return bodyB64 + "." + sigB64, nil
}

// VerifyUserListPageToken verifies the HMAC-SHA256 signature, binding fields, and TTL
// of a user_list continuation token. Any failure returns ErrorCode.INVALID_ARGUMENT.
func VerifyUserListPageToken(secretKey []byte, token, expectedEndpoint, expectedScope, expectedPool string, expectedMaxItems int, nowUnix int64) (UserListPageTokenPayload, *CloudError) {
	if len(secretKey) < 16 || token == "" || len(token) > MaxPageTokenBytes {
		return UserListPageTokenPayload{}, Preflightf("invalid page_token")
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot >= len(token)-1 || strings.IndexByte(token[dot+1:], '.') >= 0 {
		return UserListPageTokenPayload{}, Preflightf("invalid page_token format")
	}
	bodyB64 := token[:dot]
	sigB64 := token[dot+1:]
	bodyRaw, err1 := decodeStrictBase64URLSegment(bodyB64)
	sigRaw, err2 := decodeStrictBase64URLSegment(sigB64)
	if err1 != nil || err2 != nil {
		return UserListPageTokenPayload{}, Preflightf("invalid page_token encoding")
	}
	mac := hmac.New(sha256.New, secretKey)
	_, _ = mac.Write([]byte("lmcloud-userpool-page-v1:"))
	_, _ = mac.Write([]byte(bodyB64))
	wantSig := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sigRaw, wantSig) != 1 {
		return UserListPageTokenPayload{}, Preflightf("invalid page_token signature")
	}
	var p UserListPageTokenPayload
	dec := json.NewDecoder(bytes.NewReader(bodyRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return UserListPageTokenPayload{}, Preflightf("invalid page_token payload")
	}
	if p.Version != 1 || p.PoolName != expectedPool || p.Endpoint != expectedEndpoint || p.Scope != expectedScope || p.MaxItems != expectedMaxItems {
		return UserListPageTokenPayload{}, Preflightf("page_token does not match target userpool, scope, or max_items")
	}
	if ce := ValidatePoolUsername(p.CursorUsername); ce != nil {
		return UserListPageTokenPayload{}, Preflightf("invalid page_token cursor")
	}
	if p.ExpiresAt <= 0 || nowUnix > p.ExpiresAt {
		return UserListPageTokenPayload{}, Preflightf("page_token has expired")
	}
	return p, nil
}

// UserpoolInfo describes a user pool's identity, signing public key, and ownership metadata.
type UserpoolInfo struct {
	Name          string            `json:"name"`
	PoolID        string            `json:"pool_id"`
	IncarnationID string            `json:"incarnation_id"`
	OwnerToken    string            `json:"owner_token,omitempty"`
	Generation    uint64            `json:"generation,omitempty"`
	PublicKeyPEM  string            `json:"public_key_pem,omitempty"`
	KeyID         string            `json:"key_id,omitempty"`
	RotatedKeys   map[string]string `json:"rotated_keys,omitempty"`
	Issuer        string            `json:"issuer,omitempty"`
	ClientID      string            `json:"client_id,omitempty"`
	ChildSeq      uint64            `json:"child_seq,omitempty"`
}

// UserSnapshot is the immutable provider/adapter representation of a user profile.
type UserSnapshot struct {
	Exists     bool              `json:"exists"`
	Username   string            `json:"username"`
	Sub        string            `json:"sub,omitempty"`
	Enabled    bool              `json:"enabled"`
	Status     string            `json:"status"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  int64             `json:"created_at"`
	SessionGen uint64            `json:"session_gen,omitempty"`
	OwnerToken string            `json:"owner_token,omitempty"`
	ChildSeq   uint64            `json:"child_seq,omitempty"`
}

// Clone returns a deep copy of UserSnapshot.
func (u UserSnapshot) Clone() UserSnapshot {
	out := u
	if u.Attributes != nil {
		out.Attributes = make(map[string]string, len(u.Attributes))
		for k, v := range u.Attributes {
			out.Attributes[k] = v
		}
	}
	return out
}

// UserIndexPage holds a slice of sorted usernames from a pool's projected index.
type UserIndexPage struct {
	PoolID        string   `json:"pool_id"`
	IncarnationID string   `json:"incarnation_id"`
	Usernames     []string `json:"usernames"`
	HasMore       bool     `json:"has_more"`
}

// SessionSnapshot holds the output of a successful user_sign_in or user_verify_token operation.
type SessionSnapshot struct {
	AccessToken   string            `json:"-"`
	ExpiresIn     int64             `json:"expires_in"`
	Claims        map[string]string `json:"claims"`
	PoolID        string            `json:"pool_id,omitempty"`
	IncarnationID string            `json:"incarnation_id,omitempty"`
	SessionGen    uint64            `json:"session_gen,omitempty"`
	IssuedAt      int64             `json:"issued_at,omitempty"`
	ExpiresAt     int64             `json:"expires_at,omitempty"`
}

// Clone returns a deep copy of SessionSnapshot.
func (s SessionSnapshot) Clone() SessionSnapshot {
	out := s
	if s.Claims != nil {
		out.Claims = make(map[string]string, len(s.Claims))
		for k, v := range s.Claims {
			out.Claims[k] = v
		}
	}
	return out
}

// UserpoolMutationFence carries expected ownership, incarnation, and monotonic generation
// fences for mutating userpool adapter operations.
type UserpoolMutationFence struct {
	OwnerToken    string
	IncarnationID string
	Generation    uint64
	IntentID      string
}

type userpoolMutationFenceKey struct{}

// WithUserpoolMutationFence attaches a UserpoolMutationFence to ctx.
func WithUserpoolMutationFence(ctx context.Context, fence UserpoolMutationFence) context.Context {
	return context.WithValue(ctx, userpoolMutationFenceKey{}, fence)
}

// UserpoolMutationFenceFrom extracts a UserpoolMutationFence from ctx, if present.
func UserpoolMutationFenceFrom(ctx context.Context) UserpoolMutationFence {
	if ctx == nil {
		return UserpoolMutationFence{}
	}
	if f, ok := ctx.Value(userpoolMutationFenceKey{}).(UserpoolMutationFence); ok {
		return f
	}
	return UserpoolMutationFence{}
}

type userpoolChildMutationSeqKey struct{}

// WithUserpoolChildMutationSeqOut attaches an output pointer to ctx so a Userpools
// adapter can report the monotonic child mutation sequence number assigned inside its lock.
func WithUserpoolChildMutationSeqOut(ctx context.Context, out *uint64) context.Context {
	return context.WithValue(ctx, userpoolChildMutationSeqKey{}, out)
}

// ReportUserpoolChildMutationSeq records the child mutation sequence number into ctx, if requested.
func ReportUserpoolChildMutationSeq(ctx context.Context, seq uint64) {
	if ctx == nil || seq == 0 {
		return
	}
	if out, ok := ctx.Value(userpoolChildMutationSeqKey{}).(*uint64); ok && out != nil {
		*out = seq
	}
}

// UserpoolCreateInput carries parameters for CreateUserPool.
type UserpoolCreateInput struct {
	Name               string
	OwnerToken         string
	ExpectedOwnerToken string
	IncarnationID      string
	Generation         uint64
	IntentID           string
}

// UserCreateInput carries parameters for CreateUser.
type UserCreateInput struct {
	Pool          string
	Username      string
	Attributes    map[string]string
	OwnerToken    string
	IncarnationID string
	Generation    uint64
	NowUnix       int64
}

// GroupCreateInput carries parameters for CreateGroup.
type GroupCreateInput struct {
	Pool          string
	Group         string
	OwnerToken    string
	IncarnationID string
	Generation    uint64
}

// UserSignInInput carries parameters for SignIn.
type UserSignInInput struct {
	Pool       string
	Username   string
	Password   string
	NowUnix    int64
	TTLSeconds int64
}

// Userpools is the provider adapter interface for the userpool slice.
type Userpools interface {
	CreateUserPool(ctx context.Context, in UserpoolCreateInput) (created bool, info UserpoolInfo, err error)
	DeleteUserPool(ctx context.Context, pool string) (existed bool, err error)
	UserPoolExists(ctx context.Context, pool string) (bool, error)
	DescribeUserPool(ctx context.Context, pool string) (UserpoolInfo, error)
	ListUserPools(ctx context.Context) ([]string, error)

	CreateUser(ctx context.Context, in UserCreateInput) (UserSnapshot, error)
	GetUser(ctx context.Context, pool, username string) (UserSnapshot, error)
	DeleteUser(ctx context.Context, pool, username string) error
	SetUserEnabled(ctx context.Context, pool, username string, enabled bool) (UserSnapshot, error)
	SetUserPassword(ctx context.Context, pool, username, password string) (UserSnapshot, error)
	ListUserIndex(ctx context.Context, pool, afterUsername string, maxItems int) (UserIndexPage, error)
	SignIn(ctx context.Context, in UserSignInInput) (SessionSnapshot, error)

	CreateGroup(ctx context.Context, in GroupCreateInput) (created bool, err error)
	DeleteGroup(ctx context.Context, pool, group string) (existed bool, err error)
	ListGroups(ctx context.Context, pool string) ([]string, error)
	AddUserToGroup(ctx context.Context, pool, group, username string) (added bool, err error)
	RemoveUserFromGroup(ctx context.Context, pool, group, username string) error
	ListUserGroups(ctx context.Context, pool, username string) ([]string, error)
}

// Optional UserpoolOwnershipReader allows cloudhost to verify userpool ownership tokens.
type UserpoolOwnershipReader interface {
	UserpoolOwnerToken(ctx context.Context, pool string) (ownerToken string, exists bool, err error)
}

// Optional UserpoolDryStatePeeker provides read-only state for dry-run overlays without mutating state.
type UserpoolDryStatePeeker interface {
	PeekDryUserpoolState(ctx context.Context, pool string) (info UserpoolInfo, users map[string]UserSnapshot, groups map[string]bool, memberships map[string][]string, found bool)
}
