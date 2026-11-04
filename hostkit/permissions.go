// SPDX-License-Identifier: MIT

package hostkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Portable limits for the permissions slice (durable-memory/15-permissions-design.md §3.1).
const (
	MaxPolicyDocumentBytes = 8192
	MaxPolicyStatements    = 32
	MaxStatementActions    = 64
	MaxStatementResources  = 64
	MaxPolicyActionBytes   = 128
	MaxPolicyResourceBytes = 512
	MaxPrincipalBytes      = 256
	MaxAttachmentsPerRun   = 128
)

// AttachmentKind identifies whether an attachment is resource-side or identity-side.
type AttachmentKind string

const (
	AttachmentResource  AttachmentKind = "resource"
	AttachmentPrincipal AttachmentKind = "principal"
)

// PolicyStatement is a single normalized portable policy statement.
type PolicyStatement struct {
	Effect    string   `json:"effect"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

// Clone returns a deep copy of s.
func (s PolicyStatement) Clone() PolicyStatement {
	return PolicyStatement{
		Effect:    s.Effect,
		Actions:   append([]string(nil), s.Actions...),
		Resources: append([]string(nil), s.Resources...),
	}
}

// PolicyDocument is the canonical v1 portable policy document wire format.
type PolicyDocument struct {
	Version    int               `json:"v"`
	Statements []PolicyStatement `json:"statements"`
}

// PolicyAttachment represents a single replace-per-key policy attachment in the
// authoritative run journal and adapter state.
type PolicyAttachment struct {
	Key        string            `json:"key"`
	Kind       AttachmentKind    `json:"kind"`
	Target     string            `json:"target,omitempty"`
	Principal  string            `json:"principal"`
	Document   string            `json:"document"`
	Statements []PolicyStatement `json:"statements"`
	OwnerToken string            `json:"owner_token,omitempty"`
	Generation string            `json:"generation,omitempty"`
}

// Clone returns a deep copy of a.
func (a PolicyAttachment) Clone() PolicyAttachment {
	stmts := make([]PolicyStatement, len(a.Statements))
	for i, s := range a.Statements {
		stmts[i] = s.Clone()
	}
	return PolicyAttachment{
		Key:        a.Key,
		Kind:       a.Kind,
		Target:     a.Target,
		Principal:  a.Principal,
		Document:   a.Document,
		Statements: stmts,
		OwnerToken: a.OwnerToken,
		Generation: a.Generation,
	}
}

// AttachmentKey returns the canonical per-run attachment key for (kind, target, principal).
func AttachmentKey(kind AttachmentKind, target, principal string) string {
	if kind == AttachmentPrincipal {
		target = ""
	}
	return string(kind) + "\x00" + target + "\x00" + principal
}

// LintFinding is a single semantic lint diagnostic produced by LintPolicy.
type LintFinding struct {
	StatementIndex int
	Severity       string // "error" or "warning"
	Code           string
	Message        string
}

// LintReport is the immutable result of LintPolicy.
type LintReport struct {
	Findings []LintFinding
}

// Len returns the number of findings in r.
func (r LintReport) Len() int { return len(r.Findings) }

// OK reports whether zero findings have Severity == "error".
func (r LintReport) OK() bool {
	for _, f := range r.Findings {
		if f.Severity == "error" {
			return false
		}
	}
	return true
}

// AnchoredTarget identifies a concrete run-owned top-level resource referenced
// by a resource-side or identity-side policy attachment or check.
type AnchoredTarget struct {
	Kind     string // "bucket", "queue", or "table"
	Name     string
	Resource string // e.g. "storage:bucket:<b>", "queue:queue:<q>", "tables:table:<t>"
}

// Permissions is the provider-neutral adapter interface for the permissions slice.
// All validation, semantic linting, scope fences, and journal-backed reference
// evaluation are owned by cloudhost; the adapter implements caller identity
// resolution, auth enforcement, and simulator/provider control-plane projection.
type Permissions interface {
	CurrentPrincipal(ctx context.Context) (string, error)
	AttachPolicy(ctx context.Context, att PolicyAttachment) error
	DetachPolicy(ctx context.Context, kind AttachmentKind, target, principal string) error
	CheckPolicy(ctx context.Context, principal, action, resource string) error
}

var (
	principalRegex = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]{1,256}$`)
	actionRegex    = regexp.MustCompile(`^[a-z]+(\.[a-z]+){2}$`)
	segLowerRegex  = regexp.MustCompile(`^[a-z]+$`)

	knownPortableActions = map[string]string{
		"storage.bucket.create": "storage:bucket",
		"storage.bucket.read":   "storage:bucket",
		"storage.bucket.list":   "storage:bucket",
		"storage.bucket.delete": "storage:bucket",
		"storage.object.read":   "storage:object",
		"storage.object.write":  "storage:object",
		"storage.object.list":   "storage:object",
		"storage.object.delete": "storage:object",
		"queue.queue.create":    "queue:queue",
		"queue.queue.read":      "queue:queue",
		"queue.queue.list":      "queue:queue",
		"queue.queue.delete":    "queue:queue",
		"queue.queue.send":      "queue:queue",
		"queue.queue.receive":   "queue:queue",
		"queue.queue.ack":       "queue:queue",
		"queue.queue.nack":      "queue:queue",
		"tables.table.create":   "tables:table",
		"tables.table.read":     "tables:table",
		"tables.table.list":     "tables:table",
		"tables.table.write":    "tables:table",
		"tables.table.delete":   "tables:table",
	}

	escalationNamespaces = map[string]bool{
		"permissions":   true,
		"iam":           true,
		"identity":      true,
		"userpool":      true,
		"sts":           true,
		"org":           true,
		"organizations": true,
		"admin":         true,
	}

	knownResourceTypes = map[string]bool{
		"storage:bucket": true,
		"storage:object": true,
		"queue:queue":    true,
		"tables:table":   true,
	}
)

// ValidatePrincipal checks that p matches ^[A-Za-z0-9_+=,.@:/-]{1,256}$.
func ValidatePrincipal(p string) *CloudError {
	if len(p) == 0 || len(p) > MaxPrincipalBytes || !principalRegex.MatchString(p) {
		return Preflightf("invalid principal %q: must be 1..%d ASCII characters in [A-Za-z0-9_+=,.@:/-]", p, MaxPrincipalBytes)
	}
	return nil
}

// NormalizeEffect validates and canonicalizes a statement effect ("Allow" or "Deny", case-insensitive).
func NormalizeEffect(effect string) (string, *CloudError) {
	switch {
	case strings.EqualFold(effect, "Allow"):
		return "Allow", nil
	case strings.EqualFold(effect, "Deny"):
		return "Deny", nil
	default:
		return "", Preflightf("invalid statement effect %q: must be Allow or Deny", effect)
	}
}

// ValidateActionSyntax enforces Tier-1 syntax for an action string (1..128 bytes,
// matching ^[a-z]+(\.[a-z]+){2}$ with no wildcards).
func ValidateActionSyntax(action string) *CloudError {
	if len(action) == 0 || len(action) > MaxPolicyActionBytes || !actionRegex.MatchString(action) {
		return Preflightf("invalid action %q: must match <slice>.<type>.<verb> in lowercase ASCII (1..%d bytes, no wildcards)", action, MaxPolicyActionBytes)
	}
	return nil
}

// IsKnownPortableAction reports whether action is in the Appendix A portable vocabulary.
func IsKnownPortableAction(action string) bool {
	_, ok := knownPortableActions[action]
	return ok
}

// ParsedResource holds the parsed components of a Tier-1 valid resource string.
type ParsedResource struct {
	Raw           string
	Slice         string
	Type          string
	Rest          string
	Bucket        string
	KeyOrPrefix   string
	EntityKind    string // "bucket", "queue", "table", or ""
	EntityName    string // concrete entity name, or "" if wildcard/unknown
	IsWildcard    bool   // true for <slice>:<type>:* or storage:object:*/*
	HasPrefixStar bool   // true for storage:object:<b>/<prefix>*
}

// Anchored returns the concrete AnchoredTarget for r, if r anchors on a known concrete entity.
func (r ParsedResource) Anchored() (AnchoredTarget, bool) {
	if r.IsWildcard || r.EntityKind == "" || r.EntityName == "" {
		return AnchoredTarget{}, false
	}
	switch r.EntityKind {
	case "bucket":
		return AnchoredTarget{Kind: "bucket", Name: r.EntityName, Resource: "storage:bucket:" + r.EntityName}, true
	case "queue":
		return AnchoredTarget{Kind: "queue", Name: r.EntityName, Resource: "queue:queue:" + r.EntityName}, true
	case "table":
		return AnchoredTarget{Kind: "table", Name: r.EntityName, Resource: "tables:table:" + r.EntityName}, true
	default:
		return AnchoredTarget{}, false
	}
}

// ParseResourceSyntax enforces Tier-1 resource grammar (<slice>:<type>:<rest>,
// 1..512 bytes, with per-type name/key validation for known types and printable
// ASCII non-traversal segments for unknown types).
func ParseResourceSyntax(raw string, v Validator) (ParsedResource, *CloudError) {
	if len(raw) == 0 || len(raw) > MaxPolicyResourceBytes {
		return ParsedResource{}, Preflightf("resource %q must be 1..%d bytes", raw, MaxPolicyResourceBytes)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return ParsedResource{}, Preflightf("resource %q contains whitespace or control characters", raw)
		}
	}
	c1 := strings.IndexByte(raw, ':')
	if c1 <= 0 || c1 == len(raw)-1 {
		return ParsedResource{}, Preflightf("resource %q must match <slice>:<type>:<rest>", raw)
	}
	rem := raw[c1+1:]
	c2 := strings.IndexByte(rem, ':')
	if c2 <= 0 || c2 == len(rem)-1 {
		return ParsedResource{}, Preflightf("resource %q must match <slice>:<type>:<rest>", raw)
	}
	sliceName := raw[:c1]
	typeName := rem[:c2]
	rest := rem[c2+1:]
	if !segLowerRegex.MatchString(sliceName) || !segLowerRegex.MatchString(typeName) || len(rest) == 0 {
		return ParsedResource{}, Preflightf("resource %q must have lowercase <slice>:<type> and non-empty <rest>", raw)
	}

	out := ParsedResource{
		Raw:   raw,
		Slice: sliceName,
		Type:  typeName,
		Rest:  rest,
	}

	switch sliceName + ":" + typeName {
	case "storage:bucket":
		if rest == "*" {
			out.IsWildcard = true
			return out, nil
		}
		if strings.Contains(rest, "*") {
			return ParsedResource{}, Preflightf("bucket resource %q supports only whole-class '*' wildcard", raw)
		}
		if err := v.Bucket(rest); err != nil {
			return ParsedResource{}, err
		}
		out.Bucket = rest
		out.EntityKind = "bucket"
		out.EntityName = rest
		return out, nil

	case "storage:object":
		if rest == "*" || rest == "*/*" {
			out.IsWildcard = true
			return out, nil
		}
		slash := strings.IndexByte(rest, '/')
		if slash <= 0 || slash == len(rest)-1 {
			return ParsedResource{}, Preflightf("object resource %q must match storage:object:<bucket>/<key-or-prefix>", raw)
		}
		bkt := rest[:slash]
		keyPart := rest[slash+1:]
		if bkt == "*" {
			out.IsWildcard = true
		} else {
			if strings.Contains(bkt, "*") {
				return ParsedResource{}, Preflightf("object resource %q has invalid bucket wildcard %q", raw, bkt)
			}
			if err := v.Bucket(bkt); err != nil {
				return ParsedResource{}, err
			}
			out.Bucket = bkt
			out.EntityKind = "bucket"
			out.EntityName = bkt
		}
		if strings.HasSuffix(keyPart, "*") {
			prefix := strings.TrimSuffix(keyPart, "*")
			if strings.Contains(prefix, "*") {
				return ParsedResource{}, Preflightf("object resource %q may only contain a single trailing '*'", raw)
			}
			if err := v.Key(prefix + "a"); err != nil {
				return ParsedResource{}, err
			}
			out.KeyOrPrefix = keyPart
			out.HasPrefixStar = true
			return out, nil
		}
		if strings.Contains(keyPart, "*") {
			return ParsedResource{}, Preflightf("object resource %q may only contain a single trailing '*'", raw)
		}
		if err := v.Key(keyPart); err != nil {
			return ParsedResource{}, err
		}
		out.KeyOrPrefix = keyPart
		return out, nil

	case "queue:queue":
		if rest == "*" {
			out.IsWildcard = true
			return out, nil
		}
		if strings.Contains(rest, "*") {
			return ParsedResource{}, Preflightf("queue resource %q supports only whole-class '*' wildcard", raw)
		}
		if err := v.Queue(rest); err != nil {
			return ParsedResource{}, err
		}
		out.EntityKind = "queue"
		out.EntityName = rest
		return out, nil

	case "tables:table":
		if rest == "*" {
			out.IsWildcard = true
			return out, nil
		}
		if strings.Contains(rest, "*") {
			return ParsedResource{}, Preflightf("table resource %q supports only whole-class '*' wildcard", raw)
		}
		if err := v.Table(rest); err != nil {
			return ParsedResource{}, err
		}
		out.EntityKind = "table"
		out.EntityName = rest
		return out, nil

	default:
		// Unknown <slice>:<type> is syntactically valid in Tier 1 if <rest> is
		// printable ASCII without path-traversal segments and with '*' only at the end.
		for i := 0; i < len(rest); i++ {
			if rest[i] < 0x21 || rest[i] > 0x7e {
				return ParsedResource{}, Preflightf("resource %q contains non-printable ASCII in <rest>", raw)
			}
		}
		if rest == "*" {
			out.IsWildcard = true
			return out, nil
		}
		checkRest := rest
		if strings.HasSuffix(checkRest, "*") {
			checkRest = strings.TrimSuffix(checkRest, "*") + "a"
			out.HasPrefixStar = true
		}
		if strings.Contains(checkRest, "*") {
			return ParsedResource{}, Preflightf("resource %q may only contain a single trailing '*'", raw)
		}
		for _, seg := range strings.Split(checkRest, "/") {
			if seg == "" || seg == "." || seg == ".." {
				return ParsedResource{}, Preflightf("resource %q contains an empty, '.' or '..' segment", raw)
			}
		}
		return out, nil
	}
}

// ValidateAndNormalizeStatement enforces Tier-1 syntax on (effect, actions, resources)
// and returns a normalized PolicyStatement with actions and resources sorted ascending
// in UTF-8 byte order (preserving element multiplicity).
func ValidateAndNormalizeStatement(effect string, actions, resources []string, v Validator) (PolicyStatement, *CloudError) {
	normEff, cerr := NormalizeEffect(effect)
	if cerr != nil {
		return PolicyStatement{}, cerr
	}
	if len(actions) == 0 || len(actions) > MaxStatementActions {
		return PolicyStatement{}, Preflightf("statement actions count %d out of range [1, %d]", len(actions), MaxStatementActions)
	}
	if len(resources) == 0 || len(resources) > MaxStatementResources {
		return PolicyStatement{}, Preflightf("statement resources count %d out of range [1, %d]", len(resources), MaxStatementResources)
	}

	normActions := make([]string, len(actions))
	for i, a := range actions {
		if cerr := ValidateActionSyntax(a); cerr != nil {
			return PolicyStatement{}, cerr
		}
		normActions[i] = a
	}
	sort.Strings(normActions)

	normResources := make([]string, len(resources))
	for i, r := range resources {
		if _, cerr := ParseResourceSyntax(r, v); cerr != nil {
			return PolicyStatement{}, cerr
		}
		normResources[i] = r
	}
	sort.Strings(normResources)

	return PolicyStatement{
		Effect:    normEff,
		Actions:   normActions,
		Resources: normResources,
	}, nil
}

// SerializeCanonicalPolicy serializes stmts into the exact canonical v1 JSON
// string (no insignificant whitespace, insertion-ordered statements, sorted
// actions and resources) and enforces MaxPolicyStatements and MaxPolicyDocumentBytes.
func SerializeCanonicalPolicy(stmts []PolicyStatement) (string, *CloudError) {
	if len(stmts) > MaxPolicyStatements {
		return "", Preflightf("policy statement count %d exceeds maximum of %d", len(stmts), MaxPolicyStatements)
	}
	var buf bytes.Buffer
	buf.WriteString(`{"v":1,"statements":[`)
	for i, s := range stmts {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"effect":`)
		eb, _ := json.Marshal(s.Effect)
		buf.Write(eb)
		buf.WriteString(`,"actions":[`)
		for j, a := range s.Actions {
			if j > 0 {
				buf.WriteByte(',')
			}
			ab, _ := json.Marshal(a)
			buf.Write(ab)
		}
		buf.WriteString(`],"resources":[`)
		for j, r := range s.Resources {
			if j > 0 {
				buf.WriteByte(',')
			}
			rb, _ := json.Marshal(r)
			buf.Write(rb)
		}
		buf.WriteString(`]}`)
	}
	buf.WriteString(`]}`)
	out := buf.String()
	if len(out) > MaxPolicyDocumentBytes {
		return "", Preflightf("canonical policy document size %d bytes exceeds %d-byte limit", len(out), MaxPolicyDocumentBytes)
	}
	return out, nil
}

// ParsePolicyDocument strictly parses a JSON policy document, rejecting documents
// > 8192 bytes, malformed JSON, trailing tokens, duplicate object keys at any
// level, unknown fields, v != 1, > 32 statements, or any Tier-1 statement error.
func ParsePolicyDocument(doc string, v Validator) ([]PolicyStatement, string, *CloudError) {
	if len(doc) == 0 || len(doc) > MaxPolicyDocumentBytes {
		return nil, "", Preflightf("policy document size %d bytes out of range [1, %d]", len(doc), MaxPolicyDocumentBytes)
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, "", Preflightf("policy document must be a JSON object")
	}

	seenRoot := make(map[string]bool, 2)
	var (
		hasV          bool
		hasStatements bool
		stmts         []PolicyStatement
	)

	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, "", Preflightf("invalid JSON key in policy document: %v", err)
		}
		key, ok := kt.(string)
		if !ok {
			return nil, "", Preflightf("expected string key in policy document")
		}
		if seenRoot[key] {
			return nil, "", Preflightf("duplicate JSON key %q in policy document", key)
		}
		seenRoot[key] = true

		switch key {
		case "v":
			vt, err := dec.Token()
			if err != nil {
				return nil, "", Preflightf("invalid value for \"v\" in policy document")
			}
			num, ok := vt.(json.Number)
			if !ok || num.String() != "1" {
				return nil, "", Preflightf("unsupported policy document version %v (want 1)", vt)
			}
			hasV = true

		case "statements":
			stTok, err := dec.Token()
			if err != nil || stTok != json.Delim('[') {
				return nil, "", Preflightf("\"statements\" must be a JSON array")
			}
			stmts = []PolicyStatement{}
			for dec.More() {
				if len(stmts) >= MaxPolicyStatements {
					return nil, "", Preflightf("policy statement count exceeds maximum of %d", MaxPolicyStatements)
				}
				stmt, cerr := decodeStrictStatement(dec, v)
				if cerr != nil {
					return nil, "", cerr
				}
				stmts = append(stmts, stmt)
			}
			endArr, err := dec.Token()
			if err != nil || endArr != json.Delim(']') {
				return nil, "", Preflightf("unterminated \"statements\" array")
			}
			hasStatements = true

		default:
			return nil, "", Preflightf("unknown field %q in policy document", key)
		}
	}

	endObj, err := dec.Token()
	if err != nil || endObj != json.Delim('}') {
		return nil, "", Preflightf("unterminated root object in policy document")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "", Preflightf("trailing data after policy document JSON object")
	}
	if !hasV || !hasStatements {
		return nil, "", Preflightf("policy document requires both \"v\" and \"statements\" fields")
	}

	canonical, cerr := SerializeCanonicalPolicy(stmts)
	if cerr != nil {
		return nil, "", cerr
	}
	return stmts, canonical, nil
}

func decodeStrictStatement(dec *json.Decoder, v Validator) (PolicyStatement, *CloudError) {
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return PolicyStatement{}, Preflightf("each policy statement must be a JSON object")
	}
	seen := make(map[string]bool, 3)
	var (
		effect    string
		actions   []string
		resources []string
	)
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return PolicyStatement{}, Preflightf("invalid statement key: %v", err)
		}
		key, ok := kt.(string)
		if !ok {
			return PolicyStatement{}, Preflightf("expected string key in statement")
		}
		if seen[key] {
			return PolicyStatement{}, Preflightf("duplicate key %q in policy statement", key)
		}
		seen[key] = true

		switch key {
		case "effect":
			vt, err := dec.Token()
			if err != nil {
				return PolicyStatement{}, Preflightf("invalid statement \"effect\"")
			}
			s, ok := vt.(string)
			if !ok {
				return PolicyStatement{}, Preflightf("statement \"effect\" must be a string")
			}
			effect = s

		case "actions":
			arr, cerr := decodeStrictStringArray(dec, "actions", MaxStatementActions)
			if cerr != nil {
				return PolicyStatement{}, cerr
			}
			actions = arr

		case "resources":
			arr, cerr := decodeStrictStringArray(dec, "resources", MaxStatementResources)
			if cerr != nil {
				return PolicyStatement{}, cerr
			}
			resources = arr

		default:
			return PolicyStatement{}, Preflightf("unknown field %q in policy statement", key)
		}
	}
	endTok, err := dec.Token()
	if err != nil || endTok != json.Delim('}') {
		return PolicyStatement{}, Preflightf("unterminated statement object")
	}
	if !seen["effect"] || !seen["actions"] || !seen["resources"] {
		return PolicyStatement{}, Preflightf("policy statement requires \"effect\", \"actions\", and \"resources\"")
	}
	return ValidateAndNormalizeStatement(effect, actions, resources, v)
}

func decodeStrictStringArray(dec *json.Decoder, field string, maxItems int) ([]string, *CloudError) {
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		return nil, Preflightf("statement %q must be a JSON array of strings", field)
	}
	var out []string
	for dec.More() {
		if len(out) >= maxItems {
			return nil, Preflightf("statement %q exceeds maximum of %d entries", field, maxItems)
		}
		vt, err := dec.Token()
		if err != nil {
			return nil, Preflightf("invalid element in statement %q: %v", field, err)
		}
		s, ok := vt.(string)
		if !ok {
			return nil, Preflightf("statement %q elements must be strings", field)
		}
		out = append(out, s)
	}
	endTok, err := dec.Token()
	if err != nil || endTok != json.Delim(']') {
		return nil, Preflightf("unterminated %q array", field)
	}
	return out, nil
}

// LintPolicy executes Tier-2 semantic lint over stmts, returning findings in
// deterministic (statement_index, rule_code) order.
func LintPolicy(stmts []PolicyStatement, v Validator) LintReport {
	var findings []LintFinding
	if len(stmts) == 0 {
		findings = append(findings, LintFinding{
			StatementIndex: -1,
			Severity:       "error",
			Code:           "EMPTY_POLICY",
			Message:        "policy must contain at least 1 statement",
		})
	}
	if len(stmts) > MaxPolicyStatements {
		findings = append(findings, LintFinding{
			StatementIndex: -1,
			Severity:       "error",
			Code:           "STATEMENT_COUNT",
			Message:        fmt.Sprintf("policy contains %d statements (maximum %d)", len(stmts), MaxPolicyStatements),
		})
	}

	for idx, stmt := range stmts {
		byCode := map[string]LintFinding{}
		addFinding := func(sev, code, msg string) {
			if _, exists := byCode[code]; !exists {
				byCode[code] = LintFinding{
					StatementIndex: idx,
					Severity:       sev,
					Code:           code,
					Message:        msg,
				}
			}
		}

		if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
			addFinding("error", "EFFECT_INVALID", fmt.Sprintf("statement %d has invalid effect %q (must be Allow or Deny)", idx, stmt.Effect))
		}

		var (
			hasWriteOrCreate bool
			hasDelete        bool
			actionSlices     = map[string]bool{}
		)
		for _, a := range stmt.Actions {
			parts := strings.Split(a, ".")
			slicePrefix := ""
			verb := ""
			if len(parts) > 0 {
				slicePrefix = parts[0]
			}
			if len(parts) == 3 {
				verb = parts[2]
			}
			if escalationNamespaces[slicePrefix] {
				addFinding("error", "ESCALATION_NAMESPACE", fmt.Sprintf("statement %d action %q references forbidden escalation namespace %q", idx, a, slicePrefix))
				continue
			}
			if !IsKnownPortableAction(a) {
				addFinding("error", "UNKNOWN_ACTION", fmt.Sprintf("statement %d action %q is not in the portable action vocabulary", idx, a))
				continue
			}
			actionSlices[slicePrefix] = true
			switch verb {
			case "write", "create", "send":
				hasWriteOrCreate = true
			case "delete":
				hasDelete = true
			}
		}

		var (
			hasWildcardScope   bool
			hasValidKnownRes   bool
			hasMatchedResSlice bool
		)
		for _, r := range stmt.Resources {
			pr, cerr := ParseResourceSyntax(r, v)
			if cerr != nil {
				addFinding("error", "UNKNOWN_RESOURCE", fmt.Sprintf("statement %d resource %q is invalid: %s", idx, r, cerr.Message))
				continue
			}
			if escalationNamespaces[pr.Slice] {
				addFinding("error", "ESCALATION_NAMESPACE", fmt.Sprintf("statement %d resource %q references forbidden escalation namespace %q", idx, r, pr.Slice))
				continue
			}
			if !knownResourceTypes[pr.Slice+":"+pr.Type] {
				addFinding("error", "UNKNOWN_RESOURCE", fmt.Sprintf("statement %d resource %q has unknown resource type \"%s:%s\"", idx, r, pr.Slice, pr.Type))
				continue
			}
			hasValidKnownRes = true
			if actionSlices[pr.Slice] {
				hasMatchedResSlice = true
			}
			if pr.IsWildcard {
				hasWildcardScope = true
				addFinding("warning", "WILDCARD_SCOPE", fmt.Sprintf("statement %d resource %q uses a whole-class wildcard scope", idx, r))
			}
		}

		if len(actionSlices) > 0 && hasValidKnownRes && !hasMatchedResSlice {
			addFinding("error", "UNKNOWN_RESOURCE", fmt.Sprintf("statement %d resources do not match action slice", idx))
		}
		if stmt.Effect == "Allow" && hasWildcardScope && hasWriteOrCreate && hasDelete {
			addFinding("warning", "OVERBROAD_COMBINATION", fmt.Sprintf("statement %d combines write/create and delete actions on a wildcard resource scope", idx))
		}

		codes := make([]string, 0, len(byCode))
		for c := range byCode {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		for _, c := range codes {
			findings = append(findings, byCode[c])
		}
	}

	return LintReport{Findings: findings}
}

// ValidateTargetEntity parses and validates a concrete top-level entity resource
// selector for policy_attach / policy_detach (storage:bucket:<name>,
// queue:queue:<name>, or tables:table:<name> without wildcards).
func ValidateTargetEntity(resource string, v Validator) (AnchoredTarget, *CloudError) {
	pr, cerr := ParseResourceSyntax(resource, v)
	if cerr != nil {
		return AnchoredTarget{}, cerr
	}
	if pr.IsWildcard || pr.HasPrefixStar {
		return AnchoredTarget{}, Preflightf("target resource %q must name a concrete resource without wildcards", resource)
	}
	switch pr.Slice + ":" + pr.Type {
	case "storage:bucket":
		return AnchoredTarget{Kind: "bucket", Name: pr.EntityName, Resource: resource}, nil
	case "queue:queue":
		return AnchoredTarget{Kind: "queue", Name: pr.EntityName, Resource: resource}, nil
	case "tables:table":
		return AnchoredTarget{Kind: "table", Name: pr.EntityName, Resource: resource}, nil
	default:
		return AnchoredTarget{}, Preflightf("target resource %q must be a concrete storage:bucket, queue:queue, or tables:table", resource)
	}
}

// ValidateResourceAttachScope enforces the resource-side scope fence (15 §4.3):
// every statement resource in stmts must be target itself or (when target is
// storage:bucket:<b>) an object scope storage:object:<b>/<key-or-prefix> inside
// that same bucket, and every statement action must belong to the target's slice.
func ValidateResourceAttachScope(target AnchoredTarget, stmts []PolicyStatement, v Validator) *CloudError {
	for i, stmt := range stmts {
		for _, a := range stmt.Actions {
			wantType, ok := knownPortableActions[a]
			if !ok {
				return Preflightf("statement %d action %q is not a supported portable action", i, a)
			}
			actionSlice := strings.SplitN(wantType, ":", 2)[0]
			switch target.Kind {
			case "bucket":
				if actionSlice != "storage" {
					return Preflightf("statement %d action %q is incompatible with bucket target %q", i, a, target.Resource)
				}
			case "queue":
				if actionSlice != "queue" {
					return Preflightf("statement %d action %q is incompatible with queue target %q", i, a, target.Resource)
				}
			case "table":
				if actionSlice != "tables" {
					return Preflightf("statement %d action %q is incompatible with table target %q", i, a, target.Resource)
				}
			}
		}
		for _, r := range stmt.Resources {
			pr, cerr := ParseResourceSyntax(r, v)
			if cerr != nil {
				return cerr
			}
			if pr.IsWildcard {
				return Preflightf("statement %d resource %q uses a whole-class wildcard not permitted on resource attach to %q", i, r, target.Resource)
			}
			switch target.Kind {
			case "bucket":
				if (pr.Slice+":"+pr.Type != "storage:bucket" && pr.Slice+":"+pr.Type != "storage:object") || pr.EntityName != target.Name {
					return Preflightf("statement %d resource %q is outside target bucket %q", i, r, target.Resource)
				}
			case "queue":
				if pr.Slice+":"+pr.Type != "queue:queue" || pr.EntityName != target.Name {
					return Preflightf("statement %d resource %q is outside target queue %q", i, r, target.Resource)
				}
			case "table":
				if pr.Slice+":"+pr.Type != "tables:table" || pr.EntityName != target.Name {
					return Preflightf("statement %d resource %q is outside target table %q", i, r, target.Resource)
				}
			}
		}
	}
	return nil
}

// ValidatePrincipalAttachScope enforces the identity-side scope fence (15 §4.3):
// whole-class wildcards (e.g. storage:bucket:*) are refused pre-flight with
// INVALID_ARGUMENT, and every statement resource must anchor on a concrete
// entity whose existence and run ownership will be verified before attach.
func ValidatePrincipalAttachScope(stmts []PolicyStatement, v Validator) ([]AnchoredTarget, *CloudError) {
	seen := map[string]AnchoredTarget{}
	for i, stmt := range stmts {
		actionSlices := map[string]bool{}
		for _, a := range stmt.Actions {
			wantType, ok := knownPortableActions[a]
			if !ok {
				return nil, Preflightf("statement %d action %q is not a supported portable action", i, a)
			}
			actionSlices[strings.SplitN(wantType, ":", 2)[0]] = true
		}
		for _, r := range stmt.Resources {
			pr, cerr := ParseResourceSyntax(r, v)
			if cerr != nil {
				return nil, cerr
			}
			if pr.IsWildcard {
				return nil, Preflightf("statement %d resource %q uses a whole-class wildcard; policy_attach_principal requires concrete resource scopes", i, r)
			}
			if !actionSlices[pr.Slice] {
				return nil, Preflightf("statement %d resource %q does not match statement action slice", i, r)
			}
			at, ok := pr.Anchored()
			if !ok {
				return nil, Preflightf("statement %d resource %q does not anchor on a concrete bucket, queue, or table", i, r)
			}
			seen[at.Resource] = at
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]AnchoredTarget, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out, nil
}

// ValidatePolicyCheckInputs validates the pre-flight grammar of (principal, action, resource)
// for cloud.policy_check and returns the concrete AnchoredTarget whose existence must be verified.
func ValidatePolicyCheckInputs(principal, action, resource string, v Validator) (AnchoredTarget, *CloudError) {
	if cerr := ValidatePrincipal(principal); cerr != nil {
		return AnchoredTarget{}, cerr
	}
	if cerr := ValidateActionSyntax(action); cerr != nil {
		return AnchoredTarget{}, cerr
	}
	if !IsKnownPortableAction(action) {
		return AnchoredTarget{}, Preflightf("unknown portable action %q in policy_check", action)
	}
	pr, cerr := ParseResourceSyntax(resource, v)
	if cerr != nil {
		return AnchoredTarget{}, cerr
	}
	if pr.IsWildcard || pr.HasPrefixStar {
		return AnchoredTarget{}, Preflightf("policy_check resource %q must be a concrete resource without wildcards", resource)
	}
	at, ok := pr.Anchored()
	if !ok {
		return AnchoredTarget{}, Preflightf("policy_check resource %q is not a supported portable resource", resource)
	}
	actionSlice := strings.SplitN(action, ".", 2)[0]
	if pr.Slice != actionSlice {
		return AnchoredTarget{}, Preflightf("policy_check action %q is incompatible with resource %q", action, resource)
	}
	return at, nil
}

// MatchPolicyResource reports whether a statement resource pattern (exact or
// single trailing '*' prefix) matches a concrete resource string.
func MatchPolicyResource(pattern, resource string) bool {
	if pattern == resource {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(resource, prefix)
	}
	return false
}

// EvaluatePolicies evaluates the union of all active attachments for principal
// against (action, resource) using the portable evaluation contract (15 §2.4):
//   - Explicit Deny in any matching statement across any attachment returns false.
//   - Otherwise, if at least one matching statement has Allow, returns true.
//   - Otherwise returns false (default deny).
func EvaluatePolicies(attachments []PolicyAttachment, principal, action, resource string) bool {
	allowed := false
	for _, att := range attachments {
		if att.Principal != principal {
			continue
		}
		for _, stmt := range att.Statements {
			actionMatched := false
			for _, a := range stmt.Actions {
				if a == action {
					actionMatched = true
					break
				}
			}
			if !actionMatched {
				continue
			}
			resMatched := false
			for _, r := range stmt.Resources {
				if MatchPolicyResource(r, resource) {
					resMatched = true
					break
				}
			}
			if !resMatched {
				continue
			}
			if stmt.Effect == "Deny" {
				return false
			}
			if stmt.Effect == "Allow" {
				allowed = true
			}
		}
	}
	return allowed
}
