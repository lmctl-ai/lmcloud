// SPDX-License-Identifier: MIT

// Package safety implements the Stage 1 live-mode safety foundation for
// lmcloud hosts: immutable live policy validation and double opt-in gates,
// append-only fsynced recovery journals with exclusive flock leases, regional
// price-table loading and reservation-based cost metering, ownership-verifying
// adapter guards, LIFO recovery sweeps, and multi-invocation session
// supervision. It makes zero cloud network calls itself.
package safety

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

const (
	// PolicySchemaVersion is the current live-policy.json format version.
	PolicySchemaVersion = 1

	// DefaultCostCapUSD is the default per-run cost cap ($0.05).
	DefaultCostCapUSD = 0.05
	// HardCostCeilingUSD is the absolute maximum authorized per-run/campaign cap ($0.25).
	HardCostCeilingUSD = 0.25
	// DefaultCleanupReserveUSD is the portion of the cap reserved exclusively for teardown/janitor ($0.01).
	DefaultCleanupReserveUSD = 0.01

	// Default resource and runtime bounds (live-mode-design.md §5).
	DefaultMaxBuckets               = 4
	DefaultMaxQueues                = 4
	DefaultMaxObjects               = 100
	DefaultMaxMessages              = 100
	DefaultMaxObjectBytes           = 16 * 1024 * 1024 // 16 MiB
	DefaultMaxMessageBytes          = 48 * 1024        // 48 KiB
	DefaultMaxTotalBytes            = 64 * 1024 * 1024 // 64 MiB
	DefaultMaxRunSeconds            = 20 * 60          // 20 minutes
	DefaultMaxCleanupSeconds        = 5 * 60           // 5 minutes
	DefaultMaxRequestTimeoutSeconds = 10               // 10 seconds per physical cloud request attempt

	// ReservedLivePrefix is the mandatory prefix for any resource created in live mode.
	ReservedLivePrefix = "lmcloud-conf-"

	// Ownership tag keys written to provider resources.
	TagKeyRunID       = "lmcloud_run_id"
	TagKeyOwnerNonce  = "lmcloud_owner_nonce"
	TagKeyCreateToken = "lmcloud_create_token"
	TagKeyCreatedAt   = "lmcloud_created_at"
)

var (
	// runIDPattern requires `run-<epoch10+>-<12hex>` and rejects demo IDs like `r0`.
	runIDPattern = regexp.MustCompile(`^run-[0-9]{10,}-[0-9a-f]{12}$`)
	// hex12Pattern matches the 12-hex suffix of a RunID used in short resource names.
	hex12Pattern = regexp.MustCompile(`^[0-9a-f]{12}$`)
	// liveNamePattern matches portable bucket/queue names (3..63 chars, lowercase alphanumeric + hyphens).
	liveNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
)

// ExecutionMode identifies whether a host invocation routes to the in-memory
// fake, a loopback simulator, or a live cloud endpoint.
type ExecutionMode string

const (
	ModeFake ExecutionMode = "fake"
	ModeSim  ExecutionMode = "sim"
	ModeLive ExecutionMode = "live"
)

// RunLimits bounds the resources, bytes, and wall-clock duration of a live run.
type RunLimits struct {
	MaxBuckets        int   `json:"max_buckets"`
	MaxQueues         int   `json:"max_queues"`
	MaxObjects        int   `json:"max_objects"`
	MaxMessages       int   `json:"max_messages"`
	MaxObjectBytes    int64 `json:"max_object_bytes"`
	MaxMessageBytes   int64 `json:"max_message_bytes"`
	MaxTotalBytes     int64 `json:"max_total_bytes"`
	MaxRunSeconds     int   `json:"max_run_seconds"`
	MaxCleanupSeconds int   `json:"max_cleanup_seconds"`
}

// DefaultRunLimits returns the standard live conformance bounds.
func DefaultRunLimits() RunLimits {
	return RunLimits{
		MaxBuckets:        DefaultMaxBuckets,
		MaxQueues:         DefaultMaxQueues,
		MaxObjects:        DefaultMaxObjects,
		MaxMessages:       DefaultMaxMessages,
		MaxObjectBytes:    DefaultMaxObjectBytes,
		MaxMessageBytes:   DefaultMaxMessageBytes,
		MaxTotalBytes:     DefaultMaxTotalBytes,
		MaxRunSeconds:     DefaultMaxRunSeconds,
		MaxCleanupSeconds: DefaultMaxCleanupSeconds,
	}
}

func (l *RunLimits) applyDefaults() {
	d := DefaultRunLimits()
	if l.MaxBuckets <= 0 {
		l.MaxBuckets = d.MaxBuckets
	}
	if l.MaxQueues <= 0 {
		l.MaxQueues = d.MaxQueues
	}
	if l.MaxObjects <= 0 {
		l.MaxObjects = d.MaxObjects
	}
	if l.MaxMessages <= 0 {
		l.MaxMessages = d.MaxMessages
	}
	if l.MaxObjectBytes <= 0 {
		l.MaxObjectBytes = d.MaxObjectBytes
	}
	if l.MaxMessageBytes <= 0 {
		l.MaxMessageBytes = d.MaxMessageBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.MaxRunSeconds <= 0 {
		l.MaxRunSeconds = d.MaxRunSeconds
	}
	if l.MaxCleanupSeconds <= 0 {
		l.MaxCleanupSeconds = d.MaxCleanupSeconds
	}
}

func (l RunLimits) validate() error {
	if l.MaxBuckets < 1 || l.MaxBuckets > DefaultMaxBuckets {
		return fmt.Errorf("limits.max_buckets %d must be in 1..%d", l.MaxBuckets, DefaultMaxBuckets)
	}
	if l.MaxQueues < 1 || l.MaxQueues > DefaultMaxQueues {
		return fmt.Errorf("limits.max_queues %d must be in 1..%d", l.MaxQueues, DefaultMaxQueues)
	}
	if l.MaxObjects < 1 || l.MaxObjects > DefaultMaxObjects {
		return fmt.Errorf("limits.max_objects %d must be in 1..%d", l.MaxObjects, DefaultMaxObjects)
	}
	if l.MaxMessages < 1 || l.MaxMessages > DefaultMaxMessages {
		return fmt.Errorf("limits.max_messages %d must be in 1..%d", l.MaxMessages, DefaultMaxMessages)
	}
	if l.MaxObjectBytes < 1 || l.MaxObjectBytes > DefaultMaxObjectBytes {
		return fmt.Errorf("limits.max_object_bytes %d must be in 1..%d", l.MaxObjectBytes, DefaultMaxObjectBytes)
	}
	if l.MaxMessageBytes < 1 || l.MaxMessageBytes > DefaultMaxMessageBytes {
		return fmt.Errorf("limits.max_message_bytes %d must be in 1..%d", l.MaxMessageBytes, DefaultMaxMessageBytes)
	}
	if l.MaxTotalBytes < 1 || l.MaxTotalBytes > DefaultMaxTotalBytes {
		return fmt.Errorf("limits.max_total_bytes %d must be in 1..%d", l.MaxTotalBytes, DefaultMaxTotalBytes)
	}
	if l.MaxRunSeconds < 1 || l.MaxRunSeconds > DefaultMaxRunSeconds {
		return fmt.Errorf("limits.max_run_seconds %d must be in 1..%d", l.MaxRunSeconds, DefaultMaxRunSeconds)
	}
	if l.MaxCleanupSeconds < 1 || l.MaxCleanupSeconds > DefaultMaxCleanupSeconds {
		return fmt.Errorf("limits.max_cleanup_seconds %d must be in 1..%d", l.MaxCleanupSeconds, DefaultMaxCleanupSeconds)
	}
	return nil
}

// CostPolicy configures the per-run cost cap, hard ceiling, and teardown reserve.
type CostPolicy struct {
	CapUSD            float64 `json:"cap_usd"`
	CeilingUSD        float64 `json:"ceiling_usd"`
	CleanupReserveUSD float64 `json:"cleanup_reserve_usd"`
}

func (c *CostPolicy) applyDefaults() {
	if c.CapUSD == 0 {
		c.CapUSD = DefaultCostCapUSD
	}
	if c.CeilingUSD == 0 {
		c.CeilingUSD = HardCostCeilingUSD
	}
	if c.CleanupReserveUSD == 0 {
		c.CleanupReserveUSD = DefaultCleanupReserveUSD
	}
}

func (c CostPolicy) validate() error {
	if c.CeilingUSD <= 0 || c.CeilingUSD > HardCostCeilingUSD {
		return fmt.Errorf("cost.ceiling_usd %.6f must be in (0, %.2f]", c.CeilingUSD, HardCostCeilingUSD)
	}
	if c.CapUSD <= 0 || c.CapUSD > c.CeilingUSD {
		return fmt.Errorf("cost.cap_usd %.6f must be in (0, %.6f]", c.CapUSD, c.CeilingUSD)
	}
	if c.CleanupReserveUSD <= 0 || c.CleanupReserveUSD >= c.CapUSD {
		return fmt.Errorf("cost.cleanup_reserve_usd %.6f must be in (0, %.6f)", c.CleanupReserveUSD, c.CapUSD)
	}
	return nil
}

// Policy represents the immutable operator-approved `live-policy.json` file.
type Policy struct {
	SchemaVersion    int                 `json:"schema_version"`
	Provider         string              `json:"provider"`
	AllowedAccounts  []string            `json:"allowed_accounts"`
	AllowedScopes    []string            `json:"allowed_scopes"`
	AllowedRegions   []string            `json:"allowed_regions"`
	AllowedEndpoints map[string][]string `json:"allowed_endpoints"`
	AuthMode         string              `json:"auth_mode"`
	AllowMutations   bool                `json:"allow_mutations"`
	Limits           RunLimits           `json:"limits"`
	Cost             CostPolicy          `json:"cost"`
	JournalDir       string              `json:"journal_dir"`

	hash string
}

var validProviders = map[string]bool{
	"aws":   true,
	"azure": true,
	"gcp":   true,
	"oci":   true,
}

var validAuthModes = map[string]map[string]bool{
	"aws": {
		"imds_role":    true,
		"profile":      true,
		"web_identity": true,
		"env_session":  true,
	},
	"azure": {
		"aad":        true,
		"shared_key": true,
		"sas":        true,
	},
	"gcp": {
		"adc_impersonation": true,
		"service_account":   true,
		"wif":               true,
	},
	"oci": {
		"oci_profile":        true,
		"instance_principal": true,
		"resource_principal": true,
	},
}

// DefaultAWSLivePolicy returns the operator-approved Stage 1 AWS live policy
// for account 254332045686, region us-east-1, role awsspot-admin.
func DefaultAWSLivePolicy(journalDir string, allowMutations bool) Policy {
	p := Policy{
		SchemaVersion:   PolicySchemaVersion,
		Provider:        "aws",
		AllowedAccounts: []string{"254332045686"},
		AllowedScopes: []string{
			"arn:aws:iam::254332045686:role/awsspot-admin",
			"arn:aws:sts::254332045686:assumed-role/awsspot-admin/",
		},
		AllowedRegions: []string{"us-east-1"},
		AllowedEndpoints: map[string][]string{
			"storage": {"https://s3.us-east-1.amazonaws.com", "https://s3.amazonaws.com"},
			"queue":   {"https://sqs.us-east-1.amazonaws.com"},
		},
		AuthMode:       "imds_role",
		AllowMutations: allowMutations,
		Limits:         DefaultRunLimits(),
		Cost: CostPolicy{
			CapUSD:            DefaultCostCapUSD,
			CeilingUSD:        HardCostCeilingUSD,
			CleanupReserveUSD: DefaultCleanupReserveUSD,
		},
		JournalDir: journalDir,
	}
	p.computeHash()
	return p
}

// ParsePolicy strictly decodes and validates a JSON policy document, rejecting
// any unknown fields or trailing data.
func ParsePolicy(raw []byte) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse live policy: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return Policy{}, errors.New("parse live policy: trailing data after JSON object")
	}
	p.Limits.applyDefaults()
	p.Cost.applyDefaults()
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	p.computeHash()
	return p, nil
}

// LoadPolicy reads, parses, and validates a policy file from disk. If expectedHash
// is non-empty, LoadPolicy verifies that the policy's canonical hash matches.
func LoadPolicy(path, expectedHash string) (Policy, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Policy{}, errors.New("live policy path must not be empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Policy{}, fmt.Errorf("stat live policy: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("live policy %q must be a regular file", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read live policy: %w", err)
	}
	p, err := ParsePolicy(raw)
	if err != nil {
		return Policy{}, err
	}
	if expectedHash = strings.TrimSpace(expectedHash); expectedHash != "" && p.Hash() != expectedHash {
		return Policy{}, fmt.Errorf("live policy hash mismatch: got %s, want %s", p.Hash(), expectedHash)
	}
	return p, nil
}

func (p *Policy) computeHash() {
	cp := *p
	cp.hash = ""
	raw, _ := json.Marshal(cp)
	sum := sha256.Sum256(raw)
	p.hash = hex.EncodeToString(sum[:])
}

// Hash returns the canonical SHA-256 hex digest of the validated policy.
func (p Policy) Hash() string {
	if p.hash != "" {
		return p.hash
	}
	p.computeHash()
	return p.hash
}

// Validate checks every field of the policy for safety invariants.
func (p *Policy) Validate() error {
	p.Limits.applyDefaults()
	p.Cost.applyDefaults()

	if p.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("unsupported policy schema_version %d (want %d)", p.SchemaVersion, PolicySchemaVersion)
	}
	prov := strings.TrimSpace(p.Provider)
	if !validProviders[prov] {
		return fmt.Errorf("invalid policy provider %q", p.Provider)
	}
	if len(p.AllowedAccounts) == 0 {
		return errors.New("policy allowed_accounts must not be empty")
	}
	for _, acct := range p.AllowedAccounts {
		acct = strings.TrimSpace(acct)
		if acct == "" || strings.Contains(acct, "*") {
			return fmt.Errorf("invalid policy allowed_account %q (wildcards and empty strings forbidden)", acct)
		}
	}
	if len(p.AllowedScopes) == 0 {
		return errors.New("policy allowed_scopes must not be empty")
	}
	for _, sc := range p.AllowedScopes {
		sc = strings.TrimSpace(sc)
		if sc == "" || sc == "*" {
			return fmt.Errorf("invalid policy allowed_scope %q", sc)
		}
	}
	if len(p.AllowedRegions) == 0 {
		return errors.New("policy allowed_regions must not be empty")
	}
	for _, reg := range p.AllowedRegions {
		reg = strings.TrimSpace(reg)
		if reg == "" || strings.Contains(reg, "*") {
			return fmt.Errorf("invalid policy allowed_region %q", reg)
		}
	}
	modes := validAuthModes[prov]
	if !modes[p.AuthMode] {
		return fmt.Errorf("unsupported auth_mode %q for provider %q", p.AuthMode, prov)
	}
	if len(p.AllowedEndpoints) == 0 {
		return errors.New("policy allowed_endpoints must not be empty")
	}
	for svc, origins := range p.AllowedEndpoints {
		if hostkit.ValidateService(svc, false) != nil {
			return fmt.Errorf("invalid service %q in policy allowed_endpoints", svc)
		}
		if len(origins) == 0 {
			return fmt.Errorf("policy allowed_endpoints[%q] must not be empty", svc)
		}
		for _, orig := range origins {
			if err := ValidateLiveOrigin(orig); err != nil {
				return fmt.Errorf("policy allowed_endpoints[%q]: %w", svc, err)
			}
		}
	}
	if err := p.Limits.validate(); err != nil {
		return err
	}
	if err := p.Cost.validate(); err != nil {
		return err
	}
	jDir := strings.TrimSpace(p.JournalDir)
	if jDir == "" || !filepath.IsAbs(jDir) {
		return fmt.Errorf("policy journal_dir %q must be a non-empty absolute path", p.JournalDir)
	}
	p.computeHash()
	return nil
}

// ValidateLiveOrigin verifies that raw is a canonical HTTPS non-loopback origin
// with no userinfo, query, fragment, or wildcard.
func ValidateLiveOrigin(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "*") {
		return errors.New("live origin must be non-empty and contain no wildcards")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("malformed live origin URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("live origin must use https:// (got %q)", u.Scheme)
	}
	if u.User != nil {
		return errors.New("live origin must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("live origin must not contain query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("live origin has empty host")
	}
	if hostkit.IsLoopbackHost(host) {
		return fmt.Errorf("live origin %q must not be a loopback address", host)
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return fmt.Errorf("live origin %q must not be a private or unspecified IP", host)
	}
	return nil
}

// CheckScope verifies that an attested identity and scope match this policy.
func (p Policy) CheckScope(provider, account, principalOrScope, region string) error {
	if provider != p.Provider {
		return fmt.Errorf("provider mismatch: attested %q, policy requires %q", provider, p.Provider)
	}
	if !slices.Contains(p.AllowedAccounts, account) {
		return fmt.Errorf("account %q is not in policy allowed_accounts %v", account, p.AllowedAccounts)
	}
	if !slices.Contains(p.AllowedRegions, region) {
		return fmt.Errorf("region %q is not in policy allowed_regions %v", region, p.AllowedRegions)
	}
	matchedScope := false
	for _, pat := range p.AllowedScopes {
		if principalOrScope == pat || (strings.HasSuffix(pat, "/") && strings.HasPrefix(principalOrScope, pat)) {
			matchedScope = true
			break
		}
	}
	if !matchedScope {
		return fmt.Errorf("principal/scope %q is not permitted by policy allowed_scopes %v", principalOrScope, p.AllowedScopes)
	}
	return nil
}

// CheckEndpoint verifies that endpointURL is in the policy's allowed_endpoints for service.
func (p Policy) CheckEndpoint(service, endpointURL string) error {
	if err := ValidateLiveOrigin(endpointURL); err != nil {
		return err
	}
	allowed := p.AllowedEndpoints[service]
	if len(allowed) == 0 {
		return fmt.Errorf("service %q has no allowed_endpoints in policy", service)
	}
	u, err := url.Parse(strings.TrimSpace(endpointURL))
	if err != nil {
		return errors.New("malformed endpoint URL")
	}
	candOrigin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	for _, a := range allowed {
		au, err := url.Parse(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		allowOrigin := strings.ToLower(au.Scheme) + "://" + strings.ToLower(au.Host)
		if candOrigin == allowOrigin && (au.Path == "" || au.Path == "/" || strings.HasPrefix(u.Path, au.Path)) {
			return nil
		}
	}
	return fmt.Errorf("endpoint origin %q is not in policy allowed_endpoints[%q]", candOrigin, service)
}

// GateConfig describes the environment and endpoint inputs to the live mode gate.
type GateConfig struct {
	// HostPrefix is the host's env prefix (e.g. "LMAWS", "LMAZURE", "LMGCP", "LMOCI").
	HostPrefix string
	// Provider is the canonical provider name ("aws", "azure", "gcp", "oci").
	Provider string
	// Endpoints is the host's EndpointResolver.
	Endpoints *hostkit.EndpointResolver
	// PolicyPath overrides LMCLOUD_LIVE_POLICY / <PREFIX>_LIVE_POLICY.
	PolicyPath string
	// PolicyHash overrides LMCLOUD_POLICY_SHA256.
	PolicyHash string
	// OS overrides runtime.GOOS for testing platform gates.
	OS string
	// AllowNonAWSLive permits non-AWS providers in unit tests; false by default
	// per operator Stage 1 decision (AWS only for now).
	AllowNonAWSLive bool
}

// GateResult holds the resolved execution mode and (when Mode == ModeLive) the validated Policy.
type GateResult struct {
	Mode   ExecutionMode
	Policy *Policy
}

// ResolveExecutionMode enforces the double opt-in gate (LMCLOUD_LIVE=1 AND
// LM<HOST>_LIVE=1), rejects mixed live+loopback configurations, refuses
// Windows for live mode, and never falls back from live to fake.
func ResolveExecutionMode(cfg GateConfig) (GateResult, *hostkit.CloudError) {
	prefix := strings.TrimSpace(cfg.HostPrefix)
	if prefix == "" {
		prefix = "LM" + strings.ToUpper(cfg.Provider)
	}
	globalLive := strings.TrimSpace(os.Getenv("LMCLOUD_LIVE")) == "1"
	hostLiveVar := prefix + "_LIVE"
	hostLive := strings.TrimSpace(os.Getenv(hostLiveVar)) == "1"

	// Partial opt-in is always a configuration error (never silently ignored).
	if globalLive != hostLive {
		return GateResult{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LiveDoubleOptInRequired",
			fmt.Sprintf("live mode requires both LMCLOUD_LIVE=1 and %s=1 (got LMCLOUD_LIVE=%q, %s=%q)",
				hostLiveVar, os.Getenv("LMCLOUD_LIVE"), hostLiveVar, os.Getenv(hostLiveVar)),
		)
	}

	// Inspect resolved endpoints for storage and queue.
	var hasLoopback, hasRemote bool
	var loopbackSvc, remoteSvc string
	if cfg.Endpoints != nil {
		for _, svc := range []string{"storage", "queue"} {
			ep, _, cerr := cfg.Endpoints.Resolve(svc)
			if cerr != nil {
				return GateResult{}, cerr
			}
			if ep == "" {
				continue
			}
			u, err := url.Parse(ep)
			if err != nil {
				return GateResult{}, hostkit.Preflightf("invalid %s endpoint", svc)
			}
			if hostkit.IsLoopbackHost(u.Hostname()) {
				hasLoopback = true
				loopbackSvc = svc
			} else {
				hasRemote = true
				remoteSvc = svc
			}
		}
	}

	if !globalLive {
		if hasRemote {
			return GateResult{}, hostkit.ProviderError(
				hostkit.Unauthenticated,
				0,
				"LiveOptInRequired",
				fmt.Sprintf("non-loopback %s endpoint requires LMCLOUD_LIVE=1 and %s=1", remoteSvc, hostLiveVar),
			)
		}
		if hasLoopback {
			if hasLoopback && hasRemote {
				return GateResult{}, hostkit.ProviderError(
					hostkit.InvalidArgument,
					0,
					"MixedEndpointConfig",
					"cannot mix loopback simulator and remote endpoints",
				)
			}
			return GateResult{Mode: ModeSim}, nil
		}
		return GateResult{Mode: ModeFake}, nil
	}

	// Live mode is active: never fall back to fake or simulator.
	goos := cfg.OS
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos == "windows" {
		return GateResult{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"WindowsLiveUnsupported",
			"live mode is refused on Windows (flock and POSIX 0700/0600 journal guarantees required)",
		)
	}
	if hasLoopback {
		return GateResult{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"MixedLiveLoopbackConfig",
			fmt.Sprintf("live mode cannot be combined with loopback %s endpoint", loopbackSvc),
		)
	}
	// Also reject any raw emulator environment variables set alongside live mode.
	for _, emuVar := range []string{
		"STORAGE_EMULATOR_HOST",
		"PUBSUB_EMULATOR_HOST",
		"LMCLOUD_ENDPOINT",
		prefix + "_ENDPOINT",
	} {
		if v := strings.TrimSpace(os.Getenv(emuVar)); v != "" {
			if u, err := url.Parse(v); err != nil || u.Hostname() == "" || hostkit.IsLoopbackHost(u.Hostname()) || strings.EqualFold(u.Scheme, "http") {
				return GateResult{}, hostkit.ProviderError(
					hostkit.InvalidArgument,
					0,
					"MixedLiveLoopbackConfig",
					fmt.Sprintf("live mode cannot be combined with emulator/loopback environment variable %s", emuVar),
				)
			}
		}
	}

	if !cfg.AllowNonAWSLive && cfg.Provider != "aws" {
		return GateResult{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"ProviderLiveNotEnabled",
			fmt.Sprintf("live mode is currently enabled only for aws (got provider %q)", cfg.Provider),
		)
	}

	polPath := strings.TrimSpace(cfg.PolicyPath)
	if polPath == "" {
		polPath = strings.TrimSpace(os.Getenv(prefix + "_LIVE_POLICY"))
	}
	if polPath == "" {
		polPath = strings.TrimSpace(os.Getenv("LMCLOUD_LIVE_POLICY"))
	}
	if polPath == "" {
		return GateResult{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LivePolicyRequired",
			fmt.Sprintf("live mode requires a policy file via LMCLOUD_LIVE_POLICY or %s_LIVE_POLICY", prefix),
		)
	}
	polHash := strings.TrimSpace(cfg.PolicyHash)
	if polHash == "" {
		polHash = strings.TrimSpace(os.Getenv("LMCLOUD_POLICY_SHA256"))
	}
	pol, err := LoadPolicy(polPath, polHash)
	if err != nil {
		return GateResult{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"InvalidLivePolicy",
			err.Error(),
		)
	}
	if pol.Provider != cfg.Provider {
		return GateResult{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"InvalidLivePolicy",
			fmt.Sprintf("policy provider %q does not match host provider %q", pol.Provider, cfg.Provider),
		)
	}
	return GateResult{Mode: ModeLive, Policy: &pol}, nil
}

// NewRunID allocates a collision-resistant run ID (`run-<unix>-<12hex>`).
func NewRunID(now time.Time) string {
	if now.IsZero() {
		now = time.Now()
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return fmt.Sprintf("run-%d-%s", now.UTC().Unix(), hex.EncodeToString(b[:]))
}

// ValidateRunID verifies that runID matches `^run-[0-9]{10,}-[0-9a-f]{12}$`.
func ValidateRunID(runID string) error {
	if !runIDPattern.MatchString(strings.TrimSpace(runID)) {
		return fmt.Errorf("invalid run ID %q (must match ^run-[0-9]{10,}-[0-9a-f]{12}$)", runID)
	}
	return nil
}

// RunShortToken extracts the 12-hex nonce suffix from a valid RunID, or returns
// a 12-hex token if raw is already a 12-hex string.
func RunShortToken(runID string) (string, error) {
	runID = strings.TrimSpace(runID)
	if hex12Pattern.MatchString(runID) {
		return runID, nil
	}
	if err := ValidateRunID(runID); err != nil {
		return "", err
	}
	idx := strings.LastIndexByte(runID, '-')
	return runID[idx+1:], nil
}

// ExpectedLivePrefix returns the mandatory resource prefix `lmcloud-conf-<12hex>-`
// for the given runID.
func ExpectedLivePrefix(runID string) (string, error) {
	tok, err := RunShortToken(runID)
	if err != nil {
		return "", err
	}
	return ReservedLivePrefix + tok + "-", nil
}

// FormatLiveResourceName constructs a compliant `lmcloud-conf-<run12>-<case>-<seq>`
// name within 63 bytes.
func FormatLiveResourceName(runID, caseSlug string, seq int) (string, error) {
	pfx, err := ExpectedLivePrefix(runID)
	if err != nil {
		return "", err
	}
	slug := strings.ToLower(strings.Trim(caseSlug, "-"))
	if slug == "" {
		slug = "r"
	}
	name := fmt.Sprintf("%s%s-%d", pfx, slug, seq)
	if err := ValidateLiveResourceName(runID, name); err != nil {
		return "", err
	}
	return name, nil
}

// ValidateLiveResourceName verifies that name carries this run's reserved prefix
// (`lmcloud-conf-<run12>-` or `lmcloud-conf-<runID>-`) and satisfies portable
// bucket/queue naming rules.
func ValidateLiveResourceName(runID, name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 3 || len(name) > 63 || !liveNamePattern.MatchString(name) {
		return fmt.Errorf("live resource name %q must be 3..63 chars matching ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", name)
	}
	if strings.Contains(name, "--") {
		return fmt.Errorf("live resource name %q must not contain consecutive hyphens", name)
	}
	if strings.HasPrefix(name, "goog") || strings.Contains(name, "google") || strings.Contains(name, "g00gle") {
		return fmt.Errorf("live resource name %q contains reserved google substring", name)
	}
	shortPfx, err := ExpectedLivePrefix(runID)
	if err != nil {
		return err
	}
	fullPfx := ReservedLivePrefix + strings.TrimSpace(runID) + "-"
	if !strings.HasPrefix(name, shortPfx) && !strings.HasPrefix(name, fullPfx) {
		return fmt.Errorf("live resource name %q must start with %q (or %q)", name, shortPfx, fullPfx)
	}
	if name == strings.TrimSuffix(shortPfx, "-") || name == strings.TrimSuffix(fullPfx, "-") {
		return fmt.Errorf("live resource name %q must include a case/sequence suffix after the run prefix", name)
	}
	return nil
}
