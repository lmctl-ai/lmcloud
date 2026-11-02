// SPDX-License-Identifier: MIT

package safety

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

func TestDefaultAWSLivePolicy_ParseAndLoad(t *testing.T) {
	dir := t.TempDir()
	pol := DefaultAWSLivePolicy(dir, true)
	if err := pol.Validate(); err != nil {
		t.Fatalf("DefaultAWSLivePolicy Validate: %v", err)
	}
	if pol.Hash() == "" {
		t.Fatal("expected non-empty policy hash")
	}

	raw, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	polPath := filepath.Join(dir, "live-policy.json")
	if err := os.WriteFile(polPath, raw, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	loaded, err := LoadPolicy(polPath, pol.Hash())
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if loaded.Hash() != pol.Hash() {
		t.Fatalf("hash mismatch: got %s, want %s", loaded.Hash(), pol.Hash())
	}

	if _, err := LoadPolicy(polPath, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected LoadPolicy to reject hash mismatch")
	}
}

func TestParsePolicy_StrictValidation(t *testing.T) {
	dir := t.TempDir()
	base := DefaultAWSLivePolicy(dir, false)
	raw, _ := json.Marshal(base)

	// Reject unknown fields.
	unknown := strings.TrimSuffix(string(raw), "}") + `,"extra":true}`
	if _, err := ParsePolicy([]byte(unknown)); err == nil {
		t.Fatal("expected unknown field to fail")
	}

	// Reject trailing data.
	if _, err := ParsePolicy(append(raw, []byte(" {}")...)); err == nil {
		t.Fatal("expected trailing data to fail")
	}

	// Reject wildcard account.
	bad := base
	bad.AllowedAccounts = []string{"*"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected wildcard account to fail")
	}

	// Reject loopback or http endpoint.
	bad = base
	bad.AllowedEndpoints = map[string][]string{
		"storage": {"http://s3.us-east-1.amazonaws.com"},
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected http endpoint to fail")
	}
	bad.AllowedEndpoints = map[string][]string{
		"storage": {"https://127.0.0.1:4566"},
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected loopback endpoint to fail")
	}

	// Reject cost cap > ceiling or ceiling > 0.25.
	bad = base
	bad.Cost.CeilingUSD = 0.50
	if err := bad.Validate(); err == nil {
		t.Fatal("expected ceiling > 0.25 to fail")
	}
	bad = base
	bad.Cost.CapUSD = 0.30
	if err := bad.Validate(); err == nil {
		t.Fatal("expected cap > ceiling to fail")
	}

	// CheckScope and CheckEndpoint.
	if err := base.CheckScope("aws", "254332045686", "arn:aws:sts::254332045686:assumed-role/awsspot-admin/i-123", "us-east-1"); err != nil {
		t.Fatalf("CheckScope valid assumed role failed: %v", err)
	}
	if err := base.CheckScope("aws", "999999999999", "arn:aws:iam::254332045686:role/awsspot-admin", "us-east-1"); err == nil {
		t.Fatal("expected wrong account to fail CheckScope")
	}
	if err := base.CheckScope("aws", "254332045686", "arn:aws:iam::254332045686:role/other", "us-east-1"); err == nil {
		t.Fatal("expected wrong role to fail CheckScope")
	}
	if err := base.CheckEndpoint("storage", "https://s3.us-east-1.amazonaws.com"); err != nil {
		t.Fatalf("CheckEndpoint valid failed: %v", err)
	}
	if err := base.CheckEndpoint("storage", "https://s3.us-west-2.amazonaws.com"); err == nil {
		t.Fatal("expected unlisted endpoint to fail CheckEndpoint")
	}
}

func TestResolveExecutionMode_DoubleOptInAndIsolation(t *testing.T) {
	dir := t.TempDir()
	pol := DefaultAWSLivePolicy(dir, true)
	raw, _ := json.Marshal(pol)
	polPath := filepath.Join(dir, "live-policy.json")
	if err := os.WriteFile(polPath, raw, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	clearEnv := func(t *testing.T) {
		for _, k := range []string{
			"LMCLOUD_LIVE", "LMAWS_LIVE", "LMCLOUD_LIVE_POLICY", "LMAWS_LIVE_POLICY",
			"LMCLOUD_POLICY_SHA256", "LMCLOUD_ENDPOINT", "LMAWS_ENDPOINT",
			"STORAGE_EMULATOR_HOST", "PUBSUB_EMULATOR_HOST",
		} {
			t.Setenv(k, "")
		}
	}

	// 1. Default -> ModeFake.
	clearEnv(t)
	res, cerr := ResolveExecutionMode(GateConfig{HostPrefix: "LMAWS", Provider: "aws"})
	if cerr != nil || res.Mode != ModeFake {
		t.Fatalf("default mode: got (%+v, %v), want ModeFake", res, cerr)
	}

	// 2. Partial opt-in (only LMCLOUD_LIVE=1) -> error.
	clearEnv(t)
	t.Setenv("LMCLOUD_LIVE", "1")
	if _, cerr := ResolveExecutionMode(GateConfig{HostPrefix: "LMAWS", Provider: "aws"}); cerr == nil || cerr.Code != hostkit.InvalidArgument {
		t.Fatalf("expected partial opt-in error, got %v", cerr)
	}

	// 3. Partial opt-in (only LMAWS_LIVE=1) -> error.
	clearEnv(t)
	t.Setenv("LMAWS_LIVE", "1")
	if _, cerr := ResolveExecutionMode(GateConfig{HostPrefix: "LMAWS", Provider: "aws"}); cerr == nil || cerr.Code != hostkit.InvalidArgument {
		t.Fatalf("expected partial opt-in error, got %v", cerr)
	}

	// 4. Both opt-ins without policy -> error (never falls back to fake).
	clearEnv(t)
	t.Setenv("LMCLOUD_LIVE", "1")
	t.Setenv("LMAWS_LIVE", "1")
	if _, cerr := ResolveExecutionMode(GateConfig{HostPrefix: "LMAWS", Provider: "aws"}); cerr == nil || cerr.Code != hostkit.InvalidArgument {
		t.Fatalf("expected missing policy error, got %v", cerr)
	}

	// 5. Both opt-ins + valid policy -> ModeLive.
	clearEnv(t)
	t.Setenv("LMCLOUD_LIVE", "1")
	t.Setenv("LMAWS_LIVE", "1")
	t.Setenv("LMCLOUD_LIVE_POLICY", polPath)
	t.Setenv("LMCLOUD_POLICY_SHA256", pol.Hash())
	res, cerr = ResolveExecutionMode(GateConfig{HostPrefix: "LMAWS", Provider: "aws"})
	if cerr != nil || res.Mode != ModeLive || res.Policy == nil {
		t.Fatalf("valid live mode: got (%+v, %v)", res, cerr)
	}

	// 6. Windows explicitly refuses live mode.
	if _, cerr := ResolveExecutionMode(GateConfig{HostPrefix: "LMAWS", Provider: "aws", OS: "windows"}); cerr == nil || cerr.ProviderCode != "WindowsLiveUnsupported" {
		t.Fatalf("expected Windows live refusal, got %v", cerr)
	}

	// 7. Mixed live + loopback endpoint -> config error.
	epRes := &hostkit.EndpointResolver{Prefix: "LMAWS"}
	if cerr := epRes.Set("storage", "http://127.0.0.1:4566"); cerr != nil {
		t.Fatalf("Set endpoint: %v", cerr)
	}
	if _, cerr := ResolveExecutionMode(GateConfig{HostPrefix: "LMAWS", Provider: "aws", Endpoints: epRes}); cerr == nil || cerr.ProviderCode != "MixedLiveLoopbackConfig" {
		t.Fatalf("expected MixedLiveLoopbackConfig, got %v", cerr)
	}

	// 8. Non-AWS refused by default in Stage 1.
	t.Setenv("LMGCP_LIVE", "1")
	if _, cerr := ResolveExecutionMode(GateConfig{HostPrefix: "LMGCP", Provider: "gcp"}); cerr == nil || cerr.ProviderCode != "ProviderLiveNotEnabled" {
		t.Fatalf("expected ProviderLiveNotEnabled for gcp, got %v", cerr)
	}
}

func TestRunIDAndResourceNaming(t *testing.T) {
	runID := NewRunID(time.Unix(1712880000, 0))
	if err := ValidateRunID(runID); err != nil {
		t.Fatalf("ValidateRunID(%q): %v", runID, err)
	}
	if err := ValidateRunID("r0"); err == nil {
		t.Fatal("expected short demo run ID r0 to be rejected")
	}

	name, err := FormatLiveResourceName(runID, "s3-bkt", 1)
	if err != nil {
		t.Fatalf("FormatLiveResourceName: %v", err)
	}
	if err := ValidateLiveResourceName(runID, name); err != nil {
		t.Fatalf("ValidateLiveResourceName: %v", err)
	}
	if err := ValidateLiveResourceName(runID, "my-prod-bucket"); err == nil {
		t.Fatal("expected unprefixed bucket name to fail")
	}
	otherRun := NewRunID(time.Unix(1712880001, 0))
	if err := ValidateLiveResourceName(otherRun, name); err == nil {
		t.Fatal("expected another run's resource name to fail")
	}
}
