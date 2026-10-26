// SPDX-License-Identifier: MIT

package lmhost

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcode-go"
)

func TestHostSignatureParity(t *testing.T) {
	h := NewHost()
	reg := lmcode.NewRegistry()
	if err := Register(reg, h); err != nil {
		t.Fatalf("Register failed: %s", err)
	}

	hostSigs := reg.Signatures()

	lmscriptBin := os.Getenv("LMSCRIPT_BIN")
	if lmscriptBin == "" {
		var err error
		lmscriptBin, err = exec.LookPath("lmscript")
		if err != nil {
			t.Skip("lmscript not on PATH, skipping parity check")
		}
	}

	schemaPath := filepath.Join("..", "..", "schema", "lmcloud.dsl.json")
	out, err := exec.Command(lmscriptBin, "--dsl-signatures", schemaPath).CombinedOutput()
	if err != nil {
		t.Fatalf("lmscript --dsl-signatures failed: %s\n%s", err, string(out))
	}

	expectedLines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(hostSigs) != len(expectedLines) {
		t.Fatalf("signature count mismatch: got %d, want %d", len(hostSigs), len(expectedLines))
	}

	for i, line := range expectedLines {
		if hostSigs[i] != line {
			t.Errorf("line %d: got %q, want %q", i, hostSigs[i], line)
		}
	}

	hostOnlySigs := reg.HostSignatures()
	outNoStd, err := exec.Command(lmscriptBin, "--dsl-signatures", schemaPath, "--without-std").CombinedOutput()
	if err != nil {
		t.Fatalf("lmscript --dsl-signatures --without-std failed: %s\n%s", err, string(outNoStd))
	}
	expectedNoStd := strings.Split(strings.TrimSpace(string(outNoStd)), "\n")
	if len(hostOnlySigs) != len(expectedNoStd) {
		t.Fatalf("host-only signature count mismatch: got %d, want %d", len(hostOnlySigs), len(expectedNoStd))
	}
	for i, line := range expectedNoStd {
		if hostOnlySigs[i] != line {
			t.Errorf("host-only line %d: got %q, want %q", i, hostOnlySigs[i], line)
		}
	}
}

func TestHostLifecycle(t *testing.T) {
	td := t.TempDir()

	tfFile := filepath.Join(td, "main.tf")
	content := `
variable "custom_val" {
  type    = string
  default = "default_val"
}
resource "terraform_data" "greeting" {
  input = var.custom_val
}
output "message" {
  value = terraform_data.greeting.output
}
`
	if err := os.WriteFile(tfFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	h := NewHost()

	// 1. Validate before init should fail or require init
	if h.Validate(td) {
		// depending on tofu version, validate might need init or might pass
	}

	// 2. Init
	if !h.Init(td) {
		t.Fatalf("init failed: %s", h.LastError())
	}
	if h.LastError() != "" {
		t.Fatalf("unexpected last error after init: %s", h.LastError())
	}

	// 3. Validate
	if !h.Validate(td) {
		t.Fatalf("validate failed: %s", h.LastError())
	}

	// 4. Set variable
	h.Var("custom_val", "Antigravity Cloud")

	// 5. Plan
	plan := h.Plan(td)
	if plan.errored {
		t.Fatalf("plan failed: %s", plan.lastError)
	}
	if plan.Add() != 1 {
		t.Errorf("expected 1 add, got %d", plan.Add())
	}
	if plan.Change() != 0 {
		t.Errorf("expected 0 change, got %d", plan.Change())
	}
	if plan.Destroy() != 0 {
		t.Errorf("expected 0 destroy, got %d", plan.Destroy())
	}
	if !strings.Contains(plan.Summary(), "1 to add") {
		t.Errorf("unexpected summary: %s", plan.Summary())
	}

	// Save plan
	savedPlan := filepath.Join(td, "plan.tfplan")
	if !plan.Save(savedPlan) {
		t.Fatal("failed to save plan file")
	}
	if stat, err := os.Stat(savedPlan); err != nil || stat.Size() == 0 {
		t.Fatalf("saved plan file missing or empty: %s", err)
	}

	// 6. Apply
	if !h.Apply(td) {
		t.Fatalf("apply failed: %s", h.LastError())
	}

	// 7. Output
	val := h.Output(td, "message")
	if val != "Antigravity Cloud" {
		t.Fatalf("expected output 'Antigravity Cloud', got %q", val)
	}

	// 8. Output unknown name
	unknown := h.Output(td, "non_existent_key")
	if unknown != "" {
		t.Fatalf("expected empty string for non-existent output, got %q", unknown)
	}
	if h.LastError() == "" {
		t.Fatal("expected LastError to be populated for unknown output")
	}

	// 9. Show state
	stateJSON := h.ShowState(td)
	if !strings.Contains(stateJSON, "terraform_data.greeting") {
		t.Fatalf("expected state JSON to include greeting resource, got: %s", stateJSON)
	}

	// 10. Destroy
	if !h.Destroy(td) {
		t.Fatalf("destroy failed: %s", h.LastError())
	}

	// 10b. Output after destroy returns empty string and sets LastError
	postDestroy := h.Output(td, "message")
	if postDestroy != "" {
		t.Fatalf("expected empty output after destroy, got %q", postDestroy)
	}
	if h.LastError() == "" {
		t.Fatal("expected LastError to be populated when querying output after destroy")
	}

	// 11. Fmt
	unformatted := "resource   \"terraform_data\"   \"a\"   {\n  input = \"b\"\n}\n"
	formatted := h.Fmt(unformatted)
	if !strings.Contains(formatted, "resource \"terraform_data\" \"a\" {") {
		t.Fatalf("unexpected formatted text: %s", formatted)
	}

	// 12. Fmt error handling
	badHcl := "resource \"unclosed {"
	badRes := h.Fmt(badHcl)
	if badRes != badHcl {
		t.Fatalf("expected bad HCL to return original text, got: %s", badRes)
	}
	if h.LastError() == "" {
		t.Fatal("expected LastError to be set on format failure")
	}

	// 13. Error handling on non-existent dir
	if h.Init("/path/that/does/not/exist/at/all") {
		t.Fatal("expected Init to return false on missing dir")
	}
	if h.LastError() == "" {
		t.Fatal("expected LastError to be set on missing dir")
	}
}

func TestVarPersistenceAndDeclaredFiltering(t *testing.T) {
	td1 := t.TempDir()
	tf1 := `
variable "run_id" {
  type = string
}
resource "terraform_data" "item" {
  input = var.run_id
}
output "run_id_out" {
  value = terraform_data.item.output
}
`
	if err := os.WriteFile(filepath.Join(td1, "main.tf"), []byte(tf1), 0644); err != nil {
		t.Fatal(err)
	}

	// Process 1: sets run_id + an extra variable for another dir, runs init + apply
	h1 := NewHost()
	h1.Var("run_id", "run-abc123")
	h1.Var("other_dir_var", "unused-here")
	if !h1.Init(td1) {
		t.Fatalf("h1.Init failed: %s", h1.LastError())
	}
	if !h1.Apply(td1) {
		t.Fatalf("h1.Apply failed: %s", h1.LastError())
	}
	if got := h1.Output(td1, "run_id_out"); got != "run-abc123" {
		t.Fatalf("expected output 'run-abc123', got %q", got)
	}

	// Process 2 (separate Host instance, simulating separate cleanup invocation):
	// does NOT call Var("run_id", ...), yet Destroy succeeds using persisted workdir vars.
	h2 := NewHost()
	if !h2.Destroy(td1) {
		t.Fatalf("h2.Destroy without re-setting Var failed: %s", h2.LastError())
	}
	if got := strings.TrimSpace(h2.StateList(td1)); got != "" {
		t.Fatalf("expected empty state after h2.Destroy, got %q", got)
	}
}

func TestExternalProviderFilesystemMirrorInit(t *testing.T) {
	td := t.TempDir()
	platform := runtime.GOOS + "_" + runtime.GOARCH
	pluginDir := filepath.Join(td, "terraform.d", "plugins", "registry.opentofu.org", "example", "custom", "1.2.3", platform)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	binName := "terraform-provider-custom_v1.2.3"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	if err := os.WriteFile(filepath.Join(pluginDir, binName), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	tf := `
terraform {
  required_providers {
    custom = {
      source  = "example/custom"
      version = "1.2.3"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(td, "main.tf"), []byte(tf), 0644); err != nil {
		t.Fatal(err)
	}

	h := NewHost()
	if !h.Init(td) {
		t.Fatalf("Init with external provider in filesystem mirror failed: %s", h.LastError())
	}
	lockBytes, err := os.ReadFile(filepath.Join(td, ".terraform.lock.hcl"))
	if err != nil {
		t.Fatalf("expected .terraform.lock.hcl to be written: %s", err)
	}
	if !strings.Contains(string(lockBytes), "registry.opentofu.org/example/custom") {
		t.Fatalf("expected lockfile to contain example/custom, got:\n%s", string(lockBytes))
	}
}

func TestPluginCacheReuseAcrossWorkdirs(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("LMCLOUD_PLUGIN_CACHE_DIR", cacheDir)

	platform := runtime.GOOS + "_" + runtime.GOARCH
	td1 := t.TempDir()
	mirrorDir := filepath.Join(td1, "terraform.d", "plugins", "registry.opentofu.org", "example", "cachedprov", "2.0.0", platform)
	if err := os.MkdirAll(mirrorDir, 0755); err != nil {
		t.Fatal(err)
	}
	binName := "terraform-provider-cachedprov_v2.0.0"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	if err := os.WriteFile(filepath.Join(mirrorDir, binName), []byte("#!/bin/sh\necho cachedprov\n"), 0755); err != nil {
		t.Fatal(err)
	}

	tf := `
terraform {
  required_providers {
    cachedprov = {
      source  = "example/cachedprov"
      version = "2.0.0"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(td1, "main.tf"), []byte(tf), 0644); err != nil {
		t.Fatal(err)
	}

	h := NewHost()
	if !h.Init(td1) {
		t.Fatalf("Init td1 failed: %s", h.LastError())
	}

	cachedPkgDir := filepath.Join(cacheDir, "registry.opentofu.org", "example", "cachedprov", "2.0.0", platform)
	if _, err := os.Stat(cachedPkgDir + ".h1"); err != nil {
		t.Fatalf("expected sidecar .h1 hash cache at %s.h1: %s", cachedPkgDir, err)
	}

	// Second directory td2 has NO local mirror and NO lockfile; it must reuse cacheDir offline.
	td2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(td2, "main.tf"), []byte(tf), 0644); err != nil {
		t.Fatal(err)
	}
	if !h.Init(td2) {
		t.Fatalf("Init td2 from shared plugin cache failed: %s", h.LastError())
	}
	lockBytes, err := os.ReadFile(filepath.Join(td2, ".terraform.lock.hcl"))
	if err != nil {
		t.Fatalf("expected td2 .terraform.lock.hcl: %s", err)
	}
	if !strings.Contains(string(lockBytes), "registry.opentofu.org/example/cachedprov") {
		t.Fatalf("expected td2 lockfile to contain example/cachedprov, got:\n%s", string(lockBytes))
	}
}

func TestClearSpotRequestIDs(t *testing.T) {
	stateJSON := `{
  "version": 4,
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "app",
      "instances": [
        {
          "attributes": {
            "id": "i-0123456789abcdef0",
            "instance_lifecycle": "spot",
            "spot_instance_request_id": "sir-abc12345",
            "instance_market_options": [
              {
                "market_type": "spot",
                "spot_options": [
                  {
                    "spot_instance_type": "one-time",
                    "instance_interruption_behavior": "terminate"
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  ]
}`
	var doc map[string]any
	if err := json.Unmarshal([]byte(stateJSON), &doc); err != nil {
		t.Fatalf("unmarshal state failed: %s", err)
	}
	if !clearSpotRequestIDs(doc) {
		t.Fatal("expected clearSpotRequestIDs to return true on spot instance state")
	}
	if clearSpotRequestIDs(doc) {
		t.Fatal("expected second clearSpotRequestIDs call to be idempotent and return false")
	}

	res := doc["resources"].([]any)[0].(map[string]any)
	inst := res["instances"].([]any)[0].(map[string]any)
	attrs := inst["attributes"].(map[string]any)
	if got := attrs["spot_instance_request_id"]; got != "" {
		t.Fatalf("expected empty spot_instance_request_id, got %v", got)
	}
	if got := attrs["instance_lifecycle"]; got != "" {
		t.Fatalf("expected empty instance_lifecycle, got %v", got)
	}
	if got := len(attrs["instance_market_options"].([]any)); got != 0 {
		t.Fatalf("expected empty instance_market_options slice, got len %d", got)
	}
}




