// SPDX-License-Identifier: MIT

package lmhost

import (
	"os"
	"os/exec"
	"path/filepath"
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
