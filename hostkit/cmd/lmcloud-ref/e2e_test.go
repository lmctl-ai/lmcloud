// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These end-to-end checks drive the reference host through the real lmscript
// compiler. They run only when LMSCRIPT_BIN points at an lmscript launcher.

func lmscript(t *testing.T) string {
	bin := os.Getenv("LMSCRIPT_BIN")
	if bin == "" {
		t.Skip("LMSCRIPT_BIN not set")
	}
	return bin
}

func repoRoot(t *testing.T) string {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func buildRef(t *testing.T) string {
	bin := filepath.Join(t.TempDir(), "lmcloud-ref")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func runConformance(t *testing.T, ref string, env []string) string {
	cmd := exec.Command(filepath.Join(repoRoot(t), "tests", "run-conformance.sh"), ref, "all")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("conformance failed: %v\n%s", err, out)
	}
	return string(out)
}

func TestConformanceOpenMode(t *testing.T) {
	bin := lmscript(t)
	ref := buildRef(t)
	out := runConformance(t, ref, []string{"LMSCRIPT_BIN=" + bin, "LMCLOUD_REF_STATE=" + filepath.Join(t.TempDir(), "s.json")})
	if !strings.Contains(out, "# pass 25 / 25, skip 2, fail 0") {
		t.Fatalf("unexpected summary:\n%s", out)
	}
}

func TestConformanceEnforcedMode(t *testing.T) {
	bin := lmscript(t)
	ref := buildRef(t)
	out := runConformance(t, ref, []string{
		"LMSCRIPT_BIN=" + bin,
		"LMCLOUD_REF_STATE=" + filepath.Join(t.TempDir(), "s.json"),
		"LMCLOUD_REF_AUTH=enforce",
		// The scenarios rotate provider credential variables; the reference
		// host reads one of them as its caller credential.
		"LMCLOUD_REF_TOKEN_ENV=LMGCP_SIM_TOKEN",
		"LMCLOUD_REF_ALLOW=allow-token",
		"LMCLOUD_REF_DENY=deny-token",
		"LMGCP_SIM_TOKEN=allow-token",
		"LMCLOUD_ENFORCE_DENIED_GCP_TOKEN=deny-token",
	})
	if !strings.Contains(out, "# pass 25 / 25, skip 0, fail 0") {
		t.Fatalf("unexpected summary:\n%s", out)
	}
}

// Sol finding 1, end to end: `lmscript --dry-run` reaches the host as a dry
// invocation and the adapter sees zero mutator calls.
func TestDryRunThroughCompilerMakesNoMutations(t *testing.T) {
	bin := lmscript(t)
	ref := buildRef(t)
	state := filepath.Join(t.TempDir(), "s.json")
	scenarios := []string{
		"object-storage/01-bucket-lifecycle.lms",
		"object-storage/06-object-metadata-and-content-type.lms",
		"object-storage/08-object-list-pagination.lms",
		"queue/01-queue-lifecycle.lms",
		"queue/03-message-send-receive-ack.lms",
		"queue/06-visibility-timeout-and-nack.lms",
	}
	calls := regexp.MustCompile(`mutator_calls=(\d+)`)
	for _, s := range scenarios {
		path := filepath.Join(repoRoot(t), "tests", "conformance", s)
		cmd := exec.Command(bin, "--dry-run", filepath.Base(path), ref, "", "dryrun")
		cmd.Dir = filepath.Dir(path)
		cmd.Env = append(os.Environ(), "LMCLOUD_REF_STATE="+state, "LMCLOUD_REF_REPORT=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: dry run failed: %v\n%s", s, err, out)
		}
		m := calls.FindAllStringSubmatch(string(out), -1)
		if len(m) == 0 {
			t.Fatalf("%s: host was not reached in dry mode:\n%s", s, out)
		}
		for _, c := range m {
			if c[1] != "0" {
				t.Fatalf("%s: dry run made %s mutator calls:\n%s", s, c[1], out)
			}
		}
	}
	raw, _ := os.ReadFile(state)
	if strings.Contains(string(raw), "lmcloud-") {
		t.Fatalf("dry runs changed fake state: %s", raw)
	}
}

func TestSchemaAndSignatureParity(t *testing.T) {
	bin := lmscript(t)
	ref := buildRef(t)
	schemaPath := filepath.Join(repoRoot(t), "schema", "lmcloud.dsl.json")
	want, err := exec.Command(bin, "--lmcode-signatures", schemaPath).Output()
	if err != nil {
		t.Fatal(err)
	}
	got, err := exec.Command(ref, "--lmcode-signatures").Output()
	if err != nil || string(got) != string(want) {
		t.Fatalf("signature drift:\n--- lmscript\n%s\n--- ref\n%s", want, got)
	}
	raw, _ := os.ReadFile(schemaPath)
	served, err := exec.Command(ref, "--lmcode-schema", "--json").Output()
	if err != nil || string(served) != string(raw) {
		t.Fatal("--lmcode-schema --json must serve the exact schema bytes")
	}
}
