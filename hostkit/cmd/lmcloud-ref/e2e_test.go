// SPDX-License-Identifier: MIT

package main

import (
	"github.com/lmctl-ai/lmcloud/hostkit/cloudhost"
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

func TestConformanceScenarioFilter(t *testing.T) {
	bin := lmscript(t)
	ref := buildRef(t)
	out := runConformance(t, ref, []string{
		"LMSCRIPT_BIN=" + bin,
		"LMCLOUD_REF_STATE=" + filepath.Join(t.TempDir(), "s.json"),
		"LMCLOUD_SCENARIO_FILTER=04-message-unicode-and-binary",
	})
	if !strings.Contains(out, "1..1\nok 1 - queue/04-message-unicode-and-binary\n# pass 1 / 1, skip 0, fail 0") {
		t.Fatalf("unexpected filtered output:\n%s", out)
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

// hostkit v2: Program.Hooks reach the run loop and Program.Init failures exit 2.
func TestProgramHooksAndInitThroughCompiler(t *testing.T) {
	bin := lmscript(t)
	ref := buildRef(t)
	path := filepath.Join(repoRoot(t), "tests", "conformance", "object-storage", "01-bucket-lifecycle.lms")
	cmd := exec.Command(bin, filepath.Base(path), ref, "", "hooks")
	cmd.Dir = filepath.Dir(path)
	cmd.Env = append(os.Environ(), "LMCLOUD_REF_STATE="+filepath.Join(t.TempDir(), "s.json"), "LMCLOUD_REF_REPORT=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	for _, want := range []string{"lmcloud-ref hook before_run", "lmcloud-ref hook after_run"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	init := exec.Command(ref, "cloud", "--lmcode", "/nonexistent.dslb")
	init.Env = append(os.Environ(), "LMCLOUD_REF_FAIL_INIT=1")
	frame, _ := init.Output()
	if init.ProcessState.ExitCode() != 2 || !strings.Contains(string(frame), "CLI_USAGE") {
		t.Fatalf("Init failure: exit %d frame %s", init.ProcessState.ExitCode(), frame)
	}
}

// hostkit v3 (risk 7): a dry run that evaluates last_error().code() works
// when the linked lmcode-go declares enums (Registry.Enum, local replace).
func TestDryRunEvaluatesErrorCode(t *testing.T) {
	bin := lmscript(t)
	if !cloudhost.EnumsDeclared() {
		t.Skip("linked lmcode-go has no Registry.Enum (needs the lmcode-go-patched replace)")
	}
	ref := buildRef(t)
	schemaPath := filepath.Join(repoRoot(t), "schema", "lmcloud.dsl.json")
	prog := `
s = load_schema(schema="` + schemaPath + `");
p = _lmcode_ s;
  cloud.set_abort_on_error(false);
  let ex = cloud.bucket_exists("dry-enum-bucket");
  let ok_code = cloud.last_error().code() == ErrorCode.OK;
  cloud.object_get("dry-enum-missing", "k");
  let nf = cloud.last_error().code() == ErrorCode.NOT_FOUND;
  lmcode_return_put("ok_code", ok_code);
  lmcode_return_put("nf", nf);
end _lmcode_
r = run_lmcode(p, {command:["` + ref + `", "--lmcode", "$DSLFILE"]});
assert(r.ok && r.result.ok_code && r.result.nf, "dry ErrorCode evaluation failed");
println("DRY-ENUM-OK");
`
	file := filepath.Join(t.TempDir(), "dry-enum.lms")
	if err := os.WriteFile(file, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--dry-run", file)
	cmd.Env = append(os.Environ(), "LMCLOUD_REF_STATE="+filepath.Join(t.TempDir(), "s.json"))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `"dry":true`) || !strings.Contains(string(out), `"ok_code":true`) {
		t.Fatalf("dry enum run: %v\n%s", err, out)
	}
}

// hostkit v4: a provider error that echoes the create token never shows the
// token through last_error().message(), provider_code() or the abort frame.
func TestCreateTokenRedactedEndToEnd(t *testing.T) {
	bin := lmscript(t)
	ref := buildRef(t)
	schemaPath := filepath.Join(repoRoot(t), "schema", "lmcloud.dsl.json")
	prog := `
s = load_schema(schema="` + schemaPath + `");
inspect = _lmcode_ s;
  cloud.set_abort_on_error(false);
  let c = cloud.bucket_create("echo-bkt");
  let e = cloud.last_error();
  print("MESSAGE " + e.message());
  print("PROVIDER_CODE " + e.provider_code());
  let q = cloud.queue_create("echo-q");
  print("QMESSAGE " + cloud.last_error().message());
end _lmcode_
r1 = run_lmcode(inspect, {command:["` + ref + `", "--lmcode", "$DSLFILE"]});
abort = _lmcode_ s;
  cloud.bucket_create("echo-bkt");
end _lmcode_
r2 = run_lmcode(abort, {command:["` + ref + `", "--lmcode", "$DSLFILE"]});
println("ABORT " + r2.message);
assert(r1.ok && !r2.ok, "expected inspect ok and abort failure");
`
	file := filepath.Join(t.TempDir(), "echo.lms")
	if err := os.WriteFile(file, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, file)
	cmd.Env = append(os.Environ(), "LMCLOUD_REF_STATE="+filepath.Join(t.TempDir(), "s.json"), "LMCLOUD_REF_ECHO_TOKEN=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{"MESSAGE ", "PROVIDER_CODE CreateDenied.[create-token]", "QMESSAGE ", "[PERMISSION_DENIED] bucket_create (echo-bkt): bucket create rejected for client request token [create-token]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if regexp.MustCompile(`(?i)[0-9a-f]{32}`).MatchString(text) || strings.Count(text, "[create-token]") < 4 {
		t.Fatalf("create token leaked or not marked:\n%s", text)
	}
}
