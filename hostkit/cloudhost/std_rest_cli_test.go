// SPDX-License-Identifier: MIT

package cloudhost

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/schema"
)

func findLmscript(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("LMSCRIPT_BIN"); bin != "" {
		return bin
	}
	if bin, err := exec.LookPath("lmscript"); err == nil {
		return bin
	}
	for _, candidate := range []string{
		"/home/ubuntu/.nvm/versions/node/v24.22.0/bin/lmscript",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("lmscript compiler not found in LMSCRIPT_BIN or PATH")
	return ""
}

func TestStdRestAndCliSignaturesRegistered(t *testing.T) {
	reg, err := NewRegistry(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reg.StdSignatures()); got != 226 {
		t.Fatalf("expected 226 std signatures in lmcode_std_v3, got %d", got)
	}
	sigs, err := Signatures(false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(sigs, "\n")
	for _, want := range []string{
		"fn rest_config(string, string) -> void",
		"fn rest_route(string, string, string) -> void",
		"fn rest_serve() -> void",
		"fn rest_stop() -> void",
		"fn rest_cli(StrList) -> string",
		"method RestExchange.param(string) -> string",
		"method RestExchange.query(string) -> string",
		"method RestExchange.send(string) -> void",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing std REST/CLI signature %q", want)
		}
	}
}

func TestStdRestAndCliInterfacesExecution(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--lmcloud-std-rest-host" {
			fake := fakeadapter.New(fakeadapter.Options{
				StatePath: os.Getenv("LMCLOUD_TEST_STATE"),
			})
			prog := Program{
				Name:    "lmcloud-test",
				Version: "0.1.0",
				Schema:  schema.Bytes,
				NewConfig: func(dry bool) (Config, error) {
					return Config{
						Provider:  "ref",
						Store:     fake,
						Queue:     fake,
						Tables:    fake,
						Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }},
					}, nil
				},
			}
			os.Exit(prog.Main(os.Args[i+1:]))
		}
	}

	bin := findLmscript(t)
	tmp := t.TempDir()
	schemaPath := filepath.Join(tmp, "lmcloud.dsl.json")
	if err := os.WriteFile(schemaPath, schema.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	lms := `
s = load_schema(schema="` + schemaPath + `");
p = _lmcode_ s;
  @"/objects/:bucket/:key"
  fn get_object(x: RestExchange) -> void implements RestGet {
    let val = cloud.object_get(x.param("bucket"), x.param("key"));
    x.send(x.get("cli_format") + ":" + val);
  }

  @"--format"
  fn opt_format(x: RestExchange) -> void implements CliOption {
    x.set("cli_format", x.query("format"));
  }

  @"inspect"
  fn cmd_inspect(x: RestExchange) -> void implements CliCommand {
    x.send("inspect:" + x.get("cli_format") + ":" + x.body());
  }

  rest_config("prefix", "/v1");
  cloud.bucket_create("rest-bkt");
  cloud.object_put("rest-bkt", "greeting.txt", "hello-cloud");

  let cli_out = rest_cli(str_split("--format json inspect -- cloud-ready", " "));
  let get_out = rest_cli(str_split("/v1/objects/rest-bkt/greeting.txt", " "));
  lmcode_return_put("cli_out", cli_out);
  lmcode_return_put("get_out", get_out);
end _lmcode_
r = run_lmcode(p, {command: ["` + selfBin + `", "-test.run=^TestStdRestAndCliInterfacesExecution$", "--", "--lmcloud-std-rest-host", "--lmcode", "$DSLFILE"]});
assert(r.ok, "expected lmcode run to succeed");
assert(r.result.cli_out == "inspect:json:cloud-ready", "unexpected cli_out: " + r.result.cli_out);
assert(r.result.get_out == "json:hello-cloud", "unexpected get_out: " + r.result.get_out);
println("STD_REST_CLI_OK");
`
	lmsPath := filepath.Join(tmp, "rest_cli.lms")
	if err := os.WriteFile(lmsPath, []byte(lms), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, lmsPath)
	cmd.Env = append(os.Environ(), "LMCLOUD_TEST_STATE="+filepath.Join(tmp, "state.json"))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "STD_REST_CLI_OK") {
		t.Fatalf("rest_cli execution failed: %v\n%s", err, out)
	}
}
