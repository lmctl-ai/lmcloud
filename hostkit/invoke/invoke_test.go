// SPDX-License-Identifier: MIT

package invoke

import (
	"os"
	"path/filepath"
	"testing"
)

func writeManifest(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LMCODE_INVOCATION_FILE", p)
}

func TestParseArgsOrderAndDefaults(t *testing.T) {
	t.Setenv("LMCODE_INVOCATION_FILE", "")
	os.Unsetenv("LMCODE_INVOCATION_FILE")
	inv, err := ParseArgs([]string{"--last", "/a.dslb", "--lmcode", "/b.dslb", "--first", "/c.dslb"})
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.Order; len(got) != 3 || got[0] != 2 || got[1] != 1 || got[2] != 0 {
		t.Fatalf("order = %v", got)
	}
	if inv.Dry || !inv.Builder {
		t.Fatalf("standalone default is real; multi-file is builder: %+v", inv)
	}
	for _, bad := range [][]string{{"--lmcode"}, {"--lmcode", "--x"}, {"--lmcode", ""}} {
		if _, err := ParseArgs(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	if !IsInvocation([]string{"--first", "x"}) || IsInvocation([]string{"--sweep"}) || IsInvocation(nil) {
		t.Fatal("IsInvocation")
	}
}

// Sol finding 1: the standard manifest decides dry mode; no bespoke flag needed.
func TestParseArgsReadsStandardManifest(t *testing.T) {
	file := filepath.Join(t.TempDir(), "p.dslb")
	writeManifest(t, `{"version":1,"mode":"builder","dry":true,"parts":[{"index":0,"file":"`+file+`"}]}`)
	inv, err := ParseArgs([]string{"--lmcode", file})
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Dry || !inv.Builder {
		t.Fatalf("manifest dry/builder not honoured: %+v", inv)
	}
	writeManifest(t, `{"version":1,"mode":"single","dry":false,"parts":[{"index":0,"file":"`+file+`"}]}`)
	inv, err = ParseArgs([]string{"--lmcode", file})
	if err != nil || inv.Dry || inv.Builder {
		t.Fatalf("real single: %+v %v", inv, err)
	}
	writeManifest(t, `{"version":1,"mode":"single","parts":[{"index":0,"file":"`+file+`"}]}`)
	if _, err := ParseArgs([]string{"--lmcode", file}); err == nil {
		t.Fatal("manifest without dry must be rejected, never treated as real")
	}
}
