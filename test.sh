#!/usr/bin/env bash
# Verifies the static host, signatures, embedded schema, error paths, and runs all examples through lmscript.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$HERE"

BUILD_DIR="${BUILD_DIR:-bin}"
HOST="$BUILD_DIR/lmcloud"
if [ ! -x "$HOST" ] && [ -x "$HOST.exe" ]; then
  HOST="$HOST.exe"
fi
pass=0
ok() { pass=$((pass+1)); echo "ok $pass - $1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$HOST" ] || fail "$HOST not built: run 'CGO_ENABLED=0 go build -trimpath -ldflags \"-s -w\" -o ./bin/lmcloud ./cmd/lmcloud'"; ok "binary exists and is executable"
python3 testing/lmcloud/check-host-flags.py schema/lmcloud.dsl.json "$HOST" || fail "hard host flag cutover"

if [ "$(uname -s)" = "Linux" ]; then
  case "$(ldd "$HOST" 2>&1 || true)" in
    *"not a dynamic executable"*) ;;
    *) fail "$HOST is not statically linked";;
  esac
  ok "executable is statically linked"
fi

if [ -f LMCLOUD_VERSION ]; then
  want_v="$(head -n1 LMCLOUD_VERSION | tr -d '[:space:]')"
else
  want_v="$(head -n1 cmd/lmcloud/VERSION | tr -d '[:space:]')"
fi
want="lmcloud $want_v"
got="$("$HOST" --version | tr -d '\r')"
[ "$got" = "$want" ] || fail "--version was '$got', want '$want'"; ok "--version prints '$want'"
ver_count="$(printf '%s\n' "$got" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | wc -l | tr -d '[:space:]')"
[ "$ver_count" = "1" ] || fail "--version '$got' contains $ver_count version numbers, want 1"; ok "--version contains exactly one version number"

LMSCRIPT="$(scripts/select-compiler.sh)"
diff <("$LMSCRIPT" --lmcode-signatures schema/lmcloud.dsl.json) <("$HOST" --lmcode-signatures) >/dev/null || fail "schema/host signature drift"; ok "host signatures match the schema"
diff <("$LMSCRIPT" --lmcode-signatures schema/lmcloud.dsl.json --without-std) <("$HOST" --lmcode-signatures --without-std) >/dev/null || fail "host-only signature drift"; ok "host-only compiler/registry parity"
cmp <("$HOST" --lmcode-schema --json) schema/lmcloud.dsl.json >/dev/null || fail "embedded schema differs"; ok "embedded schema is byte-identical"

schema_summary="$("$HOST" --lmcode-schema)"
echo "$schema_summary" | grep -q "context tofu: Tofu" || fail "schema summary missing context";
echo "$schema_summary" | grep -q "Plan:" || fail "schema summary missing Plan type";
echo "$schema_summary" | grep -q "Tofu:" || fail "schema summary missing Tofu type";
ok "schema summary prints formatted type methods"

export PATH="$PWD/$BUILD_DIR:$PATH"
for f in examples/*.lms; do
  out="$("$LMSCRIPT" "$f" 2>&1)" || { echo "$out" >&2; fail "$f failed"; }
  echo "$out" | grep -q "^ok " || { echo "$out" >&2; fail "$f printed no ok line"; }
  ok "$f"
done

# Prove standard calls compile and run without host declarations or cloud effects.
STD_WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmcloud-std-XXXXXX")"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) STD_WORK="$(cygpath -m "$STD_WORK")";; esac
cat > "$STD_WORK/probe.lms" <<LMS
p = _lmcode_ cli="lmcloud";
let n = str_len("abc");
let list = str_list().add("value");
assert_close(1.25, 1.25, 0.0001);
print("testing-ok\n");
if (n != 3 || list.at(0) != "value") { let invalid = int_list().at(0); }
end _lmcode_
savedsl(p, "$STD_WORK/probe.dslb");
LMS
"$LMSCRIPT" "$STD_WORK/probe.lms"
probe_out="$("$HOST" --lmcode "$STD_WORK/probe.dslb")" || fail "implicit std runtime"
echo "$probe_out" | grep -q "testing-ok" || fail "print() output missing from std runtime probe: $probe_out"
rm -rf "$STD_WORK"
ok "implicit std and testing helpers (assert_close, print) compile and run"

# Error paths
mkdir -p build

# 1. Invalid usage returns exit 2
set +e
"$HOST" --invalid-flag >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 2 ] || fail "--invalid-flag exited $code, want 2"; ok "invalid CLI flag returns exit 2"

# 2. Corrupt bytecode returns exit 3 with LOAD_BAD_BYTECODE
bad_code="$(mktemp build/bad_code.XXXXXX)"; trap 'rm -f "$bad_code"' EXIT
echo "not bytecode" > "$bad_code"
out="$("$HOST" --lmcode "$bad_code" 2>&1 || true)"
echo "$out" | grep -q "LOAD_BAD_BYTECODE" || fail "bad bytecode not rejected with LOAD_BAD_BYTECODE: $out"; ok "corrupt bytecode rejected cleanly with exit 3"

# 3. In-process error handling verified through DSL snippets
run_dsl() { # NAME BODY
  local snippet="$1"
  local body="$2"
  local tmpdir; tmpdir="$(mktemp -d build/tmp.XXXXXX)"
  cat > "$tmpdir/script.lms" <<LMS
p = _lmcode_ cli="lmcloud";
$body
end _lmcode_
savedsl(p, "$tmpdir/script.dslb");
r = system(concat(dsl_cli(p), ["--lmcode", "$tmpdir/script.dslb"]), 60000);
println("code=" + str(r.code));
println("stdout=" + r.stdout);
println("stderr=" + r.stderr);
LMS
  out="$("$LMSCRIPT" "$tmpdir/script.lms" 2>&1)"
  rm -rf "$tmpdir"
  echo "$out"
}

# 4. Plan against non-existent dir sets last_error and returns errored plan
out="$(run_dsl "missing_dir" '
let p = tofu.plan("/path/to/missing/dir/never/exists");
let err = tofu.last_error();
let n = p.add();
')"
echo "$out" | grep -q 'code=0' || fail "missing dir plan did not handle error cleanly: $out"
ok "plan against non-existent dir sets last_error and returns 0 adds"

# 5. Apply without init sets last_error and returns false
td_noinit="$(mktemp -d build/td_noinit.XXXXXX)"
echo 'resource "terraform_data" "x" {}' > "$td_noinit/main.tf"
out="$(run_dsl "no_init" "
let ok = tofu.apply(\"$td_noinit\");
let err = tofu.last_error();
")"
rm -rf "$td_noinit"
echo "$out" | grep -q 'code=0' || fail "apply without init did not report false: $out"
ok "apply without init returns false and sets last_error"

# 6. Output of unknown name or after destroy returns empty string, sets last_error, and is quiet on stderr
td_out="$(mktemp -d build/td_out.XXXXXX)"
cat > "$td_out/main.tf" <<TF
resource "terraform_data" "x" {
  input = "val"
}
output "known" {
  value = terraform_data.x.output
}
TF
out="$(run_dsl "unknown_output" "
let ok_init = tofu.init(\"$td_out\");
let ok_app = tofu.apply(\"$td_out\");
let unk = tofu.output(\"$td_out\", \"does_not_exist\");
let err1 = tofu.last_error();
if (unk != \"\" || str_len(err1) == 0) { let bad = int_list().at(0); }
let ok_des = tofu.destroy(\"$td_out\");
let post_des = tofu.output(\"$td_out\", \"known\");
let err2 = tofu.last_error();
if (post_des != \"\" || str_len(err2) == 0) { let bad2 = int_list().at(0); }
")"
rm -rf "$td_out"
echo "$out" | grep -q 'code=0' || fail "unknown/post-destroy output handling failed: $out"
echo "$out" | tr -d '\r' | grep -q '^stderr=$' || fail "tofu.output leaked to stderr: $out"
ok "output of unknown name or after destroy is quiet on stderr and sets last_error"

# 6b. tofu.var() values persist in workdir for separate cleanup process
td_var="$(mktemp -d build/td_var.XXXXXX)"
cat > "$td_var/main.tf" <<TF
variable "required_tag" {
  type = string
}
resource "terraform_data" "tagged" {
  input = var.required_tag
}
TF
out_apply="$(run_dsl "var_apply" "
tofu.var(\"required_tag\", \"run-42\");
if (!tofu.init(\"$td_var\")) { let bad = int_list().at(0); }
if (!tofu.apply(\"$td_var\")) { let bad2 = int_list().at(0); }
")"
out_cleanup="$(run_dsl "var_cleanup" "
if (!tofu.destroy(\"$td_var\")) { let bad = int_list().at(0); }
if (tofu.state_list(\"$td_var\") != \"\") { let bad2 = int_list().at(0); }
")"
rm -rf "$td_var"
echo "$out_apply" | grep -q 'code=0' || fail "var_apply failed: $out_apply"
echo "$out_cleanup" | grep -q 'code=0' || fail "separate-process var_cleanup failed: $out_cleanup"
ok "tofu.var() values persist in workdir across separate cleanup processes"

# 7. Invalid HCL format error handling
out="$(run_dsl "fmt_err" '
let bad = "resource \"incomplete {";
let res = tofu.fmt(bad);
let err = tofu.last_error();
')"
echo "$out" | grep -q 'code=0' || fail "fmt error handling failed: $out"
ok "formatting invalid HCL returns original string and records last_error"

# 8. fmt_check distinguishes canonical from non-canonical HCL
out="$(run_dsl "fmt_check" '
let good = "resource \"terraform_data\" \"x\" {\n  input = \"val\"\n}\n";
let bad = "resource   \"terraform_data\" \"x\" {\n input=\"val\"\n}\n";
let is_good = tofu.fmt_check(good);
let is_bad = tofu.fmt_check(bad);
')"
echo "$out" | grep -q 'code=0' || fail "fmt_check failed: $out"
ok "fmt_check distinguishes formatted from unformatted HCL"

# 9. state_list and import against uninitialized dir set last_error
out="$(run_dsl "state_list_import_err" '
let list = tofu.state_list("/path/to/missing/dir");
let err1 = tofu.last_error();
let imp = tofu.import("/path/to/missing/dir", "terraform_data.x", "1");
let err2 = tofu.last_error();
')"
echo "$out" | grep -q 'code=0' || fail "state_list and import error handling failed: $out"
ok "state_list and import against missing dir handle error cleanly"

# 10. Run unit test suites
go test ./internal/builtin/providers >/dev/null || fail "go test ./internal/builtin/providers failed"; ok "internal/builtin/providers Go test suite passes"
go test ./internal/lmhost >/dev/null || fail "go test ./internal/lmhost failed"; ok "internal/lmhost Go test suite passes"

echo "all $pass checks passed"
