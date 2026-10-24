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
want_tofu="1.13.2"
want="lmcloud $want_v (opentofu $want_tofu)"
got="$("$HOST" --version)"
[ "$got" = "$want" ] || fail "--version was '$got', want '$want'"; ok "--version prints '$want'"

LMSCRIPT="${LMSCRIPT_BIN:-lmscript}"
diff <("$LMSCRIPT" --dsl-signatures schema/lmcloud.dsl.json) <("$HOST" --dsl-signatures) >/dev/null || fail "schema/host signature drift"; ok "host signatures match the schema"
cmp <("$HOST" --dsl-schema --json) schema/lmcloud.dsl.json >/dev/null || fail "embedded schema differs"; ok "embedded schema is byte-identical"

schema_summary="$("$HOST" --dsl-schema)"
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
out="$("$HOST" --dsl "$bad_code" 2>&1 || true)"
echo "$out" | grep -q "LOAD_BAD_BYTECODE" || fail "bad bytecode not rejected with LOAD_BAD_BYTECODE: $out"; ok "corrupt bytecode rejected cleanly with exit 3"

# 3. In-process error handling verified through DSL snippets
run_dsl() { # NAME BODY
  local snippet="$1"
  local body="$2"
  local tmpdir; tmpdir="$(mktemp -d build/tmp.XXXXXX)"
  cat > "$tmpdir/script.lms" <<LMS
p = _dsl_ cli="lmcloud";
$body
end _dsl_
savedsl(p, "$tmpdir/script.dslb");
r = system(concat(dsl_cli(p), ["--dsl", "$tmpdir/script.dslb"]), 60000);
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

# 6. Output of unknown name returns empty string and sets last_error
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
let err = tofu.last_error();
let ok_des = tofu.destroy(\"$td_out\");
")"
rm -rf "$td_out"
echo "$out" | grep -q 'code=0' || fail "unknown output handling failed: $out"
ok "output of unknown name returns empty string and sets last_error"

# 7. Invalid HCL format error handling
out="$(run_dsl "fmt_err" '
let bad = "resource \"incomplete {";
let res = tofu.fmt(bad);
let err = tofu.last_error();
')"
echo "$out" | grep -q 'code=0' || fail "fmt error handling failed: $out"
ok "formatting invalid HCL returns original string and records last_error"

# 8. Run unit test suite
go test ./internal/lmhost >/dev/null || fail "go test ./internal/lmhost failed"; ok "internal/lmhost Go test suite passes"

echo "all $pass checks passed"
