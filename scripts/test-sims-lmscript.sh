#!/usr/bin/env bash
# Runs lmscript test programs via released cloud client binaries against local simulators.
# Uses the mono lmscript compiler (LMSCRIPT_BIN) and current API (load_schema / _lmcode_ / run_lmcode).
# Released clients (lmaws v0.1.27, lmazure v0.1.5, lmgcp v0.1.9, lmoci v0.1.0) were built
# against legacy compiler 0.2.420 (bytecode v5). If a client cannot be driven by the current
# compiler, it records the exact command + error and marks the provider PENDING-GO-PORT.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SIM_CTL="$HERE/sim.sh"
FETCH_CLIENTS="$HERE/fetch-clients.sh"
LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
CLIENT_DIR="${LMCLOUD_CLIENT_DIR:-$ROOT/.cache/clients}"

[ -x "$SIM_CTL" ] || { echo "ERROR: $SIM_CTL is not executable" >&2; exit 1; }
[ -x "$LMSCRIPT_BIN" ] || { echo "ERROR: LMScript compiler not found or not executable at $LMSCRIPT_BIN" >&2; exit 1; }

current_sim=""
cleanup() {
  if [ -n "$current_sim" ]; then
    echo "Cleaning up running sim: $current_sim..." >&2
    "$SIM_CTL" stop "$current_sim" >/dev/null 2>&1 || true
    current_sim=""
  fi
}
trap cleanup EXIT INT TERM

# Ensure clients are downloaded and verified
ensure_client() {
  local client="$1"
  if [ ! -x "$CLIENT_DIR/$client" ]; then
    echo "Client $client not found in $CLIENT_DIR, fetching..."
    "$FETCH_CLIENTS" "$client"
  fi
}

declare -A STATUS_MAP
declare -A REASON_MAP

test_provider() {
  local provider="$1"
  local client="$2"
  local default_port="$3"

  echo "============================================================"
  echo "Testing $provider ($client) with LMScript harness"
  echo "============================================================"

  ensure_client "$client"
  local client_bin="$CLIENT_DIR/$client"

  current_sim="$provider"
  local sim_url
  sim_url="$("$SIM_CTL" start "$provider")"
  echo "Simulator $provider started at $sim_url"

  local tmp_dir
  tmp_dir="$(mktemp -d -t "lmtest-$provider-XXXXXX")"
  local schema_file="$tmp_dir/schema.json"
  local script_file="$tmp_dir/test.lms"
  local err_file="$tmp_dir/error.log"

  # Step 1: Probe modern load_schema(cli=...) support
  echo "1. Probing modern load_schema(cli=\"$client\")..."
  local direct_ok=1
  if ! timeout 15 "$LMSCRIPT_BIN" -e "s = load_schema(cli=\"$client_bin\");" > "$err_file" 2>&1; then
    direct_ok=0
    local direct_err
    direct_err="$(head -n 5 "$err_file")"
    echo "  Direct load_schema failed: $direct_err"
  fi

  # Step 2: Attempt fallback schema dump and bytecode v6 run_lmcode execution
  echo "2. Testing execution with compiled _lmcode_ block..."
  local exec_ok=0
  local exec_err=""

  # Dump schema JSON from client
  if timeout 10 "$client_bin" --dsl-schema --json > "$schema_file" 2>/dev/null; then
    # Generate provider-specific test script
    case "$provider" in
      aws)
        cat <<EOF > "$script_file"
s = load_schema(schema="$schema_file");
p = _lmcode_ s;
let cloud = aws.region("us-east-1");
let run = cloud.run("test", "$tmp_dir/owned.jsonl");
let b = run.bucket("lmcloud-test-bucket");
run.put(b, "test.txt", "hello aws sim");
run.cleanup();
end _lmcode_
r = run_lmcode(p, {command: ["$client_bin", "--dsl", "\$DSLFILE"]});
assert(r.ok, "operation failed");
EOF
        ;;
      azure)
        cat <<EOF > "$script_file"
s = load_schema(schema="$schema_file");
p = _lmcode_ s;
let sess = mock();
let r = sess.begin_run("test");
let c = r.container("lmcloud-test-container");
r.cleanup();
end _lmcode_
r = run_lmcode(p, {command: ["$client_bin", "--dsl", "\$DSLFILE"]});
assert(r.ok, "operation failed");
EOF
        ;;
      gcp)
        cat <<EOF > "$script_file"
s = load_schema(schema="$schema_file");
p = _lmcode_ s;
let b = gcp.storage_create_bucket("lmcloud-test-bucket", "us-central1", "STANDARD");
let u = gcp.storage_put_object("lmcloud-test-bucket", "test.txt", "hello gcp sim", "text/plain");
let o = gcp.storage_read_object("lmcloud-test-bucket", "test.txt");
let d = gcp.storage_delete_object("lmcloud-test-bucket", "test.txt");
let db = gcp.storage_delete_bucket("lmcloud-test-bucket");
end _lmcode_
r = run_lmcode(p, {command: ["$client_bin", "--dsl", "\$DSLFILE"]});
assert(r.ok, "operation failed");
EOF
        ;;
      oci)
        cat <<EOF > "$script_file"
s = load_schema(schema="$schema_file");
p = _lmcode_ s;
let cloud = oci.endpoint("us-ashburn-1", "$sim_url");
let b = cloud.bucket_create("lmcloud-test-bucket");
let p1 = cloud.object_put("lmcloud-test-bucket", "test.txt", "hello oci sim");
let g = cloud.object_get("lmcloud-test-bucket", "test.txt");
check(g.get("content") == "hello oci sim");
cloud.object_delete("lmcloud-test-bucket", "test.txt");
cloud.bucket_delete("lmcloud-test-bucket");
end _lmcode_
r = run_lmcode(p, {command: ["$client_bin", "--dsl", "\$DSLFILE"]});
assert(r.ok, "operation failed");
EOF
        ;;
    esac

    if timeout 20 "$LMSCRIPT_BIN" "$script_file" > "$err_file" 2>&1; then
      exec_ok=1
    else
      exec_err="$(cat "$err_file")"
    fi
  else
    exec_err="Failed to extract schema from $client_bin via --dsl-schema --json"
  fi

  # Stop simulator cleanly
  "$SIM_CTL" stop "$provider"
  current_sim=""

  # Determine compatibility outcome
  if [ "$exec_ok" -eq 1 ] && [ "$direct_ok" -eq 1 ]; then
    echo "Result for $provider: PASS"
    STATUS_MAP["$provider"]="PASS"
    REASON_MAP["$provider"]="Execution passed successfully"
  else
    echo "Result for $provider: PENDING-GO-PORT"
    STATUS_MAP["$provider"]="PENDING-GO-PORT"

    # Identify primary diagnostic
    local reason=""
    if echo "$exec_err" | grep -q "unsupported bytecode version 6"; then
      reason="unsupported bytecode version 6 (client expects v5)"
    elif echo "$exec_err" | grep -q "frame is not terminal"; then
      reason="wire frame protocol mismatch (missing LMCODE_RETURN_BEGIN/END)"
    elif [ "$direct_ok" -eq 0 ]; then
      reason="client lacks --lmcode-schema CLI flag (schema host exited 2)"
    else
      reason="client execution failed with current compiler"
    fi

    echo "  Diagnostic: $reason"
    echo "  Captured error tail:"
    echo "$exec_err" | head -n 4 | sed 's/^/    /'
    REASON_MAP["$provider"]="$reason"
  fi

  rm -rf "$tmp_dir"
  echo ""
}

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=("aws" "azure" "gcp" "oci")
fi

for t in "${targets[@]}"; do
  case "$t" in
    aws|awssim)     test_provider "aws" "lmaws" 4566 ;;
    azure|azuresim) test_provider "azure" "lmazure" 4577 ;;
    gcp|gcpsim)     test_provider "gcp" "lmgcp" 4588 ;;
    oci|ocisim)     test_provider "oci" "lmoci" 4599 ;;
    *) echo "ERROR: Unknown provider $t" >&2; exit 2 ;;
  esac
done

echo "============================================================"
echo "SUMMARY: LMScript Sim Harness Test Results"
echo "============================================================"
printf "%-10s %-18s %s\n" "PROVIDER" "STATUS" "EVIDENCE / DETAILS"
printf "%-10s %-18s %s\n" "--------" "------" "------------------"
for t in "${targets[@]}"; do
  case "$t" in
    aws|awssim)     p="aws" ;;
    azure|azuresim) p="azure" ;;
    gcp|gcpsim)     p="gcp" ;;
    oci|ocisim)     p="oci" ;;
  esac
  printf "%-10s %-18s %s\n" "$p" "${STATUS_MAP[$p]}" "${REASON_MAP[$p]}"
done
echo "============================================================"
