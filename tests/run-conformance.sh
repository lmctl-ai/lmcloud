#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
CONF_DIR="$ROOT/tests/conformance"
SCHEMA_FILE="$ROOT/schema/lmcloud.dsl.json"

usage() {
  echo "Usage: $0 <host-binary> [endpoint] [object-storage|queue|cost-perf|all] [run-id]" >&2
  echo "       $0 --check [object-storage|queue|cost-perf|all]" >&2
  exit 2
}

if [[ $# -lt 1 ]]; then
  usage
fi

if [[ ! -x "$LMSCRIPT_BIN" ]]; then
  echo "error: LMSCRIPT_BIN not executable: $LMSCRIPT_BIN" >&2
  exit 2
fi

collect_scenarios() {
  local slice="$1"
  case "$slice" in
    object-storage|queue|cost-perf)
      find "$CONF_DIR/$slice" -maxdepth 1 -name '*.lms' | sort
      ;;
    all|"")
      find "$CONF_DIR/object-storage" -maxdepth 1 -name '*.lms' | sort
      find "$CONF_DIR/queue" -maxdepth 1 -name '*.lms' | sort
      find "$CONF_DIR/cost-perf" -maxdepth 1 -name '*.lms' | sort
      ;;
    *)
      echo "error: unknown slice '$slice' (expected: object-storage | queue | cost-perf | all)" >&2
      exit 2
      ;;
  esac
}

# --- Embedded _lmcode_ compile gate (11-cost-perf-conformance.md §1) ------------------
# check_scenario verifies both the outer .lms syntax/splices AND compiles
# every embedded _lmcode_ block against schema/lmcloud.dsl.json by replacing
# outer ${...} splices with literal "probe" strings at the exact source line
# numbers (since outer splices otherwise defer inner lmcode bytecode compilation
# until runtime construction).
check_scenario() {
  local f="$1"
  if ! "$LMSCRIPT_BIN" --check "$f"; then
    return 1
  fi
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/lmcloud-embed-check.XXXXXX.lms")"
  python3 - "$f" "$SCHEMA_FILE" "$tmp" <<'PY'
import re, sys

src_path, schema_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src_path, "r", encoding="utf-8") as fh:
    lines = fh.readlines()

out = []
in_block = False
block_idx = 0
header_re = re.compile(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*|.*\brun_lmcode\s*\(\s*)_lmcode_\b.*;\s*(?:#.*)?$')
splice_re = re.compile(r'\$\{[^}]+\}')

for line in lines:
    stripped = line.strip()
    if not in_block:
        if "_lmcode_" in line and not stripped.startswith("#"):
            m = header_re.match(line.rstrip("\r\n"))
            if m:
                in_block = True
                block_idx += 1
                out.append(f'_blk_{block_idx} = _lmcode_ schema="{schema_path}";\n')
                continue
        out.append("# " + line if line.endswith("\n") else "# " + line + "\n")
    else:
        if stripped == "end _lmcode_":
            in_block = False
            out.append("end _lmcode_\n")
        else:
            out.append(splice_re.sub('"probe"', line))

with open(out_path, "w", encoding="utf-8") as fh:
    fh.writelines(out)
PY
  local rc=0
  if ! "$LMSCRIPT_BIN" --check "$tmp"; then
    rc=1
  fi
  rm -f "$tmp"
  return $rc
}

# Negative control: prove check_scenario rejects a spliced _lmcode_ block
# containing invalid inner lmcode syntax (which plain `lmscript --check` defers).
verify_embedded_gate_negative_control() {
  local neg
  neg="$(mktemp "${TMPDIR:-/tmp}/lmcloud-neg-ctrl.XXXXXX.lms")"
  cat >"$neg" <<EOF
endpoint = "http://127.0.0.1:4566";
p = _lmcode_ schema="$SCHEMA_FILE";
  let ep = \${endpoint};
  let bad = 1e-9;
  cloud.nonexistent_method(ep, bad);
end _lmcode_
EOF
  if check_scenario "$neg" >/dev/null 2>&1; then
    rm -f "$neg"
    echo "error: embedded _lmcode_ negative control unexpectedly passed!" >&2
    return 1
  fi
  rm -f "$neg"
  return 0
}
# -------------------------------------------------------------------------------------

pass=0
fail=0
skip=0
idx=0

if [[ "${1:-}" == "--check" ]]; then
  verify_embedded_gate_negative_control
  SLICE="${2:-all}"
  mapfile -t SCENARIOS < <(collect_scenarios "$SLICE")
  total="${#SCENARIOS[@]}"
  echo "1..$total"
  for f in "${SCENARIOS[@]}"; do
    idx=$((idx + 1))
    slice_name="$(basename "$(dirname "$f")")"
    name="$slice_name/$(basename "$f" .lms)"
    if err_out="$(check_scenario "$f" 2>&1)"; then
      echo "ok $idx - $name (--check + embedded _lmcode_ compile)"
      pass=$((pass + 1))
    else
      echo "not ok $idx - $name (--check + embedded _lmcode_ compile)"
      printf '%s\n' "$err_out" >&2
      fail=$((fail + 1))
    fi
  done
else
  HOST_BIN="$1"
  ARG2="${2:-}"
  if [[ "$ARG2" == "object-storage" || "$ARG2" == "queue" || "$ARG2" == "cost-perf" || "$ARG2" == "all" ]]; then
    ENDPOINT=""
    SLICE="$ARG2"
    RUN_ID="${3:-${LMCLOUD_RUN_ID:-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}}"
  else
    ENDPOINT="$ARG2"
    SLICE="${3:-all}"
    RUN_ID="${4:-${LMCLOUD_RUN_ID:-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}}"
  fi
  if [[ -n "$ENDPOINT" ]]; then
    export LMCLOUD_STORAGE_ENDPOINT="$ENDPOINT"
    export LMCLOUD_QUEUE_ENDPOINT="$ENDPOINT"
    export LMCLOUD_ENDPOINT="$ENDPOINT"
  fi
  mapfile -t SCENARIOS < <(collect_scenarios "$SLICE")
  total="${#SCENARIOS[@]}"
  echo "1..$total"
  for f in "${SCENARIOS[@]}"; do
    idx=$((idx + 1))
    slice_name="$(basename "$(dirname "$f")")"
    name="$slice_name/$(basename "$f" .lms)"
    if out="$("$LMSCRIPT_BIN" "$f" "$HOST_BIN" "$ENDPOINT" "$RUN_ID" 2>&1)"; then
      if [[ "$out" =~ ^SKIP:[[:space:]]*(.*)$ ]]; then
        echo "ok $idx - $name # SKIP ${BASH_REMATCH[1]}"
        skip=$((skip + 1))
      else
        echo "ok $idx - $name"
      fi
      pass=$((pass + 1))
    else
      echo "not ok $idx - $name"
      printf '%s\n' "$out" >&2
      fail=$((fail + 1))
    fi
  done
fi

echo "# pass $pass / $total, skip $skip, fail $fail"
[[ $fail -eq 0 ]]
