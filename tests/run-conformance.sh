#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
CONF_DIR="$ROOT/tests/conformance"

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

pass=0
fail=0
skip=0
idx=0

if [[ "${1:-}" == "--check" ]]; then
  SLICE="${2:-all}"
  mapfile -t SCENARIOS < <(collect_scenarios "$SLICE")
  total="${#SCENARIOS[@]}"
  echo "1..$total"
  for f in "${SCENARIOS[@]}"; do
    idx=$((idx + 1))
    slice_name="$(basename "$(dirname "$f")")"
    name="$slice_name/$(basename "$f" .lms)"
    if "$LMSCRIPT_BIN" --check "$f" >/dev/null 2>&1; then
      echo "ok $idx - $name (--check)"
      pass=$((pass + 1))
    else
      echo "not ok $idx - $name (--check)"
      "$LMSCRIPT_BIN" --check "$f" >&2 || true
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
