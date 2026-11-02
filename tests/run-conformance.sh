#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${LMSCRIPT_BIN:-}" ]]; then
  if [[ -x "/home/ubuntu/lmctl-mono/lmscript/bin/lmscript" ]]; then
    LMSCRIPT_BIN="/home/ubuntu/lmctl-mono/lmscript/bin/lmscript"
  elif command -v lmscript >/dev/null 2>&1; then
    LMSCRIPT_BIN="$(command -v lmscript)"
  else
    LMSCRIPT_BIN="/home/ubuntu/lmctl-mono/lmscript/bin/lmscript"
  fi
fi
CONF_DIR="$ROOT/tests/conformance"

usage() {
  echo "Usage: $0 [--live] [--name-prefix <prefix>] <host-binary> [endpoint] [object-storage|queue|tables|all] [run-id]" >&2
  echo "       $0 [--live] --check [object-storage|queue|tables|all]" >&2
  exit 2
}

LIVE_PROFILE="${LMCLOUD_LIVE_PROFILE:-0}"
NAME_PREFIX="${LMCLOUD_NAME_PREFIX:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --live)
      LIVE_PROFILE=1
      shift
      ;;
    --name-prefix)
      if [[ $# -lt 2 ]]; then
        usage
      fi
      NAME_PREFIX="$2"
      shift 2
      ;;
    --name-prefix=*)
      NAME_PREFIX="${1#*=}"
      shift
      ;;
    *)
      break
      ;;
  esac
done

if [[ -n "$NAME_PREFIX" ]]; then
  export LMCLOUD_NAME_PREFIX="$NAME_PREFIX"
fi

if [[ $# -lt 1 ]]; then
  usage
fi

if [[ ! -x "$LMSCRIPT_BIN" ]]; then
  echo "error: LMSCRIPT_BIN not executable: $LMSCRIPT_BIN" >&2
  exit 2
fi

is_live_excluded_scenario() {
  local base
  base="$(basename "$(dirname "$1")")/$(basename "$1")"
  case "$base" in
    tables/*.lms)
      # Slice 5 (tables) is excluded from the --live profile until naming/ownership
      # policy for table names (Azure-alnum intersection) is designed for live runs.
      return 0
      ;;
    */12-auth-enforced-denial.lms|*/13-queue-auth-enforced-denial.lms)
      return 0
      ;;
    12-auth-enforced-denial.lms|13-queue-auth-enforced-denial.lms)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

validate_slice() {
  local slice="$1"
  case "$slice" in
    object-storage|queue|tables|all|"")
      return 0
      ;;
    *)
      echo "error: unknown slice '$slice' (expected: object-storage | queue | tables | all)" >&2
      exit 2
      ;;
  esac
}

collect_scenarios() {
  local slice="$1"
  local filter="${LMCLOUD_SCENARIO_FILTER:-}"
  local raw=()
  case "$slice" in
    object-storage|queue|tables)
      mapfile -t raw < <(find "$CONF_DIR/$slice" -maxdepth 1 -name '*.lms' | sort)
      ;;
    all|"")
      mapfile -t raw < <(
        find "$CONF_DIR/object-storage" -maxdepth 1 -name '*.lms' | sort
        find "$CONF_DIR/queue" -maxdepth 1 -name '*.lms' | sort
        find "$CONF_DIR/tables" -maxdepth 1 -name '*.lms' | sort
      )
      ;;
    *)
      echo "error: unknown slice '$slice' (expected: object-storage | queue | tables | all)" >&2
      exit 2
      ;;
  esac
  for f in "${raw[@]}"; do
    if [[ "$LIVE_PROFILE" == "1" ]] && is_live_excluded_scenario "$f"; then
      continue
    fi
    if [[ -n "$filter" ]]; then
      local base base_no_ext rel rel_no_ext
      base="$(basename "$f")"
      base_no_ext="$(basename "$f" .lms)"
      rel="$(basename "$(dirname "$f")")/$base"
      rel_no_ext="$(basename "$(dirname "$f")")/$base_no_ext"
      if [[ "$filter" != "$base" && "$filter" != "$base_no_ext" && "$filter" != "$rel" && "$filter" != "$rel_no_ext" ]]; then
        continue
      fi
    fi
    printf '%s\n' "$f"
  done
}

# --- Capability skip gate (13-tables-conformance.md §1); single self-contained function ------
# Echoes "reason (host:req pending)" if the scenario must be TAP-skipped for this host, else "".
capability_skip_reason() {
  local host_bin="$1" f="$2"
  local host req line status
  host="$(basename "$host_bin" | sed 's/\.exe$//')"
  req="$(sed -n 's/^# Requires:[[:space:]]*//p' "$f" | head -n1 | tr -d '[:space:]')"
  [[ -z "$req" ]] && req="$(basename "$(dirname "$f")")"
  line="$(grep -E "^${host}:${req}=" "$ROOT/tests/capabilities.conf" 2>/dev/null | head -n1 || true)"
  status="${line#*=}"
  [[ -z "$line" ]] && status="supported"
  if [[ "$status" == pending* ]]; then
    local reason="${status#pending(}"
    reason="${reason%)}"
    echo "$reason ($host:$req pending)"
  fi
}
# ---------------------------------------------------------------------------------------------

pass=0
fail=0
skip=0
idx=0

if [[ "${1:-}" == "--check" ]]; then
  SLICE="${2:-all}"
  validate_slice "$SLICE"
  mapfile -t SCENARIOS < <(collect_scenarios "$SLICE")
  total="${#SCENARIOS[@]}"
  if [[ "$total" -eq 0 ]]; then
    echo "error: no conformance scenarios found for slice '$SLICE'" >&2
    exit 2
  fi
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
  DEFAULT_RUN_ID="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  if [[ "$LIVE_PROFILE" == "1" ]]; then
    DEFAULT_RUN_ID="run-$(date -u +%s)-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  if [[ "$ARG2" == "object-storage" || "$ARG2" == "queue" || "$ARG2" == "tables" || "$ARG2" == "all" ]]; then
    ENDPOINT=""
    SLICE="$ARG2"
    RUN_ID="${3:-${LMCLOUD_RUN_ID:-${LMAWS_RUN_ID:-$DEFAULT_RUN_ID}}}"
  else
    ENDPOINT="$ARG2"
    SLICE="${3:-all}"
    RUN_ID="${4:-${LMCLOUD_RUN_ID:-${LMAWS_RUN_ID:-$DEFAULT_RUN_ID}}}"
  fi
  if [[ "$LIVE_PROFILE" == "1" ]]; then
    export LMCLOUD_RUN_ID="$RUN_ID"
    export LMAWS_RUN_ID="${LMAWS_RUN_ID:-$RUN_ID}"
    if [[ -z "${LMCLOUD_NAME_PREFIX:-}" ]]; then
      RAND_SUFFIX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
      if [[ "$RUN_ID" =~ ^run-[0-9]{10,}-([0-9a-f]{12})$ ]]; then
        export LMCLOUD_NAME_PREFIX="lmcloud-conf-${BASH_REMATCH[1]}-${RAND_SUFFIX}-"
      else
        export LMCLOUD_NAME_PREFIX="lmcloud-conf-${RUN_ID}-${RAND_SUFFIX}-"
      fi
    fi
  fi
  if [[ -n "$ENDPOINT" ]]; then
    export LMCLOUD_STORAGE_ENDPOINT="$ENDPOINT"
    export LMCLOUD_QUEUE_ENDPOINT="$ENDPOINT"
    export LMCLOUD_TABLES_ENDPOINT="$ENDPOINT"
    export LMCLOUD_ENDPOINT="$ENDPOINT"
  fi
  validate_slice "$SLICE"
  mapfile -t SCENARIOS < <(collect_scenarios "$SLICE")
  total="${#SCENARIOS[@]}"
  if [[ "$total" -eq 0 ]]; then
    echo "error: no conformance scenarios found for slice '$SLICE'" >&2
    exit 2
  fi
  echo "1..$total"
  for f in "${SCENARIOS[@]}"; do
    idx=$((idx + 1))
    slice_name="$(basename "$(dirname "$f")")"
    name="$slice_name/$(basename "$f" .lms)"
    reason="$(capability_skip_reason "$HOST_BIN" "$f")"
    if [[ -n "$reason" ]]; then
      echo "ok $idx - $name # SKIP $reason"
      skip=$((skip + 1))
      continue
    fi
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
