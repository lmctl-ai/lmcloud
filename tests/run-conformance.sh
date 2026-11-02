#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
SUITE_DIR="$ROOT/tests/conformance/object-storage"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <host-binary> [endpoint]" >&2
  echo "       $0 --check" >&2
  exit 2
fi

if [[ ! -x "$LMSCRIPT_BIN" ]]; then
  echo "error: LMSCRIPT_BIN not executable: $LMSCRIPT_BIN" >&2
  exit 2
fi

mapfile -t SCENARIOS < <(find "$SUITE_DIR" -maxdepth 1 -name '*.lms' | sort)
total="${#SCENARIOS[@]}"
echo "1..$total"

pass=0
fail=0
idx=0

if [[ "${1:-}" == "--check" ]]; then
  for f in "${SCENARIOS[@]}"; do
    idx=$((idx + 1))
    name="$(basename "$f" .lms)"
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
  ENDPOINT="${2:-}"
  if [[ -n "$ENDPOINT" ]]; then
    export LMCLOUD_ENDPOINT="$ENDPOINT"
  fi
  for f in "${SCENARIOS[@]}"; do
    idx=$((idx + 1))
    name="$(basename "$f" .lms)"
    if "$LMSCRIPT_BIN" "$f" "$HOST_BIN" "$ENDPOINT" >/dev/null 2>&1; then
      echo "ok $idx - $name"
      pass=$((pass + 1))
    else
      echo "not ok $idx - $name"
      "$LMSCRIPT_BIN" "$f" "$HOST_BIN" "$ENDPOINT" >&2 || true
      fail=$((fail + 1))
    fi
  done
fi

echo "# pass $pass / $total, fail $fail"
[[ $fail -eq 0 ]]
