#!/usr/bin/env bash
# Stamp a release version into the working tree (used by CI only; the change is never committed).
#   scripts/stamp-version.sh --base    print the current MAJOR.MINOR
#   scripts/stamp-version.sh X.Y.Z     rewrite the version source to X.Y.Z (no-op when empty)
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f LMCLOUD_VERSION ]; then
  current="$(head -n1 LMCLOUD_VERSION | tr -d '[:space:]')"
elif [ -f cmd/lmcloud/VERSION ]; then
  current="$(head -n1 cmd/lmcloud/VERSION | tr -d '[:space:]')"
else
  current="0.1.0"
fi

[ -n "$current" ] || { echo "cannot find the version source" >&2; exit 1; }

if [ "${1:-}" = "--base" ]; then
  echo "${current%.*}"
  exit 0
fi

v="${1:-}"
[ -n "$v" ] || exit 0

if [ -f LMCLOUD_VERSION ]; then
  printf '%s\n' "$v" > LMCLOUD_VERSION
fi
if [ -d cmd/lmcloud ]; then
  printf '%s\n' "$v" > cmd/lmcloud/VERSION
fi

echo "stamped version $v (was $current)"
