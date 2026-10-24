#!/usr/bin/env bash
# Regenerates README gallery images from repo examples and commands.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

RENDERER="${RENDERER:-/home/mma/repos/lmctlhq/lmvideo/examples/terminal-shot.lms}"
[ -f "$RENDERER" ] || { echo "Renderer not found at $RENDERER" >&2; exit 1; }

export PATH="$HERE/bin:/home/mma/repos/lmctlhq/lmvideo/build:$PATH"
mkdir -p docs/images/src

for src in docs/images/src/*.txt; do
  name="$(basename "$src" .txt)"
  echo "Rendering $name..."
  lmscript "$RENDERER" "$src" "docs/images/$name.png" "$name"
done
echo "All README images rendered."
