#!/usr/bin/env bash
# Regenerates README gallery images from repo examples and commands.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

LMVIDEO_DIR="${LMVIDEO_DIR:-}"
if [ -z "$LMVIDEO_DIR" ]; then
  if [ -d "$HERE/../lmvideo" ]; then
    LMVIDEO_DIR="$HERE/../lmvideo"
  elif [ -d "$HERE/../../lmctlhq/lmvideo" ]; then
    LMVIDEO_DIR="$HERE/../../lmctlhq/lmvideo"
  else
    LMVIDEO_DIR="$HERE/../lmvideo"
  fi
fi

RENDERER="${RENDERER:-$LMVIDEO_DIR/examples/terminal-shot.lms}"
[ -f "$RENDERER" ] || { echo "Renderer not found at $RENDERER (set LMVIDEO_DIR or RENDERER)" >&2; exit 1; }

export PATH="$HERE/bin:$LMVIDEO_DIR/build:$PATH"
mkdir -p docs/images/src

for src in docs/images/src/*.txt; do
  name="$(basename "$src" .txt)"
  echo "Rendering $name..."
  lmscript "$RENDERER" "$src" "docs/images/$name.png" "$name"
done
echo "All README images rendered."
