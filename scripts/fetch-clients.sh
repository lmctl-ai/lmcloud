#!/usr/bin/env bash
# Fetches prebuilt cloud client binaries and verifies them against scripts/clients.lock.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LOCK_FILE="$HERE/clients.lock"

[ -f "$LOCK_FILE" ] || { echo "ERROR: lockfile not found at $LOCK_FILE" >&2; exit 1; }

CACHE_DIR="${LMCLOUD_CLIENT_DIR:-$ROOT/.cache/clients}"
mkdir -p "$CACHE_DIR"

# Ensure .cache is ignored if created inside repo root
if [[ "$CACHE_DIR" == "$ROOT/.cache"* ]]; then
  mkdir -p "$ROOT/.cache"
  if [ ! -f "$ROOT/.cache/.gitignore" ]; then
    printf '*\n' > "$ROOT/.cache/.gitignore"
  fi
fi

# Detect platform OS and ARCH matching release asset conventions:
# OS: linux, macos, windows
# ARCH: arm64, x64
detect_os() {
  case "$(uname -s)" in
    Linux*)   echo "linux" ;;
    Darwin*)  echo "macos" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *) echo "unsupported" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    aarch64|arm64) echo "arm64" ;;
    x86_64|amd64)  echo "x64" ;;
    *) echo "unsupported" ;;
  esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
EXT=""
if [ "$OS" = "windows" ]; then
  EXT=".exe"
fi

if [ "$OS" = "unsupported" ] || [ "$ARCH" = "unsupported" ]; then
  echo "ERROR: Unsupported OS ($OS) or architecture ($ARCH)" >&2
  exit 1
fi

compute_sha256() {
  local file="$1"
  python3 -c '
import hashlib, sys
p = sys.argv[1]
with open(p, "rb") as f:
    print(hashlib.sha256(f.read()).hexdigest())
' "$file"
}

fetch_client() {
  local client="$1"

  # Query metadata from clients.lock
  local meta
  meta="$(python3 -c '
import json, sys
lock_path, client, os_name, arch_name, ext = sys.argv[1:6]
with open(lock_path) as f:
    data = json.load(f)
if client not in data:
    sys.exit(f"Unknown client: {client}")
info = data[client]
repo = info["repository"]
tag = info["tag"]
asset = f"{client}-{os_name}-{arch_name}{ext}"
expected_sha = info["sha256"].get(asset)
if not expected_sha:
    sys.exit(f"No sha256 found for asset {asset} in {lock_path}")
print(f"{repo}\t{tag}\t{asset}\t{expected_sha}")
' "$LOCK_FILE" "$client" "$OS" "$ARCH" "$EXT")"

  local repo tag asset expected_sha
  IFS=$'\t' read -r repo tag asset expected_sha <<< "$meta"

  local target_file="$CACHE_DIR/$asset"
  local symlink_file="$CACHE_DIR/$client$EXT"

  if [ -f "$target_file" ]; then
    local actual_sha
    actual_sha="$(compute_sha256 "$target_file")"
    if [ "$actual_sha" = "$expected_sha" ]; then
      echo "Verified cached $client ($asset)"
      chmod +x "$target_file"
      ln -sf "$asset" "$symlink_file"
      return 0
    else
      echo "Cached file $asset has checksum mismatch, re-downloading..." >&2
      rm -f "$target_file"
    fi
  fi

  echo "Downloading $asset from $repo ($tag)..."
  gh release download "$tag" -R "$repo" --pattern "$asset" --dir "$CACHE_DIR"

  if [ ! -f "$target_file" ]; then
    echo "ERROR: Download succeeded but $target_file was not found" >&2
    exit 1
  fi

  local downloaded_sha
  downloaded_sha="$(compute_sha256 "$target_file")"
  if [ "$downloaded_sha" != "$expected_sha" ]; then
    rm -f "$target_file"
    echo "ERROR: SHA256 mismatch for $asset!" >&2
    echo "  Expected: $expected_sha" >&2
    echo "  Got:      $downloaded_sha" >&2
    exit 1
  fi

  chmod +x "$target_file"
  ln -sf "$asset" "$symlink_file"
  echo "Successfully verified and installed $client -> $symlink_file"
}

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=("lmaws" "lmazure" "lmgcp" "lmoci")
fi

for client in "${targets[@]}"; do
  # normalize shorthand names
  case "$client" in
    aws) client="lmaws" ;;
    azure) client="lmazure" ;;
    gcp) client="lmgcp" ;;
    oci) client="lmoci" ;;
  esac
  fetch_client "$client"
done
