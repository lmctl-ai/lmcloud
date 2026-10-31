#!/usr/bin/env bash
# Select by emitted bytecode capability, not CLI version or schema support alone.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmcloud-compiler-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# A native (mingw) python cannot see MSYS /tmp paths: hand it drive-letter paths when cygpath exists.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
candidate="${LMSCRIPT_BIN:-$(command -v lmscript || true)}"
printf '%s\n' '{"dsl.schema":2,"name":"compiler_probe","types":{},"functions":{},"context":{}}' > "$WORK/probe.schema.json"
# Source builds are qualified by emitted v6/signature capabilities below.
# JSON string quoting also supports checkouts whose paths contain spaces/quotes.
python3 - "$(native "$WORK/probe.schema.json")" "$(native "$WORK")" <<'PY'
import json,pathlib,sys
work=pathlib.Path(sys.argv[2])
(work/'probe.lms').write_text('p = _lmcode_ schema='+json.dumps(sys.argv[1])+';\nlet n = str_len("implicit std");\nend _lmcode_\nsavedsl(p, '+json.dumps(str(work/'probe.dslb'))+');\n')
PY
if [ -n "$candidate" ] &&
   "$candidate" --lmcode-signatures "$WORK/probe.schema.json" > /dev/null 2>&1 &&
   "$candidate" "$WORK/probe.lms" "$WORK/probe.dslb" > /dev/null 2>&1 &&
   python3 - "$(native "$WORK/probe.dslb")" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])
sys.exit(0 if p.is_file() and p.read_bytes()[:6] == b'DSLB\x00\x06' else 1)
PY
then
  printf '%s\n' "$candidate"
else
  if [ -n "${LMCLOUD_DEBUG:-}" ]; then
    echo "--- compiler probe diagnostics (candidate=$candidate)" >&2
    cat "$WORK/probe.lms" >&2 || true
    [ -n "$candidate" ] && "$candidate" --lmcode-signatures "$WORK/probe.schema.json" 2>&1 | head -3 >&2
    [ -n "$candidate" ] && "$candidate" "$WORK/probe.lms" "$WORK/probe.dslb" 2>&1 | head -10 >&2
    ls -la "$WORK" >&2
  fi
  echo "error: no implicit-std lmcode v6 compiler found; build mono main with the host-flag cutover so lmscript is on PATH, or set LMSCRIPT_BIN" >&2
  exit 2
fi
