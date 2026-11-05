#!/usr/bin/env bash
# Verification gate for the shared Go host kit: vet, race tests (x3), and the
# end-to-end conformance/dry-run checks against the reference host.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
gofmt_out="$(gofmt -l hostkit schema)"
[ -z "$gofmt_out" ] || { echo "gofmt needed: $gofmt_out" >&2; exit 1; }
go vet ./...
go test -race -timeout 30m -count=3 ./...
