# Host flag cutover

Only --lmcode, --lmcode-schema and --lmcode-signatures select the host language
protocol, with existing --without-std behavior intact. All retired spellings are
usage exit 2 before input loading. Raw schema/signatures and new execution retain
the existing diagnostics and failure policies; DSLB and .dslb names are unchanged.

Go modules pin SDK 65f0ef2. Source builds are checked by emitted v6/signature
capabilities, not historical package-version strings. The full static host gate
passes 38 checks: all 18 examples, metadata parity, implicit std, malformed input,
local terraform_data/provider behavior, state/error handling, variable persistence,
format/import behavior and internal provider/lmhost tests. Tracked and exact module
source spelling scans pass. Upstream OpenTofu source is not changed or submitted
upstream; this is the fork's MIT lmcloud host/caller surface.
