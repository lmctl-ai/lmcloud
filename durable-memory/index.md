# lmcloud durable memory

- Purpose: one shared lmcode schema that every `lm<provider>` host implements in sync, plus conformance tests written as lmscript programs.
- Direction: procedural scripting (lmscript `load_schema` / `_lmcode_` / `run_lmcode`), not declarative config. The former OpenTofu-based host is archived as `lmctl-ai/lmtofu`.
- Initial scope: object storage and queue, the services all four emulators support.
- Tests execute against `<provider>sim`; each `lm<provider>` additionally tests every function against its own sim.
- Hosts are Go, built on `lmctl-ai/lmcode-go`; reference sample: `lmctl-ai/lmcode-go-sample`.
- [02-object-storage-design.md](02-object-storage-design.md): shared object storage operations, types, per-provider/simulator mapping, credential chains, naming/idempotency/error rules, exclusions, and operator decisions.
- [03-object-storage-conformance.md](03-object-storage-conformance.md): 12 cross-provider conformance scenarios (`tests/conformance/object-storage/01..12-*.lms`), runner (`tests/run-conformance.sh`), and simulator enhancements. All `.lms` tests pass `lmscript --check` statically; runtime execution awaits implementation of the Go `lm<provider>` hosts.
- [05-roadmap.md](05-roadmap.md): 10-slice roadmap, fixed slice delivery order (1 storage, 2 queue, 3 perf+cost, 4 permissions, 5 tables, 6 userpool, 7 VM control-plane, 8 container, 9 lambda w/o invoke, 10 valkey), simulator-first testing principle, and simulator enhancement epics.
