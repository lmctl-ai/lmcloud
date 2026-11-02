# lmcloud durable memory

- Purpose: one shared lmcode schema that every `lm<provider>` host implements in sync, plus conformance tests written as lmscript programs.
- Direction: procedural scripting (lmscript `load_schema` / `_lmcode_` / `run_lmcode`), not declarative config. The former OpenTofu-based host is archived as `lmctl-ai/lmtofu`.
- Initial scope: object storage and queue, the services all four emulators support.
- Tests execute against `<provider>sim`; each `lm<provider>` additionally tests every function against its own sim.
- Hosts are Go, built on `lmctl-ai/lmcode-go`; reference sample: `lmctl-ai/lmcode-go-sample`.
