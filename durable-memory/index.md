# lmcloud durable memory

- Purpose: one shared lmcode schema that every `lm<provider>` host implements in sync, plus conformance tests written as lmscript programs.
- Direction: procedural scripting (lmscript `load_schema` / `_lmcode_` / `run_lmcode`), not declarative config. The former OpenTofu-based host is archived as `lmctl-ai/lmtofu`.
- Initial scope: object storage and queue, the services all four emulators support.
- Tests execute against `<provider>sim`; each `lm<provider>` additionally tests every function against its own sim.
- Hosts are Go, built on `lmctl-ai/lmcode-go`; reference sample: `lmctl-ai/lmcode-go-sample`.
- [02-object-storage-design.md](02-object-storage-design.md): shared object storage operations, types, per-provider/simulator mapping, credential chains, naming/idempotency/error rules, exclusions, and operator decisions.
- [03-object-storage-conformance.md](03-object-storage-conformance.md): 12 cross-provider object storage conformance scenarios (`tests/conformance/object-storage/01..12-*.lms`), runner (`tests/run-conformance.sh`), and simulator enhancements. All `.lms` tests pass `lmscript --check` statically; runtime execution awaits implementation of the Go `lm<provider>` hosts.
- [04-sims.md](04-sims.md): fetching and driving the four checksum-pinned simulators (`scripts/fetch-sims.sh`, `scripts/sim.sh`), client pins, smoke tests, verified simulator capabilities and enhancement list.
- [05-roadmap.md](05-roadmap.md): 10-slice roadmap, fixed slice delivery order (1 storage, 2 queue, 3 perf+cost, 4 permissions, 5 tables, 6 userpool, 7 VM control-plane, 8 container, 9 lambda w/o invoke, 10 valkey against a real `valkey/valkey` container), guiding principles ("use the real thing when cheap and local; use a sim only to emulate a cloud's API"), and simulator enhancement epics.
- [06-sim-rules.md](06-sim-rules.md): shared simulator rules design (`sim_rules_v1` SAM `Interceptor` / `Responder` methods for fault injection, throttling, latency, pagination caps, and response rewriting) and evaluation of `lmctl-ai/lmmock` (`--upstream` passthrough + `Handler` SAM entries) as an alternative/complement front proxy.
- [07-queue-design.md](07-queue-design.md): Slice 2 shared queue operations (`queue_create`, `queue_delete`, `queue_exists`, `queue_list`, `queue_send`, `queue_receive`, `queue_ack`, `queue_nack`), types (`QueueMessage`, `QueueMessageList`), per-provider/simulator mappings (SQS, Azure Queue Storage, GCP Pub/Sub topic+subscription pair, OCI Queue OCID + messages endpoint), naming/payload/visibility rules, and exclusions.
- [08-queue-conformance.md](08-queue-conformance.md): 13 cross-provider queue conformance scenarios (`tests/conformance/queue/01..13-*.lms`) and evidence-backed simulator enhancements across `awssim`, `azuresim`, `gcpsim`, and `ocisim`.
- [09-hostkit.md](09-hostkit.md): shared Go module `github.com/lmctl-ai/lmcloud` — `hostkit` (error model, retry, endpoint policy, validation, codec, pagination, queue helpers, adapter interfaces), `hostkit/invoke`, `hostkit/cloudhost` (shared schema registered once with dry previews), `hostkit/fakeadapter`, the `lmcloud-ref` reference host, the provider adapter contract, and the verification gate (conformance 25/25 without any sim).
- [09-ci-workflow-draft.yml](09-ci-workflow-draft.yml): GitHub Actions workflow DRAFT (not enabled; lives outside `.github/workflows`). Known fixes before activation: Linux-only job for the Valkey service container, a `permissions: contents: read` block, SHA-pinned actions.

### Slice 3 — Cost & Performance
- [10-cost-perf-design.md](10-cost-perf-design.md): Slice 3 cross-cutting Cost & Performance design (`cost_cap_usd`, monotone-decreasing `set_cost_cap_usd`, `estimated_cost`, `cost_report`, `metrics_reset`, `metrics`; types `CostReport`, `CostLineItem`, `MetricsReport`, `OpMetrics`; `ErrorCode.COST_CAP_EXCEEDED`, physical pre-attempt/page/probe reservations, shared campaign budget authority, reserved cleanup headroom, regional vs synthetic simulator price tables, and streaming all-call metrics + bounded 10,000-sample quantile ring buffer).
- [11-cost-perf-conformance.md](11-cost-perf-conformance.md): 10 cross-provider cost & performance conformance scenarios (`tests/conformance/cost-perf/01..10-*.lms`) and `tests/run-conformance.sh` `--check` embedded `_lmcode_` compilation gate across all slices (`35/35` passing).

## Status (integration branch)

- Four Go hosts implement the shared schema on `hostkit` and pass the 25 conformance programs against their simulators: `lmoci` (ocisim), `lmazure` (azuresim), `lmaws` (awssim), `lmgcp` (gcpsim, `lmgcp cloud`). Hosts are sim/fake only: live cloud support is deliberately not implemented and fails with `UNAUTHENTICATED` / `LiveCredentialsNotImplemented`.
- Hosts build against this module through a local `replace => ../lmcloud` and, until `Registry.Enum` is merged upstream, a local `replace` of `lmcode-go` (patched clone, branch `dry-enum-string`). Both are publish blockers.
- Simulator fixes needed by the conformance programs live on branches `fix-sdk-compat` (awssim), `fix-modify-ack-deadline` (gcpsim), `fix-azure-semantics` (azuresim); released simulator binaries lack them (hosts keep named compat options for that case).
- Run: `scripts/test-hostkit.sh` (reference host + in-memory adapter, 25/25), and each host's own `test-go.sh` / `test-cloud.sh`.
