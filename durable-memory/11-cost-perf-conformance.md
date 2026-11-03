# 11 — `lmcloud` Cost & Performance Conformance Suite (Slice 3)

## 1. Conformance Runner & Embedded `_lmcode_` Compilation Gate

The conformance runner [`tests/run-conformance.sh`](../tests/run-conformance.sh) supports selecting `object-storage`, `queue`, `cost-perf`, or `all` (default: `all`):

```bash
# Static outer .lms check PLUS full embedded _lmcode_ DSLB v6 compilation against schema/lmcloud.dsl.json:
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check object-storage
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check queue
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check cost-perf

# Execute against each provider + simulator once Go hosts implement Slice 3:
./tests/run-conformance.sh /path/to/lmaws   http://127.0.0.1:4566 cost-perf
./tests/run-conformance.sh /path/to/lmazure http://127.0.0.1:4577 cost-perf
./tests/run-conformance.sh /path/to/lmgcp   http://127.0.0.1:4588 cost-perf
./tests/run-conformance.sh /path/to/lmoci   http://127.0.0.1:4599 cost-perf
```

### Why `run-conformance.sh --check` Also Compiles Unspliced `_lmcode_` Blocks
In `lmscript`, when an `_lmcode_` block contains outer `${expr}` splices (such as `${endpoint}` or `${bkt}`), static `lmscript --check` validates the outer script and splice expressions but defers full inner `lmcode` type/syntax compilation until the literal is constructed at runtime. To catch inner `lmcode` compile errors (such as unsupported exponent literals, ternary `?:`, or unknown functions/methods) during `--check` without starting any host or simulator, `check_scenario()` in `tests/run-conformance.sh` runs both:
1. `lmscript --check "$file"` on the original `.lms` file, and
2. `lmscript --check` on a line-preserving unspliced projection where every `_lmcode_` block is bound directly to `schema/lmcloud.dsl.json` and every `${...}` splice is replaced with `"probe"`, forcing full DSLB v6 bytecode compilation of every embedded `_lmcode_` block across all slices (`object-storage`, `queue`, and `cost-perf`).

---

## 2. The 10 Cost & Performance Conformance Scenarios (`tests/conformance/cost-perf/`)

| # | File | Scenario | One-Line Expected Behavior |
|---|---|---|---|
| **01** | `01-default-cap-and-readonly-zero-cost.lms` | Default `$0.05` cap, `$0.25` hard ceiling, and `$0.00` cost on config/inspection calls | `cost_cap_usd()` defaults to `0.05`, `cost_report().ceiling_usd()` is `0.25`, `estimated_cost()` is `0.0`, `cost_report().summary()` contains `"$0.00"`, and calling `provider()`, `endpoint()`, `abort_on_error()`, `last_error()`, `cost_report()`, or `metrics()` records `0` requests and `0` calls. |
| **02** | `02-storage-cost-metering-and-line-items.lms` | Storage cost metering, per-operation `CostLineItem` breakdown, monotonic byte pricing, and no refund on delete | `bucket_create`, `object_put` (small + 4 KiB payload), `object_head`, `object_get`, and `object_list` monotonically increase `estimated_cost()`; larger `object_put` payloads cost at least as much as smaller ones; `CostReport` items are sorted lexicographically and sum to `estimated_usd()`; `object_delete` and `bucket_delete` never refund accrued cost. |
| **03** | `03-queue-cost-and-64kib-billing-units.lms` | Queue cost metering, 64 KiB billing units, and byte tracking with at-least-once deduplication | `queue_create`, `queue_send` (2 messages), bounded-poll `queue_receive` with `StrList` message-ID deduplication, `queue_nack`, `queue_ack`, and `queue_delete` populate `service() == "queue"` line items with exact `requests()`, `billing_units()`, and delivered `bytes()`. |
| **04** | `04-cost-cap-enforcement-and-teardown-immunity.lms` | Pre-attempt `ErrorCode.COST_CAP_EXCEEDED` enforcement and reserved cleanup budget for resource delete operations inside the durable total ceiling | Narrowing `set_cost_cap_usd(cloud.estimated_cost())` after seeding a bucket, object, and queue (including `queue_ack` during the work phase) sets `cost_cap_usd()` and `cost_report().cap_usd()` to `current_cost` (with `ceiling_usd() == 0.25`) and causes subsequent `object_put`, `object_get`, and `queue_send` calls to fail pre-flight with `ErrorCode.COST_CAP_EXCEEDED` (`http_status() == 0`, `provider_code() == "CostCapExceeded"`, `cap_exceeded_count() == 3`), while resource-deletion cleanup (`object_delete`, `bucket_delete`, `queue_delete`) succeeds using the reserved cleanup headroom inside the `$0.05` total ceiling (`<= ceiling_usd()`). |
| **05** | `05-cost-cap-validation-guards.lms` | Monotone-decreasing `set_cost_cap_usd` validation (`<= 0`, `> operator cap`, raising after narrowing, or `< estimated_cost()`) | Calling `set_cost_cap_usd` with `0.0`, `-0.05`, `0.06` (above initial `$0.05` operator cap), `0.250001`, `1.0`, raising from `0.04` back to `0.05`, or lowering below already-accrued `estimated_cost()` fails pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`), while narrowing `0.05 -> 0.04` succeeds. |
| **06** | `06-cost-cap-abort-on-error.lms` | Default `abort_on_error() == true` aborts the `_lmcode_` program with `[COST_CAP_EXCEEDED]` and preserves the narrowed work sub-cap across campaign invocations | Exceeding `cost_cap_usd()` with `abort_on_error() == true` aborts the `_lmcode_` block (`!r.ok`); in the subsequent cleanup invocation of the same campaign, non-cleanup work (`bucket_exists`) remains refused by the persisted work sub-cap (`ErrorCode.COST_CAP_EXCEEDED`) while `bucket_delete` succeeds using the reserved cleanup headroom inside the durable total ceiling. |
| **07** | `07-metrics-counters-and-bytes.lms` | Per-operation `calls()`, `bytes_out()`, and `bytes_in()` across storage and bounded-poll queue operations | `object_put` records exact `bytes_out()`, `object_get` records exact `bytes_in()`, `queue_send` records exact `bytes_out()`, bounded-poll `queue_receive` records exact delivered `bytes_in()`, and `MetricsReport` totals match the sum across operations. |
| **08** | `08-metrics-latency-order-invariants.lms` | Latency quantile order invariants (`0 <= min_ms <= p50_ms <= p95_ms <= max_ms <= total_ms`) | Across 5 `object_put`, 5 `object_head`, and 5 `object_get` calls, `MetricsReport` lists the 3 operations in exact lexicographical order (`object_get`, `object_head`, `object_put`) and satisfies `0.0 <= min_ms() <= p50_ms() <= p95_ms() <= max_ms() <= total_ms()` and `min_ms() <= mean_ms() <= max_ms()`, while uncalled operations report `0.0`. |
| **09** | `09-metrics-reset-scoping-and-cost-persistence.lms` | Timer scoping via `cloud.metrics_reset()` without resetting cumulative cost | `cloud.metrics_reset()` zeroes `total_calls()`, `total_bytes_out()`, and per-operation `OpMetrics` between Phase 1 and Phase 2 while preserving `cloud.estimated_cost()` and `cloud.cost_report().total_requests()`. |
| **10** | `10-metrics-error-and-retry-counters.lms` | Error, retry, and throttle counters, physical attempt billing (`calls + retries`), and `last_error()` preservation | Pre-flight `INVALID_ARGUMENT` and `COST_CAP_EXCEEDED` errors increment `total_errors()` without charging physical requests, provider `NOT_FOUND` increments both `total_errors()` and physical `requests() == calls() + retries()`, and calling `metrics()`, `cost_report()`, `estimated_cost()`, or `cost_cap_usd()` preserves `cloud.last_error()`. |
