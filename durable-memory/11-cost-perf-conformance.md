# 11 — `lmcloud` Cost & Performance Conformance Suite (Slice 3)

## 1. Conformance Runner Usage

The conformance runner [`tests/run-conformance.sh`](../tests/run-conformance.sh) supports selecting `object-storage`, `queue`, `cost-perf`, or `all` (default: `all`):

```bash
# Static compile/typecheck against schema/lmcloud.dsl.json:
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

### Determinism & Portability Rules for `cost-perf` Scenarios
- **Provider-agnostic cost assertions:** Because AWS, Azure, GCP, and OCI have distinct embedded tariffs (see [`10-cost-perf-design.md` §3.2](10-cost-perf-design.md)), conformance scenarios calibrate dynamic cost caps from `cloud.estimated_cost()` after a seed call and verify exact `requests()`, `billing_units()`, `bytes()`, and `sum(item.estimated_usd()) == report.estimated_usd()` rather than hardcoding AWS-only dollar literals.
- **No wall-clock flakiness in performance scenarios:** Performance scenarios assert exact deterministic counters (`calls()`, `errors()`, `bytes_in()`, `bytes_out()`, `retries() >= 0`, `throttles() >= 0`) and mathematical quantile ordering (`0.0 <= min_ms() <= p50_ms() <= p95_ms() <= max_ms() <= total_ms() < 60000.0` and `min_ms() <= mean_ms() <= max_ms()`), never fragile wall-clock thresholds.
- **Zero simulator enhancements required:** All 10 scenarios exercise `hostkit` / `cloudhost` cost and performance metering on top of existing Slice 1 (`storage`) and Slice 2 (`queue`) simulator endpoints (`awssim`, `azuresim`, `gcpsim`, `ocisim`, and offline `fakeadapter`).

---

## 2. The 10 Cost & Performance Conformance Scenarios (`tests/conformance/cost-perf/`)

| # | File | Scenario | One-Line Expected Behavior |
|---|---|---|---|
| **01** | `01-default-cap-and-readonly-zero-cost.lms` | Default `$0.05` cap, `$0.25` hard ceiling, and `$0.00` cost on config/inspection calls | `cost_cap_usd()` defaults to `0.05`, `cost_report().ceiling_usd()` is `0.25`, `estimated_cost()` is `0.0`, `cost_report().summary()` contains `"$0.00"`, and calling `provider()`, `endpoint()`, `abort_on_error()`, `last_error()`, `cost_report()`, or `metrics()` records `0` requests and `0` calls. |
| **02** | `02-storage-cost-metering-and-line-items.lms` | Storage cost metering, per-operation `CostLineItem` breakdown, monotonic byte pricing, and no refund on delete | `bucket_create`, `object_put` (small + 4 KiB payload), `object_head`, `object_get`, and `object_list` monotonically increase `estimated_cost()`; larger `object_put` payloads cost at least as much as smaller ones; `CostReport` items are sorted lexicographically and sum to `estimated_usd()`; `object_delete` and `bucket_delete` never refund accrued cost. |
| **03** | `03-queue-cost-and-64kib-billing-units.lms` | Queue cost metering, 64 KiB billing units, and byte tracking across `send`/`receive`/`nack`/`ack` | `queue_create`, `queue_send` (2 messages), `queue_receive`, `queue_nack`, `queue_ack`, and `queue_delete` populate `service() == "queue"` line items with exact `requests()`, `billing_units()`, and `bytes()`. |
| **04** | `04-cost-cap-enforcement-and-teardown-immunity.lms` | Pre-flight `ErrorCode.COST_CAP_EXCEEDED` enforcement and teardown immunity (`delete`/`ack`) | Setting `set_cost_cap_usd(cloud.estimated_cost())` after seeding a bucket and queue causes subsequent `object_put`, `object_get`, and `queue_send` calls to fail pre-flight with `ErrorCode.COST_CAP_EXCEEDED` (`http_status() == 0`, `provider_code() == "CostCapExceeded"`, `cap_exceeded_count() == 3`), while `queue_ack`, `object_delete`, `bucket_delete`, and `queue_delete` still succeed with `ErrorCode.OK`. |
| **05** | `05-cost-cap-validation-guards.lms` | Pre-flight validation of `set_cost_cap_usd` (`<= 0`, `> $0.25`, or `< estimated_cost()`) | Calling `set_cost_cap_usd` with `0.0`, `-0.05`, `0.250001`, `1.0`, or a value below already-accrued `estimated_cost()` fails pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`) without altering `cost_cap_usd()`. |
| **06** | `06-cost-cap-abort-on-error.lms` | Default `abort_on_error() == true` aborts the `_lmcode_` program with `[COST_CAP_EXCEEDED]` | Exceeding `cost_cap_usd()` with `abort_on_error() == true` aborts the `_lmcode_` block (`!r.ok`); a subsequent cleanup block verifies and deletes the bucket created prior to the abort. |
| **07** | `07-metrics-counters-and-bytes.lms` | Per-operation `calls()`, `bytes_out()`, and `bytes_in()` across storage and queue operations | `object_put` records exact `bytes_out()`, `object_get` records exact `bytes_in()`, `queue_send` records exact `bytes_out()`, `queue_receive` records exact `bytes_in()`, and `MetricsReport` totals match the sum across operations. |
| **08** | `08-metrics-latency-order-invariants.lms` | Latency quantile order invariants (`0 <= min_ms <= p50_ms <= p95_ms <= max_ms <= total_ms`) | Across 5 `object_put`, 5 `object_head`, and 5 `object_get` calls, `MetricsReport` lists the 3 operations in lexicographical order and satisfies `0.0 <= min_ms() <= p50_ms() <= p95_ms() <= max_ms() <= total_ms() < 60000.0` and `min_ms() <= mean_ms() <= max_ms()`, while uncalled operations report `0.0`. |
| **09** | `09-metrics-reset-scoping-and-cost-persistence.lms` | Timer scoping via `cloud.metrics_reset()` without resetting cumulative cost | `cloud.metrics_reset()` zeroes `total_calls()`, `total_bytes_out()`, and per-operation `OpMetrics` between Phase 1 and Phase 2 while preserving `cloud.estimated_cost()` and `cloud.cost_report().total_requests()`. |
| **10** | `10-metrics-error-and-retry-counters.lms` | Error, retry, and throttle counters in `metrics()` and `last_error()` preservation | Pre-flight `INVALID_ARGUMENT` and provider `NOT_FOUND` errors increment `total_errors()` and `OpMetrics.errors()` (with pre-flight errors not billed in `cost_report()`), `retries()`/`throttles()` are `>= 0`, and calling `metrics()`, `cost_report()`, `estimated_cost()`, or `cost_cap_usd()` does not overwrite `cloud.last_error()`. |
