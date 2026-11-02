# 10 — `lmcloud` Cost & Performance Design (Slice 3, Cross-Cutting)

## 1. Goals & Architectural Alignment

Slice 3 (`Perf & Cost` in [`05-roadmap.md`](05-roadmap.md)) adds **cross-cutting cost estimation, pre-attempt budget reservation, shared campaign budget authority, and per-operation performance telemetry** to `schema/lmcloud.dsl.json` on the existing `cloud` (`Cloud`) context object **without modifying any Slice 1 (Object Storage) or Slice 2 (Queue) method signature**.

1. **Physical pre-attempt cost admission & reservation (`set_cost_cap_usd`, `estimated_cost`, `cost_report`):**
   - Every physical cloud/simulator attempt—including initial requests, `hostkit.RetryPolicy` retry attempts, ownership/existence probes, and pagination page reads in `hostkit.ListAll`—is priced and reserved **before** the attempt is transmitted on the wire. Retries and multi-page reads are never collapsed into a single post-hoc charge.
   - Operations with variable response sizes (`object_get`) or multi-step control-plane sequences (`bucket_create`, `queue_create`) reserve worst-case byte bounds (`limit` or `MaxObjectBytes = 16 MiB`), probe costs, and per-resource cleanup headroom **before dispatch**, then settle to actual observed usage upon completion.
   - If reserving the next physical attempt, retry, probe, or page would exceed the active work budget (`cost_cap_usd()`), admission aborts **pre-flight** before transmitting that request with `ErrorCode.COST_CAP_EXCEEDED` (`http_status() == 0`, `provider_code() == "CostCapExceeded"`).
2. **Shared campaign budget authority & monotone-decreasing script caps:**
   - Across multi-invocation campaigns (`hostkit/safety.Supervisor` / shared `<run_id>.jsonl` journal under POSIX `flock`), budget state (`ChargedNanoUSD` and locked `ResourceCleanupNanoUSD`) is persisted across processes so child invocations share one authoritative campaign budget rather than resetting to `$0.05` per process.
   - The operator's policy or environment establishes the initial work cap (`OperatorCapUSD`, default **`$0.05` USD**, hard ceiling **`$0.25` USD**). Scripts calling `cloud.set_cost_cap_usd(cap_usd)` may **only lower (narrow) or keep equal** the active cap (`estimated_cost() <= cap_usd <= cost_cap_usd() <= OperatorCapUSD <= 0.25`); any attempt to raise the cap fails pre-flight with `ErrorCode.INVALID_ARGUMENT`.
   - **Reserved cleanup budget (bounded teardown, never unlimited):** Teardown operations (`bucket_delete`, `object_delete`, `queue_delete`, `queue_ack`) are **not** free or unlimited. They draw from a dedicated **Cleanup Reserve** (`DefaultCleanupReserveUSD = $0.01` plus per-resource cleanup reservations locked at creation time), are authorized only for verified run-owned resources (or active receipts), and are bounded by retry/poll limits. This guarantees that cleanup survives work-budget exhaustion (`set_cost_cap_usd(cloud.estimated_cost())`) while still failing closed with `ErrorCode.COST_CAP_EXCEEDED` if a runaway script or retry storm exhausts the cleanup reserve itself.
3. **Per-operation performance telemetry (`metrics_reset`, `metrics`):**
   - Scripts scope latency and throughput measurements around specific workload phases using `cloud.metrics_reset()` and inspect per-operation call counts, error counts, physical retry counts, HTTP `429` throttle counts, payload bytes (`bytes_in`, `bytes_out`), streaming all-call aggregates (`min_ms`, `max_ms`, `mean_ms`, `total_ms`), and bounded-window latency quantiles (`p50_ms`, `p95_ms`).
4. **Zero external simulator or billing API dependency:**
   - Simulators (`awssim`, `azuresim`, `gcpsim`, `ocisim`) require no new endpoints, and live hosts **never** call paid or delayed external billing APIs (AWS Cost Explorer, Azure Cost Management, GCP Cloud Billing, or OCI Usage API).

---

## 2. Schema Surface (Added to `schema/lmcloud.dsl.json`)

### 2.1 `ErrorCode` Enum Addition & Impact Analysis

Slice 3 adds one value to `ErrorCode`:
- **`COST_CAP_EXCEEDED`** — Pre-attempt cost admission guard refused the operation (or its next physical retry/page) because reserving its worst-case attempt and cleanup cost would exceed the active budget cap (`http_status() == 0`, `provider_code() == "CostCapExceeded"`).

#### Why Add `COST_CAP_EXCEEDED` Instead of Reusing one of the 8 Existing Codes?
| Candidate | Evaluation |
|---|---|
| **`COST_CAP_EXCEEDED` (Adopted, 9th enum value)** | Unambiguous in scripts (`cloud.last_error().code() == ErrorCode.COST_CAP_EXCEEDED`) and abort logs (`[COST_CAP_EXCEEDED] object_put (b/k): ...`). Cleanly separates malformed caller arguments (`set_cost_cap_usd(-1.0)` -> `INVALID_ARGUMENT`) and IAM policy denials (`403` -> `PERMISSION_DENIED`) from budget exhaustion. |
| Reuse `INVALID_ARGUMENT` (Rejected) | Conflates a valid operation (`object_put("b", "k", "data")`) that hit the run budget with a malformed bucket/key name. |
| Reuse `PRECONDITION_FAILED` or `PERMISSION_DENIED` (Rejected) | Conflates budget exhaustion with HTTP `412 If-Match` failures or HTTP `403` IAM/RBAC denials. |

### 2.2 Domain Types

#### `CostLineItem`
Immutable per-operation cost breakdown entry inside `CostReport`:
| Method | Signature | Description |
|---|---|---|
| `operation` | `() -> string` | Shared schema operation name (e.g. `"bucket_create"`, `"object_put"`, `"queue_send"`). |
| `service` | `() -> string` | Service slice identifier (`"storage"`, `"queue"`, etc.). |
| `requests` | `() -> int` | Number of admitted physical requests/attempts transmitted for this operation (`>= 0`; includes retries, probes, and pages). |
| `billing_units` | `() -> int` | Number of billing units charged (`>= 0`; 1 per storage attempt/page, or `ceil(max(bytes, 1) / 65536)` 64 KiB chunks per queue attempt). |
| `bytes` | `() -> int` | Total settled payload bytes processed by this operation (`>= 0`). |
| `unit_price_usd` | `() -> float` | Price per billing unit in USD from the active regional/reference price table. |
| `byte_price_usd_per_gib` | `() -> float` | Marginal storage-horizon or egress/transfer tariff per GiB (`1,073,741,824` bytes) in USD from the active price table. |
| `estimated_usd` | `() -> float` | Cumulative estimated cost in USD for this operation (`billing_units * unit_price_usd + ceil_ns(bytes * byte_price_usd_per_gib / 1073741824.0)`). |

#### `CostReport`
Immutable snapshot returned by `cloud.cost_report()`, iterable in `lmscript` via `for (item in report) { ... }` (`len` / `at`):
| Method | Signature | Description |
|---|---|---|
| `provider` | `() -> string` | Active provider identifier (`"aws"`, `"azure"`, `"gcp"`, `"oci"`, or `"ref"`). |
| `price_table_version` | `() -> string` | Active price table version and region/mode identifier (e.g. `"2026-04-aws-us-east-1-v1"` in live mode or `"2026-11-sim-v1"` in simulator/offline mode). |
| `cap_usd` | `() -> float` | Active work cost cap in USD (default `0.05`). |
| `ceiling_usd` | `() -> float` | Hard cost ceiling in USD (`0.25`). |
| `estimated_usd` | `() -> float` | Cumulative settled + committed estimated cost in USD (identical to `cloud.estimated_cost()`). |
| `total_requests` | `() -> int` | Sum of physical `requests()` across all metered operations (`>= 0`). |
| `total_units` | `() -> int` | Sum of `billing_units()` across all metered operations (`>= 0`). |
| `total_bytes` | `() -> int` | Sum of `bytes()` across all metered operations (`>= 0`). |
| `cap_exceeded_count` | `() -> int` | Number of operations or retry attempts refused due to `COST_CAP_EXCEEDED` (`>= 0`). |
| `len` | `() -> int` | Number of operations with `requests() > 0` in this report, sorted lexicographically by `operation()`. |
| `at` | `(index: int) -> CostLineItem` | Line item at `0 <= index < len()`. |
| `item` | `(operation: string) -> CostLineItem` | Line item for `operation` (returns a zero-valued `CostLineItem` with `requests() == 0`, `estimated_usd() == 0.0`, and the active table's unit/byte prices if `operation` has 0 calls). |
| `summary` | `() -> string` | Canonical single-line summary, e.g. `"estimated cost: $0.00000540 (provider=aws, requests=2, units=2, bytes=1024, cap=$0.05)"` or `"estimated cost: $0.00 (read-only; provider=aws, requests=0, cap=$0.05)"`. |

#### `OpMetrics`
Immutable per-operation performance statistics inside `MetricsReport`:
| Method | Signature | Description |
|---|---|---|
| `operation` | `() -> string` | Shared schema operation name (e.g. `"object_put"`, `"queue_receive"`). |
| `calls` | `() -> int` | Total logical invocations of this operation since host start or last `metrics_reset()` (`>= 0`, includes both succeeded and failed calls). |
| `errors` | `() -> int` | Invocations of this operation that ended with `code() != ErrorCode.OK` (`0 <= errors() <= calls()`). |
| `retries` | `() -> int` | Total retry attempts executed by `hostkit.RetryPolicy` during calls to this operation (`>= 0`). |
| `throttles` | `() -> int` | Total HTTP `429` (or provider throttle) responses observed by `hostkit.RetryPolicy` during calls to this operation (`>= 0`). |
| `bytes_in` | `() -> int` | Total payload bytes received across all deliveries/calls of this operation (`object_get` body bytes, `queue_receive` decoded message body bytes). |
| `bytes_out` | `() -> int` | Total payload bytes sent by this operation (`object_put` body bytes, `queue_send` raw message body bytes). |
| `min_ms` | `() -> float` | Exact all-call minimum latency in milliseconds over the current window (`0.0` when `calls() == 0`). |
| `p50_ms` | `() -> float` | 50th percentile (nearest-rank median) latency in milliseconds over the retained sliding sample window (`0.0` when `calls() == 0`). |
| `p95_ms` | `() -> float` | 95th percentile (nearest-rank) latency in milliseconds over the retained sliding sample window (`0.0` when `calls() == 0`). |
| `max_ms` | `() -> float` | Exact all-call maximum latency in milliseconds over the current window (`0.0` when `calls() == 0`). |
| `mean_ms` | `() -> float` | Exact all-call arithmetic mean latency (`total_ms() / float(calls())`, `0.0` when `calls() == 0`). |
| `total_ms` | `() -> float` | Exact all-call sum of latencies for this operation in milliseconds (`0.0` when `calls() == 0`). |

#### `MetricsReport`
Immutable snapshot returned by `cloud.metrics()`, iterable in `lmscript` via `for (opm in m) { ... }` (`len` / `at`):
| Method | Signature | Description |
|---|---|---|
| `elapsed_ms` | `() -> float` | Wall-clock milliseconds elapsed since host start or the most recent `cloud.metrics_reset()` (`>= 0.0`). |
| `total_calls` | `() -> int` | Sum of `calls()` across all metered operations in the current window (`>= 0`). |
| `total_errors` | `() -> int` | Sum of `errors()` across all metered operations in the current window (`>= 0`). |
| `total_retries` | `() -> int` | Sum of `retries()` across all metered operations in the current window (`>= 0`). |
| `total_throttles` | `() -> int` | Sum of `throttles()` across all metered operations in the current window (`>= 0`). |
| `total_bytes_in` | `() -> int` | Sum of `bytes_in()` across all metered operations in the current window (`>= 0`). |
| `total_bytes_out` | `() -> int` | Sum of `bytes_out()` across all metered operations in the current window (`>= 0`). |
| `len` | `() -> int` | Number of distinct operations with `calls() > 0` in the current window, sorted lexicographically by `operation()`. |
| `at` | `(index: int) -> OpMetrics` | `OpMetrics` at `0 <= index < len()`. |
| `op` | `(operation: string) -> OpMetrics` | `OpMetrics` for `operation` (returns a zero-valued `OpMetrics` with `calls() == 0` and `0.0` latencies if `operation` was not called in the current window). |
| `summary` | `() -> string` | Canonical single-line summary, e.g. `"metrics: calls=5, errors=0, retries=0, throttles=0, bytes_out=512, bytes_in=512"`. |

### 2.3 `Cloud` Cost & Performance Methods (`context cloud: Cloud`)

| Method | Signature | Return | Semantics & `last_error()` Behavior |
|---|---|---|---|
| `cost_cap_usd` | `() -> float` | `float` | Returns the active work cost cap in USD (default `0.05`). **Does not modify `cloud.last_error()`**. |
| `set_cost_cap_usd` | `(cap_usd: float) -> self` | `Cloud` | Narrows the active work cost cap in USD. Requires finite `0.0 < cap_usd <= cloud.cost_cap_usd() <= OperatorCapUSD <= 0.25` (`HardCostCeilingUSD`) and `cap_usd >= cloud.estimated_cost()`. Scripts can **only lower (or keep equal)** the active cap, never raise it above the operator's cap or a previously narrowed cap. If violated, fails pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`) without changing the active cap. On success, sets `cloud.last_error()` to `ErrorCode.OK`. |
| `estimated_cost` | `() -> float` | `float` | Returns cumulative estimated cost in USD for the current run/campaign (`>= 0.0`). Never reset by `metrics_reset()` and never reduced by deletes. **Does not modify `cloud.last_error()`**. |
| `cost_report` | `() -> CostReport` | `CostReport` | Returns an immutable `CostReport` snapshot of all metered operations and totals for the current run/campaign. **Does not modify `cloud.last_error()`**. |
| `metrics_reset` | `() -> self` | `Cloud` | Clears all performance counters, byte counters, retry/throttle counters, and latency samples, and restarts the `elapsed_ms()` timer. **Does NOT reset `estimated_cost()` or `cost_report()`, and does NOT modify `cloud.last_error()`**. |
| `metrics` | `() -> MetricsReport` | `MetricsReport` | Returns an immutable `MetricsReport` snapshot for the window since host start or the last `metrics_reset()`. **Does not modify `cloud.last_error()`**. |

---

## 3. Cost Admission, Regional Price Validation & Campaign Budget Authority

### 3.1 Physical Pre-Attempt Reservation & Settlement Model

Unlike a post-hoc logical estimator, `hostkit`'s cost meter gates **every physical cloud attempt** before it is transmitted:

1. **Pre-Attempt Reservation (`ReserveAttempt`):**
   - Before each physical HTTP/RPC attempt (the initial request, each retry in `hostkit.RetryPolicy.Do`, each ownership/existence probe, and each page request in `hostkit.ListAll`), the host computes an `AttemptQuote`:
     - **Request / chunk units:** `1` unit for storage requests/pages; `max(1, ceil(payload_bytes / 65536))` chunks for queue requests.
     - **Byte-horizon / egress bound:**
       - For `object_put`: payload bytes `len(body)` priced over the table's minimum retention horizon (`min_duration_seconds`, e.g., `3600` seconds in live mode, or the synthetic per-GiB allowance in simulator mode) with ceiling nanodollar rounding.
       - For `object_get`: reserves the maximum bounded response size (`limit` or `MaxObjectBytes = 16 MiB`) at the table's egress/read rate before the `GET` is sent.
     - **Cleanup reservation (`CleanupReserveNanoUSD`):** Creating a resource (`bucket_create`, `object_put`, `queue_create`, `queue_send`) reserves the tariff required to delete/ack that resource during teardown (`cleanup_reserve_nano_usd`).
   - If `ChargedNanoUSD + InFlightNanoUSD + ResourceCleanupNanoUSD + Quote.AttemptNanoUSD + Quote.CleanupReserveNanoUSD > ActiveWorkCapNanoUSD`, `ReserveAttempt` rejects the attempt **before dispatch** with `ErrorCode.COST_CAP_EXCEEDED`, increments `cap_exceeded_count()`, and leaves the network untouched.
2. **Post-Attempt Settlement (`Commit`):**
   - When the physical attempt completes:
     - For `object_get`, if the response completed cleanly with `N = len(body)` bytes, the in-flight `16 MiB` byte reservation settles to the actual `N` bytes received; if the stream failed mid-transfer after bytes were sent, the full reserved byte bound is charged.
     - If a resource creation succeeded, its `CleanupReserveNanoUSD` remains locked in `ResourceCleanupNanoUSD` until the resource is deleted (`ReleaseResourceCleanup`).
3. **Multi-Page & Retry Exhaustion:**
   - Because `hostkit.RetryPolicy.Do` and `hostkit.ListAll` call `ReserveAttempt` before **each** retry and **each** page fetch:
     - A `429 -> 503 -> 200` retry sequence reserves and charges **3 physical attempts** (`requests() == 3` in `CostReport`, `calls() == 1`, `retries() == 2`, `throttles() == 1` in `MetricsReport`).
     - If the remaining budget after attempt 2 cannot cover attempt 3, `RetryPolicy.Do` aborts before attempt 3 with `ErrorCode.COST_CAP_EXCEEDED` (`requests() == 2`, `retries() == 1`, `cap_exceeded_count() == 1`).

### 3.2 Regional Price Validation vs Synthetic Simulator Reference Tables

1. **Regional Live Price Tables (`hostkit/safety/prices/<provider>/<region>.json`):**
   - Live mode (`LMCLOUD_LIVE=1`) **never** uses provider-only price lookup. It loads `prices/<provider>/<region>.json` matching the attested target region and validates:
     - `schema_version == 1`, `provider`, `region`, `currency == "USD"`, non-empty `source_url`, `effective_date` (`YYYY-MM-DD`), and `max_age_days > 0`.
     - **Freshness gate:** If `now - effective_date > max_age_days * 24h`, or if `<provider>/<region>` has no verified price table, the host **fails closed** before any network call.
     - **No free-tier reliance:** Provider free tiers (e.g., AWS S3/SQS monthly free tier, GCP Pub/Sub free tier) are never assumed (`$0` free tier never funds admission).
   - **Stage 1 Verified Live Table (`aws/us-east-1`, `2026-04-01`):**
     - Source: [Amazon S3 Pricing (`us-east-1` Standard)](https://aws.amazon.com/s3/pricing/) and [Amazon SQS Pricing (`us-east-1` Standard)](https://aws.amazon.com/sqs/pricing/).
     - S3 Tier 1 (`PUT`/`COPY`/`POST`/`LIST`, `PutBucketTagging`): `$0.005 / 1,000` = `5,000 ns` (`$0.00000500`) per physical request.
     - S3 Tier 2 (`GET`/`HEAD`, `GetBucketTagging`): `$0.0004 / 1,000` = `400 ns` (`$0.00000040`) per physical request.
     - S3 Standard Storage (`us-east-1`): `$0.023 / GiB-month` (`23,000,000 ns / GiB-month`), prorated over `min_duration_seconds = 3600` (`1 hour` minimum live run horizon; `86,400` seconds for retained resources) with ceiling nanodollar rounding.
     - S3 Data Transfer / Egress (`object_get`): `$0.09 / GiB` (`90,000,000 ns / GiB`, worst-case internet egress rate unless intra-region EC2-to-S3 is attested).
     - S3 Delete (`DeleteObject`, `DeleteBucket`): `$0.00` request fee, plus `10,000 ns` (`bucket`) / `5,000 ns` (`object`) cleanup reserve for ownership readback probes (`GetBucketTagging` / `HeadObject`) before delete.
     - SQS Standard (`CreateQueue`, `DeleteQueue`, `GetQueueUrl`, `ListQueues`, `ListQueueTags`, `SendMessage`, `ReceiveMessage`, `DeleteMessage`, `ChangeMessageVisibility`): `$0.40 / 1,000,000` = `400 ns` (`$0.00000040`) per 64 KiB chunk (`chunk_bytes = 65536`), with `10,000 ns` cleanup reserve per queue.

2. **Synthetic Simulator Reference Tariffs (`2026-11-sim-v1`, Offline & Loopback Sim Mode Only):**
   - For deterministic offline (`fakeadapter`) and loopback simulator (`awssim`, `azuresim`, `gcpsim`, `ocisim`) conformance testing where no real cloud region is billed, `hostkit` provides a **Synthetic Simulator Reference Table (`price_table_version() == "2026-11-sim-v1"`)**.
   - **Important distinction:** The simulator reference table is **explicitly refused in live mode (`LMCLOUD_LIVE=1`)**. In particular:
     - Real GCP Cloud Pub/Sub bills by throughput (`$40 / TiB`) with a **`1,000`-byte minimum billable size per request** including message attributes/metadata ([Cloud Pub/Sub Pricing](https://cloud.google.com/pubsub/pricing)), whereas the simulator reference table uses a conservative synthetic 64 KiB chunk allowance (`2,400 ns` per 64 KiB >= `40 ns` per 1 KB) so cross-provider 64 KiB chunk unit tests behave uniformly in simulator runs.
     - Azure (`azuresim`) and OCI (`ocisim`) tariffs in the table below are synthetic simulator reference rates; live Azure and OCI regional price tables remain unpopulated (failing closed in live mode) until Stage 2+ SKU verification.

| Operation | Service | Physical Billing Unit Rule | `aws` / `ref` (`us-east-1`) | `azure` *(synthetic sim)* | `gcp` *(synthetic sim)* | `oci` *(synthetic sim)* |
|---|---|---|---|---|---|---|
| `bucket_create` | `storage` | `1` per physical attempt | `5,000 ns` | `5,000 ns` | `5,000 ns` | `5,000 ns` |
| `bucket_delete` *(cleanup-reserve)* | `storage` | `1` per physical attempt | `0 ns` | `400 ns` | `0 ns` | `0 ns` |
| `bucket_exists` | `storage` | `1` per physical attempt | `400 ns` | `400 ns` | `400 ns` | `400 ns` |
| `bucket_list` | `storage` | `1` per physical page attempt | `5,000 ns` / page | `5,000 ns` / page | `5,000 ns` / page | `5,000 ns` / page |
| `object_put` | `storage` | `1` per attempt + `bytes` | `5,000 ns` + `$0.023`/GiB | `5,000 ns` + `$0.0184`/GiB | `5,000 ns` + `$0.020`/GiB | `5,000 ns` + `$0.0255`/GiB |
| `object_get` | `storage` | `1` per attempt + `bytes` | `400 ns` + `$0.09`/GiB | `400 ns` + `$0.007`/GiB | `400 ns` + `$0.012`/GiB | `400 ns` + `$0.0085`/GiB |
| `object_head` | `storage` | `1` per physical attempt | `400 ns` | `400 ns` | `400 ns` | `400 ns` |
| `object_delete` *(cleanup-reserve)* | `storage` | `1` per physical attempt | `0 ns` | `400 ns` | `0 ns` | `0 ns` |
| `object_list` | `storage` | `1` per physical attempt | `5,000 ns` | `5,000 ns` | `5,000 ns` | `5,000 ns` |
| `object_list_all` | `storage` | `1` per physical page attempt | `5,000 ns` / page | `5,000 ns` / page | `5,000 ns` / page | `5,000 ns` / page |
| `queue_create` | `queue` | `1` per physical attempt | `400 ns` | `500 ns` | `1,000 ns` | `1,000 ns` |
| `queue_delete` *(cleanup-reserve)* | `queue` | `1` per physical attempt | `400 ns` | `400 ns` | `0 ns` | `0 ns` |
| `queue_exists` | `queue` | `1` per physical attempt | `400 ns` | `400 ns` | `400 ns` | `400 ns` |
| `queue_list` | `queue` | `1` per physical page attempt | `400 ns` / page | `500 ns` / page | `400 ns` / page | `1,000 ns` / page |
| `queue_send` | `queue` | `max(1, ceil(bytes / 65536))` | `400 ns` / 64 KiB | `400 ns` / 64 KiB | `2,400 ns` / 64 KiB | `1,000 ns` / 64 KiB |
| `queue_receive` | `queue` | `max(1, ceil(bytes / 65536))` | `400 ns` / 64 KiB | `400 ns` / 64 KiB | `2,400 ns` / 64 KiB | `1,000 ns` / 64 KiB |
| `queue_ack` *(cleanup-reserve)* | `queue` | `1` per physical attempt | `400 ns` | `400 ns` | `0 ns` | `1,000 ns` |
| `queue_nack` | `queue` | `1` per physical attempt | `400 ns` | `400 ns` | `400 ns` | `1,000 ns` |

### 3.3 Shared Campaign Authority & Bounded Cleanup Reserve

1. **Campaign-Wide Persistence (`hostkit/safety` integration):**
   - When a campaign journal (`<run_id>.jsonl`) is active across multiple host invocations (`Supervisor.RunInvocation`), every committed charge (`ChargedNanoUSD`) and active resource cleanup reservation (`ResourceCleanupNanoUSD`) is fsynced to the journal and restored on the next invocation (`CostMeter.RestoreCharged`).
2. **Monotone Cap Narrowing:**
   - Let `OperatorCapNanoUSD` be the initial cap from `live-policy.json` or `LMCLOUD_MAX_COST_USD` (default `50,000,000 ns` = `$0.05`, ceiling `250,000,000 ns` = `$0.25`).
   - `set_cost_cap_usd(newCap)` checks `newCap > 0 && newCap <= ActiveCapUSD && newCap <= OperatorCapUSD && newCap <= 0.25 && newCap >= EstimatedCostUSD`. Attempting to raise the cap above `ActiveCapUSD` or `OperatorCapUSD` is rejected with `ErrorCode.INVALID_ARGUMENT`.
3. **Reserved Cleanup Budget vs Work Cap:**
   - A dedicated `CleanupReserveNanoUSD` (default `10,000,000 ns` = `$0.01`) is held outside the script-narrowable work cap (`cost_cap_usd()`).
   - Non-teardown operations must fit within `cost_cap_usd()`.
   - Teardown operations (`bucket_delete`, `object_delete`, `queue_delete`, `queue_ack`) are admitted against `cost_cap_usd() + CleanupReserveUSD` (and release any per-resource cleanup reservation upon deletion). Thus, even after `cloud.set_cost_cap_usd(cloud.estimated_cost())`, normal cleanup of created resources succeeds, while a runaway loop of paid deletes/acks that exceeds `CleanupReserveUSD` is still stopped with `ErrorCode.COST_CAP_EXCEEDED`.

---

## 4. Performance Telemetry Model & Bounded Sample Window

### 4.1 Streaming All-Call Aggregates vs Bounded Quantile Window (`MaxLatencySamplesPerOp = 10,000`)

1. **Streaming All-Call Aggregates (`calls`, `errors`, `retries`, `throttles`, `bytes_in`, `bytes_out`, `min_ms`, `max_ms`, `total_ms`, `mean_ms`):**
   - Maintained with `O(1)` streaming accumulators per operation across **all** calls since host start or the most recent `cloud.metrics_reset()`, with **no truncation** when `calls() > 10,000`:
     - `calls` increments by `1` per logical invocation.
     - `total_ns` accumulates the exact integer nanoseconds of every call (`total_ms() = float64(total_ns) / 1e6`).
     - `min_ns` and `max_ns` track the exact all-call minimum and maximum (`min_ms() = float64(min_ns) / 1e6`, `max_ms() = float64(max_ns) / 1e6`).
     - `mean_ms() = total_ms() / float64(calls)` (exact all-call arithmetic mean).
2. **Bounded Sliding Ring Buffer for Quantiles (`p50_ms`, `p95_ms`):**
   - Each operation retains a deterministic **FIFO ring buffer** of the most recent `MaxLatencySamplesPerOp = 10,000` call durations (`samples[calls % 10_000] = dur_ns`).
   - When `calls() <= 10,000`, `W = calls()` samples are sorted (`s[0] <= ... <= s[W-1]`). When `calls() > 10,000`, the `W = 10,000` most recent samples in the ring buffer are sorted (`s[0] <= ... <= s[W-1]`):
     - `p50_ms() = float64(s[ceil(0.50 * W) - 1]) / 1e6`
     - `p95_ms() = float64(s[ceil(0.95 * W) - 1]) / 1e6`
   - Because every sample in the ring buffer is one of the observed calls in the current window (`min_ns <= s[0] <= s[W-1] <= max_ns`), the ordering invariants:
     - `0.0 <= min_ms() <= p50_ms() <= p95_ms() <= max_ms() <= total_ms()`
     - `min_ms() <= mean_ms() <= max_ms()`
     hold **unconditionally** for every `calls() >= 1`, including after sample-buffer wraparound (`calls() > 10,000`)!
   - `cloud.metrics_reset()` zeroes both the streaming accumulators and the 10,000-sample ring buffer.

### 4.2 Deterministic Retry, Delivery & Timing Rules in Conformance Tests

1. **Deterministic Retry & Attempt Accounting (`hostkit/httpguard` & `sim_rules_v1`):**
   - Unit and integration tests drive deterministic retry sequences (`429 -> 503 -> 200`, terminal `429 -> 503 -> 503 -> 503`, and mid-retry `COST_CAP_EXCEEDED` exhaustion) and assert exact counters:
     - `429 -> 503 -> 200` on `object_get`: `calls() == 1`, `errors() == 0`, `retries() == 2`, `throttles() == 1`, and `cost_report().item("object_get").requests() == 3`.
     - Terminal `429 -> 503 -> 503 -> 503`: `calls() == 1`, `errors() == 1`, `retries() == 3`, `throttles() == 1`, and `cost_report().item(op).requests() == 4`.
     - Mid-retry cap exhaustion (work cap covers 2 attempts; attempt 1 returns `429`, attempt 2 returns `503`): attempt 3 is refused pre-dispatch with `ErrorCode.COST_CAP_EXCEEDED`, `requests() == 2`, `retries() == 1`, `throttles() == 1`, `cap_exceeded_count() == 1`.
2. **At-Least-Once Queue Delivery:**
   - Queue conformance scenarios (`03`, `04`, `07`) poll `queue_receive` in a bounded loop (`attempts < 10`), deduplicate received message IDs (`StrList.contains` / `StrList.add`), and compare `cost_report().item("queue_receive").bytes()` and `metrics().op("queue_receive").bytes_in()` against the **actual delivered byte sum** across all received batches rather than assuming single-poll or exactly-once delivery.
3. **No Fragile Wall-Clock Upper Bounds:**
   - Conformance scenarios assert mathematical invariants (`0.0 <= min_ms() <= p50_ms() <= p95_ms() <= max_ms() <= total_ms()` and `min_ms() <= mean_ms() <= max_ms()`) without arbitrary `< 60000.0` whole-window wall-clock ceilings that could flake under loaded CI runners.

---

## 5. `hostkit` & Adapter Integration Contract

1. **`RetryPolicy.Do` and `ListAll` Pre-Attempt Admission Hook:**
   - `hostkit.RetryPolicy.Do` invokes an optional `BeforeAttempt func(ctx context.Context, attempt int) error` attached to `ctx` before **every** attempt (`attempt == 0, 1, ...`). If `BeforeAttempt` returns a `COST_CAP_EXCEEDED` `*CloudError`, `RetryPolicy.Do` aborts immediately without sleeping or transmitting the HTTP request.
   - `hostkit.ListAll` invokes the page admission hook before each page call (`page == 0, 1, ...`), charging each page fetch as a distinct physical request.
2. **Adapter `AttemptQuoter` & Multi-Step Probe Accounting:**
   - Adapters that perform multi-step physical requests inside a single `ObjectStore` or `Queue` method (such as `lmaws` `HeadBucket` + `CreateBucket` + `ListQueueTags`, or `lmgcp` Pub/Sub topic + subscription creation) either route each HTTP request through `hostkit.DoHTTP` (which triggers `BeforeAttempt` per physical HTTP request) or implement `safety.AttemptQuoter` (`QuoteAttempt`) to reserve the exact multi-request tariff upfront.
