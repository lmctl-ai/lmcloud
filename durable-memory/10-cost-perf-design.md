# 10 — `lmcloud` Cost & Performance Design (Slice 3, Cross-Cutting)

## 1. Goals & Architectural Alignment

Slice 3 (`Perf & Cost` in [`05-roadmap.md`](05-roadmap.md)) adds **cross-cutting per-run cost estimation, budget cap enforcement, and per-operation performance telemetry** to `schema/lmcloud.dsl.json` on the existing `cloud` (`Cloud`) context object **without modifying any Slice 1 (Object Storage) or Slice 2 (Queue) method signature**.

1. **Cost-aware scripting for real-cloud testing (`set_cost_cap_usd`, `estimated_cost`, `cost_report`):**
   - Every `lm<provider>` host (`lmaws`, `lmazure`, `lmgcp`, `lmoci`) and the reference host (`lmcloud-ref`) embeds a versioned, provider-specific on-demand price table (`price_table_version() == "2026-11-v1"`).
   - Every run defaults to a **`$0.05` USD** cost cap (`DefaultCostCapUSD = 0.05`) with an immutable **`$0.25` USD** hard ceiling (`HardCostCeilingUSD = 0.25`), matching the safety model established in `lmgcp` (`durable-memory/01-purpose-and-safety.md`), `lmaws` (`durable-memory/07-example-costs.md`), and `lmazure` (`durable-memory/05-cost-ledger.md`).
   - **Pre-dispatch admission gate:** Before dispatching any billable non-teardown operation, the host computes the operation's incremental cost from the embedded price table. If the cumulative run cost would exceed `cloud.cost_cap_usd()`, the operation is refused **pre-flight** (`http_status() == 0`) with `ErrorCode.COST_CAP_EXCEEDED` (`provider_code() == "CostCapExceeded"`).
   - **Teardown immunity:** Delete and acknowledgment operations (`bucket_delete`, `object_delete`, `queue_delete`, `queue_ack`) are **never** blocked by cost-cap exhaustion, guaranteeing that cleanup can always run after a cap refusal without leaking live cloud resources.
2. **Per-operation performance telemetry (`metrics_reset`, `metrics`):**
   - Scripts can scope latency and throughput measurements around specific workload phases using `cloud.metrics_reset()` and inspect per-operation call counts, error counts, retry counts, HTTP `429` throttle counts (from `hostkit.RetryPolicy`), payload bytes (`bytes_in`, `bytes_out`), and latency quantiles (`min_ms`, `p50_ms`, `p95_ms`, `max_ms`, `mean_ms`, `total_ms`).
3. **Zero external simulator or billing API dependency:**
   - All cost and performance accounting lives in `hostkit` and `hostkit/cloudhost`. Simulators (`awssim`, `azuresim`, `gcpsim`, `ocisim`) require no new endpoints, and live hosts **never** call paid or external billing APIs (AWS Cost Explorer, Azure Cost Management, GCP Cloud Billing, or OCI Usage API).

---

## 2. Schema Surface (Added to `schema/lmcloud.dsl.json`)

### 2.1 `ErrorCode` Enum Addition & Impact Analysis

Slice 3 adds one value to `ErrorCode`:
- **`COST_CAP_EXCEEDED`** — Pre-flight cost admission guard refused the operation because its incremental estimated cost would push `cloud.estimated_cost()` above `cloud.cost_cap_usd()` (`http_status() == 0`, `provider_code() == "CostCapExceeded"`).

#### Why Add `COST_CAP_EXCEEDED` Instead of Reusing one of the 8 Existing Codes?
| Candidate | Evaluation |
|---|---|
| **`COST_CAP_EXCEEDED` (Adopted, 9th enum value)** | Unambiguous in scripts (`cloud.last_error().code() == ErrorCode.COST_CAP_EXCEEDED`) and abort logs (`[COST_CAP_EXCEEDED] object_put (b/k): ...`). Cleanly separates malformed caller arguments (`set_cost_cap_usd(-1.0)` -> `INVALID_ARGUMENT`) and IAM policy denials (`403` -> `PERMISSION_DENIED`) from run budget exhaustion. |
| Reuse `INVALID_ARGUMENT` (Rejected) | Conflates a valid operation (`object_put("b", "k", "data")`) that hit the cumulative run budget with a malformed bucket/key name. |
| Reuse `PRECONDITION_FAILED` or `PERMISSION_DENIED` (Rejected) | Conflates client-side budget exhaustion with HTTP `412 If-Match` failures or HTTP `403` IAM/RBAC denials. |

#### Impact of Changing `schema/lmcloud.dsl.json` Bytes in Slice 3
Because Slice 3 adds new domain types and `Cloud` methods to `schema/lmcloud.dsl.json`, the raw schema SHA-256 changes regardless of whether `ErrorCode` has 8 or 9 values. The exact downstream impact when `hostkit` and the 4 hosts adopt Slice 3 is:
1. **`schema/lmcloud.dsl.json` & `schema/schema.go`:** Embedded automatically via `//go:embed lmcloud.dsl.json`.
2. **`hostkit/errors.go`:** Add `CostCapExceeded Code = "COST_CAP_EXCEEDED"` to `const (...)` and `var Codes = []Code{...}` (2 lines).
3. **`hostkit/cloudhost/register.go`:** `declareEnums(reg)` derives the enum list directly from `hostkit.Codes`, so `lmcode-go` `Registry.Enum("ErrorCode", ...)` automatically supports `ErrorCode.COST_CAP_EXCEEDED` in `--dry-run` mode with zero extra code.
4. **Provider host repositories (`lmaws`, `lmazure`, `lmgcp`, `lmoci`):** Copy updated `schema/lmcloud.dsl.json` and update the SHA-256 pin in `lmcloud.lock`. No adapter error classification switch needs to change because `COST_CAP_EXCEEDED` is raised exclusively by `cloudhost` pre-flight admission.
5. **Existing Slice 1 & Slice 2 conformance suites (25 scenarios):** Zero changes required; every existing scenario accrues `< $0.0005` against the default `$0.05` cap.

### 2.2 Domain Types

#### `CostLineItem`
Immutable per-operation cost breakdown entry inside `CostReport`:
| Method | Signature | Description |
|---|---|---|
| `operation` | `() -> string` | Shared schema operation name (e.g. `"bucket_create"`, `"object_put"`, `"queue_send"`). |
| `service` | `() -> string` | Service slice identifier (`"storage"`, `"queue"`, etc.). |
| `requests` | `() -> int` | Number of admitted calls to this operation during the run (`>= 0`). |
| `billing_units` | `() -> int` | Number of billing units charged (`>= 0`; e.g., 1 per storage call/page, or `ceil(max(bytes, 1) / 65536)` 64 KiB chunks for queue messages). |
| `bytes` | `() -> int` | Total payload bytes processed by this operation (`>= 0`). |
| `unit_price_usd` | `() -> float` | Price per billing unit in USD from the active provider's embedded price table. |
| `byte_price_usd_per_gib` | `() -> float` | Marginal data/storage allowance per GiB (`1,073,741,824` bytes) in USD from the embedded price table. |
| `estimated_usd` | `() -> float` | Cumulative estimated cost in USD for this operation (`billing_units * unit_price_usd + bytes * (byte_price_usd_per_gib / 1073741824.0)`). |

#### `CostReport`
Immutable snapshot returned by `cloud.cost_report()`, iterable in `lmscript` via `for (item in report) { ... }` (`len` / `at`):
| Method | Signature | Description |
|---|---|---|
| `provider` | `() -> string` | Active provider identifier (`"aws"`, `"azure"`, `"gcp"`, `"oci"`, or `"ref"`). |
| `price_table_version` | `() -> string` | Embedded price table version identifier (`"2026-11-v1"`). |
| `cap_usd` | `() -> float` | Active per-run cost cap in USD (default `0.05`). |
| `ceiling_usd` | `() -> float` | Hard per-run cost ceiling in USD (`0.25`). |
| `estimated_usd` | `() -> float` | Cumulative estimated run cost in USD (identical to `cloud.estimated_cost()`). |
| `total_requests` | `() -> int` | Sum of `requests()` across all metered operations (`>= 0`). |
| `total_units` | `() -> int` | Sum of `billing_units()` across all metered operations (`>= 0`). |
| `total_bytes` | `() -> int` | Sum of `bytes()` across all metered operations (`>= 0`). |
| `cap_exceeded_count` | `() -> int` | Number of operations refused pre-flight due to `COST_CAP_EXCEEDED` (`>= 0`). |
| `len` | `() -> int` | Number of operations with `requests() > 0` in this report, sorted lexicographically by `operation()`. |
| `at` | `(index: int) -> CostLineItem` | Line item at `0 <= index < len()`. |
| `item` | `(operation: string) -> CostLineItem` | Line item for `operation` (returns a zero-valued `CostLineItem` with `requests() == 0`, `estimated_usd() == 0.0`, and the provider's configured unit prices if `operation` has 0 calls). |
| `summary` | `() -> string` | Canonical single-line summary, e.g. `"estimated cost: $0.00000540 (provider=aws, requests=2, units=2, bytes=1024, cap=$0.05)"` or `"estimated cost: $0.00 (read-only; provider=aws, requests=0, cap=$0.05)"`. |

#### `OpMetrics`
Immutable per-operation performance statistics inside `MetricsReport`:
| Method | Signature | Description |
|---|---|---|
| `operation` | `() -> string` | Shared schema operation name (e.g. `"object_put"`, `"queue_receive"`). |
| `calls` | `() -> int` | Total invocations of this operation since host start or last `metrics_reset()` (`>= 0`, includes both succeeded and failed calls). |
| `errors` | `() -> int` | Invocations of this operation that ended with `code() != ErrorCode.OK` (`0 <= errors() <= calls()`). |
| `retries` | `() -> int` | Total retry attempts executed by `hostkit.RetryPolicy` during calls to this operation (`>= 0`). |
| `throttles` | `() -> int` | Total HTTP `429` (or provider throttle) responses observed by `hostkit.RetryPolicy` during calls to this operation (`>= 0`). |
| `bytes_in` | `() -> int` | Total payload bytes received by this operation (`object_get` body bytes, `queue_receive` decoded message body bytes). |
| `bytes_out` | `() -> int` | Total payload bytes sent by this operation (`object_put` body bytes, `queue_send` raw message body bytes). |
| `min_ms` | `() -> float` | Minimum call latency in milliseconds (`0.0` when `calls() == 0`). |
| `p50_ms` | `() -> float` | 50th percentile (nearest-rank median) call latency in milliseconds (`0.0` when `calls() == 0`). |
| `p95_ms` | `() -> float` | 95th percentile (nearest-rank) call latency in milliseconds (`0.0` when `calls() == 0`). |
| `max_ms` | `() -> float` | Maximum call latency in milliseconds (`0.0` when `calls() == 0`). |
| `mean_ms` | `() -> float` | Arithmetic mean call latency in milliseconds (`0.0` when `calls() == 0`). |
| `total_ms` | `() -> float` | Sum of call latencies for this operation in milliseconds (`0.0` when `calls() == 0`). |

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
| `cost_cap_usd` | `() -> float` | `float` | Returns the active per-run cost cap in USD (default `0.05`). **Does not modify `cloud.last_error()`**. |
| `set_cost_cap_usd` | `(cap_usd: float) -> self` | `Cloud` | Sets the per-run cost cap in USD. Requires finite `0.0 < cap_usd <= 0.25` (`HardCostCeilingUSD`) and `cap_usd >= cloud.estimated_cost()`. If violated, fails pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`) without changing the active cap. On success, sets `cloud.last_error()` to `ErrorCode.OK`. |
| `estimated_cost` | `() -> float` | `float` | Returns cumulative estimated cost in USD for the current run (`>= 0.0`). Never reset by `metrics_reset()` and never reduced by deletes. **Does not modify `cloud.last_error()`**. |
| `cost_report` | `() -> CostReport` | `CostReport` | Returns an immutable `CostReport` snapshot of all metered operations and totals for the current run. **Does not modify `cloud.last_error()`**. |
| `metrics_reset` | `() -> self` | `Cloud` | Clears all performance counters, byte counters, retry/throttle counters, and latency samples, and restarts the `elapsed_ms()` timer. **Does NOT reset `estimated_cost()` or `cost_report()`, and does NOT modify `cloud.last_error()`**. |
| `metrics` | `() -> MetricsReport` | `MetricsReport` | Returns an immutable `MetricsReport` snapshot for the window since host start or the last `metrics_reset()`. **Does not modify `cloud.last_error()`**. |

---

## 3. Cost Model, Embedded Price Tables & Determinism Rules

### 3.1 What Is Measured in Sim/Offline vs Live vs `--dry-run`

| Execution Mode | How Operations & Bytes Are Metered | Actual Cloud Bill | `estimated_cost()` / `cost_report()` |
|---|---|---|---|
| **Offline Fake (`fakeadapter`) & Loopback Sims (`awssim`, `azuresim`, `gcpsim`, `ocisim`)** | `cloudhost` meters every admitted operation's request count, billing units (pages / 64 KiB chunks), and payload bytes (`len(data)` / `len(body)`), applying the active provider's embedded price table. | `$0.00` (local process) | Non-zero deterministic estimate from the provider's embedded price table. |
| **Live Cloud (`aws`, `azure`, `gcp`, `oci`)** | Exact same `cloudhost` metering and embedded price table. **No billing or Cost Explorer API is ever called.** | Billed by provider according to account/free-tier/region | Same deterministic estimate (serves as a pre-dispatch safety cap and planning estimate, never an invoice). |
| **Compiler Dry Run (`lmscript --dry-run`)** | `cloudhost` dry slots run the same cost admission and metering over the dry overlay, allowing scripts to preview estimated cost and catch `COST_CAP_EXCEEDED` during `--dry-run`. | `$0.00` (zero mutations) | Same deterministic estimate for the dry-previewed operations. |

### 3.2 Embedded Per-Provider Price Tables (`2026-11-v1`)

All four hosts embed their provider price table in `hostkit` (keyed by `cloud.provider()`: `"aws"`, `"azure"`, `"gcp"`, `"oci"`, with `"ref"` aliasing `"aws"`). Internally, `hostkit` stores all prices and accumulates all charges in **integer nanodollars (`int64`, `1 USD = 1,000,000,000 nanodollars`)** so floating-point rounding never depends on operation order.

#### Slice 1 (Object Storage) & Slice 2 (Queue) Embedded Unit Tariffs

| Operation | Service | Billing Unit Rule | AWS (`us-east-1`) | Azure (`East US` LRS Hot) | GCP (`us-central1` Standard) | OCI (`us-ashburn-1` Standard) |
|---|---|---|---|---|---|---|
| `bucket_create` | `storage` | `1` per call | `$0.00000500` (`5,000 ns`) | `$0.00000500` (`5,000 ns`) | `$0.00000500` (`5,000 ns`) | `$0.00000500` (`5,000 ns`) |
| `bucket_delete` *(teardown-immune)* | `storage` | `1` per call | `$0.00000000` (`0 ns`) | `$0.00000040` (`400 ns`) | `$0.00000000` (`0 ns`) | `$0.00000000` (`0 ns`) |
| `bucket_exists` | `storage` | `1` per call | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) |
| `bucket_list` | `storage` | `max(1, pages)` | `$0.00000500` / page | `$0.00000500` / page | `$0.00000500` / page | `$0.00000500` / page |
| `object_put` | `storage` | `1` per call + `bytes` (`$0.023`–`$0.025`/GiB) | `$0.00000500` + `$0.023`/GiB | `$0.00000500` + `$0.0184`/GiB | `$0.00000500` + `$0.020`/GiB | `$0.00000500` + `$0.0255`/GiB |
| `object_get` | `storage` | `1` per call + `bytes` (`$0.004`–`$0.010`/GiB) | `$0.00000040` + `$0.009`/GiB | `$0.00000040` + `$0.007`/GiB | `$0.00000040` + `$0.012`/GiB | `$0.00000040` + `$0.0085`/GiB |
| `object_head` | `storage` | `1` per call | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) |
| `object_delete` *(teardown-immune)* | `storage` | `1` per call | `$0.00000000` (`0 ns`) | `$0.00000040` (`400 ns`) | `$0.00000000` (`0 ns`) | `$0.00000000` (`0 ns`) |
| `object_list` | `storage` | `1` per call | `$0.00000500` (`5,000 ns`) | `$0.00000500` (`5,000 ns`) | `$0.00000500` (`5,000 ns`) | `$0.00000500` (`5,000 ns`) |
| `object_list_all` | `storage` | `max(1, pages)` | `$0.00000500` / page | `$0.00000500` / page | `$0.00000500` / page | `$0.00000500` / page |
| `queue_create` | `queue` | `1` per call (`2` on GCP topic+sub) | `$0.00000040` (`400 ns`) | `$0.00000050` (`500 ns`) | `$0.00000100` (`1,000 ns`) | `$0.00000100` (`1,000 ns`) |
| `queue_delete` *(teardown-immune)* | `queue` | `1` per call | `$0.00000000` (`0 ns`) | `$0.00000040` (`400 ns`) | `$0.00000000` (`0 ns`) | `$0.00000000` (`0 ns`) |
| `queue_exists` | `queue` | `1` per call | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) |
| `queue_list` | `queue` | `max(1, pages)` | `$0.00000040` / page | `$0.00000050` / page | `$0.00000040` / page | `$0.00000100` / page |
| `queue_send` | `queue` | `max(1, ceil(bytes / 65536))` | `$0.00000040` / 64 KiB | `$0.00000040` / 64 KiB | `$0.00000240` / 64 KiB (`$40/TiB`) | `$0.00000100` / 64 KiB |
| `queue_receive` | `queue` | `max(1, ceil(bytes / 65536))` | `$0.00000040` / 64 KiB | `$0.00000040` / 64 KiB | `$0.00000240` / 64 KiB | `$0.00000100` / 64 KiB |
| `queue_ack` *(teardown-immune)* | `queue` | `1` per call | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000000` (`0 ns`) | `$0.00000100` (`1,000 ns`) |
| `queue_nack` | `queue` | `1` per call | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000040` (`400 ns`) | `$0.00000100` (`1,000 ns`) |

#### Sourcing & Update Procedure
1. **Primary sources:**
   - **AWS (`us-east-1`):** [Amazon S3 Pricing](https://aws.amazon.com/s3/pricing/) (`$0.005 / 1,000` PUT/LIST, `$0.0004 / 1,000` GET/HEAD, `$0.023 / GB-month` Standard storage) and [Amazon SQS Pricing](https://aws.amazon.com/sqs/pricing/) (`$0.40 / 1,000,000` requests per 64 KiB chunk), aligned with `lmaws/src/main/java/ai/lmctl/lmaws/CostLedger.java:17–29`.
   - **Azure (`East US` LRS Hot):** [Azure Blob Storage Pricing](https://azure.microsoft.com/en-us/pricing/details/storage/blobs/) (`$0.05 / 10,000` Write/List, `$0.004 / 10,000` Read, `$0.0184 / GB-month`) and [Azure Queue Storage Pricing](https://azure.microsoft.com/en-us/pricing/details/storage/queues/) (`$0.004 / 10,000` operations per 64 KiB), aligned with `lmazure/docs/COSTS.md`.
   - **GCP (`us-central1` Standard):** [Google Cloud Storage Pricing](https://cloud.google.com/storage/pricing) (`$0.05 / 10,000` Class A, `$0.004 / 10,000` Class B, `$0.020 / GB-month`) and [Cloud Pub/Sub Pricing](https://cloud.google.com/pubsub/pricing) (`$40 / TiB` throughput -> `~$0.0000024` per 64 KiB chunk, minimum 1 chunk), aligned with `lmgcp/internal/safety/safety.go:128–206`.
   - **OCI (`us-ashburn-1` Standard):** [OCI Object Storage Pricing](https://www.oracle.com/cloud/storage/pricing/) (`$0.005 / 1,000` Write/List, `$0.0004 / 1,000` Read, `$0.0255 / GB-month`) and [OCI Queue Pricing](https://www.oracle.com/cloud/queue/pricing/) (`$1.00 / 1,000,000` requests per 64 KiB chunk), aligned with `lmoci/src/main/java/ai/lmctl/lmoci/CostLedger.java:63–74`.
2. **How to update the embedded price tables:**
   - All four provider tables live in a single declarative Go table in `hostkit/meter.go` (`PriceTables`).
   - When updating tariffs or adding a new slice (Slices 4–10), bump `PriceTableVersion` (e.g., `"2026-11-v1"` -> `"2027-01-v1"`), update the nanodollar constants in `hostkit/meter.go`, and run `scripts/test-hostkit.sh` plus `./tests/run-conformance.sh`. Conformance scenarios derive their cap thresholds dynamically from `cloud.cost_report().item(op).unit_price_usd()` or `cloud.estimated_cost()` after a calibration call, so tariff updates never break conformance tests.

### 3.3 Cost Determinism Rules

1. **Integer nanodollar accumulation:**
   - Each call's cost in nanodollars is:
     `cost_ns = units * unit_price_ns + (bytes * byte_price_per_gib_ns + (1<<30 - 1)) / (1 << 30)` (using integer ceiling division when `bytes > 0` and `byte_price_per_gib_ns > 0` so any non-zero byte transfer with a non-zero byte tariff adds at least `1 ns`).
   - `estimated_usd()` converts `total_ns` to `float64(total_ns) / 1e9`.
2. **Pre-flight validation failures are not billed:**
   - If an operation fails client-side validation before reaching the adapter (e.g., invalid bucket name, invalid key, invalid `max_messages`, or `COST_CAP_EXCEEDED`), `requests()` and `estimated_cost()` are **not** incremented (though `metrics()` records the call and error in `total_calls()` / `total_errors()`, and `cost_report().cap_exceeded_count()` records cap refusals).
3. **Admitted provider calls are billed once per logical operation (retries do not multiply `estimated_cost()`):**
   - Once an operation passes pre-flight validation and cost-cap admission, its logical request unit is charged even if the provider returns `403`, `404`, or `409` (because the cloud request was transmitted).
   - If `hostkit.RetryPolicy` retries a transient `429` or `503` under the hood, the extra attempts are recorded in **`metrics().total_retries()`** and **`metrics().total_throttles()`**, while **`cost_report()` charges 1 logical operation** so that `estimated_cost()` is 100% deterministic across runs regardless of transient network/simulator jitter.

---

## 4. Performance Telemetry Model & Determinism Rules

### 4.1 What `cloud.metrics()` Tracks

1. **Which methods are metered:**
   - All 20 domain operations across Slice 1 and Slice 2 (`bucket_create`, `bucket_delete`, `bucket_exists`, `bucket_list`, `object_put`, `object_get`, `object_head`, `object_delete`, `object_list`, `object_list_all`, `queue_create`, `queue_delete`, `queue_exists`, `queue_list`, `queue_send`, `queue_receive`, `queue_ack`, `queue_nack`) are metered in `cloud.metrics()`.
   - Local configuration and inspection methods (`provider`, `endpoint`, `set_endpoint`, `abort_on_error`, `set_abort_on_error`, `last_error`, `cost_cap_usd`, `set_cost_cap_usd`, `estimated_cost`, `cost_report`, `metrics_reset`, `metrics`) are **not** metered as cloud operations so inspecting `cloud.metrics()` or `cloud.estimated_cost()` inside a loop never pollutes `total_calls()`.
2. **Timer scoping via `cloud.metrics_reset()`:**
   - Calling `cloud.metrics_reset()` zeroes all `OpMetrics` entries, resets `total_calls`, `total_errors`, `total_retries`, `total_throttles`, `total_bytes_in`, and `total_bytes_out` to `0`, and sets the window start time to `Now()`.
   - Scripts use `cloud.metrics_reset()` after setup (e.g., after `bucket_create` / `queue_create`) to measure only the steady-state workload phase, and again before teardown.
3. **Exact quantile calculation (`min_ms`, `p50_ms`, `p95_ms`, `max_ms`, `mean_ms`, `total_ms`):**
   - Each metered operation records call duration `d_ms = float64(dur.Nanoseconds()) / 1e6` (`>= 0.0`).
   - Up to `MaxLatencySamplesPerOp = 10,000` samples are retained per operation per reset window.
   - For `N` sorted samples `s[0] <= s[1] <= ... <= s[N-1]`:
     - `min_ms() = s[0]`
     - `p50_ms() = s[ceil(0.50 * N) - 1]`
     - `p95_ms() = s[ceil(0.95 * N) - 1]`
     - `max_ms() = s[N - 1]`
     - `total_ms() = sum(s[0..N-1])`
     - `mean_ms() = total_ms() / float64(N)`
   - **Guaranteed mathematical invariants for every operation (`N >= 0`):**
     `0.0 <= min_ms() <= p50_ms() <= p95_ms() <= max_ms() <= total_ms()` and `min_ms() <= mean_ms() <= max_ms()`.
4. **Conformance rules for performance assertions in sims:**
   - Conformance scenarios **must** assert exact deterministic counters (`calls()`, `errors()`, `bytes_in()`, `bytes_out()`, `retries() >= 0`, `throttles() >= 0`) and mathematical order invariants (`0.0 <= min_ms() <= p50_ms() <= p95_ms() <= max_ms() < 60000.0`).
   - Conformance scenarios **must never** assert fragile wall-clock lower bounds (`p50_ms() > 0.1` fails on in-memory `fakeadapter`) or tight upper bounds (`p95_ms() < 5.0` flakes on loaded CI runners).

---

## 5. `hostkit` Implementation Notes (Where Cost & Metrics Live — Do Not Implement Now)

Because every `Cloud` method already flows through `hostkit/cloudhost.Host` and every HTTP/SDK retry already flows through `hostkit.RetryPolicy`, **adapters (`lmaws`, `lmazure`, `lmgcp`, `lmoci`, `fakeadapter`) require zero interface changes** to support Slice 3.

### 5.1 Proposed Additions to `hostkit` (`hostkit/meter.go` & `hostkit/retry.go`)

```go
// In package hostkit (hostkit/meter.go):
const (
	DefaultCostCapUSD   = 0.05
	HardCostCeilingUSD  = 0.25
	PriceTableVersion   = "2026-11-v1"
	MaxSamplesPerOp     = 10_000
	CostCapProviderCode = "CostCapExceeded"
)

type OpTariff struct {
	Service            string
	UnitPriceNanoUSD   int64 // nanodollars per billing unit
	BytePricePerGiBNano int64 // nanodollars per GiB (1<<30 bytes)
	ChunkBytes         int64 // 0 = 1 unit/request; 65536 = 64 KiB chunks (queue_send/receive)
	TeardownImmune     bool  // true for bucket_delete, object_delete, queue_delete, queue_ack
}

// RetryTracker is attached to context.Context by cloudhost before calling an
// adapter method. RetryPolicy.Do automatically increments Retries, Throttles,
// and Pages on every attempt without any adapter code changes.
type RetryTracker struct {
	Retries   atomic.Int64
	Throttles atomic.Int64
	Pages     atomic.Int64
}

func WithRetryTracker(ctx context.Context) (context.Context, *RetryTracker)
func RetryTrackerFrom(ctx context.Context) *RetryTracker
```

- **How `RetryPolicy.Do` reports retries and throttles automatically (`hostkit/retry.go`):**
  - Inside `RetryPolicy.Do(ctx, idempotent, fn)`:
    - Whenever `last.Status == 429` (or `retry` is triggered after attempt `i > 0`), `RetryPolicy.Do` checks `if rt := RetryTrackerFrom(ctx); rt != nil`:
      - If `last.Status == 429`: `rt.Throttles.Add(1)`
      - If `i > 0`: `rt.Retries.Add(1)`
  - Inside `hostkit.ListAll` (`hostkit/paginate.go`):
    - Each page fetch calls `if rt := RetryTrackerFrom(ctx); rt != nil { rt.Pages.Add(1) }`, so multi-page `bucket_list`, `object_list_all`, and `queue_list` automatically charge the exact number of pages fetched!

### 5.2 How `cloudhost.Host` Wraps Every Operation (`hostkit/cloudhost/host.go`)

- `cloudhost.Host` owns a single `meter *hostkit.Meter` initialized with `PriceTableFor(cfg.Provider)` and initial cap from `LMCLOUD_MAX_COST_USD` / `<PREFIX>_MAX_COST_USD` (default `$0.05`).
- Every metered method on `cloudhost.Host` (`BucketCreate`, `ObjectPut`, `QueueSend`, etc.) calls:
  1. Pre-flight input validation (`Validator.Bucket`, etc.). If pre-flight validation fails, `h.meter.RecordFailure(op, dur, 0, 0)` increments `calls` and `errors` in `MetricsReport` without charging `CostReport`.
  2. Cost admission check: `if err := h.meter.Admit(op, bytesOut); err != nil { return ..., h.fail(op, target, err) }`. If `Admit` sees `accrued + delta > cap` on a non-teardown operation, it increments `cap_exceeded_count` and returns `&CloudError{Code: CostCapExceeded, ProviderCode: "CostCapExceeded", Message: "...", Preflight: false}` (formatted by `FormatAbort` as `[COST_CAP_EXCEEDED] <op> (<target>): ... (http=0, provider_code=CostCapExceeded)`).
  3. Attaches `ctx, rt := hostkit.WithRetryTracker(ctx)` and times the adapter call (`start := h.cfg.Now()`).
  4. On completion, `h.meter.Commit(op, units, bytesIn, bytesOut, dur, rt, cerr)` atomically updates both `CostReport` (nanodollars, requests, billing units, bytes) and `MetricsReport` (`calls`, `errors`, `retries`, `throttles`, `bytes_in`, `bytes_out`, latency sample).

---

## 6. Explicit Exclusions (Not in Slice 3)

1. **Live cloud billing / invoice queries (AWS Cost Explorer, Azure Cost Management, GCP Cloud Billing / BigQuery billing export, OCI Cost Analysis):** Out of scope; hosts never query billing APIs in Slice 3.
2. **Real-time dynamic pricing / Spot price feeds:** All prices come from the deterministic embedded price table (`price_table_version()`).
3. **Cross-process shared cost budgets:** Each host invocation has its own independent cost ledger and `$0.05` default cap (`$0.25` hard ceiling).
4. **Storage duration / wall-clock time-based billing (`GB-months` accrued over real sleep time):** To keep cost estimation 100% deterministic and independent of CPU/network speed, `object_put` charges a fixed per-GiB write/storage allowance based on byte size rather than multiplying by wall-clock seconds elapsed before `object_delete`.
5. **Latency SLA aborts:** Performance metrics are observational (`cloud.metrics()`); slow operations are bounded by `OpTimeout` (`2m`), not by percentile SLA thresholds.

---

## 7. Open Questions (With Adopted Defaults)

1. **OQ-1 (`ErrorCode` for budget exhaustion — Adopted Default: Add `ErrorCode.COST_CAP_EXCEEDED`):**
   - Should exceeding `cost_cap_usd()` report a dedicated 9th enum constant `ErrorCode.COST_CAP_EXCEEDED` (`provider_code() == "CostCapExceeded"`), or reuse `ErrorCode.PRECONDITION_FAILED` with `provider_code() == "CostCapExceeded"`?
   - **Default adopted in this design & schema:** `ErrorCode.COST_CAP_EXCEEDED` (gives scripts a direct enum check `last_error().code() == ErrorCode.COST_CAP_EXCEEDED` distinct from HTTP `412` conditional failures and `INVALID_ARGUMENT` validation errors).
2. **OQ-2 (Whether transient `RetryPolicy` retries multiply `estimated_cost()` — Adopted Default: Charge 1 logical operation in `CostReport`, count retries in `MetricsReport`):**
   - When `hostkit.RetryPolicy` retries a transient `429` or `503`, should `cost_report()` charge per HTTP attempt or per logical operation?
   - **Default adopted in this design:** Charge **1 logical operation** in `cost_report()` (and count every retry/throttle in `cloud.metrics().total_retries()` / `total_throttles()`) so `estimated_cost()` and cost-cap boundaries remain 100% deterministic even under transient simulator or live-cloud retries.
3. **OQ-3 (Behavior of `cloud.set_cost_cap_usd` in `--dry-run` mode — Adopted Default: Enforce cost cap identically in `--dry-run`):**
   - Should `lmscript --dry-run` accumulate estimated costs and enforce `set_cost_cap_usd` against the dry overlay?
   - **Default adopted in this design:** Yes — dry runs meter the previewed operations against the same embedded price table and enforce `COST_CAP_EXCEEDED`, allowing operators to preview script cost and catch budget overflows before running against a live cloud.
