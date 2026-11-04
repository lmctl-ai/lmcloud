# 16 — `lmcloud` Function Conformance Suite & Simulator Enhancements (Slice 6)

## 1. Conformance Runner Usage

[`tests/run-conformance.sh`](../tests/run-conformance.sh) accepts `object-storage`, `queue`, `cost-perf`, `tables`, `function`, or `all` (default `all`):

```bash
# Static compile/typecheck against schema/lmcloud.dsl.json (outer .lms + embedded _lmcode_ blocks):
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check all
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check function
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --live --check all

# Execute against each provider + simulator once Go Functions adapters and sim enhancements land:
./tests/run-conformance.sh /path/to/lmaws   http://127.0.0.1:4566 function
./tests/run-conformance.sh /path/to/lmazure http://127.0.0.1:4577 function
./tests/run-conformance.sh /path/to/lmgcp   http://127.0.0.1:4588 function
./tests/run-conformance.sh /path/to/lmoci   http://127.0.0.1:4599 function
```

### Naming, Live-Profile Exclusion & Capability-Skip Rules
- Function names are `lmf<NN><run_id><suffix>` matching the portable alphanumeric rule `^[a-z][a-z0-9]{2,31}$` ([`15-function-design.md` §4.1](15-function-design.md)). Every scenario embeds a per-run `run_id` (`ARGV[2]`).
- **Live-profile exclusion:** `--live` (`is_live_excluded_scenario` in `tests/run-conformance.sh`) explicitly excludes `function/` alongside `cost-perf/` and `tables/`. Running `./tests/run-conformance.sh --live --check all` compiles only the 23 live-eligible `object-storage` and `queue` scenarios; targeting `--live --check function` exits with code `2`.
- **Capability skip mechanism (`tests/capabilities.conf`):**
  1. Every scenario in `tests/conformance/function/` carries `# Requires: function` in its first 3 lines (and scenario 02 carries `# Requires: object-storage function`).
  2. Until the Go `Functions` adapter (`hostkit.Functions` + `cloudhost` bindings + `fakeadapter` + provider adapters) and simulator enhancements (`A-FN1..3`, `AZ-FN1..2`, `G-FN1..2`, `O-FN1`) are implemented, all five hosts (`lmaws`, `lmazure`, `lmgcp`, `lmoci`, `lmcloud-ref`) are marked `pending(go-function-adapter;...)` in [`tests/capabilities.conf`](../tests/capabilities.conf).
  3. The runner reports `ok N - function/NN-... # SKIP <reason>` in TAP output and counts each as `skip` (never `pass`).

---

## 2. The 13 Function Conformance Scenarios (`tests/conformance/function/`)

| # | File | Scenario | One-Line Expected Behavior |
|---|---|---|---|
| **01** | `01-function-lifecycle-inline.lms` | inline function create, exists, get, sorted list, idempotent recreate, delete, post-delete disappearance | Create two inline `"python3.12"` functions; verify `function_exists` (`false` before, `true` after), `function_get` (`exists()==true`, `state()=="active"`, `code_source()=="inline"`, non-empty `code_sha256()` and `revision_id()`), `function_list` sorted ascending, idempotent same-config `function_create` returns `false`, `function_delete` returns `true` once and `false` on repeat. |
| **02** | `02-function-create-from-object-package.lms` | create & update function from Object Storage package (`bucket`, `key`) | Upload handler bundle via `object_put`, deploy function via `set_package_object(bkt, key)`, verify `code_source()=="object"`, `package_bucket()`, `package_key()`, invoke synchronously, update package object and `function_update`, then delete function, objects, and bucket. |
| **03** | `03-function-config-conflict-and-update.lms` | `CONFLICT` on mismatched `function_create`; unconditional & conditional `function_update` | `function_create` on existing function with different runtime/handler/memory/timeout/env/code fails `CONFLICT`; `function_update` mutates code & config and rotates `revision_id()`; 3-arg `function_update` with matching `expect_revision` succeeds, whereas stale `expect_revision` fails `PRECONDITION_FAILED`. |
| **04** | `04-function-invoke-sync-json-and-logs.lms` | synchronous invocation with JSON payload, response payload, tail logs, and duration/billing metrics | Invoke `"python3.12"` and `"nodejs20.x"` functions with JSON payloads; verify `status_code()==200`, `is_error()==false`, `function_error()==""`, JSON `payload()` round-trip, captured `logs()`, `executed_version()=="$LATEST"`, `duration_ms()>=0.0`, `billed_ms()>=1`, and `memory_mb()`. |
| **05** | `05-function-invoke-error-handling.lms` | handled & unhandled runtime errors surface in `FunctionInvokeResult` with `ErrorCode.OK` | Invoke function that raises an application error vs normal return; verify `last_error().code()==ErrorCode.OK`, `status_code()==200`, `is_error()==true`, `function_error()` is `"Handled"` or `"Unhandled"`, structured error JSON in `payload()`, and diagnostic trace/print in `logs()`. |
| **06** | `06-function-env-vars-isolation.lms` | environment variable configuration, sorted inspection, runtime injection, and `remove_env` | Configure multiple env vars (`STAGE`, `FEATURE_FLAG`, `GREETING`), verify local/remote `has_env`, `env`, `env_len`, sorted `env_names`, invoke function to echo runtime `os.environ` values in JSON payload, then `remove_env` + `function_update` and verify removal in both `function_get` and `function_invoke`. |
| **07** | `07-function-timeout-and-memory-limits.lms` | discrete `memory_mb` shapes (`128..2048`), `timeout_seconds` (`1..230`), and timeout expiration | Create/update function across `{128, 256, 512, 1024}` MiB and `timeout_seconds=1`; verify `function_get` and `function_invoke` report configured `memory_mb()`; invoke slow execution exceeding `1s` timeout and verify `is_error()==true` (`function_error()=="Timeout"` or `"Unhandled"`) and `billed_ms()>=1000`. |
| **08** | `08-function-versions-and-aliases.lms` | immutable published versions (`function_publish_version`, `function_versions`) and mutable aliases (`function_alias_*`) | Publish version `"1"` (v1 code), update `"$LATEST"` to v2 code, publish version `"2"` (conditional on `revision_id()`), verify `function_versions` returns `["1", "2"]`, bind alias `"prod"` to `"1"`, invoke via `"1"`, `"2"`, `"prod"`, and `"$LATEST"` verifying each executes its frozen snapshot and returns `executed_version()`, retarget `"prod"` to `"2"`, then delete alias. |
| **09** | `09-function-concurrency-controls.lms` | concurrency limit configuration (`0`, `1..100`, `-1`) and throttle enforcement (`PRECONDITION_FAILED` / HTTP 429) | Set `concurrency` to `5`, verify readback on `function_get`; update `concurrency` to `-1` (throttle all invocations) and verify `function_invoke` fails with `ErrorCode.PRECONDITION_FAILED` (`http_status()==429`); restore `concurrency` to `0` and verify `function_invoke` succeeds again. |
| **10** | `10-function-notfound-errors.lms` | missing function, missing version/alias, and missing package bucket/object error contracts | On missing function: `function_update`, `function_invoke`, `function_publish_version`, `function_versions`, `function_alias_set`, `function_alias_get`, `function_alias_delete` -> `ErrorCode.NOT_FOUND`; `function_get` -> `exists()==false` + `ErrorCode.OK`; `function_exists` -> `false` + `OK`; `function_delete` -> `false` + `OK`; on existing function: missing version/alias invoke or `alias_set` -> `NOT_FOUND`, missing `alias_get` -> `""` + `OK`; missing package bucket/key -> `NOT_FOUND`. |
| **11** | `11-function-validation-guards.lms` | pre-flight `INVALID_ARGUMENT` (`http_status()==0`) across all validation boundaries | Verify 24 invalid inputs (bad/reserved function names, bad runtimes, bad handlers, missing/empty code source, bad memory shapes, bad timeouts, bad concurrency, reserved/invalid/oversize env vars, bad alias names, empty/non-JSON invoke payload, empty `expect_revision`) all fail pre-flight with `INVALID_ARGUMENT` and `http_status()==0`. |
| **12** | `12-function-cost-and-metrics-accounting.lms` | per-invocation GB-second & request cost metering, higher-memory cost scaling, cost cap pre-attempt refusal, teardown immunity, and `MetricsReport` | Verify `cost_report().item("function_create")` and `item("function_invoke")` (`service()=="function"`, `billing_units() > requests()`, 512 MiB invoke costs more per ms than 128 MiB invoke, `bytes() == req_bytes + resp_bytes`), `metrics().op("function_invoke")` counters & latency invariants, `set_cost_cap_usd` pre-attempt refusal (`COST_CAP_EXCEEDED`, `http_status()==0`), and `function_delete` teardown immunity under exhausted work sub-cap. |
| **13** | `13-function-auth-enforced-denial.lms` | `--auth enforce` unauthenticated (`UNAUTHENTICATED`) and policy-denied (`PERMISSION_DENIED`) matrix | Emits `SKIP` in `--auth open` mode. In `--auth enforce`: Pass 1 (bogus credentials) -> `UNAUTHENTICATED` on `function_create` and `function_invoke`; Pass 2 (restricted principal) -> `PERMISSION_DENIED` on `function_exists` (never masked as `false`/`OK`), `function_create`, and `function_invoke`. |

---

## 3. Simulator Readiness & Required Enhancements (Inspected 2026-11-03)

### 3.1 `awssim` (`/home/ubuntu/cloud/awssim`)
- **Control plane present in-process (`floci` `services/lambda`):** `CreateFunction`, `GetFunction`, `ListFunctions`, `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `DeleteFunction`, `PublishVersion`, `ListVersionsByFunction`, `CreateAlias`, `UpdateAlias`, `GetAlias`, `DeleteAlias`, `ListAliases`, `PutFunctionConcurrency`, `GetFunctionConcurrency`, `DeleteFunctionConcurrency`.
- **Enhancement A-FN1 (M — in-process invoke without Docker):** Add zero-Docker in-process handler runner in `LambdaExecutorService` for `"python3.12"` and `"nodejs20.x"` bundles (inline ZIP or S3 object via `S3Service`), enforcing `Timeout`, `Environment.Variables`, and `LambdaConcurrencyLimiter` (`ReservedConcurrentExecutions == 0` -> `429 TooManyRequestsException`), capturing 4 KiB tail logs (`X-Amz-Log-Result`), and setting `X-Amz-Function-Error` + `X-Amz-Executed-Version`.
- **Enhancement A-FN2 (S — `AuthFilter.java` Lambda routes):** Add `lambda` REST route detection (`/2015-03-31/functions*`, `/2017-10-31/functions*`, `/2019-09-30/functions*`) and action mapping to [`AuthFilter.java`](file:///home/ubuntu/cloud/awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java).
- **Enhancement A-FN3 (S — `ListFunctions` pagination):** Support `Marker` and `MaxItems` on `GET /2015-03-31/functions`.

### 3.2 `azuresim` (`/home/ubuntu/cloud/azuresim`)
- **Control plane present in-process (`floci-az` `services/functions`):** `FunctionsServiceHandler` (`/{account}-functions/admin/apps/...` and `/{account}-functions/api/...`).
- **Enhancement AZ-FN1 (M — in-process execution & rich metadata):** Extend `FunctionModels` and `FunctionsServiceHandler` to store `runtime`, `handler`, `timeoutSeconds`, `memoryMb`, `concurrency`, `environment`, `codeSha256`, `version`, and `revisionId` (plus Blob Storage package loading), and replace the static `{"mocked":true}` stub in `handleInvoke` with deterministic in-process execution returning payload, tail logs, `function_error`, `executed_version`, and duration/billing metrics.
- **Enhancement AZ-FN2 (S — `StorageAuth.java` Functions routes):** Extend [`StorageAuth.java`](file:///home/ubuntu/cloud/azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java) to authenticate and authorize `/{account}-functions/admin/...` and `/{account}-functions/api/...` in `--auth enforce` mode.

### 3.3 `gcpsim` (`/home/ubuntu/cloud/gcpsim`)
- **Control plane present in-process (`floci-gcp` `services/cloudfunctions`):** `CloudFunctionsController` (`/v2/projects/{p}/locations/{l}/functions` `createFunction`, `getFunction`, `listFunctions` with pagination, `deleteFunction`, `generateUploadUrl`).
- **Enhancement G-FN1 (M — `PATCH` update & `:call` synchronous invoke):** Add `PATCH /v2/projects/{p}/locations/{l}/functions/{id}` (`updateFunction`) and `POST /v2/projects/{p}/locations/{l}/functions/{id}:call` (in-process handler execution with GCS source bundle loading, env vars, timeout, concurrency, tail logs, and error status).
- **Enhancement G-FN2 (S — `BearerGuard.java` Cloud Functions IAM):** Permit `/v2/projects/{p}/locations/{l}/functions*` in [`BearerGuard.java`](file:///home/ubuntu/cloud/gcpsim/src/main/java/ai/lmctl/gcpsim/BearerGuard.java) and map `cloudfunctions.functions.{create,get,list,update,delete,invoke}`.

### 3.4 `ocisim` (`/home/ubuntu/cloud/ocisim`)
- **Control plane & enforce auth present in-process (`floci-oci` `services/functions` + `OciPolicyEngine.java`):** `/20181201/applications`, `/20181201/functions`, and `/20181201/functions/{id}/actions/invoke` are already routed in mock mode (`floci-oci.services.functions.mock=true`) and mapped in [`OciPolicyEngine.java:757-789`](file:///home/ubuntu/cloud/ocisim/src/main/java/ai/lmctl/ocisim/OciPolicyEngine.java#L757-L789) (`fn-app`, `fn-function`, `fn-invocation`).
- **Enhancement O-FN1 (M — in-process handler execution in mock mode):** Extend `floci-oci` Functions mock mode to load inline/Object-Storage code bundles and execute `"python3.12"` / `"nodejs20.x"` handlers on `POST /20181201/functions/{id}/actions/invoke` with timeout, memory, concurrency, tail logs (`opc-fn-log-result`), and error headers (`opc-fn-error`, `opc-fn-executed-version`).
