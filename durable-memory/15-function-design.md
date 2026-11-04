# 15 — Slice 6 (Function / Serverless Compute) Design & Cross-Cloud Mapping

## 1. Scope & Guiding Principles

Slice 6 (`function`) introduces a portable, synchronous serverless function lifecycle and invocation API across AWS, Azure, GCP, and OCI. A single `lmscript` / `lmcode` program can create, configure, update, version, alias, list, delete, and synchronously invoke serverless functions with JSON payloads, structured logs, error classification, environment variables, timeout/memory/concurrency controls, and per-invocation cost accounting without provider-specific conditionals.

### 1.1 Non-Goals (Out of Scope for Slice 6)
To guarantee strict 4-cloud portability, deterministic local simulator execution without a Docker daemon, and bounded live-cloud blast radius, the following provider-specific features are **out of scope** for Slice 6:
- **Asynchronous / event-driven invocation (`Event` mode) and event-source mappings** (SQS/PubSub/Blob/Stream triggers, dead-letter queues, destinations).
- **Streaming responses (` InvokeWithResponseStream`)** and WebSocket/HTTP raw request routing (all portable invocations use synchronous `RequestResponse` JSON payloads).
- **Weighted traffic-shifting aliases** (aliases in Slice 6 map 1:1 to a single immutable published version).
- **Provisioned concurrency / warm instance pools** (which incur continuous idle hourly charges on live clouds; Slice 6 exposes only on-demand execution and max/reserved concurrency caps).
- **Custom container images, layers, VPC attachment, EFS/file-system mounts, and custom IAM execution roles** (in live mode, functions execute only under a pre-provisioned, least-privilege sandbox role supplied by operator configuration).

---

## 2. `lmcode` Schema Surface (`schema/lmcloud.dsl.json`)

### 2.1 Domain Types

#### `FunctionConfig`
Mutable builder and readback descriptor for a serverless function's configuration, code source, limits, environment variables, and version metadata. Constructed locally via `cloud.function_config(runtime, handler)` and returned by `cloud.function_get` and `cloud.function_update`.

| Method | Signature | Description |
|---|---|---|
| `name` | `() -> string` | Function name (`""` on a local unattached builder; populated on server-returned configs). |
| `exists` | `() -> bool` | `true` when returned by `function_get` / `function_update` for an existing function; `false` on a local builder or when `function_get` targets a non-existent function/qualifier. |
| `state` | `() -> string` | Normalized lifecycle state: `"active"` when ready on the provider, or `""` on a local builder / absent function. |
| `runtime` | `() -> string` | Portable runtime identifier (`"python3.12"` or `"nodejs20.x"`). |
| `set_runtime` | `(runtime: string) -> self` | Sets the runtime identifier; validates against the portable runtime allowlist pre-flight. |
| `handler` | `() -> string` | Entrypoint handler (`"<module>.<function>"`, e.g., `"index.handler"`). |
| `set_handler` | `(handler: string) -> self` | Sets the entrypoint handler; validates `<module>.<export>` syntax pre-flight. |
| `code_source` | `() -> string` | `"inline"`, `"object"`, or `""` (unset). Setting one source clears the other. |
| `inline_code` | `() -> string` | Inline UTF-8 source code when `code_source() == "inline"` (`""` on server readback if the provider only stores the packaged archive, or the stored inline source). |
| `set_inline_code` | `(code: string) -> self` | Sets inline source code (`1..65536` UTF-8 bytes) and sets `code_source()` to `"inline"`, clearing `package_bucket`/`package_key`. |
| `package_bucket` | `() -> string` | Source object-storage bucket when `code_source() == "object"`, else `""`. |
| `package_key` | `() -> string` | Source object-storage key when `code_source() == "object"`, else `""`. |
| `set_package_object` | `(bucket: string, key: string) -> self` | Configures deployment from an object-storage package in `(bucket, key)` and sets `code_source()` to `"object"`, clearing `inline_code`. |
| `code_sha256` | `() -> string` | Hex-encoded (64 lowercase hex chars) or base64-normalized SHA-256 digest of the canonical deployment bundle (`""` on a local builder before packaging if `code_source() == "object"`). |
| `timeout_seconds` | `() -> int` | Execution timeout in seconds (default `3`, portable range `1..230`). |
| `set_timeout_seconds` | `(seconds: int) -> self` | Sets execution timeout in seconds (`1..230`). |
| `memory_mb` | `() -> int` | Allocated memory in MiB (default `128`, portable discrete set `{128, 256, 512, 1024, 2048}`). |
| `set_memory_mb` | `(mb: int) -> self` | Sets allocated memory in MiB (`{128, 256, 512, 1024, 2048}`). |
| `concurrency` | `() -> int` | Max concurrent executions: `0` = unreserved/default scaling, `1..100` = reserved/max concurrency cap, `-1` = throttle all invocations (`0` reserved on AWS). |
| `set_concurrency` | `(max_concurrent: int) -> self` | Sets concurrency limit (`-1`, `0`, or `1..100`). |
| `env` | `(key: string) -> string` | Returns environment variable value for `key` (or `""` and sets `INVALID_ARGUMENT` if `key` is absent). |
| `has_env` | `(key: string) -> bool` | `true` if environment variable `key` is present. |
| `set_env` | `(key: string, value: string) -> self` | Sets environment variable `key = value`; validates key grammar, reserved prefixes, and aggregate 4 KiB user env budget pre-flight. |
| `remove_env` | `(key: string) -> self` | Removes environment variable `key` (no-op if absent). |
| `env_names` | `() -> StrList` | Sorted (`ASCII` ascending) list of configured user environment variable names. |
| `env_len` | `() -> int` | Count of configured user environment variables (`0..64`). |
| `version` | `() -> string` | Version identifier: `"$LATEST"` for the mutable head, or a positive decimal version string (`"1"`, `"2"`, ...) for a published immutable snapshot. |
| `revision_id` | `() -> string` | Non-empty opaque revision token that changes on every committed code, configuration, concurrency, or version-publish mutation. Used for optimistic concurrency in `function_update` and `function_publish_version`. |

#### `FunctionInvokeResult`
Result of a synchronous `cloud.function_invoke` call.

| Method | Signature | Description |
|---|---|---|
| `status_code` | `() -> int` | HTTP-equivalent synchronous execution status (`200` for completed synchronous execution, including handled/unhandled function errors; `0` on transport/control-plane error). |
| `payload` | `() -> string` | UTF-8 JSON response body returned by the function (or structured JSON error payload when `is_error() == true`). |
| `logs` | `() -> string` | Captured UTF-8 execution log tail (`<= 4096` bytes). |
| `function_error` | `() -> string` | `""` on normal return; `"Handled"`, `"Unhandled"`, or `"Timeout"` when the function invocation failed inside the runtime. |
| `is_error` | `() -> bool` | `true` iff `str_len(function_error()) > 0`. |
| `executed_version` | `() -> string` | The resolved function version that executed (`"$LATEST"` or a published version number such as `"1"`, even when invoked via an alias). |
| `duration_ms` | `() -> float` | Measured execution wall time in milliseconds (`>= 0.0`). |
| `billed_ms` | `() -> int` | Billed execution duration in milliseconds (`>= 1`; rounded up to integer ms, capped at `timeout_seconds * 1000` on timeout). |
| `memory_mb` | `() -> int` | Configured memory size (in MiB) of the executed version, used to compute GB-second billing units. |

### 2.2 `Cloud` Methods

| Method | Signature(s) | Return Type | Semantics |
|---|---|---|---|
| `function_config` | `(runtime: string, handler: string)` | `FunctionConfig` | Creates a local `FunctionConfig` builder initialized with `runtime`, `handler`, `timeout_seconds = 3`, `memory_mb = 128`, `concurrency = 0`, and empty `env`. Validates `runtime` and `handler` pre-flight. |
| `function_create` | `(name: string, config: FunctionConfig)` | `bool` | Creates function `name` and waits until its state is `"active"`. Returns `true` if newly created, `false` if `name` already exists in the same run/scope with an **identical** canonical configuration (`runtime`, `handler`, `code_sha256`, `timeout_seconds`, `memory_mb`, `concurrency`, and `env`), or fails with `ErrorCode.CONFLICT` if `name` already exists with any differing configuration or foreign ownership. |
| `function_update` | `(name: string, config: FunctionConfig)`<br>`(name: string, config: FunctionConfig, expect_revision: string)` | `FunctionConfig` | Updates `$LATEST` code, configuration, env vars, and concurrency of existing function `name`, waits until the update completes and the function is `"active"`, and returns the updated `FunctionConfig` with a fresh `revision_id()`. The 3-arg overload requires the current `revision_id()` to equal `expect_revision` (non-empty; empty `expect_revision` fails pre-flight with `INVALID_ARGUMENT`); a mismatch fails with `ErrorCode.PRECONDITION_FAILED`. Missing function fails with `ErrorCode.NOT_FOUND`. |
| `function_delete` | `(name: string)` | `bool` | Fences `name` as `"deleting"`, deletes all aliases, published versions, host-staged packages, the native function, and finally the catalog tombstone. Returns `true` if the function existed and was deleted, `false` (`ErrorCode.OK`) if already absent. Draws from cleanup reserve (`isCleanup = true`). |
| `function_exists` | `(name: string)` | `bool` | Returns `true` if `name` exists and is `"active"`, `false` if absent or `"deleting"` (`ErrorCode.OK`). Never masks `UNAUTHENTICATED` or `PERMISSION_DENIED`. |
| `function_get` | `(name: string)`<br>`(name: string, qualifier: string)` | `FunctionConfig` | Strongly consistent metadata/config read for `$LATEST` (1-arg or `qualifier == "$LATEST"`), a published version (`"1"`, `"2"`, ...), or an alias (`"prod"`). If the function (or requested qualifier) does not exist, returns a `FunctionConfig` with `exists() == false` and `last_error().code() == ErrorCode.OK` (mirrors `object_head` and `item_get`). |
| `function_list` | `()` | `StrList` | Returns all `"active"` function names in ascending ASCII lexicographical order, automatically following all provider pagination tokens (`ListAll`) and filtering out reserved catalog/staging resources. |
| `function_publish_version` | `(name: string)`<br>`(name: string, expect_revision: string)` | `string` | Snapshots the current `$LATEST` code + configuration (`runtime`, `handler`, `code_sha256`, `timeout_seconds`, `memory_mb`, `env`) as an immutable numbered version (`"1"`, `"2"`, ...), rotates `$LATEST`'s `revision_id()`, and returns the published version string. If `$LATEST` matches the most recently published version snapshot identically, returns that version idempotently or allocates the next monotonic version consistently per catalog rules (§4.4). 2-arg overload checks `expect_revision` (`PRECONDITION_FAILED` on mismatch). Missing function -> `NOT_FOUND`. |
| `function_versions` | `(name: string)` | `StrList` | Lists all published immutable version strings (excluding `"$LATEST"`) for function `name` in ascending numerical order (`"1"`, `"2"`, ..., `"10"`). Missing function -> `NOT_FOUND`. |
| `function_alias_set` | `(name: string, alias: string, version: string)` | `void` | Creates or updates mutable alias `alias` on function `name` to point to published `version`. Fails with `NOT_FOUND` if `name` or published `version` does not exist. |
| `function_alias_get` | `(name: string, alias: string)` | `string` | Returns the published `version` string targeted by `alias`, or `""` with `ErrorCode.OK` if `name` exists but `alias` does not exist. Fails with `NOT_FOUND` if function `name` does not exist. |
| `function_alias_delete` | `(name: string, alias: string)` | `bool` | Deletes `alias` on function `name`. Returns `true` if deleted, `false` (`ErrorCode.OK`) if `alias` was already absent on existing function `name`. Fails with `NOT_FOUND` if function `name` does not exist. |
| `function_invoke` | `(name: string, payload_json: string)`<br>`(name: string, qualifier: string, payload_json: string)` | `FunctionInvokeResult` | Synchronously invokes function `name` (at `"$LATEST"` for 2-arg, or at `qualifier` — `"$LATEST"`, version number, or alias — for 3-arg) with validated UTF-8 JSON `payload_json`, capturing tail logs and execution metrics. Missing function or missing version/alias fails with `NOT_FOUND`. Concurrency throttling (`429`) fails with `PRECONDITION_FAILED` (`http_status() == 429`). |

Also, `cloud.set_endpoint("function", url)` (and `"all"`) routes function control-plane and data-plane requests to `url`, and the CLI/runner honors `LMCLOUD_FUNCTION_ENDPOINT` (falling back to `LMCLOUD_ENDPOINT`).

---

## 3. Cross-Provider Mapping & Simulator Capabilities

### 3.1 Provider Service Mapping

| Concept | AWS (`lmaws` / `awssim` `:4566`) | Azure (`lmazure` / `azuresim` `:4577`) | GCP (`lmgcp` / `gcpsim` `:4588`) | OCI (`lmoci` / `ocisim` `:4599`) |
|---|---|---|---|---|
| **Service** | AWS Lambda (`2015-03-31`) | Azure Functions (`/{account}-functions/admin/apps/...` & `/api/...`) | Cloud Functions v2 (`/v2/projects/{p}/locations/{l}/functions`) | OCI Functions (`20181201` `/applications` + `/functions` + `/actions/invoke`) |
| **Container Scope** | Region + Account | Function App (`lmcloudfnapp` or per-function app) + Catalog `lmcloudfnmeta` | Project + Location (`us-central1`) + Catalog `lmcloudfnmeta` | Compartment + Application (`lmcloud-fn-app`) + Catalog `lmcloudfnmeta` |
| **Create** | `POST /2015-03-31/functions` (`CreateFunction`) | Catalog claim in `lmcloudfnmeta` + `PUT /{acct}-functions/admin/apps/{app}/functions/{name}` | Catalog claim in `lmcloudfnmeta` + `POST /v2/.../functions?functionId={name}` | Catalog claim in `lmcloudfnmeta` + `POST /20181201/functions` |
| **Update** | `PUT .../functions/{name}/code` + `PUT .../functions/{name}/configuration` + concurrency | Conditional catalog update in `lmcloudfnmeta` + `PUT .../functions/{name}` | Conditional catalog update in `lmcloudfnmeta` + `PATCH /v2/.../functions/{name}` | Conditional catalog update in `lmcloudfnmeta` + `PUT /20181201/functions/{id}` |
| **Get / Exists** | `GET /2015-03-31/functions/{name}[?Qualifier=]` | Catalog read in `lmcloudfnmeta` + `GET .../functions/{name}` | Catalog read in `lmcloudfnmeta` + `GET /v2/.../functions/{name}` | Catalog read in `lmcloudfnmeta` + `GET /20181201/functions/{id}` |
| **List** | `GET /2015-03-31/functions` (`Marker`/`MaxItems`) | Catalog query in `lmcloudfnmeta` + `GET .../functions` | Catalog query in `lmcloudfnmeta` + `GET /v2/.../functions` (`pageSize`/`pageToken`) | `GET /20181201/functions?applicationId=...` (`limit`/`page`) |
| **Delete** | Fenced delete of aliases, versions, concurrency, `DELETE /2015-03-31/functions/{name}` | Mark `"deleting"` in `lmcloudfnmeta`, `DELETE .../functions/{name}`, delete tombstone last | Mark `"deleting"` in `lmcloudfnmeta`, `DELETE /v2/.../functions/{name}`, delete tombstone last | Mark `"deleting"` in `lmcloudfnmeta`, `DELETE /20181201/functions/{id}`, delete tombstone last |
| **Versions & Aliases** | Native `POST/GET .../versions` + `POST/PUT/GET/DELETE .../aliases` (mirrored in journal/catalog) | Catalog-managed immutable version snapshots & alias pointers in `lmcloudfnmeta` + versioned deployment slot | Catalog-managed immutable version snapshots & alias pointers in `lmcloudfnmeta` | Catalog-managed immutable version snapshots & alias pointers in `lmcloudfnmeta` |
| **Concurrency** | `PUT/DELETE /2017-10-31/functions/{name}/concurrency` (`ReservedConcurrentExecutions`) | Catalog + in-process / sim semaphore (`maxConcurrency`) | `serviceConfig.maxInstanceCount` + catalog / sim semaphore | Catalog + sim concurrency limiter |
| **Sync Invoke** | `POST /2015-03-31/functions/{name}/invocations[?Qualifier=]` (`X-Amz-Invocation-Type: RequestResponse`, `X-Amz-Log-Type: Tail`) | `POST /{acct}-functions/api/{app}/{name}` (`x-lmcloud-qualifier`, `x-lmcloud-log-type: Tail`) | `POST /v2/projects/{p}/locations/{l}/functions/{name}:call` | `POST /20181201/functions/{id}/actions/invoke` (`fn-invoke-type: sync`) |

### 3.2 Simulator Audit & Enhancement Epics (Zero-Docker In-Process Execution)

By Guiding Principle 2 ([`05-roadmap.md`](file:///home/ubuntu/cloud/lmcloud/durable-memory/05-roadmap.md)), all conformance tests against `awssim`, `azuresim`, `gcpsim`, and `ocisim` must execute **in-process with zero Docker daemon dependency** while faithfully emulating real cloud semantics:

1. **`awssim` (`floci` `services/lambda` + `AuthFilter.java`):**
   - **Already present upstream:** `LambdaController`, `LambdaConcurrencyController`, `LambdaTagController`, and `LambdaService` implement `CreateFunction`, `GetFunction`, `ListFunctions`, `UpdateFunctionConfiguration`, `UpdateFunctionCode`, `DeleteFunction`, `PublishVersion`, `ListVersionsByFunction`, `CreateAlias`, `UpdateAlias`, `GetAlias`, `DeleteAlias`, `ListAliases`, `PutFunctionConcurrency`, `GetFunctionConcurrency`, `DeleteFunctionConcurrency`, and `LambdaConcurrencyLimiter`.
   - **Sim gap A-FN1 (In-process handler evaluation without Docker):** `LambdaExecutorService.invoke` currently attempts to launch a Docker container via `WarmPool` / `LambdaRuntimeLauncher`. `awssim` must add an in-process execution fallback (active by default when Docker is disabled/unavailable or `FLOCI_LAMBDA_INPROCESS=true`) that unpacks the function's ZIP archive (`ZipFile` or S3 bucket/key via `S3Service`), executes the `"python3.12"` or `"nodejs20.x"` entrypoint handler in a bounded local subprocess / embedded evaluator with the configured `Environment.Variables` and `Timeout`, enforces `LambdaConcurrencyLimiter` (`ReservedConcurrentExecutions == 0` or exceeded -> `429 TooManyRequestsException`), captures `stdout`/`stderr` into `X-Amz-Log-Result` (base64, `<= 4096` bytes when `X-Amz-Log-Type: Tail`), and sets `X-Amz-Function-Error: Handled` / `Unhandled` (and `"Timeout"` / `"Unhandled"` when execution exceeds `Timeout`) plus `X-Amz-Executed-Version`.
   - **Sim gap A-FN2 (`AuthFilter.java` enforce-mode routing):** [`AuthFilter.java`](file:///home/ubuntu/cloud/awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java) currently permits only `s3`, `dynamodb`, and `sqs` in `--auth enforce` mode (`service == null` rejects `/2015-03-31/functions...`). Extend `AuthFilter.java` to recognize SigV4 service `"lambda"` on `/2015-03-31/functions*`, `/2017-10-31/functions*`, `/2019-09-30/functions*`, and `/2020-06-30/functions*` and authorize `lambda:CreateFunction`, `lambda:GetFunction`, `lambda:GetFunctionConfiguration`, `lambda:ListFunctions`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `lambda:DeleteFunction`, `lambda:InvokeFunction`, `lambda:PublishVersion`, `lambda:ListVersionsByFunction`, `lambda:CreateAlias`, `lambda:UpdateAlias`, `lambda:GetAlias`, `lambda:DeleteAlias`, `lambda:ListAliases`, `lambda:PutFunctionConcurrency`, `lambda:GetFunctionConcurrency`, `lambda:DeleteFunctionConcurrency`, `lambda:TagResource`, and `lambda:ListTags`.
   - **Sim gap A-FN3 (`ListFunctions` pagination):** Ensure `GET /2015-03-31/functions` honors `MaxItems` and `Marker` (`NextMarker`) in deterministic sorted order.

2. **`azuresim` (`floci-az` `services/functions` + `StorageAuth.java`):**
   - **Already present upstream:** `FunctionsServiceHandler` exposes `PUT/GET/DELETE /{account}-functions/admin/apps/{appName}/functions/{funcName}`, `GET .../functions`, and `POST /{account}-functions/api/{appName}/{funcName}` with `mocked = true` when Docker is absent.
   - **Sim gap AZ-FN1 (Deterministic in-process execution & metadata):** Enhance `FunctionsServiceHandler` / `FunctionModels` so `DeployFunctionRequest` and `FunctionDefinition` persist `runtime`, `handler`, `timeoutSeconds`, `memoryMb`, `concurrency`, `environment`, `codeSha256`, `version`, and `revisionId` (and support reading package ZIP bytes from `BlobService` when `packageBucket`/`packageKey` is supplied), and so `handleInvoke` in mocked/in-process mode executes the deployed handler (instead of returning the static `{"mocked":true}` stub), enforces timeout and concurrency (`429`), and returns structured execution output (`status_code`, `payload`, `logs`, `function_error`, `executed_version`, `duration_ms`, `billed_ms`).
   - **Sim gap AZ-FN2 (`StorageAuth.java` enforce-mode routing):** Extend [`StorageAuth.java`](file:///home/ubuntu/cloud/azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java) so requests to `/{account}-functions/admin/...` and `/{account}-functions/api/...` are authenticated and authorized in `--auth enforce` mode (`Microsoft.Web/sites/functions/write`, `Microsoft.Web/sites/functions/read`, `Microsoft.Web/sites/functions/delete`, `Microsoft.Web/sites/functions/invoke/action`) rather than falling through to the default path-style deny.

3. **`gcpsim` (`floci-gcp` `services/cloudfunctions` + `BearerGuard.java`):**
   - **Already present upstream:** `CloudFunctionsController` implements `POST /v2/projects/{p}/locations/{l}/functions?functionId={id}`, `GET .../functions` (paginated with `pageSize`/`pageToken`, sorted), `GET .../functions/{id}`, `DELETE .../functions/{id}`, and `POST .../functions:generateUploadUrl`.
   - **Sim gap G-FN1 (`PATCH` update & `:call` synchronous invoke endpoints):** Add `PATCH /v2/projects/{p}/locations/{l}/functions/{id}` (`updateFunction`) and `POST /v2/projects/{p}/locations/{l}/functions/{id}:call` (synchronous invocation accepting `{"data": "<json>", "qualifier": "..."}` and executing the packaged handler from GCS / inline bundle in-process with timeout, concurrency, log tail capture, and error reporting).
   - **Sim gap G-FN2 (`BearerGuard.java` enforce-mode routing):** Extend [`BearerGuard.java`](file:///home/ubuntu/cloud/gcpsim/src/main/java/ai/lmctl/gcpsim/BearerGuard.java) to admit `/v2/projects/{p}/locations/{l}/functions*` and check IAM permissions `cloudfunctions.functions.create`, `cloudfunctions.functions.get`, `cloudfunctions.functions.list`, `cloudfunctions.functions.update`, `cloudfunctions.functions.delete`, and `cloudfunctions.functions.invoke` (or `cloudfunctions.functions.call`) against resource `projects/{p}/locations/{l}/functions/{id}`.

4. **`ocisim` (`floci-oci` `services/functions` + `OciPolicyEngine.java`):**
   - **Already present upstream:** `Main.java` sets `floci-oci.services.functions.mock=true` (zero Docker), and [`OciPolicyEngine.java:757-789`](file:///home/ubuntu/cloud/ocisim/src/main/java/ai/lmctl/ocisim/OciPolicyEngine.java#L757-L789) **already maps** `--auth enforce` policies for `/20181201/applications` (`fn-app`), `/20181201/functions` (`fn-function`), and `/20181201/functions/{id}/actions/invoke` (`fn-invocation`).
   - **Sim gap O-FN1 (In-process code bundle evaluation & concurrency/timeout fidelity):** In `floci-oci` mock mode, extend function creation/update (`config` / freeformTags / Object Storage bundle reference) and `InvokeFunction` (`POST /20181201/functions/{id}/actions/invoke`) so that instead of returning an empty mock stub, it evaluates the deployed handler bundle with configured `config` environment variables, `timeoutInSeconds`, `memoryInMBs`, and concurrency cap, returning response payload, base64 tail logs header (`opc-fn-log-result`), function error header (`opc-fn-error`), and executed version header (`opc-fn-executed-version`).

---

## 4. Detailed Portable Semantics & Invariants

### 4.1 Naming, Runtime, Handler, and Pre-Flight Validation Guards

Every validation rule below is enforced **pre-flight** in `cloudhost` / `hostkit` before any network request or cost reservation occurs. Any violation sets `last_error()` to `ErrorCode.INVALID_ARGUMENT` with `http_status() == 0` and aborts (when `abort_on_error() == true`).

1. **Function Name (`name`):**
   - Regex: `^[a-z][a-z0-9]{2,31}$` (3 to 32 lowercase ASCII alphanumeric characters, beginning with a lowercase letter).
   - Rationale: Azure Function Apps / Storage-backed function hosts forbid hyphens or mixed case in storage-derived identifiers, while AWS, GCP, and OCI accept lowercase alphanumeric names of length 3–32 without translation.
   - **Reserved names rejected pre-flight (`INVALID_ARGUMENT`, `http_status() == 0`):** `"lmcloudmeta"`, `"lmcloudfnmeta"`, `"tables"`, `"functions"`, `"default"`, `"system"`.
2. **Runtime (`runtime`):**
   - Portable allowlist: `"python3.12"` and `"nodejs20.x"`.
   - Any other string (e.g., `""`, `"python2.7"`, `"go1.x"`, `"ruby3.2"`) fails pre-flight with `INVALID_ARGUMENT`.
   - Provider mapping:
     - AWS Lambda: `"python3.12"`, `"nodejs20.x"`.
     - Azure Functions: `"python"` (`3.12`), `"node"` (`20`).
     - GCP Cloud Functions Gen2: `"python312"`, `"nodejs20"`.
     - OCI Functions: `"python"` (`3.12`), `"node"` (`20`).
3. **Handler (`handler`):**
   - Regex: `^[A-Za-z_][A-Za-z0-9_]{0,31}\.[A-Za-z_][A-Za-z0-9_]{0,31}$` (total length `3..65` ASCII characters, exactly one dot separating `<module>.<export>`, e.g., `"index.handler"` or `"main.handle"`).
   - Empty strings, path traversal (`"../index.handler"`), slashes, or missing/multiple dots fail pre-flight with `INVALID_ARGUMENT`.
4. **Code Source (`inline` vs. `object`):**
   - A `FunctionConfig` passed to `function_create` or `function_update` MUST have `code_source()` equal to either `"inline"` or `"object"`. An unconfigured `FunctionConfig` (`code_source() == ""`) fails pre-flight with `INVALID_ARGUMENT`.
   - **Inline code (`set_inline_code(code)`):**
     - `code` must be valid UTF-8, contain no NUL byte (`\x00`), and have length `1 <= utf8_len(code) <= 65536` bytes (64 KiB).
     - The host packages `code` into a deterministic in-memory ZIP archive containing a single file named `<module>.py` (for `"python3.12"`) or `<module>.js` (for `"nodejs20.x"`), where `<module>` is the prefix of `handler()` before `.`, with fixed ZIP header timestamp `1980-01-01 00:00:00 UTC` and mode `0644`. `code_sha256()` is the lowercase hex SHA-256 of this canonical ZIP archive (computed immediately on `set_inline_code` / `set_handler` / `set_runtime`).
   - **Object-storage package (`set_package_object(bucket, key)`):**
     - `bucket` must satisfy the Slice 1 bucket-name validator (`3..63` chars, lowercase alnum/hyphens) and `key` must satisfy the Slice 1 object-key validator (`1..1024` UTF-8 bytes, no NUL). Invalid `bucket` or `key` fails pre-flight with `INVALID_ARGUMENT` (`http_status() == 0`).
     - During `function_create` or `function_update`, the adapter verifies and reads/stages the object via `hostkit.RunSubOperation(ctx, "storage", "object_get", ...)` with a bounded `io.LimitReader` of **16 MiB (`16,777,216` bytes)**.
     - If the bucket or object does not exist in Object Storage, `function_create` / `function_update` fails with `ErrorCode.NOT_FOUND`.
     - If the object exceeds 16 MiB, or is neither a valid ZIP archive nor a valid UTF-8 source script, `function_create` / `function_update` fails with `ErrorCode.INVALID_ARGUMENT`.
5. **Timeout (`timeout_seconds`) and Memory (`memory_mb`):**
   - `timeout_seconds`: default `3` seconds; portable allowed range is **`1..230` seconds** inclusive (bounded by Azure Consumption HTTP trigger timeout of 230 s). Values `< 1` or `> 230` fail pre-flight with `INVALID_ARGUMENT` (`http_status() == 0`).
   - `memory_mb`: default `128` MiB; portable allowed values are the discrete set **`{128, 256, 512, 1024, 2048}` MiB** (required by OCI Functions' discrete memory shape constraint and valid on AWS, Azure, and GCP). Any other integer fails pre-flight with `INVALID_ARGUMENT` (`http_status() == 0`).
6. **Concurrency (`concurrency`):**
   - Default `0` (unreserved / provider default scaling).
   - Allowed values: `-1` (explicitly throttle all invocations: maps to AWS `ReservedConcurrentExecutions = 0`), `0` (unreserved), or `1..100` (maximum concurrent executions).
   - Any integer `< -1` or `> 100` fails pre-flight with `INVALID_ARGUMENT` (`http_status() == 0`).
7. **Environment Variables (`set_env`, `remove_env`, `env`):**
   - Key regex: `^[A-Za-z_][A-Za-z0-9_]{0,63}$` (1 to 64 ASCII characters).
   - **Reserved key prefixes / names rejected pre-flight (`INVALID_ARGUMENT`, `http_status() == 0`):**
     - Leading underscore `"_"` (e.g., `"_HANDLER"`, `"_LMCLOUD_META"`),
     - `"AWS_*"`, `"LAMBDA_*"` (reserved by AWS Lambda),
     - `"AZURE_*"`, `"FUNCTIONS_*"`, `"WEBSITE_*"` (reserved by Azure Functions),
     - `"GOOGLE_*"`, `"K_SERVICE"`, `"K_REVISION"`, `"K_CONFIGURATION"`, `"PORT"` (reserved by GCP Cloud Functions Gen2 / Cloud Run),
     - `"OCI_*"`, `"FN_*"` (reserved by OCI Functions),
     - `"LMCLOUD_*"` (reserved by `lmcloud` host runtime).
   - Value: valid UTF-8 without NUL (`\x00`), `0..4096` UTF-8 bytes.
   - **User environment quota (independent of provider/host internal metadata):**
     - Maximum **64 user environment variables** (`env_len() <= 64`).
     - Aggregate user environment byte size: $\sum (\text{utf8\_len}(k) + \text{utf8\_len}(v)) \le 4096$ bytes (matching AWS Lambda's 4 KiB total environment variable limit). Exceeding 64 variables or 4096 total user bytes fails pre-flight in `set_env` with `INVALID_ARGUMENT` and `http_status() == 0`, leaving the `FunctionConfig` unmodified.
8. **Qualifiers, Versions, and Aliases:**
   - Published version strings are positive decimal integers (`"1"`, `"2"`, ...) allocated monotonically by `function_publish_version`.
   - Alias name regex: `^[a-z][a-z0-9_]{1,31}$` (2 to 32 chars, starting with a lowercase ASCII letter so an alias name is syntactically disjoint from numeric version strings and `"$LATEST"`).
   - **Reserved alias names rejected pre-flight (`INVALID_ARGUMENT`, `http_status() == 0`):** `"latest"`, `"default"`, `"system"`.
   - In `function_alias_set(name, alias, version)`, `version` must match `^[1-9][0-9]{0,8}$` (cannot alias `"$LATEST"` or another alias); invalid `alias` or `version` syntax fails pre-flight with `INVALID_ARGUMENT` (`http_status() == 0`).
9. **Synchronous Invocation Payload (`payload_json`) and Bounds:**
   - `payload_json` must be a non-empty UTF-8 string (`1 <= utf8_len(payload_json) <= 1048576` bytes = 1 MiB) whose content is a valid RFC 8259 JSON value (`json.Valid([]byte(payload_json))` with no NUL bytes). Passing `""`, invalid JSON (`"{unclosed"`), or `> 1 MiB` fails pre-flight with `INVALID_ARGUMENT` and `http_status() == 0`.
   - Response payload read from the provider is bounded by `io.LimitReader` at **1 MiB (`1,048,576` bytes)**; if a function returns a response larger than 1 MiB, the host aborts the read and returns `ErrorCode.INVALID_ARGUMENT` (or `function_error() == "Unhandled"` if the provider itself rejected the oversize response).
   - Captured execution logs (`result.logs()`) are bounded at **4 KiB (`4,096` UTF-8 bytes)** (matching AWS Lambda `X-Amz-Log-Result` tail limit). If longer, the last 4,096 UTF-8-safe bytes are retained.

---

### 4.2 Portable Inline Handler Contract

So that a single inline function definition in conformance scenarios (`01`–`13`) runs identically on all four simulators and live clouds when using `"python3.12"` or `"nodejs20.x"`, the standard handler signature is:

- **Python (`"python3.12"`, e.g. `handler = "index.handler"`):**
  ```python
  def handler(event, context):
      # event: parsed JSON value (dict, list, str, int, float, bool, or None)
      # stdout/stderr: print(...) lines are captured in result.logs()
      # os.environ: contains all configured user env vars
      # return: any JSON-serializable value (serialized to UTF-8 JSON in result.payload())
      # raise ValueError("boom"): surfaces as is_error() == true, function_error() == "Handled" or "Unhandled"
      return {"ok": True, "echo": event}
  ```
- **Node.js (`"nodejs20.x"`, e.g. `handler = "index.handler"`):**
  ```javascript
  exports.handler = async (event, context) => {
      console.log("invoked");
      return { ok: true, echo: event };
  };
  ```
- On GCP Cloud Functions Gen2 and OCI Functions (which natively expose HTTP request/response signatures on live clouds while AWS Lambda and Azure Functions support `(event, context)`), the host's deterministic bundler injects a tiny wrapper module (`__lmcloud_entry.py` / `__lmcloud_entry.js`) around the user's `<module>.<export>` so that the user's `(event, context)` function receives the parsed JSON `payload_json`, captures `stdout`/`stderr` tail logs, and returns a canonical JSON envelope without requiring user code to import provider-specific FDK/Functions-Framework libraries.

---

### 4.3 Create Readiness, Idempotency, Update Conditional Semantics, and Delete Fencing

1. **`function_create(name, config) -> bool`:**
   - Computes the canonical config fingerprint over `(runtime, handler, code_source, code_sha256, timeout_seconds, memory_mb, concurrency, canonical_env)`.
   - If `name` does not exist:
     - Claims ownership in the local run journal (`hostkit/safety`) and in the provider catalog (`lmcloudfnmeta` / AWS tags), creates the function, and polls boundedly (up to the operation context deadline, `<= 60 s`) until `State == Active`.
     - Allocates initial `version() == "$LATEST"` and a fresh 128-bit random hex `revision_id()`.
     - Locks the per-function cleanup reserve (`$0.00000200`) inside the run's cleanup budget.
     - Returns `true`.
   - If `name` already exists and is `"active"`:
     - Verifies ownership (`lmcloud-run-id`, `lmcloud-scope`, `lmcloud-create-token`). Foreign or untagged resources in `--live` mode fail closed with `ErrorCode.PERMISSION_DENIED` (or `ErrorCode.CONFLICT` in simulator open mode if config differs).
     - If owned by the current run/scope and the canonical config fingerprint matches **identically**, returns `false` (`ErrorCode.OK`).
     - If **any** field of the canonical config fingerprint differs (different `runtime`, `handler`, `code_sha256`, `timeout_seconds`, `memory_mb`, `concurrency`, or `env`), fails with `ErrorCode.CONFLICT`.
2. **`function_update(name, config [, expect_revision]) -> FunctionConfig`:**
   - If `name` is absent or `"deleting"`, fails with `ErrorCode.NOT_FOUND`.
   - In the 3-arg overload, if `expect_revision` is `""`, fails pre-flight with `INVALID_ARGUMENT` (`http_status() == 0`). If `expect_revision` does not match the function's current `revision_id()`, fails with `ErrorCode.PRECONDITION_FAILED` without mutating code or configuration.
   - Applies the code and configuration update to `$LATEST` (leaving previously published immutable versions `"1"`, `"2"`, ... untouched!), waits until `LastUpdateStatus == Successful` and `State == Active`, rotates `$LATEST`'s `revision_id()` to a fresh 128-bit hex token, and returns the updated `FunctionConfig`.
   - Because conditional `function_update(name, config, expect_revision)` is non-idempotent once it rotates `revision_id()`, ambiguous mid-flight transport errors on conditional updates are **never blindly retried**.
3. **Catalog & Deletion Fencing (`function_delete(name) -> bool`):**
   - Just as Slice 5 uses `lmcloudmeta` for table lifecycle fencing ([`12-tables-design.md` §3.5](file:///home/ubuntu/cloud/lmcloud/durable-memory/12-tables-design.md)), Slice 6 uses a reserved catalog (`lmcloudfnmeta`, backed by the provider's native metadata store or tag/state contract) to fence multi-step function lifecycle operations:
     - **Step 1 (Tombstone Fence):** Conditionally transition the catalog record for `name` from `"active"` to `"deleting"` (with a new `revision_id`). Once marked `"deleting"`, all read/list/invoke/update/version/alias operations immediately treat `name` as absent (`NOT_FOUND` / `false`).
     - **Step 2 (Bounded Child & Native Resource Cleanup):** Enumerate and delete all aliases, published versions, host-staged deployment objects, and the native provider function resource. Every physical request is executed via `hostkit.RunSubOperation` with `isCleanup = true`.
     - **Step 3 (Delete Tombstone Last):** Only after all child resources and the native function are confirmed deleted (`200`/`204`/`404`) is the `"deleting"` catalog record removed and the function's cleanup reserve unlocked in the local journal.

---

### 4.4 Versions and Aliases

1. **Immutable Versions (`function_publish_version`, `function_versions`):**
   - Every newly created function starts with mutable head `version() == "$LATEST"` and zero published versions (`function_versions(name)` returns an empty `StrList`).
   - `function_publish_version(name [, expect_revision]) -> string`:
     - Verifies `name` exists (`NOT_FOUND` if missing) and, if `expect_revision` is supplied, matches `$LATEST`'s `revision_id()` (`PRECONDITION_FAILED` on mismatch).
     - Allocates the next monotonic positive integer version string (`"1"`, `"2"`, `"3"`, ...) for function `name`, freezes an immutable snapshot of `$LATEST`'s `runtime`, `handler`, `code_source`, `inline_code`/`package_bucket`+`package_key`, `code_sha256`, `timeout_seconds`, `memory_mb`, and `env` under that version number, rotates `$LATEST`'s `revision_id()`, and returns the published version string (e.g., `"1"`).
     - Subsequent `function_update` calls mutate only `"$LATEST"`; invoking or reading version `"1"` via `function_invoke(name, "1", payload)` or `function_get(name, "1")` always executes/returns the frozen snapshot of version `"1"`.
   - `function_versions(name) -> StrList`:
     - Returns all published version strings for `name` sorted in ascending numeric order (`"1"`, `"2"`, ..., `"10"`).
2. **Mutable Aliases (`function_alias_set`, `function_alias_get`, `function_alias_delete`):**
   - An alias is a named pointer (`^[a-z][a-z0-9_]{1,31}$`, e.g., `"prod"`, `"staging"`, `"v1_live"`) belonging to function `name` that targets a single published version string (`"1"`, `"2"`, ...).
   - `function_alias_set(name, alias, version)`:
     - Fails with `NOT_FOUND` if function `name` does not exist **or** if `version` has not been published on `name`.
     - Atomically creates or retargets `alias` to `version`.
   - `function_alias_get(name, alias) -> string`:
     - Fails with `NOT_FOUND` if function `name` does not exist.
     - Returns the target `version` string if `alias` exists, or `""` with `ErrorCode.OK` if `alias` does not exist on `name`.
   - `function_alias_delete(name, alias) -> bool`:
     - Fails with `NOT_FOUND` if function `name` does not exist.
     - Returns `true` if `alias` existed and was deleted, or `false` (`ErrorCode.OK`) if `alias` was already absent.
   - Invoking via an alias (`cloud.function_invoke(name, "prod", payload)`) resolves `"prod"` to its target published version (e.g., `"1"`), executes that version's frozen code and configuration, and returns `result.executed_version() == "1"`.

---

### 4.5 Concurrency Semantics

- `config.concurrency()` controls per-function concurrency:
  - `0` (default): unreserved concurrency (uses account/region default pool).
  - `1..100`: reserves/caps concurrent executions of `name` (across all versions/aliases of `name`) to at most `concurrency` simultaneous invocations.
  - `-1`: throttles all invocations of `name` (maps to AWS `ReservedConcurrentExecutions = 0`).
- When `function_invoke` is called on a function whose `concurrency()` is `-1`, or when `concurrency() >= 1` and all `concurrency()` execution slots are currently occupied by in-flight invocations, the provider/simulator rejects the invocation with HTTP `429 Too Many Requests` (`TooManyRequestsException` / `RateLimited`), which maps to `ErrorCode.PRECONDITION_FAILED` with `http_status() == 429` (`last_error().code() == ErrorCode.PRECONDITION_FAILED`).

---

### 4.6 Cost & Performance Accounting (`CostReport` & `MetricsReport`)

Slice 6 integrates directly with the Slice 3 (`cost-perf`) journal-backed cost meter and latency tracker ([`10-cost-perf-design.md`](file:///home/ubuntu/cloud/lmcloud/durable-memory/10-cost-perf-design.md)):

#### 1. Canonical Tariff Table (`service == "function"`)

| Operation | `service()` | Request / Unit Price (`unit_price_usd`) | Billing Units Formula (`billing_units`) | Byte Transfer Price (`byte_price_usd_per_gib`) | Cleanup Reserve Impact |
|---|---|---|---|---|---|
| `function_create` | `"function"` | `$0.00000020` / req | `1` per physical attempt (+ any `RunSubOperation` storage/catalog calls) | `$0.00` | Locks `$0.00000200` per created function |
| `function_update` | `"function"` | `$0.00000020` / req | `1` per physical attempt (+ any `RunSubOperation` calls) | `$0.00` | None |
| `function_delete` | `"function"` | `$0.00000020` / req | `1` per physical attempt (+ child version/alias deletes via `RunSubOperation`) | `$0.00` | Uses cleanup headroom (`isCleanup = true`); unlocks function reserve on completion |
| `function_exists` | `"function"` | `$0.00000020` / req | `1` per physical attempt | `$0.00` | None |
| `function_get` | `"function"` | `$0.00000020` / req | `1` per physical attempt | `$0.00` | None |
| `function_list` | `"function"` | `$0.00000020` / req | `1` per physical page request | `$0.00` | None |
| `function_publish_version` | `"function"` | `$0.00000020` / req | `1` per physical attempt | `$0.00` | None |
| `function_versions` | `"function"` | `$0.00000020` / req | `1` per physical page request | `$0.00` | None |
| `function_alias_set` | `"function"` | `$0.00000020` / req | `1` per physical attempt | `$0.00` | None |
| `function_alias_get` | `"function"` | `$0.00000020` / req | `1` per physical attempt | `$0.00` | None |
| `function_alias_delete` | `"function"` | `$0.00000020` / req | `1` per physical attempt | `$0.00` | None |
| `function_invoke` | `"function"` | `$0.0000000021` / unit | `1 + billed_ms * (memory_mb / 128)` per physical attempt | `$0.09` / GiB (`bytes_out + bytes_in`) | None (ordinary work) |

*Note on `function_invoke` billing units and line-item coherence:*
- Each `function_invoke` physical attempt consumes `1` base request unit plus `billed_ms * (memory_mb / 128)` compute units (1 compute unit = 1 ms at 128 MiB = $\frac{1}{8000}$ GB-second; at `$0.0000000021` per unit, 1 GB-second = $8000 \times \$0.0000000021 = \$0.0000168 \approx \$0.00001667$ AWS Lambda GB-s rate).
- Because `unit_price_usd` is uniform (`$0.0000000021`) across all units in the `function_invoke` line item, the Slice 3 invariant
  $$\text{estimated\_usd} = \text{billing\_units} \times \text{unit\_price\_usd} + \left(\frac{\text{bytes}}{2^{30}}\right) \times \text{byte\_price\_usd\_per\_gib}$$
  holds **exactly** for `rep.item("function_invoke")` across arbitrary mixes of memory sizes and execution durations!
- Furthermore, when a function invocation returns a function-level error (`result.is_error() == true`, e.g. `"Handled"`, `"Unhandled"`, or `"Timeout"`), the provider executed the function and billed for the wall time (`billed_ms >= 1`), so both `CostReport` and `MetricsReport` record the request, billing units, payload bytes, and latency.

#### 2. Pre-Attempt Worst-Case Admission (`ReserveBeforeAttempt`) & Post-Attempt Settlement (`SettleAttempt`)
To prevent an invocation with a large timeout and memory allocation from overspending `cost_cap_usd()` or the `$0.25` hard ceiling while running:
1. **Before dispatching `function_invoke`:** The host determines the worst-case compute duration and memory for the target function (`timeout_seconds * 1000` ms at `memory_mb` MiB; if the function's config is not yet cached in the local run journal, a 1-request metadata lookup is admitted via `RunSubOperation` first, or conservative ceiling `230,000 ms * (2048 / 128)` is used only when unknown). Using the known `(timeout_seconds, memory_mb)` of the target function/qualifier:
   $$\text{max\_units} = 1 + (\text{timeout\_seconds} \times 1000) \times \left(\frac{\text{memory\_mb}}{128}\right), \quad \text{max\_bytes} = \text{utf8\_len}(\text{payload\_json}) + 1048576$$
   The host reserves `max_units` and `max_bytes` via `ReserveBeforeAttempt` before sending the HTTP request. If this worst-case reservation exceeds the active work sub-cap (`cost_cap_usd()`) or operator total ceiling, `function_invoke` fails immediately pre-flight with `ErrorCode.COST_CAP_EXCEEDED` (`http_status() == 0`).
2. **Upon response completion:** The host settles the attempt via `SettleAttempt` using the actual `billed_ms` (`1 <= billed_ms <= timeout_seconds * 1000`) and actual wire payload bytes (`utf8_len(payload_json) + utf8_len(result.payload())`), returning the unused reservation headroom to the work budget.

---

### 4.7 Live-Mode Fail-Closed Safety (`14-live-safety.md`)

In accordance with [`14-live-safety.md`](file:///home/ubuntu/cloud/lmcloud/durable-memory/14-live-safety.md):
- The conformance runner `--live` profile (`tests/run-conformance.sh`) **excludes** `function` scenarios alongside `cost-perf` and `tables` until live-mode function role sandboxing, naming prefix translation, and capability certification are explicitly enabled per host.
- In `--live` mode on any host, `function_*` operations fail closed (`PERMISSION_DENIED`) unless:
  1. The function name carries the run's required live prefix or mapped physical prefix and is recorded in the local `hostkit/safety` journal with matching `(run_id, scope_prefix, create_token)`,
  2. An explicit, operator-supplied sandboxed execution role ARN / service account (`LMCLOUD_LIVE_FUNCTION_ROLE`) is configured (hosts NEVER auto-create IAM roles or policies in `--live` mode), and
  3. Pre-attempt worst-case cost reservation (`ReserveBeforeAttempt`) succeeds within the durable journal ceiling (`<= $0.25`).
