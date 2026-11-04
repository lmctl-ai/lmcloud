# 15 — Slice 6 (Function / Serverless Compute) Design & Cross-Cloud Mapping

## 1. Scope & Guiding Principles

Slice 6 (`function`) defines a portable, synchronous serverless function lifecycle and invocation contract across AWS, Azure, GCP, and OCI. A single `lmscript` / `lmcode` program can create, configure, update, publish immutable versions, manage aliases, list, delete, and synchronously invoke serverless functions with JSON payloads, bounded tail logs, structured error classification, environment variables, timeout/memory/concurrency controls, and per-invocation cost accounting without provider-specific branches.

### 1.1 Non-Goals (Out of Scope for Slice 6)
To guarantee four-cloud portability, zero-Docker local simulator execution, and bounded live-cloud blast radius, the following are **out of scope**:
- **Asynchronous / event-driven invocation (`Event` mode) and triggers** (SQS/PubSub/Storage/Stream event sources, dead-letter queues, destinations).
- **Streaming responses (`InvokeWithResponseStream`)** and raw HTTP path/header routing (all portable invocations use synchronous JSON `RequestResponse` payloads).
- **Weighted traffic-shifting aliases** (a Slice 6 alias points 1:1 to a single immutable published version).
- **Provisioned concurrency / always-warm billing plans** (which incur continuous idle hourly charges on live clouds; Slice 6 uses on-demand execution only).
- **Custom container images, layers, VPC networking, EFS mounts, and script-defined IAM roles** (in live mode, functions execute only under an operator-supplied, pre-provisioned least-privilege execution identity).

---

## 2. `lmcode` Schema Surface (`schema/lmcloud.dsl.json`)

### 2.1 Domain Types

#### `FunctionConfig`
Mutable builder and readback descriptor for a serverless function's configuration, code source, limits, environment variables, and version metadata. Constructed locally via `cloud.function_config(runtime, handler)` and returned by `cloud.function_get` and `cloud.function_update`.

| Method | Signature | Description |
|---|---|---|
| `name` | `() -> string` | Function name (`""` on a local unattached builder; populated on server-returned configs). |
| `exists` | `() -> bool` | `true` when returned by `function_get` / `function_update` for an existing function; `false` on a local builder or when `function_get` targets a missing function/qualifier. |
| `state` | `() -> string` | Normalized lifecycle state: `"active"` when ready on the provider, or `""` on a local builder / absent function. |
| `runtime` | `() -> string` | Portable runtime identifier (`"python3.12"` or `"nodejs20.x"`). |
| `set_runtime` | `(runtime: string) -> self` | Sets the runtime identifier; validates against the portable runtime allowlist pre-flight. |
| `handler` | `() -> string` | Entrypoint handler (`"<module>.<function>"`, e.g., `"index.handler"`). |
| `set_handler` | `(handler: string) -> self` | Sets the entrypoint handler; validates `<module>.<export>` syntax pre-flight. |
| `code_source` | `() -> string` | `"inline"`, `"object"`, or `""` (unset). Setting one source clears the other. |
| `inline_code` | `() -> string` | Inline UTF-8 source code when `code_source() == "inline"` (preserved in catalog readback so a server-returned config can be mutated and passed to `function_update`), else `""`. |
| `set_inline_code` | `(code: string) -> self` | Sets inline source code (`1..65536` UTF-8 bytes), sets `code_source()` to `"inline"`, clears `package_bucket`/`package_key`, and recomputes the canonical 64-hex `code_sha256()`. |
| `package_bucket` | `() -> string` | Original source object-storage bucket when `code_source() == "object"`, else `""`. |
| `package_key` | `() -> string` | Original source object-storage key when `code_source() == "object"`, else `""`. |
| `set_package_object` | `(bucket: string, key: string) -> self` | Configures deployment from an object-storage package in `(bucket, key)`, sets `code_source()` to `"object"`, clears `inline_code`, and marks the builder to stage a fresh bundle from `(bucket, key)` on the next `function_create` / `function_update`. |
| `code_sha256` | `() -> string` | **64-character lowercase hexadecimal** (`^[0-9a-f]{64}$`) SHA-256 digest of the canonical deployment archive (`""` only on an un-staged local `"object"` builder before `function_create`/`function_update`). |
| `timeout_seconds` | `() -> int` | Execution timeout in seconds (default `3`, portable range `1..230`). |
| `set_timeout_seconds` | `(seconds: int) -> self` | Sets execution timeout in seconds (`1..230`). |
| `memory_mb` | `() -> int` | Logical allocated memory & billing tier in MiB (default `128`, portable discrete set `{128, 256, 512, 1024, 2048}`). |
| `set_memory_mb` | `(mb: int) -> self` | Sets logical allocated memory in MiB (`{128, 256, 512, 1024, 2048}`). |
| `concurrency` | `() -> int` | Max concurrent executions: `0` = unreserved/default scaling, `1..100` = hard concurrent execution cap across the function, `-1` = throttle all invocations. |
| `set_concurrency` | `(max_concurrent: int) -> self` | Sets concurrency limit (`-1`, `0`, or `1..100`). |
| `env` | `(key: string) -> string` | Returns environment variable value for `key` (or `""` and sets `INVALID_ARGUMENT` with `http_status() == 0` if `key` is absent). |
| `has_env` | `(key: string) -> bool` | `true` if environment variable `key` is present. |
| `set_env` | `(key: string, value: string) -> self` | Sets environment variable `key = value`; validates key grammar, reserved prefixes, 64-var count cap, and aggregate 4096-byte user env budget pre-flight. |
| `remove_env` | `(key: string) -> self` | Removes environment variable `key` (no-op if absent). |
| `env_names` | `() -> StrList` | Sorted (`ASCII` ascending) list of configured user environment variable names. |
| `env_len` | `() -> int` | Count of configured user environment variables (`0..64`). |
| `version` | `() -> string` | Version identifier: `"$LATEST"` for the mutable head, or a positive decimal version string (`"1"`, `"2"`, ...) for a published immutable snapshot. |
| `revision_id` | `() -> string` | Non-empty 128-bit lowercase hex revision token rotated on every committed create, update, version-publish, or concurrency mutation. Used for optimistic concurrency in `function_update` and `function_publish_version`. |

#### `FunctionInvokeResult`
Result of a synchronous `cloud.function_invoke` call.

| Method | Signature | Description |
|---|---|---|
| `status_code` | `() -> int` | Synchronous execution status (`200` for completed execution, including handled/unhandled/timeout function errors; `0` on transport/control-plane error). |
| `payload` | `() -> string` | UTF-8 JSON response body returned by the function (`<= 1 MiB`), or structured JSON error object when `is_error() == true`. |
| `logs` | `() -> string` | Captured UTF-8 execution log tail (`<= 4096` bytes). |
| `function_error` | `() -> string` | `""` on normal return; `"Handled"`, `"Unhandled"`, or `"Timeout"` when the function execution failed inside the runtime. |
| `is_error` | `() -> bool` | `true` iff `str_len(function_error()) > 0`. |
| `executed_version` | `() -> string` | The immutable version (`"1"`, `"2"`, ...) or `"$LATEST"` that actually executed. |
| `duration_ms` | `() -> float` | Measured execution wall time in milliseconds (`>= 0.0`). |
| `billed_ms` | `() -> int` | Authoritative billed duration in milliseconds (`1 <= billed_ms <= timeout_seconds * 1000`). |
| `memory_mb` | `() -> int` | Configured logical memory size (in MiB) of the executed version. |

### 2.2 `Cloud` Methods

| Method | Signature(s) | Return Type | Semantics |
|---|---|---|---|
| `function_config` | `(runtime: string, handler: string)` | `FunctionConfig` | Creates a local `FunctionConfig` builder initialized with `runtime`, `handler`, `timeout_seconds = 3`, `memory_mb = 128`, `concurrency = 0`, and empty `env`. Validates `runtime` and `handler` pre-flight. |
| `function_create` | `(name: string, config: FunctionConfig)` | `bool` | Creates function `name`, stages its content-addressed package bundle, and waits until `"active"`. Returns `true` if newly created. If `name` already exists in the current authorized scope: returns `false` (`ErrorCode.OK`) iff the canonical configuration fingerprint (`runtime`, `handler`, `code_sha256`, `timeout_seconds`, `memory_mb`, `concurrency`, `env`) matches identically; fails with `ErrorCode.CONFLICT` if any configuration field differs. In `--live` mode, an existing resource with foreign or missing ownership metadata fails closed with `ErrorCode.PERMISSION_DENIED`. |
| `function_update` | `(name: string, config: FunctionConfig)`<br>`(name: string, config: FunctionConfig, expect_revision: string)` | `FunctionConfig` | Acquires the catalog writer lease for `name`, updates `$LATEST` code, configuration, env vars, and concurrency, waits until `"active"`, rotates `revision_id()`, and returns the updated `FunctionConfig`. If `config` is a mutated readback descriptor whose code source was not re-set, retains the existing content-addressed bundle (`code_sha256()`) without re-reading the external source bucket. The 3-arg overload requires `expect_revision` to be non-empty (`INVALID_ARGUMENT` if `""`) and equal to current `revision_id()` (`PRECONDITION_FAILED` on mismatch). Missing function -> `NOT_FOUND`. |
| `function_delete` | `(name: string)` | `bool` | Transitions `name` to `"deleting"` in `lmcloudfnmeta`, deletes all aliases, published versions, owned staged package bundles, the native function, and finally the catalog tombstone. Returns `true` if deleted, `false` (`ErrorCode.OK`) if already absent. Draws from cleanup reserve (`isCleanup = true`). |
| `function_exists` | `(name: string)` | `bool` | Returns `true` if `name` exists and is `"active"`, `false` if absent or `"deleting"` (`ErrorCode.OK`). Never masks `UNAUTHENTICATED` or `PERMISSION_DENIED`. |
| `function_get` | `(name: string)`<br>`(name: string, qualifier: string)` | `FunctionConfig` | Strongly consistent readback for `$LATEST` (1-arg or `qualifier == "$LATEST"`), a published version (`"1"`, `"2"`, ...), or an alias (`"prod"`). Returns a `FunctionConfig` with preserved `code_sha256()` (and `inline_code()` or `package_bucket()`/`package_key()`) suitable for passing back to `function_update`. If the function or qualifier is absent, returns `exists() == false` with `ErrorCode.OK`. |
| `function_list` | `()` | `StrList` | Returns all `"active"` function names in ascending ASCII lexicographical order (`ListAll` across pages, excluding reserved catalog/staging resources). |
| `function_publish_version` | `(name: string)`<br>`(name: string, expect_revision: string)` | `string` | Always allocates the next monotonic positive integer version (`"1"`, `"2"`, ...; up to the portable limit of 16 versions per function), locks the per-version cleanup reserve, deploys/pins an immutable versioned deployment target backed by the retained content-addressed bundle, rotates `$LATEST`'s `revision_id()`, and returns the new version string. 2-arg overload enforces `expect_revision` (`PRECONDITION_FAILED` on mismatch, `INVALID_ARGUMENT` if `""`). Missing function -> `NOT_FOUND`. |
| `function_versions` | `(name: string)` | `StrList` | Lists all published immutable version strings (excluding `"$LATEST"`) for `name` in ascending numeric order (`"1"`, `"2"`, ..., `"10"`). Missing function -> `NOT_FOUND`. |
| `function_alias_set` | `(name: string, alias: string, version: string)` | `void` | Creates or atomically retargets alias `alias` on `name` to published `version` (locking the per-alias cleanup reserve on new alias creation; max 16 aliases per function). Fails with `NOT_FOUND` if `name` or published `version` does not exist. |
| `function_alias_get` | `(name: string, alias: string)` | `string` | Returns the target `version` string for `alias`, or `""` with `ErrorCode.OK` if `name` exists but `alias` is absent. Missing function -> `NOT_FOUND`. |
| `function_alias_delete` | `(name: string, alias: string)` | `bool` | Deletes `alias` on `name` and releases its per-alias cleanup reserve. Returns `true` if deleted, `false` (`ErrorCode.OK`) if `alias` was already absent. Missing function -> `NOT_FOUND`. |
| `function_invoke` | `(name: string, payload_json: string)`<br>`(name: string, qualifier: string, payload_json: string)` | `FunctionInvokeResult` | Resolves `qualifier` (`"$LATEST"` default, version number, or alias) to its pinned deployment revision and `(timeout_seconds, memory_mb)`, reserves worst-case invocation cost, acquires a concurrency slot when `concurrency > 0`, and synchronously invokes the target revision with `payload_json`. Missing function/version/alias -> `NOT_FOUND`. Throttled (`concurrency == -1` or all slots busy / HTTP `429`) -> `PRECONDITION_FAILED` (`http_status() == 429`). |

---

## 3. Native Cloud Wire Mappings vs. Simulator Transport Mappings

To avoid conflating real cloud wire protocols with local single-port simulator transport conveniences, Slice 6 explicitly separates **Native Cloud Wire Mapping** from **Simulator Transport Mapping** for every provider.

### 3.1 Native Cloud Wire Mapping (Live Clouds)

| Aspect | AWS Lambda (Native) | Azure Functions (Native) | GCP Cloud Functions Gen2 (Native) | OCI Functions (Native) |
|---|---|---|---|---|
| **Hosting Plan** | AWS Lambda on-demand (`x86_64`) | Azure Functions Linux Flex Consumption (or Linux Consumption) | Cloud Functions v2 (Gen2, Cloud Run-backed) | OCI Functions on-demand (`20181201`) |
| **Authoritative Catalog & Staging** | DynamoDB catalog table `lmcloudfnmeta` + S3 bucket `lmcloudfn-pkgs-{acct}-{region}` for content-addressed bundles `/{name}/{incarnation}/{code_sha256}.zip` | Azure Table `lmcloudfnmeta` + Blob container `lmcloudfn-pkgs` for content-addressed bundles `/{name}/{incarnation}/{code_sha256}.zip` | Firestore collection `lmcloudfnmeta` + GCS bucket `lmcloudfn-pkgs-{project}` for content-addressed bundles `/{name}/{incarnation}/{code_sha256}.zip` | OCI Object Storage conditional-ETag catalog bucket `lmcloudfnmeta` (or NoSQL table when O1 lands) + bucket `lmcloudfn-pkgs` for bundles |
| **Control-Plane Create / Update** | `POST /2015-03-31/functions`, `PUT .../functions/{name}/code` (from staged S3 objectVersion), `PUT .../functions/{name}/configuration`, `PUT /2017-10-31/functions/{name}/concurrency` | ARM `PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app}` + Kudu ZipDeploy `POST https://{app}.scm.azurewebsites.net/api/zipdeploy` deploying `{name}__rev_{rev}` route | `POST /v2/projects/{p}/locations/{l}/functions?functionId={name}` and `PATCH /v2/projects/{p}/locations/{l}/functions/{name}?updateMask=...` pointing `storageSource` at staged GCS object + generation | `POST /20181201/applications` (run-scoped app) + `POST /20181201/functions` / `PUT /20181201/functions/{id}` deploying revision artifact |
| **Immutable Version Deployment (`"1"`, `"2"`)** | Native `POST /2015-03-31/functions/{name}/versions` (`PublishVersion`) returning immutable ARN `...:{name}:{ver}` | Deploys immutable versioned function route `{name}__v{ver}` inside the Function App bound to frozen blob `/{code_sha256}.zip` and config in `lmcloudfnmeta` | Pins the immutable Cloud Run `Revision` (`serviceConfig.revision`) created at publish time (or dedicated revision service `{name}--v{ver}`) backed by immutable GCS object generation | Creates a dedicated immutable OCI Function resource `{name}--v{ver}` (`POST /20181201/functions`) whose immutable `functionId` OCID is stored in `lmcloudfnmeta.versions[ver]` |
| **Physical Memory Mapping** | Exact `{128, 256, 512, 1024, 2048}` MB (`MemorySize`) | Logical limit `{128..2048}` MiB enforced in wrapper (`RLIMIT_AS` / `--max-old-space-size`); physical Flex SKU ceil-mapped (`{128,256,512}->512 MB`, `{1024,2048}->2048 MB`, billed at physical SKU in live price table) | Exact `{128, 256, 512, 1024, 2048}` MiB (`serviceConfig.availableMemory` = `"128Mi"`..`"2048Mi"`) | Exact `{128, 256, 512, 1024, 2048}` MB (`memoryInMBs`) |
| **Native Invocation Wire Protocol** | `POST /2015-03-31/functions/{name}/invocations?Qualifier={ver}` (`X-Amz-Invocation-Type: RequestResponse`, `X-Amz-Log-Type: Tail`), SigV4 `lambda:InvokeFunction` | `POST https://{app}.azurewebsites.net/api/{name}__v{ver}` (or `{name}__rev_{rev}`) with Entra bearer token (`Microsoft.Web/sites/functions/invoke/action`) or host key | **No `:call` method in v2!** Invokes the deployed Cloud Run HTTPS endpoint `POST <serviceConfig.uri>` with an OIDC **ID token** (`Authorization: Bearer <id_token>`, `aud = serviceConfig.uri`), authorized by Cloud Run `run.routes.invoke` (`roles/run.invoker`) | `POST https://<invoke-endpoint>/20181201/functions/{target_ocid}/actions/invoke` (`fn-invoke-type: sync`), RSA-signed with `fn-invocation` (`FUNCTION_INVOKE`) permission |
| **Entrypoint Handler Shim** | Native `(event, context)` (optional log/error canonicalizer shim) | **Required** `__lmcloud_azure_entry` HTTP-trigger shim (`azure.functions.HttpRequest` -> `handler(event, context)` -> structured JSON envelope `{payload, logs_b64, function_error, duration_ms}`) | **Required** `__lmcloud_gcp_entry` Functions-Framework HTTP shim (HTTP POST JSON body -> `handler(event, context)` -> structured JSON envelope `{payload, logs_b64, function_error, duration_ms}`) | **Required** `__lmcloud_oci_entry` FDK HTTP/stdin shim (request body -> `handler(event, context)` -> structured JSON envelope + `opc-fn-*` headers) |

#### Native GCP v2 Invocation Endpoint Derivation & `httpguard` Rule
Because native GCP Cloud Functions v2 returns a data-plane `serviceConfig.uri` (`https://<service>-<hash>-<region>.a.run.app`) on a different hostname from the control-plane `cloudfunctions.googleapis.com` endpoint:
- In `--live` mode, `httpguard` permits an invocation `POST` to a `serviceConfig.uri` **if and only if**:
  1. The URI scheme is `https`, the host matches `^[a-z0-9-]+-[a-z0-9]+-[a-z0-9-]+\.a\.run\.app$`, and the exact URI was returned by an authenticated `getFunction` call for an owned function in the current run journal,
  2. Cross-origin HTTP redirects (`3xx`) on invocation remain strictly disabled (`ErrRedirectBlocked`), and
  3. The request carries an OIDC ID token minted for the target `serviceConfig.uri` audience (`aud`).
- In simulator mode (`gcpsim`), `serviceConfig.uri` points back to the simulator's own loopback listener (`http://127.0.0.1:4588/__run/projects/{p}/locations/{l}/services/{name}/revisions/{rev}:invoke`), so all traffic stays on the single configured loopback origin.

### 3.2 Simulator Transport Mapping & Required Simulator Epics (Zero-Docker In-Process Execution)

All four local simulators execute on a single loopback HTTP listener per provider (`:4566`, `:4577`, `:4588`, `:4599`) with **zero Docker daemon dependency**:

1. **`awssim` (`:4566`, `floci` `services/lambda` + `AuthFilter.java`):**
   - **Wire fidelity:** Matches native AWS Lambda REST routes (`/2015-03-31/functions*`, `/2017-10-31/functions*`, `/2019-09-30/functions*`) and DynamoDB/S3 catalog/staging routes directly.
   - **Enhancement A-FN1 (In-process sandbox runner):** When Docker is absent or `FLOCI_LAMBDA_INPROCESS=true`, `LambdaExecutorService` extracts the deployment ZIP under the §4.2.1 archive guards and executes the `"python3.12"` or `"nodejs20.x"` handler in an isolated, credential-scrubbed subprocess (`env -i`, process-group `SIGKILL` on timeout, `RLIMIT_AS` memory limit), returning payload, `X-Amz-Log-Result` (base64 tail `<= 4096` UTF-8 bytes), `X-Amz-Function-Error` (`Handled` | `Unhandled` | `Timeout`), and `X-Amz-Executed-Version`.
   - **Enhancement A-FN2 (`AuthFilter.java` Lambda SigV4 routing):** Extend [`AuthFilter.java`](file:///home/ubuntu/cloud/awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java) to map SigV4 service `"lambda"` routes to `lambda:CreateFunction`, `lambda:GetFunction`, `lambda:GetFunctionConfiguration`, `lambda:ListFunctions`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `lambda:DeleteFunction`, `lambda:InvokeFunction`, `lambda:PublishVersion`, `lambda:ListVersionsByFunction`, `lambda:CreateAlias`, `lambda:UpdateAlias`, `lambda:GetAlias`, `lambda:DeleteAlias`, `lambda:ListAliases`, `lambda:PutFunctionConcurrency`, `lambda:GetFunctionConcurrency`, `lambda:DeleteFunctionConcurrency`, `lambda:TagResource`, and `lambda:ListTags`.
   - **Enhancement A-FN3 (`ListFunctions` pagination):** Honor `Marker` and `MaxItems` on `GET /2015-03-31/functions` in deterministic sorted order.

2. **`azuresim` (`:4577`, `floci-az` `services/functions` + `StorageAuth.java`):**
   - **Simulator transport consolidation (explicitly labeled sim-only routing):** To avoid requiring separate `management.azure.com`, `{app}.scm.azurewebsites.net`, and `{app}.azurewebsites.net` virtual hosts on local loopback, `azuresim` consolidates control plane and HTTP trigger invocation onto `/{account}-functions/admin/apps/{app}/functions/{func}` and `POST /{account}-functions/api/{app}/{func}`. Regardless of transport path, the deployed bundle inside `azuresim` uses the **same `__lmcloud_azure_entry` HTTP trigger wrapper** as native Azure Functions.
   - **Enhancement AZ-FN1 (In-process execution & versioned function routes):** Extend `FunctionsServiceHandler` / `FunctionModels` to persist `runtime`, `handler`, `timeoutSeconds`, `memoryMb`, `concurrency`, `environment`, `codeSha256`, `version`, and `revisionId`, load staged ZIP bundles from `BlobService`, and execute the wrapped handler in-process under §4.2.1 sandbox limits instead of returning `{"mocked":true}`.
   - **Enhancement AZ-FN2 (`StorageAuth.java` enforce routing):** Authenticate and authorize `/{account}-functions/admin/...` (`Microsoft.Web/sites/functions/read|write|delete`) and `/{account}-functions/api/...` (`Microsoft.Web/sites/functions/invoke/action`) in [`StorageAuth.java`](file:///home/ubuntu/cloud/azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java) (and ensure `/{account}-table/` is authorized for the `lmcloudfnmeta` catalog).

3. **`gcpsim` (`:4588`, `floci-gcp` `services/cloudfunctions` + `BearerGuard.java`):**
   - **Wire fidelity & local Cloud Run URI emulation:** Control plane uses native v2 routes (`POST/GET/PATCH/DELETE /v2/projects/{p}/locations/{l}/functions*`). Each created/updated function sets `serviceConfig.uri` to the simulator's local Cloud Run loopback route `http://<host>:<port>/__run/projects/{p}/locations/{l}/services/{name}/revisions/{rev}:invoke` (explicitly labeled as `gcpsim`'s loopback representation of the Cloud Run `*.a.run.app` service URL).
   - **Enhancement G-FN1 (`PATCH` update & Cloud Run revision HTTP invoke):** Add `PATCH /v2/projects/{p}/locations/{l}/functions/{name}` (allocating a new immutable `serviceConfig.revision` and `serviceConfig.uri`) and the Cloud Run revision HTTP invocation handler at `/__run/projects/{p}/locations/{l}/services/{name}/revisions/{rev}:invoke` executing the `__lmcloud_gcp_entry`-wrapped bundle under §4.2.1 sandbox limits.
   - **Enhancement G-FN2 (`BearerGuard.java` v2 control-plane + `run.routes.invoke` data-plane IAM):** Extend [`BearerGuard.java`](file:///home/ubuntu/cloud/gcpsim/src/main/java/ai/lmctl/gcpsim/BearerGuard.java) to authorize:
     - `/v2/projects/{p}/locations/{l}/functions*` with `cloudfunctions.functions.{create,get,list,update,delete}` on `projects/{p}/locations/{l}/functions/{name}`, and
     - `/__run/projects/{p}/locations/{l}/services/{name}/revisions/{rev}:invoke` with `run.routes.invoke` (and valid bearer/ID token for that target service).

4. **`ocisim` (`:4599`, `floci-oci` `services/functions` + `OciPolicyEngine.java`):**
   - **Wire fidelity:** Uses native OCI Functions `20181201` routes (`/20181201/applications`, `/20181201/functions`, and `POST /20181201/functions/{id}/actions/invoke`), which are already mapped in [`OciPolicyEngine.java:757-789`](file:///home/ubuntu/cloud/ocisim/src/main/java/ai/lmctl/ocisim/OciPolicyEngine.java#L757-L789) (`fn-app`, `fn-function`, `fn-invocation`).
   - **Enhancement O-FN1 (In-process handler execution for archive/staged bundles):** Extend `floci-oci` Functions mock mode so `POST /20181201/functions/{id}/actions/invoke` loads the function's staged archive from Object Storage (`lmcloudfn-pkgs`), executes the `__lmcloud_oci_entry`-wrapped handler under §4.2.1 sandbox limits, and returns the structured response body and `opc-fn-*` execution metadata.

---

## 4. Detailed Portable Semantics, Fencing, and Safety Invariants

### 4.1 Naming, Runtime, Handler, Quotas, and Pre-Flight Validation Guards

Every rule below is enforced **pre-flight** in `cloudhost` / `hostkit` before any network call or cost reservation. Any violation sets `last_error()` to `ErrorCode.INVALID_ARGUMENT` with `http_status() == 0` and aborts (when `abort_on_error() == true`).

1. **Function Name (`name`):**
   - Regex: `^[a-z][a-z0-9]{2,31}$` (3 to 32 lowercase ASCII alphanumeric characters, starting with a lowercase letter).
   - **Reserved names rejected pre-flight (`INVALID_ARGUMENT`, `http_status() == 0`):** `"lmcloudmeta"`, `"lmcloudfnmeta"`, `"tables"`, `"functions"`, `"default"`, `"system"`.
2. **Runtime (`runtime`):**
   - Portable allowlist: `"python3.12"` and `"nodejs20.x"`. Any other value fails pre-flight with `INVALID_ARGUMENT`.
3. **Handler (`handler`):**
   - Regex: `^[A-Za-z_][A-Za-z0-9_]{0,31}\.[A-Za-z_][A-Za-z0-9_]{0,31}$` (total length `3..65` ASCII chars, `<module>.<export>`).
4. **Code Source & Immutable Content-Addressed Packaging:**
   - **Inline code (`set_inline_code(code)`):**
     - `code` must be valid UTF-8, contain no NUL (`\x00`), and have length **`1 <= utf8_len(code) <= 65536` bytes (64 KiB)**. (`65536` bytes is accepted; `65537` bytes fails pre-flight with `INVALID_ARGUMENT` and `http_status() == 0`.)
     - `set_inline_code` immediately constructs the canonical deterministic ZIP archive (user file `<module>.py` or `<module>.js` + provider entrypoint shim `__lmcloud_<provider>_entry`, fixed ZIP timestamp `1980-01-01 00:00:00 UTC`, mode `0644`) and sets `code_sha256()` to its **64-character lowercase hex SHA-256 digest**.
   - **Object-storage package (`set_package_object(bucket, key)`):**
     - `bucket` must satisfy the Slice 1 bucket-name grammar and `key` must satisfy the Slice 1 object-key grammar (`1..1024` UTF-8 bytes, no NUL).
     - On `function_create` or `function_update` (when a new object source was configured via `set_package_object`), the host downloads `(bucket, key)` via `hostkit.RunSubOperation(ctx, "storage", "object_get", ...)` using an **`N+1` sentinel reader of `16,777,217` bytes (`16 MiB + 1` byte)** and records the object's version/ETag. Missing bucket/object fails with `ErrorCode.NOT_FOUND`; `>= 16,777,217` bytes or invalid archive/script fails with `ErrorCode.INVALID_ARGUMENT`.
     - The host validates the package under §4.2.1, computes its 64-char lowercase hex `code_sha256()`, and uploads an **immutable, run-owned content-addressed copy** to the reserved staging store `lmcloudfn-pkgs/{name}/{incarnation_id}/{code_sha256}.zip` (metered via `RunSubOperation`).
   - **Readback-as-Builder Preservation:**
     - `function_get` returns a `FunctionConfig` populated with the committed `code_sha256()`, `code_source()`, `inline_code()` (for `"inline"`), and `package_bucket()`/`package_key()` (for `"object"`).
     - Passing a mutated `FunctionConfig` from `function_get` to `function_update` (without calling `set_inline_code` or `set_package_object`) reuses the retained immutable staged bundle identified by `code_sha256()` — it **never** re-reads the user's mutable `(bucket, key)` object and **never** fails even if the user later overwrote or deleted `(bucket, key)`!
5. **Timeout (`timeout_seconds`) and Memory (`memory_mb`):**
   - `timeout_seconds`: default `3`, allowed range **`1..230` seconds** inclusive.
   - `memory_mb`: default `128`, allowed discrete values **`{128, 256, 512, 1024, 2048}` MiB**.
6. **Concurrency (`concurrency`):**
   - Default `0` (unreserved), allowed range **`-1` (throttle all), `0`, or `1..100`**.
7. **Environment Variables (`env`):**
   - Key regex: `^[A-Za-z_][A-Za-z0-9_]{0,63}$`.
   - **Reserved key prefixes / names rejected pre-flight (`INVALID_ARGUMENT`, `http_status() == 0`):** leading `"_"`, `"AWS_*"`, `"LAMBDA_*"`, `"AZURE_*"`, `"FUNCTIONS_*"`, `"WEBSITE_*"`, `"GOOGLE_*"`, `"K_SERVICE"`, `"K_REVISION"`, `"K_CONFIGURATION"`, `"PORT"`, `"OCI_*"`, `"FN_*"`, `"LMCLOUD_*"`.
   - Value: valid UTF-8 without NUL (`\x00`), `0..4096` UTF-8 bytes.
   - **User environment quota:** at most **`64` user variables** (`64` accepted, `65`th rejected pre-flight) and $\sum (\text{utf8\_len}(k) + \text{utf8\_len}(v)) \le 4096$ UTF-8 bytes (`4096` accepted, `4097` rejected pre-flight). Internal host/wrapper variables are excluded from the user quota.
8. **Versions, Aliases, and Child Quotas:**
   - Version strings: positive decimal integers (`^[1-9][0-9]{0,8}$`). At most **16 published versions** per function (`1..16`; a 17th `function_publish_version` call fails with `ErrorCode.PRECONDITION_FAILED`).
   - Alias names: `^[a-z][a-z0-9_]{1,31}$` (2..32 chars, starting with `[a-z]`). Reserved alias names `"latest"`, `"default"`, `"system"` are rejected pre-flight with `INVALID_ARGUMENT`. At most **16 aliases** per function (`0..16`; creating a 17th distinct alias fails with `ErrorCode.PRECONDITION_FAILED`).
   - `expect_revision` on 3-arg `function_update` and 2-arg `function_publish_version`: must be non-empty (`""` fails pre-flight with `INVALID_ARGUMENT` and `http_status() == 0`).
9. **Synchronous Invocation Payload & Output Bounds:**
   - `payload_json`: `1..1048576` UTF-8 bytes (`1 MiB`), valid RFC 8259 JSON, no NUL bytes (`""`, non-JSON, or `>= 1,048,577` bytes fails pre-flight with `INVALID_ARGUMENT` and `http_status() == 0`).
   - **Oversize handler return value (`> 1 MiB`):** The wrapper/adapter reads the serialized handler response through an **`N+1` sentinel reader of `1,048,577` bytes (`1 MiB + 1` byte)**. If the handler output reaches `1,048,577` bytes, execution completes with `last_error().code() == ErrorCode.OK`, `status_code() == 200`, `is_error() == true`, `function_error() == "Unhandled"`, and `payload()` set to `{"errorType":"ResponseSizeExceeded","errorMessage":"function response payload exceeded 1048576 bytes"}`.
   - **Outer HTTP wire envelope bound:** The raw HTTP response body from the provider/simulator is bounded by an outer `N+1` reader of **`2,097,153` bytes (`2 MiB + 1` byte)**; exceeding the outer wire cap fails closed with `ErrorCode.INTERNAL`.

---

### 4.2 Portable Inline Handler Contract, Sandbox Isolation, and Archive Safety

#### 4.2.1 Package Archive Safety (Zip-Bomb & Path Traversal Defense)
Before any `"object"` package archive is staged or extracted:
1. **Compressed size limit:** `<= 16 MiB` (`16,777,216` bytes), verified via `io.LimitReader(r, 16*1024*1024 + 1)`.
2. **Uncompressed cumulative extracted size limit:** **`<= 64 MiB` (`67,108,864` bytes)** across all entries, enforced via per-entry and cumulative `io.LimitReader(64*1024*1024 + 1)`.
3. **Entry count limit:** **`<= 256` entries** per ZIP archive.
4. **Entry path & mode hygiene:** Every ZIP entry is rejected (`INVALID_ARGUMENT`) if its path is empty, starts with `/` or `\`, contains `\` or `:` or NUL, contains any `..` segment, normalizes outside the extraction root, collides case-insensitively with a prior entry, is encrypted, or carries non-regular file mode bits (symlinks, hardlinks, FIFOs, sockets, devices, setuid/setgid are strictly forbidden).

#### 4.2.2 Subprocess Sandbox Isolation, Resource Limits, and Credential Scrubbing
When any simulator (`awssim`, `azuresim`, `gcpsim`, `ocisim`) or `fakeadapter` executes a function handler in-process:
1. **Explicitly Cleared Environment (`env -i`):** The child process starts with an empty environment populated **only** with safe runtime variables (`PATH=/usr/bin:/bin`, `HOME=<ephemeral-dir>`, `TMPDIR=<ephemeral-dir>`, `LANG=C.UTF-8`, `PYTHONDONTWRITEBYTECODE=1`, `NODE_OPTIONS=--max-old-space-size=<memory_mb>`) plus the function's configured user `env` map. Ambient host/CI/simulator secrets (`AWS_SECRET_ACCESS_KEY`, `LMAWS_SIM_*`, `LMAZURE_SIM_*`, `LMGCP_SIM_*`, `LMOCI_SIM_*`, `GITHUB_TOKEN`, etc.) are **never** inherited.
2. **Ephemeral Working Directory:** Each invocation extracts/mounts the immutable bundle into a fresh `0700` temporary directory (`mkdtemp`) that is recursively removed upon invocation completion.
3. **Process-Group Enforcement & Memory/FD/PID Limits:**
   - The subprocess launches in a dedicated OS process group (`Setpgid: true` / `start_new_session=True`) with virtual/heap memory capped at `memory_mb` MiB (`RLIMIT_AS` / `--max-old-space-size`), `RLIMIT_NOFILE = 64`, and `RLIMIT_NPROC = 32`.
   - If the process exceeds `memory_mb` (`MemoryError` / `ERR_WORKER_OUT_OF_MEMORY` / `SIGKILL`/`SIGABRT`), the wrapper returns `status_code() == 200`, `is_error() == true`, `function_error() == "Unhandled"`.
   - If execution exceeds `timeout_seconds` or the parent context is cancelled, the supervisor sends `SIGKILL` to the **entire process group** (`kill(-pgid, SIGKILL)`) and waits for process-group termination before returning (`function_error() == "Timeout"`, `billed_ms == timeout_seconds * 1000`).
4. **Bounded Live Output Drain:** `stdout`/`stderr` are drained concurrently through a ring buffer that caps total captured output at `64 KiB` (discarding any further output to `/dev/null` so noisy loops cannot block pipes or exhaust memory) and retains the final **`4,096` UTF-8-safe bytes** (never splitting a multi-byte UTF-8 rune at the truncation boundary) for `result.logs()`.
5. **Sensitive Environment Redaction in Host Diagnostics:** While `FunctionConfig.env(k)` and user handler payloads intentionally read user env vars, `cloudhost` registers non-empty user env values with `ErrorState.AddRedaction` so that `CloudError.message()`, `provider_code()`, abort frames, and host journals never leak user environment variable values.

---

### 4.3 Authoritative Catalog (`lmcloudfnmeta`), Writer Lease Fencing, and Recovery

To prevent race conditions across multi-step create/update/publish/delete sequences and concurrent child processes, **all four providers** coordinate function lifecycle state through the authoritative catalog `lmcloudfnmeta` (and local `hostkit/safety` journal):

1. **Catalog Record Schema (`lmcloudfnmeta` keyed by `name`):**
   - `state`: `"creating"` | `"active"` | `"mutating"` | `"deleting"`
   - `incarnation_id`: 128-bit random hex token generated once per `function_create`
   - `revision_id`: 128-bit random hex token rotated on every committed mutation
   - `op_gen`: monotonic integer incremented on every conditional catalog write
   - `lease_owner`, `lease_until_unix_ms`: exclusive writer lease (`30 s` TTL)
   - `run_id`, `scope_prefix`, `create_token`: immutable ownership triad linked to the local `hostkit/safety` journal
   - `latest`: committed `FunctionSnapshot` (`runtime`, `handler`, `code_source`, `inline_code`, `package_bucket`, `package_key`, `code_sha256`, `native_rev_id`, `timeout_seconds`, `memory_mb`, `concurrency`, `env`)
   - `versions`: map of `"1".."16"` -> immutable `FunctionSnapshot` (including `native_version_id` / `serviceConfig.uri` / OCI `functionId`)
   - `aliases`: map of `alias_name` -> `version_string`
2. **Create Intent & Ambiguous-Create Recovery:**
   - Before any network call in `function_create(name, cfg)`, the host writes and fsyncs a `PendingCreate` entry in the local `hostkit/safety` journal (`run_id`, `scope_prefix`, `create_token`, `incarnation_id`) and locks the base function cleanup reserve (`$0.00000500`).
   - Next, the adapter performs a conditional create-if-absent (`PutIfAbsent`) in `lmcloudfnmeta` with `state = "creating"`. If a record already exists:
     - In `--live` mode, if `(run_id, scope_prefix, create_token)` does not match the current run, fail closed with `ErrorCode.PERMISSION_DENIED`.
     - If `state == "active"` and the canonical config fingerprint matches identically, return `false` (`ErrorCode.OK`); if any config field differs, fail with `ErrorCode.CONFLICT`.
     - If `state == "creating"` from an interrupted prior attempt with the **same** `create_token`, resume idempotently; otherwise fail with `ErrorCode.CONFLICT`.
   - Once the staged bundle and native function are created and `"active"`, the adapter conditionally transitions `lmcloudfnmeta` from `("creating", op_gen)` to `("active", op_gen + 1, initial_revision_id)` and commits the journal entry.
3. **Serialized Multi-Step Update, Publish, and Alias Fencing:**
   - Every `function_update`, `function_publish_version`, `function_alias_set`, or `function_alias_delete` first performs a conditional catalog write transitioning `state` from `"active"` to `"mutating"` (verifying `revision_id == expect_revision` when supplied, increment `op_gen`, set `lease_owner`).
   - If `revision_id != expect_revision`, fail immediately with `ErrorCode.PRECONDITION_FAILED` before any native code/config call.
   - If another writer holds `"mutating"`, fail with `ErrorCode.CONFLICT`; if `"deleting"` or absent, fail with `ErrorCode.NOT_FOUND`.
   - All staged objects and native revisions created under this mutation are tagged/named with `(incarnation_id, op_gen)` so a stale writer whose lease expired can never overwrite a newer mutation or a recreated incarnation.
   - When all native calls succeed, the writer conditionally transitions `lmcloudfnmeta` from `("mutating", op_gen)` to `("active", op_gen + 1, new_revision_id)`. If a multi-step update fails partway through, recovery re-applies the last committed `latest` snapshot from `lmcloudfnmeta` before clearing `"mutating"`.
4. **Fenced Deletion (`function_delete` & `Sweep`):**
   - Conditionally transitions `lmcloudfnmeta` to `state = "deleting"` (bumping `op_gen` and `revision_id`). Once `"deleting"`, all `function_exists`, `function_get`, `function_list`, `function_update`, `function_publish_version`, `function_alias_*`, and `function_invoke` calls treat `name` as absent (`false` / `NOT_FOUND`).
   - Deletes all aliases, published version deployments, staged content-addressed bundles under `lmcloudfn-pkgs/{name}/{incarnation_id}/`, and the native function (each metered via `hostkit.RunSubOperation` with `isCleanup = true`).
   - Deletes the `"deleting"` tombstone in `lmcloudfnmeta` **last** and releases the function's locked cleanup reserves only after every child and native resource is confirmed removed (`200`/`204`/`404`).

---

### 4.4 Cost Admission, Settlement, and Cleanup Reserves (`CostReport` & `MetricsReport`)

#### 1. Integer-Nanodollar Tariff Model (`service == "function"`)
To align with `hostkit/safety/cost.go`'s exact integer-nanodollar (`$10^{-9}`) arithmetic and real cloud serverless pricing structures:
- **Synthetic Simulator Reference Tariff (`unit_price_usd = $0.000000002` = exact `2` nanodollars/unit):**
  - **Control-plane operations** (`function_create`, `function_update`, `function_delete`, `function_exists`, `function_get`, `function_list`, `function_publish_version`, `function_versions`, `function_alias_set`, `function_alias_get`, `function_alias_delete`):
    - `unit_price_usd = $0.00000020` (`200` nanodollars / request unit), `1` billing unit per physical HTTP attempt (plus any `RunSubOperation` storage/catalog calls metered under their respective operations).
  - **Data-plane invocation (`function_invoke`):**
    - `unit_price_usd = $0.000000002` (`2` nanodollars / unit), `byte_price_usd_per_gib = $0.09` / GiB (`bytes_out + bytes_in`).
    - Each physical invocation attempt charges **`100` base request units** (`100 * 2 nanodollars = 200 nanodollars = $0.00000020`, matching AWS Lambda's `$0.20 / 1M requests` base fee) **plus** `billed_ms * (memory_mb / 128)` compute units (`2` nanodollars per 128 MiB-ms = `$0.000016 / GB-s`):
      $$\text{billing\_units}(\text{function\_invoke}) = 100 + \text{billed\_ms} \times \left(\frac{\text{memory\_mb}}{128}\right)$$
    - Every unit is an exact integer multiple of `2` nanodollars, so `billing_units * unit_price_usd` has zero fractional-nanodollar rounding error.
- **Live-Mode Verified Regional Price Tables (`10-cost-perf-design.md` & `14-live-safety.md`):**
  - The synthetic tariff above is **strictly for simulator/fake runs**. In `--live` mode, `hostkit/safety` fails closed unless a verified regional price table (`prices/<provider>/<region>.json`, `verified: true`, age `<= 90` days) is loaded, pricing request fees, physical SKU memory-duration (including Azure Flex physical instance ceil-mapping), staging storage, and log/artifact transfer with **ceiling rounding to integer nanodollars**.

#### 2. Pinned Pre-Attempt Invocation Admission & Trusted Duration Settlement
To prevent the stale-cache / alias-retarget under-reservation hazard across concurrent processes:
1. **Resolve & Pin Before Admission:**
   - Every `function_invoke(name, qualifier, payload_json)` first resolves `qualifier` via a metered catalog read (`RunSubOperation`) in `lmcloudfnmeta`, obtaining the target's **immutable deployment revision identifier** (`native_version_id` / `revision_id`) AND its committed `(timeout_seconds, memory_mb)`.
   - The subsequent invocation request dispatches **specifically to that pinned revision/version target** (not an unpinned mutable pointer). If any provider fallback path cannot pin the revision at dispatch time, `ReserveBeforeAttempt` MUST reserve the **portable global maximum** (`100 + 230,000 * (2048 / 128) = 3,680,100` units + `1 MiB` response egress) prior to dispatch.
2. **Pre-Attempt Reservation (`ReserveBeforeAttempt`):**
   - For the pinned target `(timeout_seconds, memory_mb)`:
     $$\text{max\_units} = 100 + (\text{timeout\_seconds} \times 1000) \times \left(\frac{\text{memory\_mb}}{128}\right), \quad \text{max\_bytes} = \text{utf8\_len}(\text{payload\_json}) + 1048576$$
   - If reserving `(max_units, max_bytes)` exceeds the active script work sub-cap (`cost_cap_usd()`) or operator total ceiling (`<= $0.25`), `function_invoke` is refused pre-flight with `ErrorCode.COST_CAP_EXCEEDED` (`http_status() == 0`).
3. **Trusted Duration Authority & Conservative Retention on Ambiguous Failure:**
   - `billed_ms` is never trusted from unverified user payload text. On completed responses (`200`), `settled_billed_ms` is computed as:
     $$\text{settled\_billed\_ms} = \max\bigl(1,\; \text{provider\_billed\_ms},\; \min(\lceil \text{host\_elapsed\_ms} \rceil,\; \text{timeout\_seconds} \times 1000)\bigr)$$
   - **No-Replay & Full Reservation Retention on Lost Replies:** `function_invoke` is non-idempotent (`hostkit/retry.go` POST no-replay rule). Once dispatched on the wire, it is **never retried**. If the HTTP call fails due to transport drop, context cancellation, client timeout, malformed metrics, or process crash, the **entire worst-case reservation (`max_units`, `max_bytes`) is permanently retained** in the journal because remote execution may continue until `timeout_seconds`.

#### 3. Incremental Cleanup Reserves for Functions, Versions, and Aliases
To guarantee `function_delete` and `Sweep` always have sufficient cleanup budget inside the durable total ceiling regardless of how many versions and aliases a script creates:
- `function_create`: locks **`25` control-plane request units (`$0.00000500`)** covering tombstone fence, list probes, base staged-bundle delete, native function delete, and tombstone delete with `3×` retry headroom.
- `function_publish_version` (up to 16 versions): locks an **additional `6` request units (`$0.00000120`)** per published version before dispatch (covering version delete + versioned staged-bundle delete × `3` retries).
- `function_alias_set` (when creating a new alias, up to 16 aliases): locks an **additional `3` request units (`$0.00000060`)** per alias before dispatch (released on `function_alias_delete` or consumed/released on `function_delete`).
- If locking the required cleanup reserve for `function_create`, `function_publish_version`, or `function_alias_set` would exceed the reserved cleanup headroom / operator total ceiling, the operation fails pre-flight with `ErrorCode.COST_CAP_EXCEEDED`.

---

### 4.5 Dry-Run (`lmscript --dry-run`) Semantics
In `cloudhost`, all `function_*` mutators and `function_invoke` have explicit Dry slots:
- `function_invoke` is classified as an effectful execution operation: in `--dry-run` mode it executes **zero** handler code and makes **zero** network calls, returning a deterministic preview `FunctionInvokeResult` (`status_code() == 200`, `payload() == "{}"`, `logs() == ""`, `function_error() == ""`, `is_error() == false`, `executed_version()` matching the resolved dry version, `duration_ms() == 0.0`, `billed_ms() == 1`, `memory_mb()` from the dry config).
- `function_create`, `function_update`, `function_delete`, `function_publish_version`, `function_alias_set`, and `function_alias_delete` mutate the run-local dry overlay so `function_exists`, `function_get`, `function_list`, `function_versions`, and `function_alias_get` stay coherent without network traffic.
