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
| `version` | `() -> string` | Portable version identifier: `"$LATEST"` for the mutable head, or a positive decimal version string (`"1"`, `"2"`, ...) for a published immutable snapshot. |
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
| `executed_version` | `() -> string` | The portable version (`"1"`, `"2"`, ...) or `"$LATEST"` that actually executed. |
| `duration_ms` | `() -> float` | Measured execution wall time in milliseconds (`>= 0.0`). |
| `billed_ms` | `() -> int` | Authoritative billed duration in milliseconds (`1 <= billed_ms <= timeout_seconds * 1000`). |
| `memory_mb` | `() -> int` | Configured logical memory size (in MiB) of the executed version. |

### 2.2 `Cloud` Methods

| Method | Signature(s) | Return Type | Semantics |
|---|---|---|---|
| `function_config` | `(runtime: string, handler: string)` | `FunctionConfig` | Creates a local `FunctionConfig` builder initialized with `runtime`, `handler`, `timeout_seconds = 3`, `memory_mb = 128`, `concurrency = 0`, and empty `env`. Validates `runtime` and `handler` pre-flight. |
| `function_create` | `(name: string, config: FunctionConfig)` | `bool` | Creates function `name` under a fresh `incarnation_id`, stages its content-addressed package bundle, deploys initial generation target (`op_gen = 1`), polls its provider operation to terminal `"active"` state, and commits `lmcloudfnmeta`. Returns `true` if newly created. If `name` already exists in the current authorized scope: returns `false` (`ErrorCode.OK`) iff the canonical configuration fingerprint (`runtime`, `handler`, `code_sha256`, `timeout_seconds`, `memory_mb`, `concurrency`, `env`) matches identically; fails with `ErrorCode.CONFLICT` if any configuration field differs. In `--live` mode, an existing resource with foreign or missing ownership metadata fails closed with `ErrorCode.PERMISSION_DENIED`. |
| `function_update` | `(name: string, config: FunctionConfig)`<br>`(name: string, config: FunctionConfig, expect_revision: string)` | `FunctionConfig` | Acquires the catalog writer lease for `name`, drains any unpinned `pending_gc` / terminal interrupted `candidate` artifacts (failing closed with `ErrorCode.CONFLICT` backpressure if `2` displaced revisions remain pinned by active invocations or non-terminal provider operations), deploys the new `$LATEST` target (an immutable per-generation target `lmfn-{name}-{inc8}-g{op_gen}` on GCP/Azure/OCI, or `RevisionId`-preconditioned update on AWS), polls the provider operation (`pending_op_id` / `LastUpdateStatus`) via metered `RunSubOperation` calls until authoritative terminal `"active"` status is observed, atomically flips `lmcloudfnmeta.latest` and rotates `revision_id()`, garbage-collects the displaced unreferenced `$LATEST` bundle/target (or queues it in `pending_gc` if still pinned by an in-flight invocation), and returns the updated `FunctionConfig`. If `config` is a mutated readback descriptor whose code source was not re-set, retains the existing content-addressed bundle (`code_sha256()`) without re-reading the external source bucket. The 3-arg overload requires `expect_revision` to be non-empty (`INVALID_ARGUMENT` if `""`) and equal to current `revision_id()` (`PRECONDITION_FAILED` on mismatch). Missing function -> `NOT_FOUND`. |
| `function_delete` | `(name: string)` | `bool` | Transitions `name` to `"deleting"` in `lmcloudfnmeta`, cancels/polls any non-terminal provider operation (`candidate.pending_op_id` / `pending_gc[*].pending_op_id` / `LastUpdateStatus == "InProgress"`) via metered `RunSubOperation` calls until authoritative terminal status is confirmed (retaining the `"deleting"` tombstone and locked cleanup reserve if any operation remains non-terminal or ambiguous at deadline expiry), deletes all aliases, published version deployments, owned staged package bundles, and generation/base native function targets, and finally deletes the catalog tombstone. Returns `true` if deleted, `false` (`ErrorCode.OK`) if already absent. Draws from locked cleanup reserves (`isCleanup = true`). |
| `function_exists` | `(name: string)` | `bool` | Returns `true` if `name` exists and is `"active"` (or `"mutating"` over an active incarnation), `false` if absent, `"creating"`, or `"deleting"` (`ErrorCode.OK`). Never masks `UNAUTHENTICATED` or `PERMISSION_DENIED`. |
| `function_get` | `(name: string)`<br>`(name: string, qualifier: string)` | `FunctionConfig` | Strongly consistent readback for `$LATEST` (1-arg or `qualifier == "$LATEST"`), a published version (`"1"`, `"2"`, ...), or an alias (`"prod"`). Returns the last committed `"active"` `FunctionConfig` with preserved `code_sha256()` (and `inline_code()` or `package_bucket()`/`package_key()`) suitable for passing back to `function_update`. If the function or qualifier is absent, returns `exists() == false` with `ErrorCode.OK`. |
| `function_list` | `()` | `StrList` | Returns all `"active"` logical function names in ascending ASCII lexicographical order (`ListAll` across pages, excluding reserved catalog/staging resources and `"creating"`/`"deleting"` records). |
| `function_publish_version` | `(name: string)`<br>`(name: string, expect_revision: string)` | `string` | Always allocates the next monotonic portable version string (`"1"`, `"2"`, ...; up to 16 versions per function), locks the per-version cleanup reserve (`$0.00003000`), deploys/pins an immutable versioned deployment target backed by the retained content-addressed bundle, polls its provider operation to terminal `"active"` state, rotates `$LATEST`'s `revision_id()`, and returns the new portable version string. 2-arg overload enforces `expect_revision` (`PRECONDITION_FAILED` on mismatch, `INVALID_ARGUMENT` if `""`). Missing function -> `NOT_FOUND`. |
| `function_versions` | `(name: string)` | `StrList` | Lists all published immutable version strings (excluding `"$LATEST"`) for `name` in ascending numeric order (`"1"`, `"2"`, ..., `"10"`). Missing function -> `NOT_FOUND`. |
| `function_alias_set` | `(name: string, alias: string, version: string)` | `void` | Creates or atomically retargets alias `alias` on `name` to published portable `version` (locking the per-alias cleanup reserve `$0.00001000` on new alias creation; max 16 aliases per function). Fails with `NOT_FOUND` if `name` or published `version` does not exist. |
| `function_alias_get` | `(name: string, alias: string)` | `string` | Returns the target portable `version` string for `alias`, or `""` with `ErrorCode.OK` if `name` exists but `alias` is absent. Missing function -> `NOT_FOUND`. |
| `function_alias_delete` | `(name: string, alias: string)` | `bool` | Deletes `alias` on `name` and releases its per-alias cleanup reserve. Returns `true` if deleted, `false` (`ErrorCode.OK`) if `alias` was already absent. Missing function -> `NOT_FOUND`. |
| `function_invoke` | `(name: string, payload_json: string)`<br>`(name: string, qualifier: string, payload_json: string)` | `FunctionInvokeResult` | Resolves `qualifier` (`"$LATEST"` default, portable version number, or alias) in `lmcloudfnmeta` to its pinned immutable deployment target and `(timeout_seconds, memory_mb)`, reserves worst-case invocation cost, registers an in-flight invocation pin in `lmcloudfnmeta` (`slots[1..K]` when `concurrency > 0`, or `active_invocations[invocation_id]` when `concurrency == 0` so GC never deletes an artifact used by an active invocation), and synchronously invokes the pinned target with `payload_json`. Missing function/version/alias -> `NOT_FOUND`. Throttled (`concurrency == -1` or all slots busy / HTTP `429`) -> `ErrorCode.PRECONDITION_FAILED` (`http_status() == 429`). |

---

## 3. Native Cloud Wire Mappings vs. Simulator Transport Mappings

To avoid conflating real cloud wire protocols with local single-port simulator conveniences, Slice 6 explicitly separates **Native Cloud Wire Mapping** from **Simulator Transport Mapping** for every provider, maps logical function names to **incarnation-scoped physical provider identities** (`lmfn-{name}-{inc8}`), and isolates within-incarnation updates via **immutable per-generation deployment targets** (`lmfn-{name}-{inc8}-g{op_gen}`) and **authoritative provider operation terminality barriers** (never relying on client HTTP socket timeouts as proof that a server-side deployment has stopped).

### 3.1 Native Cloud Wire Mapping (Live Clouds)

| Aspect | AWS Lambda (Native) | Azure Functions (Native) | GCP Cloud Functions Gen2 (Native) | OCI Functions (Native) |
|---|---|---|---|---|
| **Hosting Plan** | AWS Lambda on-demand (`x86_64`) | Azure Functions **Linux Consumption (`Y1` Dynamic SKU)** (or certified zero-idle-cost on-demand ACA Functions SKU for `2048 MiB`; live path remains uncertified/`LiveFunctionNotCertified` until empirical `2048 MiB` resident-memory certification passes) | Cloud Functions v2 (Gen2, Cloud Run-backed) | OCI Functions on-demand (`20181201`) |
| **Authoritative Catalog & Staging** | DynamoDB catalog table `lmcloudfnmeta` + S3 bucket `lmcloudfn-pkgs-{acct}-{region}` for content-addressed bundles `/{name}/{inc8}/{code_sha256}.zip` | Azure Table `lmcloudfnmeta` + Blob container `lmcloudfn-pkgs` for content-addressed bundles `/{name}/{inc8}/{code_sha256}.zip` | Firestore collection `lmcloudfnmeta` + GCS bucket `lmcloudfn-pkgs-{project}` for content-addressed bundles `/{name}/{inc8}/{code_sha256}.zip` | OCI Object Storage conditional-ETag catalog bucket `lmcloudfnmeta` (or NoSQL table when O1 lands) + bucket `lmcloudfn-pkgs` for bundles |
| **Physical Resource Naming (Incarnation- & Generation-Scoped)** | Lambda Function `lmfn-{name}-{inc8}` (`inc8` = 8-char random lowercase alnum from `incarnation_id`) | Per-generation Function Apps `lmfn-{name}-{inc8}-g{op_gen}` + per-version Function Apps `lmfn-{name}-{inc8}-v{k}` (no shared mutable app root across generations/versions) | Per-generation Cloud Functions `lmfn-{name}-{inc8}-g{op_gen}` + per-version Cloud Functions `lmfn-{name}-{inc8}-v{k}` (never updating a shared base function in place) | OCI Application (run-scoped) + per-generation Functions `lmfn-{name}-{inc8}-g{op_gen}` and per-version Functions `lmfn-{name}-{inc8}-v{k}` |
| **Control-Plane Create / Update & Asynchronous Operation Terminality** | `POST /2015-03-31/functions` (`lmfn-{name}-{inc8}`); updates pass native conditional **`RevisionId`** on `PUT .../code` and `PUT .../configuration` (`412` on mismatch) AND poll `GET .../configuration` (metered via `RunSubOperation`) until `LastUpdateStatus in {"Successful", "Failed"}` (never mutating or recovering while `LastUpdateStatus == "InProgress"`) | Creates immutable target `lmfn-{name}-{inc8}-g{op_gen}` via ARM `PUT .../sites/lmfn-{name}-{inc8}-g{op_gen}` + Kudu `POST .../api/zipdeploy?isAsync=true`, records the returned deployment/operation ID in `lmcloudfnmeta.candidate.pending_op_id`, and polls `GET .../api/deployments/{id}` (metered via `RunSubOperation`) until terminal status (`status == 4 Success` or `3 Failed`) before flipping `lmcloudfnmeta.latest` | Creates immutable generation target `POST /v2/projects/{p}/locations/{l}/functions?functionId=lmfn-{name}-{inc8}-g{op_gen}`, records the returned long-running `Operation` name in `lmcloudfnmeta.candidate.pending_op_id`, and polls `GET /v2/{op_name}` (metered via `RunSubOperation`) until `done == true` before flipping `lmcloudfnmeta.latest` | `POST /20181201/functions` creating immutable generation target `lmfn-{name}-{inc8}-g{op_gen}`, records target OCID in `lmcloudfnmeta.candidate`, and polls `GET /20181201/functions/{id}` (metered via `RunSubOperation`) until `lifecycleState in {"ACTIVE", "FAILED"}` before flipping `lmcloudfnmeta.latest` |
| **Immutable Version Mapping (`"1".."16"`)** | Portable version `"k"` (`1..16`) is mapped in `lmcloudfnmeta.versions["k"]` to `{native_aws_ver, code_sha256, config}`. Because AWS `PublishVersion` is a no-op if code/config is unchanged, `function_publish_version` first updates `Description = "lmcloud-v{k}-{op_gen}"` (with `RevisionId`), polls `LastUpdateStatus == "Successful"`, and then calls `POST .../versions` (`RevisionId`), guaranteeing a distinct immutable AWS version ARN `...:lmfn-{name}-{inc8}:{native_aws_ver}` for every portable publish! | Creates a dedicated immutable target `lmfn-{name}-{inc8}-v{k}` containing its self-contained `v{k}/__lmcloud_manifest.json` (`runtime`, `handler`, `timeout_seconds`, `memory_mb`, `env`) and extracted `v{k}/code/` from `{code_sha256}.zip`, polls its Kudu deployment to `status == 4 (Success)`, and records its immutable target endpoint in `lmcloudfnmeta.versions["k"]` | Creates a **dedicated immutable Cloud Function v2 resource** `lmfn-{name}-{inc8}-v{k}` (`POST /v2/.../functions?functionId=lmfn-{name}-{inc8}-v{k}`), polls its long-running `Operation` (`GET /v2/{op_name}`) until `done == true`, and stores its immutable `serviceConfig.uri` in `lmcloudfnmeta.versions["k"].service_uri` | Creates a dedicated immutable OCI Function resource `lmfn-{name}-{inc8}-v{k}` (`POST /20181201/functions`) with frozen `timeoutInSeconds`, `memoryInMBs`, `config` env, and bundle digest, polls until `lifecycleState == "ACTIVE"`, and stores its immutable OCID in `lmcloudfnmeta.versions["k"].native_id` |
| **Physical Memory Mapping** | Exact `{128, 256, 512, 1024, 2048}` MB (`MemorySize`) | Logical tier `{128..2048}` MiB enforced in `__lmcloud_azure_entry` wrapper (cgroup v2 / RSS monitor + heap limit); note that Linux Consumption (`Y1`) has a documented `1536 MB` (`1.5 GB`) physical host ceiling whereas the portable set includes `2048 MiB`, so native `--live` Azure remains uncertified (`LiveFunctionNotCertified`) until a `>= 2048 MiB` zero-idle-cost SKU passes empirical allocation certification | Exact `{128, 256, 512, 1024, 2048}` MiB (`serviceConfig.availableMemory` = `"128Mi"`..`"2048Mi"`) | Exact `{128, 256, 512, 1024, 2048}` MB (`memoryInMBs`) |
| **Native Invocation Wire Protocol** | `POST /2015-03-31/functions/lmfn-{name}-{inc8}/invocations?Qualifier={native_aws_ver}` (`X-Amz-Invocation-Type: RequestResponse`, `X-Amz-Log-Type: Tail`), SigV4 `lambda:InvokeFunction` | `POST https://lmfn-{name}-{inc8}-{target_route}.azurewebsites.net/api/{target_route}` (`target_route` = `g{op_gen}` for `$LATEST` or `v{k}` for version `"k"`) with Entra bearer token (`Microsoft.Web/sites/functions/invoke/action`) or function key | **No `:call` method in v2!** Invokes the target's dedicated `service_uri` (`POST <target_service_uri>`, either `lmfn-{name}-{inc8}-g{op_gen}` for `$LATEST` or `lmfn-{name}-{inc8}-v{k}` for version `"k"`) with an OIDC **ID token** (`Authorization: Bearer <id_token>`, `aud = target_service_uri`) and Cloud Run `run.routes.invoke` (`roles/run.invoker`) | `POST https://<invoke-endpoint>/20181201/functions/{target_ocid}/actions/invoke` (`fn-invoke-type: sync`), RSA-signed with `fn-invocation` (`FUNCTION_INVOKE`) permission |
| **Entrypoint Handler Shim** | Native `(event, context)` + log/error canonicalizer shim | **Required** `__lmcloud_azure_entry` HTTP-trigger shim reading `<route>/__lmcloud_manifest.json` (`env`, `timeout_seconds`, `memory_mb`) -> isolated subprocess `handler(event, context)` -> structured JSON envelope | **Required** `__lmcloud_gcp_entry` Functions-Framework HTTP shim -> isolated subprocess `handler(event, context)` -> structured JSON envelope | **Required** `__lmcloud_oci_entry` FDK HTTP shim -> isolated subprocess `handler(event, context)` -> structured JSON envelope + `opc-fn-*` headers |

#### Native GCP v2 Invocation Endpoint Derivation & `httpguard` Rule
Because native GCP Cloud Functions v2 returns a data-plane `serviceConfig.uri` (`https://<service>-<hash>-<region>.a.run.app`) on a different hostname from the control-plane `cloudfunctions.googleapis.com` endpoint:
- In `--live` mode, `httpguard` permits an invocation `POST` to a `target_service_uri` **if and only if**:
  1. The URI scheme is `https`, the host matches `^[a-z0-9-]+-[a-z0-9]+-[a-z0-9-]+\.a\.run\.app$`, and the exact URI was returned by an authenticated `getFunction` call for an owned function (`lmfn-{name}-{inc8}-g{op_gen}` or `lmfn-{name}-{inc8}-v{k}`) recorded in the current run journal,
  2. Cross-origin HTTP redirects (`3xx`) on invocation remain strictly disabled (`ErrRedirectBlocked`), and
  3. The request carries an OIDC ID token minted specifically for `aud = target_service_uri`.
- In simulator mode (`gcpsim`), `serviceConfig.uri` points back to the simulator's own loopback listener (`http://127.0.0.1:4588/__run/projects/{p}/locations/{l}/services/{service}/revisions/{rev}:invoke`), so all traffic stays on the single configured loopback origin.

### 3.2 Simulator Transport Mapping & Required Simulator Epics (Zero-Docker In-Process Execution)

All four local simulators execute on a single loopback HTTP listener per provider (`:4566`, `:4577`, `:4588`, `:4599`) with **zero Docker daemon dependency**, emulating the incarnation-scoped physical targets, immutable generation/version targets, and operation terminality checks above:

1. **`awssim` (`:4566`, `floci` `services/lambda` + `AuthFilter.java`):**
   - **Wire fidelity:** Matches native AWS Lambda REST routes (`/2015-03-31/functions*`, `/2017-10-31/functions*`, `/2019-09-30/functions*`), enforces `RevisionId` preconditions (`412 PreconditionFailedException`) and `LastUpdateStatus` serialization (`409 ResourceConflictException` if an update is in progress) on `UpdateFunctionCode`, `UpdateFunctionConfiguration`, and `PublishVersion`, and executes handlers inside the §4.2.2 namespace-isolated sandbox (`A-FN1`), with SigV4 `"lambda"` authorization in [`AuthFilter.java`](file:///home/ubuntu/cloud/awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java) (`A-FN2`) and sorted `Marker`/`MaxItems` pagination on `ListFunctions` (`A-FN3`).
2. **`azuresim` (`:4577`, `floci-az` `services/functions` + `StorageAuth.java`):**
   - **Simulator transport consolidation (explicitly labeled sim-only routing):** Consolidates ARM, Kudu ZipDeploy + deployment status polling, and Function App HTTP trigger routes onto `/{account}-functions/admin/apps/{app}/functions/{route}`, `/{account}-functions/admin/apps/{app}/deployments/{deploymentId}`, and `POST /{account}-functions/api/{app}/{route}` on the single loopback listener. Each deployed generation/version target (`lmfn-{name}-{inc8}-g{op_gen}` or `lmfn-{name}-{inc8}-v{k}`) executes its self-contained `__lmcloud_manifest.json` + `__lmcloud_azure_entry` bundle inside the §4.2.2 namespace-isolated sandbox (`AZ-FN1`), authorized by [`StorageAuth.java`](file:///home/ubuntu/cloud/azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java) (`AZ-FN2`).
3. **`gcpsim` (`:4588`, `floci-gcp` `services/cloudfunctions` + `BearerGuard.java`):**
   - **Wire fidelity & local Cloud Run URI emulation:** Supports `POST/GET/PATCH/DELETE /v2/projects/{p}/locations/{l}/functions*` and long-running operation status `GET /v2/projects/{p}/locations/{l}/operations/{op}` for immutable generation services `lmfn-{name}-{inc8}-g{op_gen}` and immutable version services `lmfn-{name}-{inc8}-v{k}`, setting each function's `serviceConfig.uri` to `http://<host>:<port>/__run/projects/{p}/locations/{l}/services/{service}/revisions/{rev}:invoke` (explicitly labeled as `gcpsim`'s loopback representation of the Cloud Run `*.a.run.app` URL) (`G-FN1`). [`BearerGuard.java`](file:///home/ubuntu/cloud/gcpsim/src/main/java/ai/lmctl/gcpsim/BearerGuard.java) enforces `cloudfunctions.functions.{create,get,list,update,delete}` on `/v2/.../functions*` and `/v2/.../operations*` and `run.routes.invoke` (with ID-token audience check) on `/__run/...:invoke` (`G-FN2`).
4. **`ocisim` (`:4599`, `floci-oci` `services/functions` + `OciPolicyEngine.java`):**
   - **Wire fidelity:** Uses native OCI Functions `20181201` routes (`/20181201/applications`, `/20181201/functions`, and `POST /20181201/functions/{id}/actions/invoke`, already mapped in [`OciPolicyEngine.java:757-789`](file:///home/ubuntu/cloud/ocisim/src/main/java/ai/lmctl/ocisim/OciPolicyEngine.java#L757-L789)), extended so mock `InvokeFunction` loads the target OCI Function's staged bundle from Object Storage (`lmcloudfn-pkgs`) and executes `__lmcloud_oci_entry` inside the §4.2.2 namespace-isolated sandbox (`O-FN1`).

---

## 4. Detailed Portable Semantics, Fencing, Isolation, and Safety Invariants

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
     - The host validates the package under §4.2.1, computes its 64-char lowercase hex `code_sha256()`, and uploads an **immutable, run-owned content-addressed copy** to the reserved staging store `lmcloudfn-pkgs/{name}/{inc8}/{code_sha256}.zip` (metered via `RunSubOperation`).
   - **Readback-as-Builder Preservation:**
     - `function_get` returns a `FunctionConfig` populated with the committed `code_sha256()`, `code_source()`, `inline_code()` (for `"inline"`), and `package_bucket()`/`package_key()` (for `"object"`).
     - Passing a mutated `FunctionConfig` from `function_get` to `function_update` (without calling `set_inline_code` or `set_package_object`) reuses the retained immutable staged bundle identified by `code_sha256()` — it **never** re-reads the user's mutable `(bucket, key)` object and **never** fails even if the user later overwrote or deleted `(bucket, key)`.
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

### 4.2 Package Archive Safety, Namespace Execution Isolation, and Secret/Log Policy

#### 4.2.1 Package Archive Safety (Zip-Bomb & Path Traversal Defense)
Before any `"object"` package archive is staged or extracted:
1. **Compressed size limit:** `<= 16 MiB` (`16,777,216` bytes), verified via `io.LimitReader(r, 16*1024*1024 + 1)`.
2. **Uncompressed cumulative extracted size limit:** **`<= 64 MiB` (`67,108,864` bytes)** across all entries, enforced via per-entry and cumulative `io.LimitReader(64*1024*1024 + 1)`.
3. **Entry count limit:** **`<= 256` entries** per ZIP archive.
4. **Entry path & mode hygiene:** Every ZIP entry is rejected (`INVALID_ARGUMENT`) if its path is empty, starts with `/` or `\`, contains `\` or `:` or NUL, contains any `..` segment, normalizes outside the extraction root, collides case-insensitively with a prior entry, is encrypted, or carries non-regular file mode bits (symlinks, hardlinks, FIFOs, sockets, devices, setuid/setgid are strictly forbidden).

#### 4.2.2 OS Namespace Sandbox Isolation (Fail-Closed) & Resource Limits
Merely clearing `os.environ` (`env -i`), chdir'ing into a `0700` directory, and creating a process group do **not** isolate a same-UID OS subprocess from reading `/proc/<parent>/environ`, reading host credential/journal files outside its working directory, contacting loopback control-plane ports, or escaping via `setsid()` in a forked child. Therefore:
1. **Mandatory Linux User/PID/Mount/Network Namespace Jail (`CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC` / `bwrap --unshare-all --die-with-parent`):**
   - **PID Namespace (`CLONE_NEWPID`) + Private `/proc` Mount:** Each handler invocation runs as PID 1 inside a fresh PID namespace with a new procfs mount (`/proc`). Parent/simulator/host processes do **not exist** inside `/proc` (blocking `/proc/<parent>/environ` and `/proc/<parent>/fd` reads), and when the namespace PID 1 terminates on completion or `timeout_seconds`, the Linux kernel **unconditionally kills (`SIGKILL`) every descendant process in the PID namespace**, including descendants that called `setsid()` / double-forked.
   - **Mount Namespace (`CLONE_NEWNS` + `pivot_root`):** The sandbox root filesystem exposes **only** read-only system runtime directories (`/usr`, `/lib`, `/lib64`, `/bin`), a minimal `/dev` (`null`, `zero`, `urandom`), the private `/proc`, an ephemeral `tmpfs` `/tmp` (`size=16m,mode=1777`), and the read-only extracted bundle at `/var/task`. The host filesystem (`/home`, `/tmp` host files, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.oci`, and `LMCLOUD_STATE_DIR` journals) is **unmounted and physically unreachable** inside the mount namespace.
   - **Network Namespace (`CLONE_NEWNET`):** The handler runs in an isolated network namespace with no route to host loopback (`127.0.0.1:4566..4599`) or external networks, preventing SSRF against local simulator control planes or cloud metadata endpoints.
   - **Cleared Environment & Runtime-Compatible Physical Memory Quotas:** Inside the namespace jail, the process starts with `clearenv` populated only with `PATH=/usr/bin:/bin`, `HOME=/tmp`, `TMPDIR=/tmp`, `LANG=C.UTF-8`, `PYTHONDONTWRITEBYTECODE=1`, `NODE_OPTIONS=--max-old-space-size=<max(64, memory_mb - 32)>`, and the function's configured user `env` map, plus `RLIMIT_NOFILE = 64` and `RLIMIT_NPROC = 32`. Because Node.js (`V8`) reserves a multi-GiB uncommitted `PROT_NONE` virtual address space cage at startup even when resident heap is `< 32 MiB` (so a naive `RLIMIT_AS = 128 MiB` would prevent `"nodejs20.x"` from starting), `memory_mb` is enforced against **physical resident + swap memory (`VmRSS + VmSwap`)** via cgroup v2 `memory.max = memory_mb MiB` (`memory.swap.max = 0`) and a `5 ms` parent `/proc/<pid>/statm` RSS monitor (plus `RLIMIT_DATA = memory_mb MiB` on `"python3.12"` and `--max-old-space-size` on `"nodejs20.x"`), verified by Gate G3 to start both runtimes cleanly at `128 MiB` and terminate resident allocations exceeding `memory_mb` with `"Unhandled"`.
   - **Fail-Closed Startup Self-Test:** Before serving any `function_invoke` request, the simulator/host runner executes a startup self-test verifying that `CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET` isolation is active, blocks parent procfs, host `/tmp`, and host loopback access, and boots both `"python3.12"` and `"nodejs20.x"` under the `128 MiB` memory limiter; if unavailable on the host kernel, `function_invoke` **fails closed** (`ErrorCode.INTERNAL`) rather than falling back to an unisolated subprocess.
2. **Bounded Live Output Drain:** `stdout`/`stderr` from the sandbox are drained concurrently through a ring buffer that caps total captured output at `64 KiB` (draining any further output to `/dev/null`) and retains the final **`4,096` UTF-8-safe bytes** (never splitting a multi-byte UTF-8 rune) for `result.logs()`.
3. **Explicit Redaction Policy — `result.logs()` / `result.payload()` vs. Host Diagnostics & Journals:**
   - **Handler output (`result.logs()` and `result.payload()`) is NOT redacted for configured `cfg.env` values:** If user handler code explicitly prints or returns a configured user environment variable (`os.environ["APP_ENV"]`), `result.logs()` and `result.payload()` return it verbatim (matching AWS Lambda `X-Amz-Log-Result` semantics and conformance scenario `06`). Because `result.logs()` and `result.payload()` preserve intentional handler outputs, **any higher-level test runner, CI log publisher, or report collector outside `lmcloud` must treat `FunctionInvokeResult.logs()` and `payload()` as potentially sensitive user data**.
   - **Host diagnostics, abort traces, and durable journals ARE redacted:** `ErrorState.AddRedaction` registers all non-empty user `cfg.env` values so `CloudError.message()`, `CloudError.provider_code()`, and abort frames never echo user env values, and the `hostkit/safety` journal stores only byte counts and `code_sha256` / config digests — never plaintext `env` values, `logs()`, or `payload()`.

---

### 4.3 Authoritative Catalog (`lmcloudfnmeta`), Incarnation Fencing, Asynchronous Operation Terminality, Bounded Staging GC, and Concurrency Slots

All four providers coordinate function lifecycle state through the authoritative catalog `lmcloudfnmeta` (and local `hostkit/safety` journal):

#### 4.3.1 Catalog Record Schema (`lmcloudfnmeta` keyed by logical `name`)
- `state`: `"creating"` | `"active"` | `"mutating"` | `"deleting"`
- `incarnation_id`: 128-bit random hex token generated once per `function_create` (with 8-char prefix `inc8` embedded in all physical resource names `lmfn-{name}-{inc8}*`)
- `revision_id`: 128-bit random hex token rotated on every committed mutation
- `op_gen`: monotonic integer incremented on every conditional catalog write
- `lease_owner`, `lease_until_unix_ms`: exclusive writer lease (`35 s` TTL)
- `run_id`, `scope_prefix`, `create_token`: immutable ownership triad linked to the local `hostkit/safety` journal
- `latest`: committed `FunctionSnapshot` (`runtime`, `handler`, `code_source`, `inline_code`, `package_bucket`, `package_key`, `code_sha256`, `physical_target_id`, `native_rev_id`, `timeout_seconds`, `memory_mb`, `concurrency`, `env`)
- `candidate`: optional in-flight `CandidateDeployment` (`{code_sha256, physical_target_id, pending_op_id, op_started_unix_ms}`, `<= 1` entry) recorded **before** staging a bundle or dispatching a native create/update call during `"mutating"` (with `pending_op_id = "inflight-unconfirmed"` written prior to HTTP dispatch and updated to the provider's concrete Operation/Deployment ID upon HTTP reply)
- `pending_gc`: bounded list (`<= 2` entries) of displaced or aborted unversioned `{code_sha256, physical_target_id, pending_op_id}` artifacts awaiting synchronous garbage collection once unpinned and operation-terminal
- `versions`: map of `"1".."16"` -> immutable `FunctionSnapshot` (including `physical_target_id` / `service_uri` / `native_aws_ver` / `functionId`)
- `aliases`: map of `alias_name` (`<= 16`) -> portable `version_string` (`"1".."16"`)
- `slots`: map of `"1"..str(concurrency)` -> `{invocation_id, physical_target_id, code_sha256, expires_at_unix_ms}` for distributed concurrency admission (`concurrency > 0`)
- `active_invocations`: map of `invocation_id` (`<= 100`) -> `{physical_target_id, code_sha256, expires_at_unix_ms}` tracking active unreserved (`concurrency == 0`) invocations so GC never deletes an artifact still used by an in-flight invocation

#### 4.3.2 Effective Native Write Fencing: Incarnation Isolation, Immutable Generation Targets, and Authoritative Operation Terminality
**Crucial Invariant — Client Socket Deadlines Do NOT Prove Server-Side Quiescence:** A host HTTP socket timeout (`30 s`) and a catalog writer lease (`35 s`) bound only local client wait time; they **never** prove that an accepted server-side asynchronous operation (GCP `Operation`, Azure `zipdeploy?isAsync=true` / ARM deployment, AWS `LastUpdateStatus == "InProgress"`, OCI `CREATING`/`UPDATING`) has stopped. Therefore, Slice 6 enforces native write fencing without relying on elapsed socket/lease time:
1. **Cross-Incarnation Isolation (`lmfn-{name}-{inc8}*`):** Every `function_create` allocates a fresh `inc8` and names all physical provider resources `lmfn-{name}-{inc8}*`, so a delayed request or background operation from a deleted incarnation can **never** mutate a newly created incarnation `lmfn-{name}-{new_inc8}*`.
2. **Immutable Per-Generation Targets (`lmfn-{name}-{inc8}-g{op_gen}` on GCP, Azure, OCI):**
   - On GCP, Azure, and OCI, `function_create` (`op_gen = 1`) and every `function_update` (`op_gen = g`) create a **new immutable physical deployment target** `lmfn-{name}-{inc8}-g{op_gen}` rather than updating a shared serving target in place.
   - The writer records `candidate = {code_sha256, physical_target_id: "lmfn-{name}-{inc8}-g{op_gen}", pending_op_id}` in `lmcloudfnmeta`, polls the provider's operation/deployment endpoint via metered `RunSubOperation` calls until **authoritative terminal success** (`done == true` on GCP `GET /v2/{op_name}`, `status == 4 (Success)` on Azure Kudu `/api/deployments/{id}`, `lifecycleState == "ACTIVE"` on OCI `GetFunction`), and only then conditionally flips `lmcloudfnmeta.latest` from `("mutating", op_gen)` to `("active", op_gen + 1)` pointing at `lmfn-{name}-{inc8}-g{op_gen}`.
   - If writer A's lease expires while `g1`'s backend operation is still running, and a subsequent writer B (or recovery) runs, writer B moves `g1` into `pending_gc` (retaining `g1`'s `pending_op_id` so `g1` stays quarantined from deletion until its operation terminates) and deploys a fresh target `g2 = lmfn-{name}-{inc8}-g{op_gen+1}`. Even when `g1`'s asynchronous operation eventually completes at `t = 60`, it finishes on the unreferenced target `g1` and **cannot** alter `g2`'s code, configuration, or traffic.
3. **Authoritative Operation Serialization & Precondition Barrier on AWS (`RevisionId` + `LastUpdateStatus`):**
   - On AWS Lambda (`lmfn-{name}-{inc8}`), every update passes the native conditional `RevisionId` recorded in `lmcloudfnmeta` (`412 PreconditionFailedException` on mismatch) and polls `GetFunctionConfiguration` (metered via `RunSubOperation`) until `LastUpdateStatus in {"Successful", "Failed"}` before committing `lmcloudfnmeta.latest` with the newly returned `RevisionId`.
   - If writer A's lease expires and writer B (or recovery) encounters `state == "mutating"`, writer B **must** first call `GetFunctionConfiguration` (metered via `RunSubOperation`): while `LastUpdateStatus == "InProgress"`, `lmfn-{name}-{inc8}` remains quarantined (writer B either polls until terminal status within its deadline or fails closed with `ErrorCode.CONFLICT` / `http_status() == 409`, never issuing a conflicting write or trusting elapsed time). Once `LastUpdateStatus` is terminal, writer B uses the authoritative `RevisionId` from `GetFunctionConfiguration` for any subsequent conditional write.
4. **Operation-Terminal Deletion & Quarantine Barrier (`function_delete` & `Sweep`):**
   - Before tearing down any physical target (`latest`, `candidate`, or `pending_gc[*]`) that has a non-empty `pending_op_id` or in-progress status, `function_delete` / `Sweep` issues a metered cancel/status poll (`RunSubOperation`) until authoritative terminal status (`done == true`, `LastUpdateStatus != "InProgress"`, `status in {Success, Failed, Cancelled}`, `lifecycleState in {ACTIVE, FAILED}`) is observed.
   - If any provider operation remains non-terminal or its status is ambiguous when the caller's deadline expires, `function_delete` / `Sweep` **retains the `"deleting"` tombstone in `lmcloudfnmeta` and keeps the locked cleanup reserve intact** so a subsequent sweep completes the deletion once the provider operation terminates.

#### 4.3.3 Synchronous Garbage Collection, In-Flight Invocation Pinning, Backpressure, and Bounded Retained Artifacts (`<= 19`)
To prevent repeated `function_update` calls from accumulating unbounded staged bundles or native targets while never deleting an artifact still used by an active invocation or pending operation:
1. **In-Flight Pinning Predicate (`is_pinned`, Including `concurrency == 0`):** An unversioned artifact `{code_sha256, physical_target_id, pending_op_id}` is **pinned** if and only if:
   - (a) Its `pending_op_id` is non-empty and a metered provider status poll has not yet observed a terminal operation state, **OR**
   - (b) Any non-expired entry (`expires_at_unix_ms > now`) in `slots` (when `concurrency > 0`) **or** `active_invocations` (when `concurrency == 0`) references `{code_sha256, physical_target_id}`.
   Pinned artifacts are **never** deleted while `is_pinned` is true.
2. **Pre-Update Drain & Deterministic Backpressure (`len(pending_gc) <= 2`):** At the start of `function_update` (after acquiring the `"mutating"` lease), any interrupted `candidate` is folded into `pending_gc`, and the adapter inspects every entry in `pending_gc`:
   - For each entry whose `is_pinned` is `false` (operation is terminal and no active invocation in `slots` or `active_invocations` references it), the adapter synchronously deletes its unreferenced staged bundle and native generation target (metered as ordinary work via `RunSubOperation`) and removes the entry from `pending_gc`.
   - **Backpressure When Pinned Artifacts Fill `pending_gc`:** If after the drain pass `len(pending_gc) >= 2` (because `2` prior displaced revisions are still actively executing invocations or awaiting non-terminal provider operations), `function_update` **refuses to stage a 4th unversioned artifact** and fails closed with `ErrorCode.CONFLICT` (`http_status() == 409`) before uploading any new bundle or creating any new native target.
3. **Pre-Staging Candidate Registration:** Before uploading `{new_sha}.zip` or creating `lmfn-{name}-{inc8}-g{op_gen}`, the writer records `candidate = {code_sha256: new_sha, physical_target_id: new_target_id, pending_op_id: "inflight-unconfirmed"}` in `lmcloudfnmeta`.
4. **Post-Commit Synchronous GC of Displaced `$LATEST`:** When `function_update` commits `new_latest` to `lmcloudfnmeta`, if `old_latest` is **not referenced by any published version `1..16`**:
   - If `is_pinned(old_latest)` is `false`, the adapter immediately deletes `old_latest`'s unreferenced staged bundle and native generation target via `RunSubOperation`.
   - If `is_pinned(old_latest)` is `true` (an in-flight invocation in `slots` or `active_invocations` is still running on `old_latest`), the adapter appends `old_latest` to `pending_gc` (`<= 2`), where the next update or delete drains it once the invocation finishes.
5. **Strict Artifact Ceiling (`<= 19` Total):** Because pre-update backpressure guarantees `len(pending_gc) <= 1` before staging a new `candidate` (`<= 1`) alongside `$LATEST` (`1`), a function never has more than **`3` unversioned bundles/targets + `len(versions)` (`<= 16`) versioned bundles/targets = `<= 19` total artifacts** on the provider at any time.

#### 4.3.4 Fenced Deletion (`function_delete` & `Sweep`)
- Conditionally transitions `lmcloudfnmeta` to `state = "deleting"`. Once `"deleting"`, all `function_exists`, `function_get`, `function_list`, `function_update`, `function_publish_version`, `function_alias_*`, and `function_invoke` calls treat `name` as absent (`false` / `NOT_FOUND`).
- Cancels/polls any non-terminal provider operations (`candidate`, `pending_gc`, `latest`) to terminal state via metered `RunSubOperation` calls, then deletes all aliases (`<= 16`), published version deployments (`<= 16`), retained staged bundles (`<= 3 + len(versions)` `<= 19`) under `lmcloudfn-pkgs/{name}/{inc8}/`, and all generation/base native function targets `lmfn-{name}-{inc8}*` (each metered via `hostkit.RunSubOperation` with `isCleanup = true`).
- Deletes the `"deleting"` tombstone in `lmcloudfnmeta` **last** and releases the function's locked cleanup reserves only after every child and native resource is confirmed removed (`200`/`204`/`404`) and no operation remains non-terminal.

#### 4.3.5 Distributed Concurrency Slot & Active-Invocation Pin Authority Across Processes/Cancellations
- Concurrency (`concurrency == -1`, `0`, or `1..100`) and in-flight GC protection are enforced authoritatively across all processes, versions, and aliases of `name` via `slots` and `active_invocations` in `lmcloudfnmeta`:
  - When `concurrency == -1`, `function_invoke` immediately fails with `ErrorCode.PRECONDITION_FAILED` (`http_status() == 429`) upon reading the catalog snapshot.
  - When `concurrency == K` (`1..100`), before dispatching the invocation HTTP request, the caller performs a conditional catalog write acquiring a slot `s in "1"..str(K)` whose entry is absent or expired (`expires_at_unix_ms < now`), setting `slots[s] = {invocation_id, physical_target_id, code_sha256, expires_at_unix_ms: now + timeout_seconds*1000 + 5000}`. If all `K` slots are unexpired, the conditional write fails and `function_invoke` fails immediately with `ErrorCode.PRECONDITION_FAILED` (`http_status() == 429`).
  - When `concurrency == 0` (unreserved default), the pre-dispatch catalog write records `active_invocations[invocation_id] = {physical_target_id, code_sha256, expires_at_unix_ms: now + timeout_seconds*1000 + 5000}` (cleaning any expired entries) so `is_pinned` protects the resolved target from GC while the invocation runs.
  - **No Early Release on Caller Death or Cancellation:** `slots[s]` and `active_invocations[invocation_id]` are released early (conditional on `invocation_id`) **only** when the provider returns a completed HTTP response (`200` or pre-execution `4xx`). If the caller process is killed, its context is cancelled, or the transport connection drops while the remote invocation may still be running, the entry remains held in `lmcloudfnmeta` until `expires_at_unix_ms` (`timeout_seconds + 5 s`), preventing both premature concurrency slot reuse and premature GC deletion while the orphaned remote execution finishes.

---

### 4.4 Cost Admission, Settlement, and Cleanup Reserves (`CostReport` & `MetricsReport`)

#### 1. Integer-Nanodollar Tariff Model (`service == "function"`)
To align with `hostkit/safety/cost.go`'s exact integer-nanodollar (`$10^{-9}`) arithmetic and real cloud serverless pricing structures:
- **Synthetic Simulator Reference Tariff:**
  - **Control-plane operations** (`function_create`, `function_update`, `function_delete`, `function_exists`, `function_get`, `function_list`, `function_publish_version`, `function_versions`, `function_alias_set`, `function_alias_get`, `function_alias_delete`):
    - `unit_price_usd = $0.00000020` (`200` nanodollars / request unit), `1` billing unit per physical HTTP attempt (plus any `RunSubOperation` storage/catalog calls metered under their respective `storage` / `tables` operations).
  - **Data-plane invocation (`function_invoke`):**
    - `unit_price_usd = $0.000000002` (`2` nanodollars / unit), `byte_price_usd_per_gib = $0.09` / GiB.
    - Each physical invocation attempt charges **`100` base request units** (`100 * 2 nanodollars = 200 nanodollars = $0.00000020`, matching AWS Lambda's `$0.20 / 1M requests` base fee) **plus** `billed_ms * (memory_mb / 128)` compute units (`2` nanodollars per 128 MiB-ms = `$0.000016 / GB-s`):
      $$\text{billing\_units}(\text{function\_invoke}) = 100 + \text{billed\_ms} \times \left(\frac{\text{memory\_mb}}{128}\right)$$
    - Every unit is an exact integer multiple of `2` nanodollars, so `billing_units * unit_price_usd` has zero fractional-nanodollar rounding error.
- **Live-Mode Verified Regional Price Tables (`10-cost-perf-design.md` & `14-live-safety.md`):**
  - The synthetic tariff above is **strictly for simulator/fake runs**. In `--live` mode, `hostkit/safety` fails closed unless a verified regional price table (`prices/<provider>/<region>.json`, `verified: true`, age `<= 90` days) is loaded, pricing request fees, physical SKU memory-duration, Cloud Build / staging storage, and physical wire/log/artifact transfer with **ceiling rounding to integer nanodollars**.

#### 2. Pinned Pre-Attempt Invocation Admission, Physical vs. Logical Bytes, and Validated Duration Settlement
1. **Resolve & Pin Before Admission:**
   - Every `function_invoke(name, qualifier, payload_json)` first resolves `qualifier` via a metered catalog read (`RunSubOperation`) in `lmcloudfnmeta`, obtaining the target's **immutable physical deployment identifier** (`physical_target_id` / `service_uri` / `native_aws_ver` / `functionId`) AND its committed `(timeout_seconds, memory_mb)`.
   - The subsequent invocation request dispatches **specifically to that pinned immutable target**. (If any fallback path cannot pin the target at dispatch time, `ReserveBeforeAttempt` reserves the portable global maximum `100 + 230,000 * (2048 / 128) = 3,680,100` units.)
2. **Pre-Attempt Reservation (`ReserveBeforeAttempt` — Conservative Outer Wire Bound):**
   - For the pinned target `(timeout_seconds, memory_mb)`:
     $$\text{max\_units} = 100 + (\text{timeout\_seconds} \times 1000) \times \left(\frac{\text{memory\_mb}}{128}\right), \quad \text{max\_wire\_bytes} = \text{utf8\_len}(\text{payload\_json}) + 2097152$$
   - Note that pre-attempt admission reserves the full **`2 MiB` (`2,097,152` bytes) outer wire envelope** (covering up to `1 MiB` response payload + base64 tail logs + HTTP/JSON envelope overhead) so physical network transfer can never exceed the admitted byte budget. If reserving `(max_units, max_wire_bytes)` exceeds the active script work sub-cap (`cost_cap_usd()`) or operator total ceiling (`<= $0.25`), `function_invoke` is refused pre-flight with `ErrorCode.COST_CAP_EXCEEDED` (`http_status() == 0`).
3. **Authoritative Duration Validation & Settlement:**
   - On a completed `200` response, the adapter validates `provider_billed_ms`: it must be present, an integer, and satisfy `1 <= provider_billed_ms <= timeout_seconds * 1000`.
   - **Malformed / Out-of-Range Billing Metadata Retains Full Reservation:** If `provider_billed_ms` is missing, non-integer, `< 1`, or `> timeout_seconds * 1000`, the host treats the billing metadata as unverifiable and settles at the **full worst-case duration (`timeout_seconds * 1000` ms)** — never clamping a corrupt value downward to release money!
   - When `provider_billed_ms` is valid, `settled_billed_ms` is:
     $$\text{settled\_billed\_ms} = \max\bigl(1,\; \text{provider\_billed\_ms},\; \min(\lceil \text{host\_elapsed\_ms} \rceil,\; \text{timeout\_seconds} \times 1000)\bigr)$$
   - In simulator/reference `CostReport` and `MetricsReport`, settled `bytes()` / `bytes_out()` / `bytes_in()` record the deterministic logical JSON payload bytes (`utf8_len(payload_json) + utf8_len(result.payload())`) for cross-provider conformance parity, while in `--live` mode the cost journal settles against physical wire bytes (`request_wire_bytes + response_wire_bytes + log_bytes`).
   - **No-Replay & Full Reservation Retention on Lost Replies:** `function_invoke` is non-idempotent (`hostkit/retry.go` POST no-replay rule). Once dispatched on the wire, it is **never retried**. If the HTTP call fails due to transport drop, context cancellation, client timeout, or process crash, the **entire worst-case reservation (`max_units`, `max_wire_bytes`) is permanently retained** in the journal.

#### 3. Provider-Tariff-Derived Cleanup Reserves (`function_create`, `function_publish_version`, `function_alias_set`)
Because tearing down a function touches `tables` (`lmcloudfnmeta` catalog reads/writes at up to `$0.00000125`/op), `storage` (`lmcloudfn-pkgs` `object_list` at `$0.00000500`/req and `object_delete`), and `function` control-plane calls (`$0.00000020`/req), cleanup commitments are derived from the **actual multi-service tariffs with `3×` retry headroom**:
- `function_create`: locks **`$0.00015000` (`150,000` nanodollars)** base cleanup reserve, covering: `1` catalog read + `1` `"deleting"` tombstone write + `3` base operation cancel/status probes + `1` staged-prefix `object_list` page + `3` base staged-bundle deletes (`$LATEST` + `pending_gc` / `candidate`) + `1` native list probe + `3` base native target deletes + `1` final catalog tombstone delete, all × `3` retry attempts.
- `function_publish_version` (`1..16`): locks an **additional `$0.00003000` (`30,000` nanodollars)** per published version before dispatch, covering `1` versioned staged-bundle delete + `1` dedicated native version/service/function delete + `1` catalog update × `3` retry attempts.
- `function_alias_set` (when creating a new alias, `1..16`): locks an **additional `$0.00001000` (`10,000` nanodollars)** per alias before dispatch (released on `function_alias_delete` or consumed/released on `function_delete`).
- Even with maximum children (`16` versions + `16` aliases), a function's total locked cleanup reserve is `$0.00079000` (`< $0.001`), fitting comfortably inside the `$0.01` default cleanup headroom while strictly covering every multi-service teardown call and retry. If locking any cleanup reserve would exceed the cleanup budget / operator total ceiling, the operation fails pre-flight with `ErrorCode.COST_CAP_EXCEEDED`.

---

### 4.5 Dry-Run (`lmscript --dry-run`) Semantics
In `cloudhost`, all `function_*` mutators and `function_invoke` have explicit Dry slots:
- `function_invoke` is classified as an effectful execution operation: in `--dry-run` mode it spawns **zero** handler processes and makes **zero** network calls, returning a deterministic preview `FunctionInvokeResult` (`status_code() == 200`, `payload() == "{}"`, `logs() == ""`, `function_error() == ""`, `is_error() == false`, `executed_version()` matching the resolved dry version, `duration_ms() == 0.0`, `billed_ms() == 1`, `memory_mb()` from the dry config).
- `function_create`, `function_update`, `function_delete`, `function_publish_version`, `function_alias_set`, and `function_alias_delete` mutate the run-local dry overlay so `function_exists`, `function_get`, `function_list`, `function_versions`, and `function_alias_get` stay coherent without network traffic.

---

### 4.6 Live-Mode Fail-Closed Safety (`14-live-safety.md`)

In accordance with [`14-live-safety.md`](file:///home/ubuntu/cloud/lmcloud/durable-memory/14-live-safety.md):
1. **Runner Exclusion:** The conformance runner `--live` profile (`tests/run-conformance.sh`) explicitly excludes `function/` alongside `cost-perf/`, `tables/`, and `permissions/`.
2. **Direct Adapter Fail-Closed Gate:** Every host's `Functions` adapter in `--live` mode refuses all `function_*` operations pre-flight with `ErrorCode.PERMISSION_DENIED` (`LiveFunctionNotCertified`) until the provider's live function adapter, verified regional price table, and execution role isolation pass certification.
3. **Mandatory Live Execution Guardrails (Once Certified):**
   - Double opt-in (`--live` CLI flag + `LMCLOUD_LIVE=I_UNDERSTAND_REAL_CLOUD_COSTS` + immutable `live-policy.json` in `LMCLOUD_STATE_DIR`),
   - Explicit operator-supplied, pre-provisioned least-privilege execution identity (`LMCLOUD_LIVE_FUNCTION_ROLE`, allowlisted in `live-policy.json`; hosts **never** create or attach IAM roles/policies in `--live` mode),
   - Logical function `name` must carry the run's required live prefix (`LMCLOUD_NAME_PREFIX`) and match the `(run_id, scope_prefix, create_token)` recorded in both the local `hostkit/safety` journal and `lmcloudfnmeta` (any foreign or untagged resource fails closed with `ErrorCode.PERMISSION_DENIED`), and
   - Verified regional price table (`prices/<provider>/<region>.json`, `verified: true`, age `<= 90` days) with pre-attempt worst-case cost reservation inside the durable `$0.25` hard ceiling.
