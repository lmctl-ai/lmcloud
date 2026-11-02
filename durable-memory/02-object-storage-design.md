# 02 — Object Storage Slice Design (`lmcloud`)

## 1. Overview & Schema Binding Contract (M1)

`lmcloud` defines a single provider-neutral `lmcode` schema (`schema/lmcloud.dsl.json`, `"dsl.schema": 2`, `"name": "lmcloud"`) implemented identically by all four Go hosts built on `github.com/lmctl-ai/lmcode-go`:
- `lmaws` (AWS S3 / `awssim`)
- `lmazure` (Azure Blob Storage / `azuresim`)
- `lmgcp` (Google Cloud Storage / `gcpsim`)
- `lmoci` (OCI Object Storage / `ocisim`)

### 1.1 Canonical Schema Identity & CI Byte-Identity Gate (M1)
- **Raw domain-only schema bytes:** Following `spec/schema.md` (§"The implicit standard merge: effective vs raw schema" and §"Binding: the SHA-256 of the exact bytes") and `lmcode-go-sample/sample-suite/CONTRACT.md`, `schema/lmcloud.dsl.json` is maintained in **raw domain-only form** (declaring `lmcloud`'s own enums, types, context `cloud: Cloud`, and `print`/`assert_close`, while referencing standard types `StrList` and `StrMap`). Both `lmscript` (`parseDslSchema`) and `lmcode-go` (`lmcode.Load` + `lmcode.RegisterStd`) merge the standard library catalog in memory while computing `sha256(schema.bytes)` over the raw `schema/lmcloud.dsl.json` bytes.
- **Byte-identical host discovery:** All four Go hosts embed `schema/lmcloud.dsl.json` verbatim (`//go:embed`) and emit byte-identical output for `--lmcode-schema --json`, `--lmcode-schema`, and `--lmcode-signatures`.
- **No provider-specific extensions:** No host may add provider-specific types, methods, or overloads to `schema/lmcloud.dsl.json`.
- **CI gate:** CI must run `cmp -s` across `lmaws --lmcode-schema --json`, `lmazure --lmcode-schema --json`, `lmgcp --lmcode-schema --json`, `lmoci --lmcode-schema --json`, and `lmscript --lmcode-schema --json schema/lmcloud.dsl.json`.

```lms
program = _lmcode_ schema="schema/lmcloud.dsl.json";
  cloud.set_endpoint("storage", "http://127.0.0.1:4566");
  cloud.bucket_create("app-artifacts");
  let meta_in = str_map().set("env", "dev");
  let meta = cloud.object_put("app-artifacts", "releases/v1.txt", "hello world", "text/plain", meta_in);
  print(meta.etag());
  let body = cloud.object_get("app-artifacts", "releases/v1.txt");
  print(body);
end _lmcode_
r = run_lmcode(program, {command:["lmaws", "--lmcode", "$DSLFILE"]});
```

---

## 2. Common Denominator Operations & Types

### 2.1 Context Object (`cloud: Cloud`)

| Category | Signature | Behavior |
|---|---|---|
| Provider identity | `cloud.provider() -> string` | Returns `"aws"`, `"azure"`, `"gcp"`, or `"oci"`. |
| Endpoint query (M4) | `cloud.endpoint(service: string) -> string` | Active base endpoint URL for `service` (e.g. `"storage"`, `"queue"`; empty string when using default live cloud endpoints). Any userinfo is stripped (M2). |
| Endpoint override (M4) | `cloud.set_endpoint(service: string, url: string) -> self` | Overrides the endpoint URL for `service` (`"storage"`, `"queue"`, `"tables"`, `"vm"`, `"container"`, `"lambda"`, `"valkey"`, `"userpool"`, `"permissions"`, `"cost"`, or `"*"` for all services). Unknown service or non-loopback `http://` fails pre-flight with `ErrorCode.INVALID_ARGUMENT` (M2, M4). |
| Error abort mode | `cloud.abort_on_error() -> bool` | Whether non-probe errors abort the `_lmcode_` block (`true` by default). |
| Set abort mode | `cloud.set_abort_on_error(abort: bool) -> self` | Toggles whether failed operations abort (`true`, default) or return a sentinel value and record `cloud.last_error()` (`false`). |
| Error inspection | `cloud.last_error() -> CloudError` | Structured error from the most recent operation (`ErrorCode.OK` if none). |
| Bucket create (H3) | `cloud.bucket_create(bucket: string) -> bool` | Ensures `bucket` exists in the active scope. Returns `true` if newly created, `false` if already existed and owned by the caller's scope (`lmaws` issues `HEAD` before `PUT` because S3 `us-east-1` returns `200` on re-creating an owned bucket). Fails on invalid name or foreign bucket conflict. |
| Bucket delete | `cloud.bucket_delete(bucket: string) -> bool` | Deletes an empty `bucket`. Returns `true` if deleted, `false` if already absent. Fails with `ErrorCode.CONFLICT` if the bucket is non-empty. |
| Bucket exists | `cloud.bucket_exists(bucket: string) -> bool` | Returns `true` if `bucket` exists and is accessible, `false` on `404` (`NoSuchBucket`/`ContainerNotFound`/`notFound`/`BucketNotFound`). Fails on `401`/`403` (and OCI `404 NotAuthorizedOrNotFound`, see H1) rather than masking auth errors as `false`. |
| Bucket list (M7) | `cloud.bucket_list() -> StrList` | Follows all continuation pages (`ContinuationToken` / `NextMarker` / `nextPageToken` / `opc-next-page`) and returns all bucket names in the active account/project/compartment in ascending lexicographical UTF-8 byte order. |
| Object put (basic) | `cloud.object_put(bucket: string, key: string, data: string) -> ObjectMeta` | Uploads raw bytes `data` with `"application/octet-stream"` and empty user metadata. Overwrites existing object atomically. |
| Object put (full) | `cloud.object_put(bucket: string, key: string, data: string, content_type: string, metadata: StrMap) -> ObjectMeta` | Uploads raw bytes `data` with validated `content_type` (M5) and custom `metadata` (`StrMap`). |
| Object get | `cloud.object_get(bucket: string, key: string) -> string` | Downloads raw object bytes. Fails with `ErrorCode.NOT_FOUND` if bucket or key does not exist. |
| Object head | `cloud.object_head(bucket: string, key: string) -> ObjectMeta` | Fetches object metadata without body. If the bucket exists and the object key does not exist (`404`), returns an `ObjectMeta` with `exists() == false` and `ErrorCode.OK`; if the bucket does not exist (`NOT_FOUND`) or auth fails (`PERMISSION_DENIED`), raises a host error. |
| Object delete (M8) | `cloud.object_delete(bucket: string, key: string) -> void` | Ensures `key` is absent from `bucket`. Idempotent when `bucket` exists: succeeds with `ErrorCode.OK` whether `key` existed or was already missing. Fails with `ErrorCode.NOT_FOUND` if `bucket` does not exist. |
| Object list (prefix) | `cloud.object_list(bucket: string, prefix: string) -> ObjectListPage` | Lists up to 1000 objects matching `prefix` from the start of `bucket`. |
| Object list (paged) | `cloud.object_list(bucket: string, prefix: string, max_keys: int, page_token: string) -> ObjectListPage` | Lists up to `max_keys` (`1..1000`, `0` = default `1000`) objects matching `prefix`, continuing from opaque `page_token` (`""` for first page). |
| Object list all (M7) | `cloud.object_list_all(bucket: string, prefix: string) -> StrList` | Follows all continuation tokens for `prefix` in `bucket` and returns all matching object keys in ascending lexicographical UTF-8 byte order. |

### 2.2 Value Types & Enums

- **`ErrorCode` (enum)**:
  - `OK` — No error
  - `INVALID_ARGUMENT` — Bucket name, object key, `content_type`, metadata key/value/size, service name, endpoint URL, or pagination argument failed pre-flight validation
  - `NOT_FOUND` — Bucket or object does not exist (`404`)
  - `CONFLICT` — Bucket already owned by another tenant (`409`) or bucket is not empty on `bucket_delete` (`409`)
  - `PRECONDITION_FAILED` — Conditional check failed (`412`)
  - `UNAUTHENTICATED` — Missing or invalid credentials/signature (`401` or body-bearing auth-failure `403`, see H2)
  - `PERMISSION_DENIED` — Authenticated caller lacks IAM/RBAC permission (`403`, or OCI `404 NotAuthorizedOrNotFound`, see H1)
  - `INTERNAL` — Upstream `5xx` after retries, transport failure, or unexpected response
- **`CloudError`**:
  - `ok() -> bool` (`code() == ErrorCode.OK`)
  - `code() -> ErrorCode`
  - `http_status() -> int` (`0` for pre-flight validation errors)
  - `provider_code() -> string` (raw provider code, e.g. `"NoSuchKey"`, `"BlobNotFound"`, `"BucketNotEmpty"`, `"NotAuthorizedOrNotFound"`)
  - `message() -> string` (redacted diagnostic message)
- **`ObjectMeta`** (returned by `object_put` and `object_head`):
  - `exists() -> bool`
  - `bucket() -> string`
  - `key() -> string`
  - `size() -> int` (payload length in bytes)
  - `etag() -> string` (opaque provider ETag with surrounding `"` stripped; see L4)
  - `content_type() -> string` (defaults to `"application/octet-stream"`)
  - `metadata() -> StrMap` (lowercased user metadata keys with provider prefixes stripped)
- **`ObjectSummary`** (element of `ObjectListPage`):
  - `key() -> string`
  - `size() -> int`
  - `etag() -> string` (opaque provider ETag with surrounding `"` stripped; see L4)
- **`ObjectListPage`** (iterable in `for (item in page)` via `len`/`at`):
  - `len() -> int`
  - `at(index: int) -> ObjectSummary`
  - `keys() -> StrList`
  - `has_more() -> bool`
  - `next_token() -> string` (`""` when `!has_more()`)

---

## 3. Per-Provider Mapping, Credentials & Endpoint Overrides

### 3.1 Operations Mapping

| `lmcloud` Operation | AWS S3 (`lmaws` / `awssim`) | Azure Blob (`lmazure` / `azuresim`) | Google Cloud Storage (`lmgcp` / `gcpsim`) | OCI Object Storage (`lmoci` / `ocisim`) |
|---|---|---|---|---|
| `bucket_create(b)` (H3) | `HEAD /{b}` first (if `200`, return `false`); else `PUT /{b}` (`CreateBucketConfiguration` if region != `us-east-1`) | `PUT /{account}/{b}?restype=container` (`201` -> `true`, `409 ContainerAlreadyExists` -> `false`) | `POST /storage/v1/b?project={project}` (`{"name": b}`; `200` -> `true`, `409` + owned -> `false`) | `POST /n/{ns}/b/` (`{"name": b, "compartmentId": comp}`; `200` -> `true`, `409 BucketAlreadyExists` + owned -> `false`) |
| `bucket_delete(b)` | `DELETE /{b}` | Check empty via `GET /{account}/{b}?restype=container&comp=list&maxresults=1`, then `DELETE /{account}/{b}?restype=container` | `DELETE /storage/v1/b/{b}` | `DELETE /n/{ns}/b/{b}` |
| `bucket_exists(b)` | `HEAD /{b}` | `GET /{account}/{b}?restype=container` (`HEAD` also supported) | `GET /storage/v1/b/{b}` | `HEAD /n/{ns}/b/{b}` (or `GET /n/{ns}/b/{b}` to inspect error code on `404`, see H1) |
| `bucket_list()` (M7) | `GET /` (`ListBuckets`, following `ContinuationToken`) | `GET /{account}?comp=list` (`ListContainers`, following `NextMarker`) | `GET /storage/v1/b?project={project}` (following `nextPageToken`) | `GET /n/{ns}/b/?compartmentId={comp}` (following `opc-next-page`) |
| `object_put(...)` | `PUT /{b}/{k}` + `Content-Type` + `x-amz-meta-*` | `PUT /{account}/{b}/{k}` + `x-ms-blob-type: BlockBlob` + `Content-Type` + `x-ms-meta-*` | `POST /upload/storage/v1/b/{b}/o?uploadType=multipart` (JSON metadata part + raw payload part) | `PUT /n/{ns}/b/{b}/o/{k}` + `Content-Type` + `opc-meta-*` |
| `object_get(b, k)` | `GET /{b}/{k}` | `GET /{account}/{b}/{k}` | `GET /storage/v1/b/{b}/o/{escaped_k}?alt=media` | `GET /n/{ns}/b/{b}/o/{k}` |
| `object_head(b, k)` | `HEAD /{b}/{k}` (requires `s3:ListBucket` for `404` vs `403`, see H2) | `HEAD /{account}/{b}/{k}` | `GET /storage/v1/b/{b}/o/{escaped_k}` (JSON metadata) | `HEAD /n/{ns}/b/{b}/o/{k}` |
| `object_delete(b, k)` (M8) | `HEAD /{b}` if needed, then `DELETE /{b}/{k}` -> `void` | `DELETE /{account}/{b}/{k}` (ignore `BlobNotFound` `404` when container exists) -> `void` | `DELETE /storage/v1/b/{b}/o/{escaped_k}` (ignore object `404` when bucket exists) -> `void` | `DELETE /n/{ns}/b/{b}/o/{k}` (ignore `ObjectNotFound` `404` when bucket exists) -> `void` |
| `object_list(b, p, m, t)` | `GET /{b}?list-type=2&prefix={p}&max-keys={m}&continuation-token={t}` | `GET /{account}/{b}?restype=container&comp=list&prefix={p}&maxresults={m}&marker={t}` | `GET /storage/v1/b/{b}/o?prefix={p}&maxResults={m}&pageToken={t}` | `GET /n/{ns}/b/{b}/o?prefix={p}&limit={m}&start={t}&fields=name,size,etag,timeCreated,md5` |
| `object_list_all(b, p)` (M7) | Loops `object_list(b, p, 1000, token)` until `!has_more()` | Loops `object_list(b, p, 1000, token)` until `!has_more()` | Loops `object_list(b, p, 1000, token)` until `!has_more()` | Loops `object_list(b, p, 1000, token)` until `!has_more()` |

### 3.2 Credential Chains & Ambient Scope Resolution (M2, M3)

When connecting to a **live cloud** (no loopback endpoint override), each host resolves credentials and scope using the standard provider chain. When a **loopback endpoint override** is active (`127.0.0.1`, `localhost`, `[::1]`), **ambient live credentials (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`, `AZURE_STORAGE_TOKEN`/`AZURE_STORAGE_KEY`, `LMGCP_TOKEN`/`GOOGLE_APPLICATION_CREDENTIALS`, `~/.oci/config` live profiles) are NEVER sent (M2)**; only simulator/static credentials (`LMCLOUD_SIM_*` / `LM<PROVIDER>_SIM_*` or built-in open-mode defaults) are used:

| Provider | Live Cloud Credential Chain (M3) | Loopback Simulator Credentials & Scope Defaults (M2, M3) |
|---|---|---|
| **AWS (`lmaws`)** | 1. Env: `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`), region from `AWS_REGION` / `AWS_DEFAULT_REGION`.<br>2. Shared config/credentials files (`~/.aws/credentials`, `~/.aws/config`) using `AWS_PROFILE` (default `"default"`).<br>3. ECS container credentials / EC2 IMDSv2 role. | Credentials: `LMAWS_SIM_ACCESS_KEY_ID` / `LMAWS_SIM_SECRET_ACCESS_KEY` (default `"test"` / `"test"`).<br>Scope: Region `us-east-1`, Account `000000000000`, Path-Style addressing (`UsePathStyle: true`). |
| **Azure (`lmazure`)** | 1. SharedKey: `AZURE_STORAGE_ACCOUNT` + `AZURE_STORAGE_KEY`.<br>2. SAS token: `AZURE_STORAGE_ACCOUNT` + `AZURE_STORAGE_SAS_TOKEN`.<br>3. Bearer token: `AZURE_STORAGE_ACCOUNT` + `AZURE_STORAGE_TOKEN`.<br>4. Entra ID Service Principal: `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`. | Account: `LMAZURE_SIM_ACCOUNT` (default `"devstoreaccount1"`).<br>Auth: `LMAZURE_SIM_TOKEN` (Bearer) or `LMAZURE_SIM_KEY` (SharedKey; defaults to Azurite well-known key in enforce mode or anonymous in open mode). |
| **GCP (`lmgcp`)** | 1. Explicit OAuth2 access token: `LMGCP_TOKEN` or `GOOGLE_OAUTH_ACCESS_TOKEN`.<br>2. Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS` service-account JSON key file, or `~/.config/gcloud/application_default_credentials.json`).<br>3. GCE metadata server.<br>Project from `GOOGLE_CLOUD_PROJECT` / `CLOUDSDK_CORE_PROJECT`; location from `LMGCP_LOCATION` (default `"US"`). | Project: `LMGCP_SIM_PROJECT` (default `"gcpsim-local"`), Location: `"US"`.<br>Auth: `LMGCP_SIM_TOKEN` (`Authorization: Bearer <token>` when set; omitted in open mode). |
| **OCI (`lmoci`)** | 1. Env vars: `OCI_TENANCY_OCID`, `OCI_USER_OCID`, `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY_PATH` (or `OCI_PRIVATE_KEY`), `OCI_REGION`, `OCI_COMPARTMENT_ID`, `OCI_NAMESPACE`.<br>2. Config file: `OCI_CONFIG_FILE` (default `~/.oci/config`) with profile `OCI_CONFIG_PROFILE` (default `"DEFAULT"`). | Namespace: `LMOCI_SIM_NAMESPACE` or discovered via `GET /n/` (fallback `"floci-local"`).<br>Compartment: `LMOCI_SIM_COMPARTMENT_ID` (default `"ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000"`).<br>Region: `"us-ashburn-1"`.<br>Auth: synthetic `keyId` for `floci-local` in open mode; RSA-SHA256 signature from `LMOCI_SIM_KEY_ID` + `LMOCI_SIM_PRIVATE_KEY_PATH` in enforce mode. |

### 3.3 Per-Service Endpoint Override & URL Sanitization (M2, M4)

Hosts resolve the active endpoint for a `service` (here `"storage"`) in precedence order:
1. Explicit runtime call `cloud.set_endpoint("storage", url)` (or `cloud.set_endpoint("*", url)`)
2. Per-service environment variable: `LMCLOUD_STORAGE_ENDPOINT`, then provider-specific `LMAWS_STORAGE_ENDPOINT`, `LMAZURE_STORAGE_ENDPOINT`, `LMGCP_STORAGE_ENDPOINT`, `LMOCI_STORAGE_ENDPOINT`
3. Shared fallback environment variable: `LMCLOUD_ENDPOINT`, then `LMAWS_ENDPOINT`, `LMAZURE_ENDPOINT`, `LMGCP_ENDPOINT`, `LMOCI_ENDPOINT`
4. Default cloud production endpoint (when unset)

**Endpoint security rules (M2):**
- Plain `http://` URLs are accepted **only** when the parsed hostname is a loopback address (`127.0.0.1`, `localhost`, or `[::1]`). Any non-loopback `http://` URL (including `http://127.0.0.1.evil.example`) is rejected pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`).
- Non-loopback endpoint overrides must use `https://`.
- URLs containing userinfo (`http://user:secret@127.0.0.1:4566`) have userinfo stripped (or are rejected with `INVALID_ARGUMENT`), and neither `cloud.endpoint(service)` nor any error message may ever contain userinfo, query secrets, or headers.

| Simulator | Default Loopback Endpoint | Open Mode (Default) | Enforce Mode (`--auth enforce`) |
|---|---|---|---|
| `awssim` | `http://127.0.0.1:4566` | Accepts any SigV4 or unsigned request | Verifies SigV4 signature & IAM policies |
| `azuresim` | `http://127.0.0.1:4577` | Accepts any request under `/devstoreaccount1` | Verifies SharedKey HMAC-SHA256 or Bearer token & RBAC |
| `gcpsim` | `http://127.0.0.1:4588` | Accepts any JSON API request | Verifies `Authorization: Bearer <token>` & IAM bindings (JSON API only) |
| `ocisim` | `http://127.0.0.1:4599` | Extracts tenancy from `Authorization: Signature` `keyId` without RSA check | Verifies RSA-SHA256 HTTP signature & IAM policy rules |

---

## 4. Portable Naming, Percent-Encoding, `content_type` & Metadata Rules

Every host validates all inputs client-side **before** making network calls so invalid inputs fail identically with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`) on all four clouds:

1. **Bucket names (`bucket`) — RE2 + explicit procedural checks (L1):**
   - Must match the RE2-compatible character class and length rule `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$` (length 3..63 bytes; lowercase ASCII letters `a-z`, digits `0-9`, and hyphens `-`; starts and ends with `[a-z0-9]`).
   - Explicit procedural rejections (no PCRE lookahead):
     - Reject if `bucket` contains consecutive hyphens `"--"` (rejected by Azure Blob containers and S3 `--ol-s3` rules).
     - Reject if `bucket` starts with `"xn--"`, `"sthree-"`, `"sthree-configurator"`, or `"amzn-s3-demo-"`, or ends with `"-s3alias"` or `"--ol-s3"` (AWS S3 reserved prefixes/suffixes).
     - Reject if `bucket` starts with `"goog"` or contains `"google"` or `"g00gle"` (GCS reserved strings).
2. **Object keys (`key`) & per-segment percent-encoding (M6):**
   - **Pre-flight validation:**
     - Length: 1..1024 UTF-8 bytes, must be valid UTF-8.
     - Reject if `key` starts or ends with `/`, or contains empty segments (`//`).
     - Reject if `key` contains backslash `\` (Azure Blob converts/rejects `\`).
     - Reject if `key` ends with `.` or if any `/`-delimited segment is `.` or `..` or ends with `.` (`seg == "."`, `seg == ".."`, or `strings.HasSuffix(seg, ".")`, which Azure Blob strips/rejects).
     - Reject if `key` contains any ASCII control character (`0x00..0x1F` or `0x7F`, including `\r`, `\n`, `\x00`).
     - Printable special characters including space (` `), `+`, `%`, `?`, `#`, and multi-byte Unicode (`雪`, `🚀`) are **valid** in object keys.
   - **Per-segment wire percent-encoding (M6):**
     - Split `key` on `/`; for each segment, percent-encode every UTF-8 byte outside RFC 3986 `unreserved` (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`) as uppercase `%XX` (so space -> `%20`, `+` -> `%2B`, `%` -> `%25`, `?` -> `%3F`, `#` -> `%23`):
       - **AWS S3 (`lmaws`):** Join encoded segments with `/` in the request path (`/{bucket}/{seg1}/{seg2}`) and use the exact same path in SigV4 canonical request signing.
       - **Azure Blob (`lmazure`):** Join encoded segments with `/` in the request path (`/{account}/{bucket}/{seg1}/{seg2}`) and sign the exact wire raw path in SharedKey canonicalized resource.
       - **GCS (`lmgcp`):** On `GET`/`PATCH`/`DELETE /storage/v1/b/{bucket}/o/{object}`, percent-encode the entire `key` as a single path segment (including `/` as `%2F`); on `POST /upload/storage/v1/b/{bucket}/o?uploadType=multipart`, pass the raw UTF-8 `key` in the JSON metadata `"name"` field.
       - **OCI (`lmoci`):** Join encoded segments with `/` after `/n/{ns}/b/{bucket}/o/` and sign the exact wire `request-target`.
3. **Content-Type validation (`content_type`) (M5):**
   - Must be 1..255 bytes of printable ASCII (`0x20..0x7E`), containing no CR (`\r`), LF (`\n`), or NUL (`\x00`), and containing a `/` separating non-empty `type/subtype`. Empty or control-character `content_type` fails pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`).
4. **Custom metadata (`metadata: StrMap`) (L7):**
   - Keys must match `^[a-z][a-z0-9_]{0,62}$` (lowercase ASCII letter followed by lowercase ASCII letters, digits, or underscores; required for Azure `x-ms-meta-*` C# identifier compatibility).
   - Values must be printable ASCII (`0x20..0x7E`) without leading or trailing ASCII whitespace, max 32 entries and 2048 bytes combined (`sum(len(k) + len(v)) <= 2048`).
   - Hosts transparently add `x-amz-meta-` (S3), `x-ms-meta-` (Azure), `opc-meta-` (OCI), or JSON `metadata` map entries (GCS) on `object_put`, and strip the prefix + lowercase keys on `object_head`.
   - `TODO(verify-live-oci-metadata)`: Live OCI Object Storage per-header and aggregate `opc-meta-*` limits/case normalization under edge cases are unverified against live OCI and must be confirmed during live-cloud qualification (L7).

---

## 5. Uniform Error Model, Abort Format & Retry Policy (H1, H2, L5)

| `ErrorCode` | HTTP Status | S3 (`awssim`) | Azure (`azuresim`) | GCS (`gcpsim`) | OCI (`ocisim` / Live OCI) |
|---|---|---|---|---|---|
| `INVALID_ARGUMENT` | `0` / `400` | Pre-flight / `InvalidBucketName` | Pre-flight / `InvalidResourceName` | Pre-flight / `invalid` | Pre-flight / `InvalidParameter` |
| `NOT_FOUND` | `404` | `NoSuchBucket`, `NoSuchKey` | `ContainerNotFound`, `BlobNotFound` | `notFound` | `BucketNotFound`, `ObjectNotFound` |
| `CONFLICT` | `409` | `BucketAlreadyExists`, `BucketNotEmpty` | `ContainerAlreadyExists`, non-empty guard | `conflict` (exists / non-empty) | `BucketAlreadyExists`, `BucketNotEmpty` |
| `PRECONDITION_FAILED` | `412` | `PreconditionFailed` | `ConditionNotMet` | `conditionNotMet` | `IfMatchFailed` |
| `UNAUTHENTICATED` | `401` / `403` | `InvalidAccessKeyId`, `SignatureDoesNotMatch`, `MissingAuthenticationToken` (body-bearing ops, see H2) | `AuthenticationFailed` (`x-ms-error-code`) | `UNAUTHENTICATED` (`401`) | `NotAuthenticated` (`401`) |
| `PERMISSION_DENIED` | `403` / `404` (OCI) | `AccessDenied`, or `403` on `HEAD` (H2) | `AuthorizationPermissionMismatch`, `AuthorizationFailure` | `PERMISSION_DENIED` (`403`) | `403 NotAuthorizedOrNotFound` (`ocisim`) AND `404 NotAuthorizedOrNotFound` (live OCI, see H1) |
| `INTERNAL` | `5xx` / net | `InternalError` | `InternalError` | `backendError` | `InternalError` |

### 5.1 Provider-Specific Error Classification Rules (H1, H2)

1. **H1 — OCI `NotAuthorizedOrNotFound` (404 on live OCI vs 403 on `ocisim`):**
   - Real OCI Object Storage returns HTTP `404` (not `403`) with JSON `"code": "NotAuthorizedOrNotFound"` when an authenticated caller lacks `inspect` permission on a bucket or compartment, whereas `ocisim` (`OciAuthFilter.java`) returns HTTP `403` with `"code": "NotAuthorizedOrNotFound"` on policy denial and HTTP `404` with `"code": "BucketNotFound"` / `"ObjectNotFound"` when a resource is absent.
   - **Mapping rule:** `lmoci` MUST map both `403 NotAuthorizedOrNotFound` and `404 NotAuthorizedOrNotFound` to `ErrorCode.PERMISSION_DENIED` — **never** to `exists == false` or `ErrorCode.NOT_FOUND`. Only `404` with `"code": "BucketNotFound"` or `"ObjectNotFound"` maps to `ErrorCode.NOT_FOUND` / `exists == false`. On `bucket_exists` / `object_head`, if `HEAD` returns `404` without a body, `lmoci` issues a lightweight `GET /n/{ns}/b/{bucket}` (metadata only) or inspects `opc-error-code` when needed to distinguish `BucketNotFound` from `NotAuthorizedOrNotFound`.
   - **Live-OCI limitation:** On live OCI, if a caller lacks `BUCKET_INSPECT` / `OBJECT_INSPECT` on the compartment/bucket, even a genuinely non-existent bucket returns `404 NotAuthorizedOrNotFound`, so `lmoci` surfaces `PERMISSION_DENIED`. Consequently, the OCI portion of conformance scenario `12-auth-enforced-denial` is **sim-only**.
2. **H2 — S3 `HEAD` has no response body (`403` classification & `s3:ListBucket` requirement):**
   - S3 `HEAD /{bucket}` (`bucket_exists`) and `HEAD /{bucket}/{key}` (`object_head`) never return an XML body on the wire. Therefore, an HTTP `403` on S3 `HEAD` maps to `ErrorCode.PERMISSION_DENIED`, while `ErrorCode.UNAUTHENTICATED` (`InvalidAccessKeyId`, `SignatureDoesNotMatch`) is recognized via body-bearing operations (`GET`, `PUT`, `DELETE`, `ListBuckets`, `ListObjectsV2`) or by re-issuing a failed `HEAD` as a signed body-bearing `GET` when detailed classification is needed.
   - **S3 `s3:ListBucket` requirement for `object_head`:** AWS S3 requires `s3:ListBucket` permission on the bucket to return `404 Not Found` on `HEAD /{bucket}/{key}` (or `GET /{bucket}/{key}`) when `key` does not exist; without `s3:ListBucket`, S3 returns `403 Forbidden` for missing keys, which `lmaws` maps to `ErrorCode.PERMISSION_DENIED`.

### 5.2 Located `RUN_HOST` Abort Message Format & Transient Retry Policy (L5)

- **Abort message format (L5):** When `cloud.abort_on_error() == true` (the default), any failed operation aborts the `_lmcode_` block with a located `RUN_HOST` error whose message has the exact prefix `[<ErrorCode>]`:
  - Network/provider error: `[<ErrorCode>] <op> (<target>): <redacted summary> (http=<status>, provider_code=<code_or_none>)`
    (e.g. `[NOT_FOUND] object_get (my-bucket/missing.txt): object not found (http=404, provider_code=NoSuchKey)`).
  - Pre-flight validation error: `[INVALID_ARGUMENT] <op>: <reason>` (with `http_status() == 0` and `provider_code() == ""`).
- **Retry policy for `429` / `503 SlowDown` / transient `5xx` (L5):**
  - All four hosts automatically retry HTTP `429 Too Many Requests`, HTTP `503` (`SlowDown` / `ServerBusy` / `ServiceUnavailable`), and transient HTTP `500`/`502`/`504` up to **3 attempts** (initial + 2 retries) with exponential backoff + full jitter (`100ms`, `250ms`, `500ms`, honoring `Retry-After` up to `2s`).
  - If all attempts fail, the host records `ErrorCode.INTERNAL` (with the final `http_status()` and `provider_code()`) and aborts if `abort_on_error()` is `true`.

---

## 6. Idempotency & Edge-Case Normalization (H3, M8)

1. **`bucket_create(bucket) -> bool` (H3):**
   - **S3 `us-east-1` `HEAD`-before-`PUT` rule (H3):** Because AWS S3 in `us-east-1` (and `awssim`) returns HTTP `200 OK` instead of `409` when `CreateBucket` is called on a bucket already owned by the caller, `lmaws` **must** issue `HEAD /{bucket}` before `PUT /{bucket}`: if `HEAD` returns `200`, `bucket_create` returns `false` with `ErrorCode.OK`; if `HEAD` returns `404`, `lmaws` issues `PUT /{bucket}` and returns `true`.
   - On Azure, GCS, and OCI, creating a new bucket returns `200`/`201` (`true`); if the provider returns `409` (`ContainerAlreadyExists` / `conflict` / `BucketAlreadyExists`), the host checks `bucket_exists(bucket)`: if accessible in the caller's scope, returns `false` with `ErrorCode.OK`; otherwise fails with `ErrorCode.CONFLICT`.
2. **`bucket_delete(bucket) -> bool`:**
   - **Non-empty bucket guard on Azure:** S3, GCS, and OCI natively reject deleting a non-empty bucket with HTTP `409 BucketNotEmpty`, whereas Azure Blob REST `DELETE ?restype=container` deletes the container and all blobs inside it. `lmazure` performs a 1-key list check (`maxresults=1`) before deleting the container and fails with `ErrorCode.CONFLICT` (`"BucketNotEmpty"`) if any blob exists.
   - **Missing bucket:** If the bucket does not exist (`404`), `bucket_delete` sets `last_error` to `ErrorCode.OK` and returns `false`.
3. **`object_delete(bucket, key) -> void` (M8):**
   - Returns `void` because S3 `DELETE` returns `204 No Content` regardless of whether `key` existed prior to the call.
   - If `bucket` does not exist, fails with `ErrorCode.NOT_FOUND` (on S3, where `DELETE /{bucket}/{key}` returns `404 NoSuchBucket` in the XML error body, and on Azure/GCS/OCI via error code or `bucket_exists` disambiguation).
   - If `bucket` exists, `object_delete` is idempotent: whether `key` was deleted or was already absent (`404` on Azure/GCS/OCI), `last_error` is `ErrorCode.OK` and `key` is absent afterwards.
4. **`bucket_exists(bucket)` and `object_head(bucket, key)`:**
   - Only a genuine missing-resource `404` (`NoSuchBucket`/`NoSuchKey`, `ContainerNotFound`/`BlobNotFound`, GCS `notFound`, OCI `BucketNotFound`/`ObjectNotFound`) produces `false` / `ObjectMeta.exists() == false` with `ErrorCode.OK`.
   - Calling `object_head(bucket, key)` when `bucket` itself does not exist fails with `ErrorCode.NOT_FOUND`.

---

## 7. Size, Encoding, ETag & Pagination Specification (M7, L3, L4, L6, L7)

- **Maximum object size:** `16 MiB` (`16,777,216` bytes) per `object_put` / `object_get`, matching the enforce-mode body limit in `awssim` and `gcpsim`. Payloads exceeding 16 MiB fail pre-flight with `ErrorCode.INVALID_ARGUMENT`.
- **Binary safety & hex test convention (L6):** In `lmcode-go`, the `lmcode` `string` primitive is backed by a raw byte slice (`[]byte`) without UTF-8 replacement, so arbitrary binary payloads (including `\x00` and invalid UTF-8 sequences like `\xff\xfe`) round-trip byte-for-byte through `object_put` and `object_get`. Conformance tests construct non-UTF-8 binary test payloads exclusively via `str_hex_decode(...)` and verify them via `str_hex_encode(...)` (L6).
- **ETag semantics (L4):** `etag()` returns a non-empty opaque string with surrounding ASCII double quotes (`"`) stripped. Callers may only compare ETags for equality (`==`) or inequality (`!=`) on the **same object within the same provider** (e.g. verifying that overwriting an object changes its ETag); callers must never assume ETags are MD5 hashes or compare ETags across providers.
- **List pagination specification (`object_list`, `object_list_all`, `bucket_list`) (M7, L3):**
  - `max_keys`: `0` selects the default (`1000`); explicit values in `1..1000` request at most `max_keys` items per page; values `< 0` or `> 1000` fail pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`).
  - **Page sizing:** A provider may return fewer than `max_keys` items on a page even when `has_more() == true`; callers must loop while `page.has_more()` rather than assuming fixed page splits (M7).
  - **Token invariant:** `page.has_more()` is `true` if and only if `str_len(page.next_token()) > 0`. On the final page (`!page.has_more()`), `page.next_token()` is `""`.
  - **Ordering:** Keys are returned in ascending lexicographical UTF-8 byte order (`memcmp` order) within each page and monotonically across pages.
  - **Exhaustive helpers (M7):** `cloud.object_list_all(bucket, prefix) -> StrList` and `cloud.bucket_list() -> StrList` follow every continuation token until `!has_more()`.

---

## 8. Deliberately Excluded from the Shared Slice

The following features are excluded from the v1 `lmcloud` object storage slice:
1. **Multipart / resumable / chunked streaming uploads (>16 MiB).**
2. **Presigned URLs / Azure SAS generation / OCI Pre-Authenticated Requests (PARs).**
3. **Object versioning, soft delete & retention/object-lock.**
4. **Server-side copy & atomic rename.**
5. **Bucket ACLs, public-access blocks, CORS, lifecycle policies & KMS key management.**
6. **Bucket-level tags.**
7. **Byte-range `GET` and conditional `If-Match` / `If-None-Match` mutations.**

---

## 9. Decisions

1. **Error signaling mode (abort-by-default + `set_abort_on_error` + `[ERROR_CODE]` prefix, L5):**
   - By default (`cloud.abort_on_error() == true`), failed operations abort the `_lmcode_` program with a located `RUN_HOST` error (`r.ok == false`) prefixed with `[<ErrorCode>]`.
   - Existence probes (`bucket_exists`, `object_head` on a missing key in an existing bucket) and idempotent operations (`bucket_create` on an owned bucket, `bucket_delete` on a missing bucket, `object_delete` on a missing key in an existing bucket) succeed without aborting and set `cloud.last_error()` to `ErrorCode.OK`.
   - Calling `cloud.set_abort_on_error(false)` allows `_lmcode_` programs to inspect `cloud.last_error()` directly without aborting.
2. **Flat method naming + per-service `set_endpoint(service, url)` (M4):**
   - Object storage operations live directly on `cloud` (`bucket_*`, `object_*`), and `cloud.set_endpoint(service, url)` / `cloud.endpoint(service)` take a service identifier (`"storage"`, `"queue"`, etc.) so future slices never alter existing method signatures.
3. **Azure non-empty `bucket_delete` parity & S3 `HEAD`-before-`PUT` `bucket_create` parity (H3):**
   - `lmazure` performs a pre-flight `maxresults=1` blob list check before container deletion and fails with `ErrorCode.CONFLICT` (`BucketNotEmpty`) if any blob is present.
   - `lmaws` performs `HEAD /{bucket}` before `PUT /{bucket}` in `bucket_create` so re-creating an owned bucket in `us-east-1` returns `false` instead of `true`.
4. **Strict pre-flight validation (M5, M6, L1):**
   - Bucket names (RE2 + explicit `--`, S3 reserved, and GCS `goog`/`google` checks), object keys (rejecting `\`, trailing `.`, empty/dot segments, control chars; per-segment RFC 3986 percent-encoding), `content_type` (printable ASCII `type/subtype`, no CR/LF), and metadata keys (`^[a-z][a-z0-9_]{0,62}$`) are validated pre-flight on all four hosts (`ErrorCode.INVALID_ARGUMENT`, `http_status() == 0`).
5. **Simulator test boundary & unique run naming (L2):**
   - Simulators (`awssim`, `azuresim`, `gcpsim`, `ocisim`) are driven **exclusively** by `lmscript` programs through the `lmcode` host binary (`lm<provider>`), never via `curl` or out-of-band HTTP requests, and conformance tests parameterize bucket names with a per-run unique suffix to prevent global collisions and Azure `ContainerBeingDeleted` conflicts.
