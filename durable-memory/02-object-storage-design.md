# 02 — Object Storage Slice Design (`lmcloud`)

## 1. Overview & Execution Model

`lmcloud` defines a single provider-neutral `lmcode` schema (`schema/lmcloud.dsl.json`, `"dsl.schema": 2`, `"name": "lmcloud"`) implemented identically by all four Go hosts built on `github.com/lmctl-ai/lmcode-go`:
- `lmaws` (AWS S3 / `awssim`)
- `lmazure` (Azure Blob Storage / `azuresim`)
- `lmgcp` (Google Cloud Storage / `gcpsim`)
- `lmoci` (OCI Object Storage / `ocisim`)

An `lmscript` program compiles once against `lmcloud.dsl.json` (or via `load_schema(cli="lm<provider>")`) and runs unchanged against any provider:

```lms
s = load_schema(schema="schema/lmcloud.dsl.json");
p = _lmcode_ s;
  cloud.bucket_create("app-artifacts");
  let meta_in = str_map().set("env", "dev");
  let meta = cloud.object_put("app-artifacts", "releases/v1.txt", "hello world", "text/plain", meta_in);
  print(meta.etag());
  let body = cloud.object_get("app-artifacts", "releases/v1.txt");
  print(body);
end _lmcode_
r = run_lmcode(p, options={command: ["lmaws"]});
```

---

## 2. Common Denominator Operations & Types

### 2.1 Context Object (`cloud: Cloud`)

| Category | Signature | Behavior |
|---|---|---|
| Provider identity | `cloud.provider() -> string` | Returns `"aws"`, `"azure"`, `"gcp"`, or `"oci"`. |
| Endpoint config | `cloud.endpoint() -> string` | Active base endpoint URL (empty string when using default live cloud endpoints). |
| Endpoint override | `cloud.set_endpoint(url: string) -> self` | Overrides the storage endpoint at runtime (e.g. `http://127.0.0.1:4566`). |
| Error inspection | `cloud.last_error() -> CloudError` | Structured error from the most recent operation (`ErrorCode.OK` if none). |
| Bucket create | `cloud.bucket_create(bucket: string) -> bool` | Ensures `bucket` exists in the active scope. Returns `true` if newly created, `false` if already existed and owned by the caller's scope. Fails on invalid name or foreign bucket conflict. |
| Bucket delete | `cloud.bucket_delete(bucket: string) -> bool` | Deletes an empty `bucket`. Returns `true` if deleted, `false` if already absent. Fails with `ErrorCode.CONFLICT` if the bucket is non-empty. |
| Bucket exists | `cloud.bucket_exists(bucket: string) -> bool` | Returns `true` if `bucket` exists and is accessible, `false` on `404 Not Found`. Fails on `401`/`403` rather than masking auth errors as `false`. |
| Bucket list | `cloud.bucket_list() -> StrList` | Lists bucket names in the active account/project/compartment in ascending lexicographical UTF-8 byte order. |
| Object put (basic) | `cloud.object_put(bucket: string, key: string, data: string) -> ObjectMeta` | Uploads raw bytes `data` with `"application/octet-stream"` and empty user metadata. Overwrites existing object atomically. |
| Object put (full) | `cloud.object_put(bucket: string, key: string, data: string, content_type: string, metadata: StrMap) -> ObjectMeta` | Uploads raw bytes `data` with explicit `content_type` and custom `metadata` (`StrMap`). |
| Object get | `cloud.object_get(bucket: string, key: string) -> string` | Downloads raw object bytes. Fails with `ErrorCode.NOT_FOUND` if bucket or key does not exist. |
| Object head | `cloud.object_head(bucket: string, key: string) -> ObjectMeta` | Fetches object metadata without body. If the object does not exist (`404`), returns an `ObjectMeta` with `exists() == false` (no host abort); if the bucket does not exist or auth fails, raises a host error (`NOT_FOUND` / `PERMISSION_DENIED`). |
| Object delete | `cloud.object_delete(bucket: string, key: string) -> bool` | Deletes `key` from `bucket`. Idempotent on missing key: returns `true` if the object existed and was deleted (or when the provider does not distinguish, see §6), `false` when known absent; never fails on missing key in an existing bucket. |
| Object list (prefix) | `cloud.object_list(bucket: string, prefix: string) -> ObjectListPage` | Lists up to 1000 objects matching `prefix` from the start of `bucket`. |
| Object list (paged) | `cloud.object_list(bucket: string, prefix: string, max_keys: int, page_token: string) -> ObjectListPage` | Lists up to `max_keys` (`1..1000`, `0` = default `1000`) objects matching `prefix`, continuing from opaque `page_token` (`""` for first page). |

### 2.2 Value Types & Enums

- **`ErrorCode` (enum)**:
  - `OK` (`0`) — No error
  - `INVALID_ARGUMENT` (`1`) — Bucket name, key, metadata key/size, or pagination argument failed portable validation
  - `NOT_FOUND` (`2`) — Bucket or object does not exist (`404`)
  - `CONFLICT` (`3`) — Bucket already owned by another tenant (`409`) or bucket is not empty on `bucket_delete` (`409`)
  - `PRECONDITION_FAILED` (`4`) — Conditional check failed (`412`)
  - `UNAUTHENTICATED` (`5`) — Missing or invalid credentials/signature (`401` or auth-failure `403`)
  - `PERMISSION_DENIED` (`6`) — Authenticated caller lacks IAM/RBAC permission (`403`)
  - `INTERNAL` (`7`) — Upstream `5xx`, transport failure, or unexpected response
- **`CloudError`**:
  - `ok() -> bool` (`code() == ErrorCode.OK`)
  - `code() -> ErrorCode`
  - `http_status() -> int` (`0` for pre-flight validation errors)
  - `provider_code() -> string` (raw provider code, e.g. `"NoSuchKey"`, `"BlobNotFound"`, `"BucketNotEmpty"`)
  - `message() -> string`
- **`ObjectMeta`** (returned by `object_put` and `object_head`):
  - `exists() -> bool`
  - `bucket() -> string`
  - `key() -> string`
  - `size() -> int` (payload length in bytes)
  - `etag() -> string` (normalized without surrounding double quotes `""`)
  - `content_type() -> string` (defaults to `"application/octet-stream"`)
  - `metadata() -> StrMap` (lowercased user metadata keys with provider prefixes stripped)
- **`ObjectSummary`** (element of `ObjectListPage`):
  - `key() -> string`
  - `size() -> int`
  - `etag() -> string` (normalized without surrounding quotes)
- **`ObjectListPage`** (iterable in `for (item in page)` via `len`/`at`):
  - `len() -> int`
  - `at(index: int) -> ObjectSummary`
  - `keys() -> StrList`
  - `has_more() -> bool`
  - `next_token() -> string` (`""` when `!has_more()`)

---

## 3. Per-Provider Mapping Table

### 3.1 Operations Mapping

| `lmcloud` Operation | AWS S3 (`lmaws` / `awssim`) | Azure Blob (`lmazure` / `azuresim`) | Google Cloud Storage (`lmgcp` / `gcpsim`) | OCI Object Storage (`lmoci` / `ocisim`) |
|---|---|---|---|---|
| `bucket_create(b)` | `PUT /{b}` (`CreateBucketConfiguration` if region != `us-east-1`) | `PUT /{account}/{b}?restype=container` | `POST /storage/v1/b?project={project}` (`{"name": b}`) | `POST /n/{ns}/b/` (`{"name": b, "compartmentId": comp}`) |
| `bucket_delete(b)` | `DELETE /{b}` | Check empty via `GET /{account}/{b}?restype=container&comp=list&maxresults=1`, then `DELETE /{account}/{b}?restype=container` | `DELETE /storage/v1/b/{b}` | `DELETE /n/{ns}/b/{b}` |
| `bucket_exists(b)` | `HEAD /{b}` | `GET /{account}/{b}?restype=container` (`HEAD` also supported) | `GET /storage/v1/b/{b}` | `HEAD /n/{ns}/b/{b}` |
| `bucket_list()` | `GET /` (`ListBuckets`) | `GET /{account}?comp=list` (`ListContainers`) | `GET /storage/v1/b?project={project}` | `GET /n/{ns}/b/?compartmentId={comp}` |
| `object_put(...)` | `PUT /{b}/{k}` + `Content-Type` + `x-amz-meta-*` | `PUT /{account}/{b}/{k}` + `x-ms-blob-type: BlockBlob` + `Content-Type` + `x-ms-meta-*` | `POST /upload/storage/v1/b/{b}/o?uploadType=multipart` (JSON metadata part + raw payload part) | `PUT /n/{ns}/b/{b}/o/{k}` + `Content-Type` + `opc-meta-*` |
| `object_get(b, k)` | `GET /{b}/{k}` | `GET /{account}/{b}/{k}` | `GET /storage/v1/b/{b}/o/{url_escaped_k}?alt=media` | `GET /n/{ns}/b/{b}/o/{k}` |
| `object_head(b, k)` | `HEAD /{b}/{k}` | `HEAD /{account}/{b}/{k}` | `GET /storage/v1/b/{b}/o/{url_escaped_k}` (JSON metadata) | `HEAD /n/{ns}/b/{b}/o/{k}` |
| `object_delete(b, k)` | `DELETE /{b}/{k}` | `DELETE /{account}/{b}/{k}` | `DELETE /storage/v1/b/{b}/o/{url_escaped_k}` | `DELETE /n/{ns}/b/{b}/o/{k}` |
| `object_list(b, p, m, t)` | `GET /{b}?list-type=2&prefix={p}&max-keys={m}&continuation-token={t}` | `GET /{account}/{b}?restype=container&comp=list&prefix={p}&maxresults={m}&marker={t}` | `GET /storage/v1/b/{b}/o?prefix={p}&maxResults={m}&pageToken={t}` | `GET /n/{ns}/b/{b}/o?prefix={p}&limit={m}&start={t}&fields=name,size,etag,timeCreated,md5` |

### 3.2 Ambient Scope: Namespace, Account, Project, Region & Compartment

Because `lmcloud` programs are provider-neutral, bucket and object calls do not take provider-specific parent scopes (`account`, `project`, `namespace`, `compartment_id`) in their method signatures. Instead, each host resolves its ambient scope from environment variables / credentials with deterministic defaults for local `<provider>sim` execution:

| Provider | Scope Parameters | Environment Variables | `<provider>sim` Default |
|---|---|---|---|
| **AWS (`lmaws`)** | Region, Account ID, Path-Style | `AWS_REGION` / `AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Region `us-east-1`, Account `000000000000`, `test`/`test`, Path-Style enabled whenever endpoint is overridden |
| **Azure (`lmazure`)** | Storage Account Name, SharedKey / Bearer Token | `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_KEY`, `AZURE_STORAGE_TOKEN` | Account `devstoreaccount1`, Azurite well-known key in SharedKey mode or open mode |
| **GCP (`lmgcp`)** | Project ID, Location, Bearer Token | `GOOGLE_CLOUD_PROJECT` / `CLOUDSDK_CORE_PROJECT`, `LMGCP_LOCATION`, `LMGCP_TOKEN` | Project `gcpsim-local`, Location `US` |
| **OCI (`lmoci`)** | Namespace, Compartment OCID, Region, Tenancy/User/Key | `OCI_NAMESPACE`, `OCI_COMPARTMENT_ID`, `OCI_REGION` | Namespace discovered via `GET /n/` (fallback `floci-local`), Compartment defaults to tenancy OCID (`ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000`), Region `us-ashburn-1` |

### 3.3 Endpoint Override & Simulator Ports

Hosts resolve the active endpoint in precedence order:
1. Explicit runtime call `cloud.set_endpoint(url)`
2. Shared environment variable `LMCLOUD_ENDPOINT`
3. Provider-specific environment variable (`LMAWS_ENDPOINT`, `LMAZURE_ENDPOINT`, `LMGCP_ENDPOINT`, `LMOCI_ENDPOINT`)
4. Default cloud production endpoint (when unset)

| Simulator | Default Loopback Endpoint | Open Mode (Default) | Enforce Mode (`--auth enforce`) |
|---|---|---|---|
| `awssim` | `http://127.0.0.1:4566` | Accepts any SigV4 or unsigned request | Verifies SigV4 signature & IAM policies |
| `azuresim` | `http://127.0.0.1:4577` | Accepts any request under `/devstoreaccount1` | Verifies SharedKey HMAC-SHA256 or Bearer token & RBAC |
| `gcpsim` | `http://127.0.0.1:4588` | Accepts any JSON API request | Verifies `Authorization: Bearer <token>` & IAM bindings (JSON API only; XML/resumable/batch rejected) |
| `ocisim` | `http://127.0.0.1:4599` | Extracts tenancy from `Authorization: Signature` `keyId` (or default `floci-local`) without RSA check | Verifies RSA-SHA256 HTTP signature & IAM policy rules |

---

## 4. Portable Naming & Metadata Rules

Every host validates names client-side **before** making network calls so invalid inputs fail identically with `ErrorCode.INVALID_ARGUMENT` on all four clouds:

1. **Bucket names (`bucket`)**:
   - Regex: `^[a-z0-9](?:[a-z0-9]|-(?!-)){1,61}[a-z0-9]$` (length 3..63).
   - Lowercase ASCII letters, digits, and single hyphens only.
   - Disallows consecutive hyphens `--` (rejected by Azure Blob containers), underscores `_` (rejected by S3 and Azure), dots `.` (S3 virtual-host TLS/IP rules), and leading prefix `goog` or substring `google` (rejected by GCS).
2. **Object keys (`key`)**:
   - Length: 1..1024 UTF-8 bytes.
   - Must not start or end with `/`, must not contain empty path segments (`//`), dot segments (`.` or `..`), NUL (`\x00`), or CR/LF (`\r`, `\n`). This satisfies `azuresim` and `gcpsim` enforce-mode path sanitizers as well as S3/OCI key rules.
3. **Custom metadata (`metadata: StrMap`)**:
   - Keys must match `^[a-z][a-z0-9_]{0,62}$` (lowercase ASCII letter followed by lowercase ASCII letters, digits, or underscores).
   - Rationale: Azure Blob `x-ms-meta-*` headers require valid C# identifiers (letters, digits, underscores; cannot start with a digit; hyphens are rejected), while S3/Azure/OCI lowercase HTTP header names.
   - Hosts transparently add `x-amz-meta-` (S3), `x-ms-meta-` (Azure), `opc-meta-` (OCI), or JSON `metadata` map entries (GCS) on `object_put`, and strip the prefix + lowercase keys on `object_head`.

---

## 5. Uniform Error Model

| `ErrorCode` | HTTP Status | S3 (`awssim`) | Azure (`azuresim`) | GCS (`gcpsim`) | OCI (`ocisim`) |
|---|---|---|---|---|---|
| `INVALID_ARGUMENT` | `0` / `400` | Pre-flight / `InvalidBucketName` | Pre-flight / `InvalidResourceName` | Pre-flight / `invalid` | Pre-flight / `InvalidParameter` |
| `NOT_FOUND` | `404` | `NoSuchBucket`, `NoSuchKey` | `ContainerNotFound`, `BlobNotFound` | `notFound` | `BucketNotFound`, `ObjectNotFound` |
| `CONFLICT` | `409` | `BucketAlreadyExists`, `BucketNotEmpty` | `ContainerAlreadyExists`, non-empty guard | `conflict` (exists / non-empty) | `BucketAlreadyExists`, `BucketNotEmpty` |
| `PRECONDITION_FAILED` | `412` | `PreconditionFailed` | `ConditionNotMet` | `conditionNotMet` | `IfMatchFailed` |
| `UNAUTHENTICATED` | `401` / `403` | `InvalidAccessKeyId`, `SignatureDoesNotMatch`, `MissingAuthenticationToken` | `AuthenticationFailed` | `UNAUTHENTICATED` (`401`) | `NotAuthenticated` (`401`) |
| `PERMISSION_DENIED` | `403` | `AccessDenied` | `AuthorizationPermissionMismatch`, `AuthorizationFailure` | `PERMISSION_DENIED` (`403`) | `NotAuthorizedOrNotFound` (`403`) |
| `INTERNAL` | `5xx` / net | `InternalError` | `InternalError` | `backendError` | `InternalError` |

**Note on OCI `403 NotAuthorizedOrNotFound`:** OCI returns HTTP `403` with `NotAuthorizedOrNotFound` for unauthorized operations when `--auth enforce` is active, and HTTP `404` (`BucketNotFound` / `ObjectNotFound`) when an authenticated caller accesses a missing resource in an allowed compartment. Therefore `lmoci` maps HTTP `404` to `NOT_FOUND` and HTTP `403` to `PERMISSION_DENIED`.

---

## 6. Idempotency & Edge-Case Normalization

1. **`bucket_create(bucket)`**:
   - If the bucket is newly created (`200`/`201`), returns `true`.
   - If the bucket already exists (`409 BucketAlreadyOwnedByYou` / `ContainerAlreadyExists` / `conflict` / `BucketAlreadyExists`), the host verifies whether the bucket is accessible in the caller's scope (`bucket_exists(bucket)`): if accessible, returns `false` (idempotent success); otherwise fails with `ErrorCode.CONFLICT`.
2. **`bucket_delete(bucket)`**:
   - **Non-empty bucket guard on Azure:** S3, GCS, and OCI natively reject deleting a non-empty bucket with HTTP `409 BucketNotEmpty`, whereas Azure Blob REST `DELETE ?restype=container` deletes the container and all blobs inside it. To guarantee identical cross-cloud behavior, `lmazure` performs a 1-key list check (`maxresults=1`) before deleting the container and fails with `ErrorCode.CONFLICT` (`"BucketNotEmpty"`) if any blob exists.
   - **Missing bucket:** If the bucket does not exist (`404`), `bucket_delete` sets `last_error` to `OK` and returns `false` (idempotent post-condition: bucket is absent).
3. **`object_delete(bucket, key)`**:
   - If `bucket` does not exist, fails with `ErrorCode.NOT_FOUND`.
   - If `bucket` exists and `key` is missing: S3 returns `204 No Content` natively; Azure, GCS, and OCI return `404`. All four hosts normalize a missing-key `404` (when the bucket exists) into an idempotent success (`last_error = OK`, returns `false` if known missing or `true` if deleted).
4. **`bucket_exists(bucket)` and `object_head(bucket, key)`**:
   - Only HTTP `404` for the target resource produces `false` / `ObjectMeta.exists() == false`.
   - `401` and `403` always fail with `UNAUTHENTICATED` / `PERMISSION_DENIED`.
   - Calling `object_head(bucket, key)` when `bucket` itself does not exist fails with `ErrorCode.NOT_FOUND` (on S3/Azure/GCS where `HEAD` only returns `404` without body, the host disambiguates via `bucket_exists(bucket)` on a `404`).

---

## 7. Size, Encoding & Pagination Limits

- **Maximum object size:** `16 MiB` (`16,777,216` bytes) per `object_put` / `object_get`. This matches the enforce-mode body limit in `awssim` and `gcpsim` and keeps in-memory `lmcode` string buffers bounded. Payloads exceeding 16 MiB fail pre-flight with `ErrorCode.INVALID_ARGUMENT`.
- **Binary safety:** In `lmcode-go`, the `lmcode` `string` primitive is backed by a raw byte slice without UTF-8 replacement, so arbitrary binary payloads (including `\x00` and invalid UTF-8 sequences like `\xff\xfe`) round-trip byte-for-byte through `object_put` and `object_get`. `lmcode` standard library helpers `str_base64_encode`/`str_base64_decode` and `str_hex_encode`/`str_hex_decode` are also available in `_lmcode_` blocks.
- **Metadata size limit:** Maximum 32 entries and 2048 bytes combined (`sum(len(k) + len(v)) <= 2048`), validated pre-flight (`ErrorCode.INVALID_ARGUMENT`). Metadata values must be printable ASCII (`0x20..0x7E`) without leading/trailing whitespace so HTTP header transport is lossless across S3, Azure, GCS, and OCI.
- **Pagination (`object_list`):**
  - `max_keys`: `0` selects the default (`1000`); explicit values must be in `1..1000` (outside `0..1000` fails with `ErrorCode.INVALID_ARGUMENT`).
  - `page_token`: Opaque string returned by `page.next_token()`. All four providers and sims return keys in ascending UTF-8 byte order, so paging with `next_token()` visits every matching key in deterministic lexicographical order.

---

## 8. Deliberately Excluded from the Shared Slice

The following features are excluded from the v1 `lmcloud` object storage slice because they lack uniform semantics across all four clouds/emulators or belong to provider-specific extensions:
1. **Multipart / resumable / chunked streaming uploads (>16 MiB):** `gcpsim` enforce mode disables resumable uploads, and S3 multipart vs Azure `PutBlock`/`PutBlockList` vs OCI multipart have incompatible state machines.
2. **Presigned URLs / Azure SAS tokens / OCI Pre-Authenticated Requests (PARs):** Auth query formats and signing inputs differ per cloud.
3. **Object versioning, soft delete & retention/object-lock:** Not uniformly supported across sims or needed for core procedural workflows.
4. **Server-side copy & atomic rename:** OCI exposes `RenameObject` while S3/Azure/GCS require `CopyObject` + `DeleteObject` with different cross-bucket/header rules.
5. **Bucket ACLs, public-access blocks, CORS, lifecycle policies & KMS key management:** Declarative/IAM concerns outside the procedural data-plane slice.
6. **Bucket-level tags:** Azure Blob containers use `x-ms-meta-*` headers, GCS buckets use lowercase labels, and S3/OCI use tag sets.
7. **Byte-range `GET` and conditional `If-Match` / `If-None-Match` mutations:** Deferred to a future slice if required.
