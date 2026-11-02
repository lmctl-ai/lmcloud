# 07 — `lmcloud` Queue Design (Slice 2)

## 1. Goals & Architectural Alignment

Slice 2 extends `schema/lmcloud.dsl.json` with a **provider-neutral point-to-point Queue API** on the existing `cloud` (`Cloud`) context object **without modifying any Slice 1 (Object Storage) signature**. Every `lmscript` queue program runs unchanged against:

1. **Local emulators (primary conformance target):**
   - `lmaws` ↔ `awssim` (`http://127.0.0.1:4566`, S3 + SQS)
   - `lmazure` ↔ `azuresim` (`http://127.0.0.1:4577`, Blob + Queue Storage)
   - `lmgcp` ↔ `gcpsim` (`http://127.0.0.1:4588`, GCS + Cloud Pub/Sub)
   - `lmoci` ↔ `ocisim` (`http://127.0.0.1:4599`, Object Storage + OCI Queue)
2. **Real clouds (`aws`, `azure`, `gcp`, `oci`)** using the same credential chains and endpoint configuration rules defined in [`02-object-storage-design.md`](02-object-storage-design.md).

### Endpoint Resolution for Queue (L1)
Queue endpoint resolution follows the **single canonical precedence table in [`02-object-storage-design.md` §3.3](02-object-storage-design.md#L123-L135)**:
- `cloud.endpoint("queue")` returns the effective sanitized queue endpoint URL.
- `cloud.set_endpoint("queue", url)` (or `cloud.set_endpoint("all", url)` for all services) overrides the queue endpoint at runtime (`"all"` is the universal wildcard service name everywhere).

---

## 2. Schema Surface (Added to `schema/lmcloud.dsl.json`)

### 2.1 Domain Types

#### `QueueMessage`
| Method | Signature | Description |
|---|---|---|
| `id` | `() -> string` | Provider-assigned message identifier (non-empty). |
| `body` | `() -> string` | Exact message payload bytes returned as an `lmscript` byte-preserving `string`. |
| `receipt` | `() -> string` | Opaque receipt token required by `queue_ack` and `queue_nack` (non-empty; valid until the next `queue_nack` or `queue_ack` on this message). |

#### `QueueMessageList`
Iterable in `lmscript` via `for (msg in batch) { ... }` (backed by `len` and `at`):
| Method | Signature | Description |
|---|---|---|
| `len` | `() -> int` | Number of messages returned in this receive call (`0 <= len() <= max_messages`). |
| `at` | `(int) -> QueueMessage` | Message at index `i` (`0 <= i < len()`). |

### 2.2 `Cloud` Queue Methods (`context cloud: Cloud`)

| Method | Signature(s) | Return | Semantics |
|---|---|---|---|
| `queue_create` | `(name: string) -> bool` | `bool` | Ensures queue `name` exists. Returns `true` if newly created, `false` if it already existed in the caller's scope (account / storage account / project / compartment). |
| `queue_delete` | `(name: string) -> bool` | `bool` | Deletes queue `name` (does **not** require the queue to be empty). Returns `true` if deleted, `false` if it did not exist (`404`). |
| `queue_exists` | `(name: string) -> bool` | `bool` | Probe: returns `true` if queue `name` exists and is accessible, `false` if `404`. Aborts on `401`/`403` (and OCI `404 NotAuthorizedOrNotFound`) unless `cloud.set_abort_on_error(false)` is set (L6). |
| `queue_list` | `() -> StrList` | `StrList` | Returns all queue names in the configured account/project/compartment, following all provider pages internally and sorted lexicographically (`a`..`z`). |
| `queue_send` | `(queue: string, body: string) -> string` | `string` | Enqueues `body` onto `queue` and returns the non-empty provider message `id`. |
| `queue_receive` | `(queue: string) -> QueueMessageList`<br>`(queue: string, max_messages: int, wait_seconds: int, visibility_timeout: int) -> QueueMessageList` | `QueueMessageList` | Receives up to `max_messages` (`1..10`) from `queue`, waiting up to `wait_seconds` (`0..20`) for messages to arrive and hiding returned messages from other consumers for `visibility_timeout` (`0..600`) seconds. The 1-arg overload uses defaults `(queue, 1, 0, 30)`. Returns an empty `QueueMessageList` (`len() == 0`) when no visible messages are available. |
| `queue_ack` | `(queue: string, receipt: string) -> void` | `void` | Permanently acknowledges (deletes) the message identified by `receipt` from `queue`. |
| `queue_nack` | `(queue: string, receipt: string, visibility_timeout: int) -> string` | `string` | Updates the visibility timeout (`0..600` seconds) of the in-flight message identified by `receipt` and **returns the new receipt token** (H1). Passing `visibility_timeout = 0` marks the message **eligible for immediate redelivery (note: on GCP Pub/Sub, redelivery may take several seconds)** (M1). **A receipt is valid until the next `queue_nack` or `queue_ack` on it; callers must always use the returned receipt for any subsequent `queue_nack` or `queue_ack`.** |

---

## 3. Provider & Simulator Mapping

### 3.1 How Each Provider Maps to the Flat Queue Model

1. **AWS SQS (`lmaws` ↔ `awssim` `:4566`):**
   - Protocol: AWS JSON 1.0 (`POST /`, `Content-Type: application/x-amz-json-1.0`, `X-Amz-Target: AmazonSQS.<Action>`).
   - Queue URL cache: `lmaws` resolves `QueueName` → `QueueUrl` via `GetQueueUrl` (or `CreateQueue`) and caches it in memory per queue name.
   - **Idempotent `queue_create`:** Like S3 `us-east-1` `CreateBucket`, SQS `CreateQueue` returns `200 OK` even when the queue already exists with matching attributes. Therefore, `lmaws` calls `GetQueueUrl({"QueueName": name})` first: if it succeeds (`200`), `queue_create` returns `false`; if it returns `AWS.SimpleQueueService.NonExistentQueue`, `lmaws` calls `CreateQueue({"QueueName": name})` and returns `true`.
   - **`queue_nack` receipt return (H1):** SQS `ChangeMessageVisibility` keeps the existing `ReceiptHandle` valid, so `lmaws` returns the input `receipt` string unchanged.
2. **Azure Queue Storage (`lmazure` ↔ `azuresim` `:4577`):**
   - **Loopback path-style vs live host-style routing:**
     - On live Azure, Queue Storage lives at `https://<account>.queue.core.windows.net/<queue>`.
     - On `azuresim` loopback path-style (`http://127.0.0.1:4577`), `azuresim` routes Blob Storage at `/<account>/<container>` and Queue Storage at **`/<account>-queue/<queue>`** (e.g., `/devstoreaccount1-queue/<queue>`; see `azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java:229–230` and `scripts/test-storage.py:75`). When `lmazure` uses a loopback endpoint override without a `.queue.` hostname, it automatically prefixes queue paths with `/<account>-queue`.
   - **Idempotent `queue_create`:** Azure `PUT /<account>-queue/<queue>` returns `201 Created` when newly created and `204 No Content` when the queue already exists with identical metadata (`201` → `true`, `204` → `false`).
   - **Composite `receipt` token & `x-ms-popreceipt` rotation on `UpdateMessage` (H1):**
     - Azure `DeleteMessage` (`DELETE .../messages/<messageid>?popreceipt=<popreceipt>`) and `UpdateMessage` (`PUT .../messages/<messageid>?popreceipt=<popreceipt>&visibilitytimeout=<sec>`) require both `MessageId` and `PopReceipt` (no `<QueueMessage>` body is sent when only updating visibility, so **`MessageText` is NOT stored in the receipt token**).
     - `lmazure` encodes `QueueMessage.receipt()` as `base64url(MessageId + "\n" + PopReceipt)`.
     - **Why `queue_nack` returns a new receipt string (H1):** Every Azure `UpdateMessage` response (`204 No Content`) returns a **new** `x-ms-popreceipt` header and invalidates the old `PopReceipt`. `lmazure` reads `x-ms-popreceipt` from the `UpdateMessage` response and returns `base64url(MessageId + "\n" + newPopReceipt)`. If a caller passes `visibility_timeout == 0` to `queue_receive`, `lmazure` requests `visibilitytimeout=1` on `GET .../messages`, immediately issues `UpdateMessage` with `visibilitytimeout=0`, and populates `QueueMessage.receipt()` with the new `x-ms-popreceipt` from that `UpdateMessage` call.
   - **Long polling (`wait_seconds`):** Azure Queue Storage REST `GET .../messages` has no server-side wait parameter; when `wait_seconds > 0`, `lmazure` polls up to `wait_seconds` with `250 ms` backoff intervals until at least one message is returned or the deadline expires.
3. **Google Cloud Pub/Sub (`lmgcp` ↔ `gcpsim` `:4588`):**
   - **Topic + Subscription pair behind one queue name (M4):**
     - In Cloud Pub/Sub, messages published to a topic *before* a subscription exists are dropped immediately, and default subscriptions expire after 31 days of inactivity unless `"expirationPolicy": {}` is specified.
     - Therefore, `queue_create(name)` creates **both**:
       1. Topic `projects/{project}/topics/{name}` (`PUT /v1/projects/{project}/topics/{name}`)
       2. Default pull subscription `projects/{project}/subscriptions/{name}` (`PUT /v1/projects/{project}/subscriptions/{name}` with body `{"topic": "projects/{project}/topics/{name}", "ackDeadlineSeconds": 30, "expirationPolicy": {}}` so the subscription **never expires**, M4).
     - If both topic and subscription already exist (`409 ALREADY_EXISTS`), `queue_create` returns `false`; if either was missing and created/repaired, it returns `true`.
     - `queue_delete(name)` deletes the subscription `projects/{project}/subscriptions/{name}` (ignoring `404`) and then deletes the topic `projects/{project}/topics/{name}` (returning `true` if either existed and was deleted, `false` if both were already `404`).
     - **`queue_exists(name)` requires BOTH topic and subscription (M4):** `lmgcp` checks `GET /v1/projects/{project}/topics/{name}` **and** `GET /v1/projects/{project}/subscriptions/{name}` (verifying its `"topic"` equals `"projects/{project}/topics/{name}"`), returning `true` only when both exist.
     - **`queue_list()` requires BOTH topic and subscription (M4):** `lmgcp` lists all topics (`GET /v1/projects/{project}/topics`, following `nextPageToken`) and all subscriptions (`GET /v1/projects/{project}/subscriptions`, following `nextPageToken`), and returns the sorted **intersection** of names `{q}` for which both `projects/{project}/topics/{q}` and `projects/{project}/subscriptions/{q}` (bound to that topic) exist.
   - **Receive with `returnImmediately: false` deadline loop and unconditional `modifyAckDeadline` (H3, L4):**
     - Pub/Sub's `returnImmediately: true` is deprecated and frequently returns 0 messages even when messages are queued. Therefore, `lmgcp` **always** calls `POST /v1/projects/{project}/subscriptions/{name}:pull` with **`{"maxMessages": max_messages, "returnImmediately": false}`** under a client-side HTTP context deadline of **`max(wait_seconds, 1)` seconds**, looping `:pull` until at least one message is returned or the `max(wait_seconds, 1)` deadline expires (H3).
     - Whenever one or more messages are returned by `:pull`, `lmgcp` **unconditionally** calls `POST /v1/projects/{project}/subscriptions/{name}:modifyAckDeadline` with `{"ackIds": [...], "ackDeadlineSeconds": visibility_timeout}` before returning the `QueueMessageList` to the caller (no `visibility_timeout != 30` shortcut, L4).
     - On `queue_nack`, `lmgcp` calls `:modifyAckDeadline` and returns the input `receipt` (`ackId`) unchanged (H1).
4. **OCI Queue (`lmoci` ↔ `ocisim` `:4599`):**
   - **Queue Name (`displayName`) ↔ OCID (`queueId`) resolution:**
     - OCI Queue REST URLs address queues by OCID (`/20210201/queues/{queueId}`), while `lmcloud` programs address queues by portable `name` (`displayName`) (matching how existing Java `lmoci` resolves `displayName` in `OciBackend.java:876–893`).
     - `lmoci` maintains an in-memory map `queueName -> {queueId, messagesEndpoint}`, populated on `queue_create`, `queue_exists`, and `queue_list`, and resolved on cache miss via `GET /20210201/queues?compartmentId={comp}&displayName={name}` (filtering client-side as well for exact `displayName == name` and `lifecycleState == "ACTIVE"`).
   - **Idempotent `queue_create` & async work requests (`202 Accepted`):**
     - OCI allows multiple queues with the same `displayName` unless checked first. Therefore, `lmoci` first queries `GET /20210201/queues?compartmentId={comp}&displayName={name}`: if an active queue with `displayName == name` exists, `queue_create` caches its OCID and returns `false`.
     - Otherwise, `lmoci` calls `POST /20210201/queues` with `{"compartmentId": comp, "displayName": name}`. Both `ocisim` and live OCI return `202 Accepted` (with `opc-work-request-id`). `lmoci` then polls `GET /20210201/queues?compartmentId={comp}&displayName={name}` until the queue appears with `lifecycleState == "ACTIVE"` (instant in `ocisim`; a few seconds on live OCI), caches its `id` and `messagesEndpoint`, and returns `true`.
   - **Separate `messagesEndpoint` on live OCI vs simulator:**
     - On live OCI, control-plane operations (`CreateQueue`, `DeleteQueue`, `GetQueue`, `ListQueues`) use `https://messaging.{region}.oci.oraclecloud.com`, while data-plane operations (`PutMessages`, `GetMessages`, `DeleteMessage`, `UpdateMessage`) use the queue's `messagesEndpoint` returned by `GetQueue`. When a loopback endpoint override (`ocisim`) is active, `lmoci` sends both control-plane and data-plane requests to the loopback simulator URL.
   - **`queue_nack` receipt return (H1):** `PUT /20210201/queues/{id}/messages/{urlEscape(receipt)}` (`UpdateMessage`) updates `visibilityInSeconds` and returns the updated receipt (or preserves `receipt`), which `lmoci` returns from `queue_nack`.

### 3.2 Operation Mapping Table

| `lmcloud` Method | AWS SQS (`awssim` `:4566`) | Azure Queue (`azuresim` `:4577`) | GCP Pub/Sub (`gcpsim` `:4588`) | OCI Queue (`ocisim` `:4599`) |
|---|---|---|---|---|
| `queue_create(q)` | `GetQueueUrl` probe; if 404 → `CreateQueue({"QueueName": q})` | `PUT /<acct>-queue/{q}` (`201` → `true`, `204` → `false`) | `PUT /v1/projects/{p}/topics/{q}` + `PUT /v1/projects/{p}/subscriptions/{q}` (`expirationPolicy: {}`; `true` if created, `false` if both existed, M4) | `GET /20210201/queues?compartmentId={c}&displayName={q}`; if empty → `POST /20210201/queues` (`202`) + poll active |
| `queue_delete(q)` | `GetQueueUrl` + `DeleteQueue({"QueueUrl": u})` (`true`; 404 → `false`) | `DELETE /<acct>-queue/{q}` (`204` → `true`, `404` → `false`) | `DELETE /v1/projects/{p}/subscriptions/{q}` + `DELETE /v1/projects/{p}/topics/{q}` (`200` → `true`, `404` → `false`) | Resolve `queueId`; if none → `false`; else `DELETE /20210201/queues/{id}` (`202`/`204` → `true`) + evict cache |
| `queue_exists(q)` | `GetQueueUrl({"QueueName": q})` (`200` → `true`, `NonExistentQueue` → `false`) | `GET /<acct>-queue/{q}?comp=metadata` (`200` → `true`, `404` → `false`) | `GET /v1/projects/{p}/topics/{q}` **AND** `GET /v1/projects/{p}/subscriptions/{q}` (both `200` → `true`, else `false`, M4) | Resolve `queueId` via `GET /20210201/queues?compartmentId={c}&displayName={q}` + `GET /20210201/queues/{id}` |
| `queue_list()` | `ListQueues` (loop `NextToken`), extract queue name from each URL, sort | `GET /<acct>-queue?comp=list` (loop `NextMarker`), sort | List all topics AND all subscriptions (loop `nextPageToken`), intersect matching `{q}` pairs, sort (M4) | `GET /20210201/queues?compartmentId={c}` (loop `opc-next-page`), filter `ACTIVE`, extract `displayName`, sort |
| `queue_send(q, body)` | `SendMessage({"QueueUrl": u, "MessageBody": wireBody})` → `MessageId` | `POST /<acct>-queue/{q}/messages` (`<QueueMessage><MessageText>base64(wireBody)</MessageText></QueueMessage>`) → `MessageId` | `POST /v1/projects/{p}/topics/{q}:publish` (`{"messages":[{"data": base64(wireBody)}]}`) → `messageIds[0]` | `POST /20210201/queues/{id}/messages` (`{"messages":[{"content": wireBody}]}`) → `messages[0].id` (as string) |
| `queue_receive(q, max, wait, vis)` | `ReceiveMessage({"QueueUrl": u, "MaxNumberOfMessages": max, "WaitTimeSeconds": wait, "VisibilityTimeout": vis})` | `GET /<acct>-queue/{q}/messages?numofmessages={max}&visibilitytimeout={max(vis,1)}` (poll up to `wait`s if empty; if `vis==0`, `UpdateMessage(0)`) | Loop `POST /v1/projects/{p}/subscriptions/{q}:pull` (`returnImmediately: false`) up to `max(wait,1)`s deadline (H3), then **always** `:modifyAckDeadline(vis)` (L4) | `GET /20210201/queues/{id}/messages?limit={max}&timeoutInSeconds={wait}&visibilityInSeconds={vis}` |
| `queue_ack(q, receipt)` | `DeleteMessage({"QueueUrl": u, "ReceiptHandle": receipt})` | `DELETE /<acct>-queue/{q}/messages/{msgId}?popreceipt={pop}` | `POST /v1/projects/{p}/subscriptions/{q}:acknowledge` (`{"ackIds": [receipt]}`) | `DELETE /20210201/queues/{id}/messages/{urlEscape(receipt)}` |
| `queue_nack(q, receipt, vis) -> string` | `ChangeMessageVisibility({"QueueUrl": u, "ReceiptHandle": receipt, "VisibilityTimeout": vis})` → returns `receipt` | `PUT /<acct>-queue/{q}/messages/{msgId}?popreceipt={pop}&visibilitytimeout={vis}` → returns new `base64url(msgId + "\n" + x-ms-popreceipt)` (H1) | `POST /v1/projects/{p}/subscriptions/{q}:modifyAckDeadline` (`{"ackIds": [receipt], "ackDeadlineSeconds": vis}`) → returns `receipt` | `PUT /20210201/queues/{id}/messages/{urlEscape(receipt)}` (`{"visibilityInSeconds": vis}`) → returns updated/same `receipt` |

---

## 4. Portable Naming, Payload Encoding, and Parameter Rules

### 4.1 Portable Queue Naming Rules (Enforced Pre-Flight by All 4 Hosts)
- **Intersection of provider constraints:**
  - **Azure Queue Storage**: 3–63 characters, lowercase ASCII letters, digits, and single hyphens (`-`); must start and end with a letter or digit; no consecutive hyphens (`--`).
  - **GCP Pub/Sub** topics/subscriptions: 3–255 chars, must start with a lowercase letter (`^[a-z]`), cannot start with `goog` (and we disallow `google` / `g00gle` substrings for uniform validation across slices).
  - **AWS SQS**: 1–80 chars (`[a-zA-Z0-9_-]`).
  - **OCI Queue**: `displayName` 1–255 chars.
- **Portable queue name rule (enforced pre-flight with `ErrorCode.INVALID_ARGUMENT`, `http_status() == 0`):**
  1. Length `3..63` bytes, starting with a lowercase ASCII letter `[a-z]`, ending with `[a-z0-9]`, and containing only `[a-z0-9-]`: RE2 pattern `^[a-z][a-z0-9-]{1,61}[a-z0-9]$`.
  2. Must **not** contain consecutive hyphens (`--`).
  3. Must **not** start with `goog` or contain `google` or `g00gle`.

### 4.2 Portable Empty-Payload Sentinel & Binary Wire Encoding (H2) and Size Limit (M2)
- **Why a single portable empty-body sentinel is required on EVERY provider (H2):**
  - **AWS SQS** `SendMessage` rejects `MessageBody: ""` (`InvalidParameterValue` / `MissingParameter`).
  - **GCP Pub/Sub** `topics.publish` rejects a `PubsubMessage` when both `data` (`""`) and `attributes` are empty (`400 INVALID_ARGUMENT: Must specify at least one of data or attributes`).
  - **OCI Queue** `PutMessages` (`PutMessagesDetailsEntry.content`) requires `content` to be a non-empty string (`minLength: 1`, verified in official Oracle Cloud Infrastructure Queue API documentation).
- **Canonical `lmcloud` wire payload encoding (applied uniformly across all 4 hosts, H2):**
  1. **Empty string (`body == ""`):** Encoded as the reserved 17-byte ASCII sentinel **`"__lmcloud_empty__"`** before transport (so it is non-empty on SQS, Pub/Sub, OCI Queue, and Azure Queue), and decoded back to `""` on `queue_receive`.
  2. **Literal prefix escaping (`str_starts_with(body, "__lmcloud_")`):** Any non-empty user payload starting with `"__lmcloud_"` is escaped as **`"__lmcloud_esc__:" + body`** and unescaped on `queue_receive`, guaranteeing zero collision with `"__lmcloud_empty__"`, `"__lmcloud_b64__:"`, or `"__lmcloud_esc__:"`.
  3. **Binary & control-character transport:**
     - **Azure Queue Storage (`lmazure`)** and **GCP Pub/Sub (`lmgcp`)** base64-encode the resulting `wireBody` on the wire (`<MessageText>base64(wireBody)</MessageText>` and `messages[].data = base64(wireBody)`) and base64-decode on `queue_receive` (for non-empty payloads on Azure/Pub/Sub that do not start with `"__lmcloud_"`, `wireBody == body` so raw binary `body` is base64-encoded directly without double-encoding).
     - **AWS SQS (`lmaws`)** and **OCI Queue (`lmoci`)** carry `content` / `MessageBody` as JSON strings (which reject invalid UTF-8 and control bytes `\x00`–`\x08`, `\x0B`, `\x0C`, `\x0E`–`\x1F`, `\x7F`). Valid UTF-8 payloads without those control bytes use `wireBody` directly; payloads containing non-UTF-8 bytes or control characters are encoded as **`"__lmcloud_b64__:" + base64(body)`** and decoded transparently on `queue_receive`.
- **Portable payload size limit: `49,152` bytes (`48 KiB`) raw `body` (M2):**
  - **Verified provider message size limits (M2):**
    - **Azure Queue Storage:** `64 KiB` (`65,536` bytes) of XML `<MessageText>` (`48 KiB` = `49,152` raw bytes after `4/3` base64 expansion: `49152 * 4 / 3 = 65536` bytes).
    - **AWS SQS:** `256 KiB` (`262,144` bytes).
    - **OCI Queue:** **`256 KiB` (`262,144` bytes)** per message (`PutMessages` batch limit is `512 KiB` and up to 20 messages; `64 KiB` is only OCI Queue's billing chunk unit, verified in official Oracle Cloud Infrastructure Queue documentation).
    - **GCP Pub/Sub:** `10 MiB` (`10,485,760` bytes).
  - **Why `49,152` bytes (`48 KiB`) works for both text and binary across all 4 clouds:**
    - On **Azure**, a `49,152`-byte text or binary payload base64-encodes to `65,536` bytes (`64 KiB`), fitting Azure's exact `64 KiB` `<MessageText>` limit (unless a `49,152`-byte payload literally starts with `"__lmcloud_"`, which adds the 16-byte escape prefix; for arbitrary binary and normal text up to `49,152` bytes, `wireBody == body`).
    - On **SQS** and **OCI Queue**, a `49,152`-byte raw binary payload encoded as `"__lmcloud_b64__:" + base64(body)` is `16 + 65,536 = 65,552` bytes, which is well below SQS and OCI Queue's `262,144`-byte (`256 KiB`) limit!
  - All four hosts enforce `len(body) <= 49152` pre-flight on `queue_send`: if `len(body) > 49152`, the host aborts immediately with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`).

### 4.3 `queue_receive` and `queue_nack` Parameter Bounds (Enforced Pre-Flight)
All four hosts validate these bounds pre-flight and abort with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`) if violated:
- `max_messages`: **`1 <= max_messages <= 10`** (SQS limits `MaxNumberOfMessages` to `1..10`).
- `wait_seconds`: **`0 <= wait_seconds <= 20`** (SQS and OCI limit `WaitTimeSeconds` / `timeoutInSeconds` to `0..20`).
- `visibility_timeout`: **`0 <= visibility_timeout <= 600`** (GCP Pub/Sub limits `ackDeadlineSeconds` to `0..600` seconds).
- `receipt` (in `queue_ack` / `queue_nack`): empty string (`receipt == ""`) fails pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`).

---

## 5. Delivery, Ordering, Retention, Error Precedence, and Cooldown Semantics

1. **At-least-once delivery; unordered standard queues:**
   - All four providers provide **at-least-once** delivery; message ordering is **NOT** guaranteed. Conformance tests and user scripts must compare message sets/counts rather than assuming FIFO order, and must loop on `queue_receive` up to a bounded attempt count when collecting multiple messages.
2. **Portable minimum message retention: 4 days (`345,600` seconds) (L3):**
   - Across all four providers, unacknowledged messages are retained for a portable minimum of **4 days** (`345,600` seconds: AWS SQS default is 4 days; OCI Queue default is 4 days; Azure Queue Storage default is 7 days; GCP Pub/Sub default is 7 days).
3. **Receipt lifecycle, `queue_ack`, and `queue_nack` semantics (H1, M1):**
   - **Receipt validity rule (H1):** A receipt token is valid only until the next `queue_nack` or `queue_ack` on that delivery. Calling `new_receipt = cloud.queue_nack(queue, receipt, vis)` returns the updated receipt token; callers **must** pass `new_receipt` to any subsequent `queue_nack` or `queue_ack`.
   - **Immediate redelivery via `queue_nack(queue, receipt, 0)` (M1):** Passing `visibility_timeout = 0` marks the message **eligible for immediate redelivery (note: on GCP Pub/Sub, redelivery after `modifyAckDeadline(0)` may take several seconds, so callers should poll `queue_receive` with bounded retries)**.
   - **`queue_ack` idempotency:** Re-acknowledging an already-acknowledged receipt on an existing queue is idempotent (`ErrorCode.OK`; `lmazure` and `lmoci` treat `404 MessageNotFound` on `DELETE .../messages/...` when the queue itself exists as a completed ack).
4. **Error precedence for `queue_ack` and `queue_nack`: missing queue (`NOT_FOUND`) before malformed/invalid receipt (`INVALID_ARGUMENT`) (M5):**
   - Pre-flight (`http_status() == 0`) rejects only invalid queue names, out-of-range `visibility_timeout`, or an **empty** receipt (`receipt == ""`).
   - When `queue` is a valid name and `receipt != ""`, **missing queue (`ErrorCode.NOT_FOUND`) always takes precedence over a malformed or invalid receipt (`ErrorCode.INVALID_ARGUMENT`)**:
     - On `lmaws`, `lmgcp`, and `lmoci`, resolving the queue URL / subscription / queue OCID or calling the provider endpoint on a non-existent queue returns `404` (`ErrorCode.NOT_FOUND`) before evaluating the receipt token.
     - On `lmazure`, if a non-empty `receipt` fails local `base64url(MessageId + "\n" + PopReceipt)` decoding, `lmazure` first probes `GET /<acct>-queue/<queue>?comp=metadata`: if the queue does not exist (`404 QueueNotFound`), it reports `ErrorCode.NOT_FOUND`; only if the queue exists does it report `ErrorCode.INVALID_ARGUMENT`.
     - If the queue exists and a non-empty receipt is rejected by the provider on `queue_nack` (SQS `ReceiptHandleIsInvalid`, Azure `400 InvalidQueryParameterValue` / `404 MessageNotFound`, Pub/Sub `400 INVALID_ARGUMENT`, OCI `400`/`404`), the host maps the receipt failure to `ErrorCode.INVALID_ARGUMENT`.
5. **SQS 60-second queue-name reuse cooldown (`QueueDeletedRecently`) & eventual consistency (M3):**
   - On live AWS SQS, recreating a queue with the **same name** within 60 seconds of `DeleteQueue` fails with `AWS.SimpleQueueService.QueueDeletedRecently`. Conformance tests must never delete and recreate the same queue name.
   - Because live AWS SQS `ListQueues` and post-`DeleteQueue` `GetQueueUrl` visibility can be eventually consistent across endpoints, conformance assertions on `queue_list()` after `queue_create` and `!queue_exists()` after `queue_delete` use a bounded poll loop (M3).

---

## 6. Explicit Exclusions (Not in Slice 2)

1. **FIFO queues, message groups, and content-based deduplication.**
2. **Per-message delivery delay (`delay_seconds` on send).**
3. **Message attributes / custom key-value headers.**
4. **Dead-letter queue (DLQ) redrive configuration.**
5. **`queue_purge` and approximate message counts.**
6. **Push subscriptions / webhook endpoints.**

---

## 7. Decisions (TASK 1e)

1. **`queue_nack` returns the updated receipt (`string`) and Azure receipt drops `MessageText` (H1):**
   - `queue_nack(queue, receipt, visibility_timeout) -> string` returns the new receipt token (required because Azure `UpdateMessage` rotates `x-ms-popreceipt` on every call; non-Azure hosts return the existing/updated receipt). `lmazure`'s receipt token contains only `MessageId` and `PopReceipt`.
2. **Single reserved portable empty-body sentinel (`"__lmcloud_empty__"`) across all providers (H2):**
   - All four hosts encode `body == ""` as `"__lmcloud_empty__"` (and escape literal `"__lmcloud_*"` payloads with `"__lmcloud_esc__:"`) so empty messages work identically on SQS, Pub/Sub, OCI Queue, and Azure Queue Storage.
3. **Pub/Sub `returnImmediately: false` with `max(wait_seconds, 1)` deadline + unconditional `modifyAckDeadline` + `expirationPolicy: {}` + topic+subscription intersection (H3, M4, L4):**
   - `lmgcp` creates subscriptions with `"expirationPolicy": {}` (never expires), requires both topic and subscription in `queue_exists` and `queue_list`, always pulls with `returnImmediately: false` under a `max(wait_seconds, 1)` deadline, and always calls `modifyAckDeadline(visibility_timeout)`.
4. **Verified `256 KiB` OCI Queue limit & `48 KiB` (`49,152`-byte) portable raw payload limit (M2):**
   - OCI Queue's limit is `256 KiB` (`64 KiB` is billing chunk size); Azure Queue Storage (`64 KiB` XML `<MessageText>` → `48 KiB` raw bytes before base64) defines the `49,152`-byte portable ceiling for both text and binary payloads.
5. **Missing queue (`NOT_FOUND`) precedes malformed non-empty receipt (`INVALID_ARGUMENT`) (M5):**
   - For non-empty receipts, `queue_ack` and `queue_nack` check/report queue existence (`ErrorCode.NOT_FOUND`) before reporting a malformed or invalid receipt (`ErrorCode.INVALID_ARGUMENT`).
