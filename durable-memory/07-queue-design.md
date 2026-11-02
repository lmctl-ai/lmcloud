# 07 — `lmcloud` Queue Design (Slice 2)

## 1. Goals & Architectural Alignment

Slice 2 extends `schema/lmcloud.dsl.json` with a **provider-neutral point-to-point Queue API** on the existing `cloud` (`Cloud`) context object **without modifying any Slice 1 (Object Storage) signature**. Every `lmscript` queue program runs unchanged against:

1. **Local emulators (primary conformance target):**
   - `lmaws` ↔ `awssim` (`http://127.0.0.1:4566`, S3 + SQS)
   - `lmazure` ↔ `azuresim` (`http://127.0.0.1:4577`, Blob + Queue Storage)
   - `lmgcp` ↔ `gcpsim` (`http://127.0.0.1:4588`, GCS + Cloud Pub/Sub)
   - `lmoci` ↔ `ocisim` (`http://127.0.0.1:4599`, Object Storage + OCI Queue)
2. **Real clouds (`aws`, `azure`, `gcp`, `oci`)** using the same credential chains and endpoint configuration rules defined in [`02-object-storage-design.md`](02-object-storage-design.md).

### Endpoint Resolution for Queue
As established in `02-object-storage-design.md` §3:
- `cloud.endpoint("queue")` returns the effective sanitized queue endpoint URL.
- `cloud.set_endpoint("queue", url)` (or `cloud.set_endpoint("all", url)`) overrides the queue endpoint at runtime.
- Precedence (highest to lowest):
  1. `cloud.set_endpoint("queue", url)` or `cloud.set_endpoint("all", url)`
  2. `LMCLOUD_QUEUE_ENDPOINT`
  3. `LMCLOUD_ENDPOINT`
  4. Provider-native simulator/cloud env vars (`AWS_ENDPOINT_URL_SQS` / `AWS_ENDPOINT_URL`, `AZURE_QUEUE_ENDPOINT`, `PUBSUB_EMULATOR_HOST`, `OCI_QUEUE_ENDPOINT`)
  5. Live cloud regional endpoint.

---

## 2. Schema Surface (Added to `schema/lmcloud.dsl.json`)

### 2.1 Domain Types

#### `QueueMessage`
| Method | Signature | Description |
|---|---|---|
| `id` | `() -> string` | Provider-assigned message identifier (non-empty). |
| `body` | `() -> string` | Exact message payload bytes returned as an `lmscript` byte-preserving `string`. |
| `receipt` | `() -> string` | Opaque receipt token required by `queue_ack` and `queue_nack` (non-empty; format is provider-specific and opaque to callers). |

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
| `queue_exists` | `(name: string) -> bool` | `bool` | Probe: returns `true` if queue `name` exists and is accessible, `false` if `404`. Aborts on `401`/`403` unless `abort_on_error == false`. |
| `queue_list` | `() -> StrList` | `StrList` | Returns all queue names in the configured account/project/compartment, following all provider pages internally and sorted lexicographically (`a`..`z`). |
| `queue_send` | `(queue: string, body: string) -> string` | `string` | Enqueues `body` onto `queue` and returns the non-empty provider message `id`. |
| `queue_receive` | `(queue: string) -> QueueMessageList`<br>`(queue: string, max_messages: int, wait_seconds: int, visibility_timeout: int) -> QueueMessageList` | `QueueMessageList` | Receives up to `max_messages` (`1..10`) from `queue`, waiting up to `wait_seconds` (`0..20`) for messages to arrive and hiding returned messages from other consumers for `visibility_timeout` (`0..600`) seconds. The 1-arg overload uses defaults `(queue, 1, 0, 30)`. Returns an empty `QueueMessageList` (`len() == 0`) when no visible messages are available. |
| `queue_ack` | `(queue: string, receipt: string) -> void` | `void` | Permanently acknowledges (deletes) the message identified by `receipt` from `queue`. |
| `queue_nack` | `(queue: string, receipt: string, visibility_timeout: int) -> void` | `void` | Updates the visibility timeout (`0..600` seconds) of the in-flight message identified by `receipt`. Passing `visibility_timeout = 0` immediately makes the message visible for redelivery ("nack"). |

---

## 3. Provider & Simulator Mapping

### 3.1 How Each Provider Maps to the Flat Queue Model

1. **AWS SQS (`lmaws` ↔ `awssim` `:4566`):**
   - Protocol: AWS JSON 1.0 (`POST /`, `Content-Type: application/x-amz-json-1.0`, `X-Amz-Target: AmazonSQS.<Action>`).
   - Queue URL cache: `lmaws` resolves `QueueName` → `QueueUrl` via `GetQueueUrl` (or `CreateQueue`) and caches it in memory per queue name.
   - **Idempotent `queue_create`:** Like S3 `us-east-1` `CreateBucket`, SQS `CreateQueue` returns `200 OK` even when the queue already exists with matching attributes. Therefore, `lmaws` calls `GetQueueUrl({"QueueName": name})` first: if it succeeds (`200`), `queue_create` returns `false`; if it returns `AWS.SimpleQueueService.NonExistentQueue`, `lmaws` calls `CreateQueue({"QueueName": name})` and returns `true`.
2. **Azure Queue Storage (`lmazure` ↔ `azuresim` `:4577`):**
   - **Loopback path-style vs live host-style routing:**
     - On live Azure, Queue Storage lives at `https://<account>.queue.core.windows.net/<queue>`.
     - On `azuresim` loopback path-style (`http://127.0.0.1:4577`), `azuresim` routes Blob Storage at `/<account>/<container>` and Queue Storage at **`/<account>-queue/<queue>`** (e.g., `/devstoreaccount1-queue/<queue>`; see `azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java:229–230` and `scripts/test-storage.py:75`). When `lmazure` uses a loopback endpoint override without a `.queue.` hostname, it automatically prefixes queue paths with `/<account>-queue`.
   - **Idempotent `queue_create`:** Azure `PUT /<account>-queue/<queue>` returns `201 Created` when newly created and `204 No Content` when the queue already exists with identical metadata (`lmazure` also probes `GET /<account>-queue/<queue>?comp=metadata` if needed so `201` → `true` and `204` → `false`).
   - **Composite `receipt` token:** Azure `DeleteMessage` (`DELETE .../messages/<messageid>?popreceipt=<popreceipt>`) and `UpdateMessage` (`PUT .../messages/<messageid>?popreceipt=<popreceipt>&visibilitytimeout=<sec>`) require both `MessageId` and `PopReceipt` (and `UpdateMessage` in Azure Queue REST optionally accepts `<QueueMessage><MessageText>...</MessageText></QueueMessage>`). `lmazure` encodes `QueueMessage.receipt()` as `"<MessageId>\n<PopReceipt>\n<WireMessageText>"` (base64url-encoded as a single opaque token) so `queue_ack` and `queue_nack` have everything Azure requires without extra round-trips.
   - **Long polling (`wait_seconds`):** Azure Queue Storage REST `GET .../messages` has no server-side wait parameter; when `wait_seconds > 0`, `lmazure` polls up to `wait_seconds` with `250 ms` backoff intervals until at least one message is returned or the deadline expires.
   - **Immediate redelivery (`visibility_timeout == 0` on `queue_receive`):** Azure Queue `GET .../messages` requires `visibilitytimeout >= 1` (`1..604800`); if a caller passes `visibility_timeout == 0` to `queue_receive`, `lmazure` requests `visibilitytimeout=1` on `GET` and immediately issues `UpdateMessage` with `visibilitytimeout=0` on each returned message before returning the batch.
3. **Google Cloud Pub/Sub (`lmgcp` ↔ `gcpsim` `:4588`):**
   - **Topic + Subscription pair behind one queue name:**
     - In Cloud Pub/Sub, messages published to a topic *before* a subscription exists are dropped immediately.
     - Therefore, `queue_create(name)` creates **both**:
       1. Topic `projects/{project}/topics/{name}` (`PUT /v1/projects/{project}/topics/{name}`)
       2. Default pull subscription `projects/{project}/subscriptions/{name}` (`PUT /v1/projects/{project}/subscriptions/{name}` with body `{"topic": "projects/{project}/topics/{name}", "ackDeadlineSeconds": 30}`).
     - If the topic already exists (`409 ALREADY_EXISTS`), `lmgcp` ensures the companion subscription `{name}` also exists and returns `false`; if newly created, it returns `true`.
     - `queue_delete(name)` deletes the subscription `projects/{project}/subscriptions/{name}` (ignoring `404`) and then deletes the topic `projects/{project}/topics/{name}` (returning `true` if the topic existed and was deleted, `false` if both were already `404`).
     - `queue_exists(name)` checks `GET /v1/projects/{project}/topics/{name}` (and verifies `GET /v1/projects/{project}/subscriptions/{name}`).
     - `queue_list()` lists `GET /v1/projects/{project}/topics` (following `nextPageToken`), strips the `projects/{project}/topics/` prefix, and returns the sorted names.
   - **Receive & per-call visibility timeout:**
     - `POST /v1/projects/{project}/subscriptions/{name}:pull` takes `{"maxMessages": max_messages, "returnImmediately": (wait_seconds == 0)}`.
     - If `visibility_timeout != 30` and messages are returned, `lmgcp` immediately applies `POST /v1/projects/{project}/subscriptions/{name}:modifyAckDeadline` with `{"ackIds": [...], "ackDeadlineSeconds": visibility_timeout}` before returning the `QueueMessageList` to the caller.
4. **OCI Queue (`lmoci` ↔ `ocisim` `:4599`):**
   - **Queue Name (`displayName`) ↔ OCID (`queueId`) resolution:**
     - OCI Queue REST URLs address queues by OCID (`/20210201/queues/{queueId}`), while `lmcloud` programs address queues by portable `name` (`displayName`).
     - `lmoci` maintains an in-memory map `queueName -> {queueId, messagesEndpoint}`, populated on `queue_create`, `queue_exists`, and `queue_list`, and resolved on cache miss via `GET /20210201/queues?compartmentId={comp}&displayName={name}` (selecting the queue whose `displayName == name` and `lifecycleState != "DELETED"` / `"DELETING"`).
   - **Idempotent `queue_create` & async work requests (`202 Accepted`):**
     - OCI allows multiple queues with the same `displayName` unless checked first. Therefore, `lmoci` first queries `GET /20210201/queues?compartmentId={comp}&displayName={name}`: if an active queue with `displayName == name` exists, `queue_create` caches its OCID and returns `false`.
     - Otherwise, `lmoci` calls `POST /20210201/queues` with `{"compartmentId": comp, "displayName": name}`. Both `ocisim` and live OCI return `202 Accepted` (with `opc-work-request-id`). `lmoci` then polls `GET /20210201/queues?compartmentId={comp}&displayName={name}` until the queue appears with `lifecycleState == "ACTIVE"` (instant in `ocisim`; a few seconds on live OCI), caches its `id` and `messagesEndpoint`, and returns `true`.
   - **Separate `messagesEndpoint` on live OCI vs simulator:**
     - On live OCI, control-plane operations (`CreateQueue`, `DeleteQueue`, `GetQueue`, `ListQueues`) use `https://messaging.{region}.oci.oraclecloud.com`, while data-plane operations (`PutMessages`, `GetMessages`, `DeleteMessage`, `UpdateMessage`) use the queue's `messagesEndpoint` returned by `GetQueue` (`https://cell-1.queue.messaging.{region}.oci.oraclecloud.com`). When a loopback endpoint override (`ocisim`) is active, `lmoci` sends both control-plane and data-plane requests to the loopback simulator URL.

### 3.2 Operation Mapping Table

| `lmcloud` Method | AWS SQS (`awssim` `:4566`) | Azure Queue (`azuresim` `:4577`) | GCP Pub/Sub (`gcpsim` `:4588`) | OCI Queue (`ocisim` `:4599`) |
|---|---|---|---|---|
| `queue_create(q)` | `GetQueueUrl` probe; if 404 → `CreateQueue({"QueueName": q})` | `PUT /<acct>-queue/{q}` (`201` → `true`, `204` → `false`) | `PUT /v1/projects/{p}/topics/{q}` + `PUT /v1/projects/{p}/subscriptions/{q}` (`200` → `true`, `409` → `false`) | `GET /20210201/queues?compartmentId={c}&displayName={q}`; if empty → `POST /20210201/queues` (`202`) + poll active |
| `queue_delete(q)` | `GetQueueUrl` + `DeleteQueue({"QueueUrl": u})` (`true`; 404 → `false`) | `DELETE /<acct>-queue/{q}` (`204` → `true`, `404` → `false`) | `DELETE /v1/projects/{p}/subscriptions/{q}` + `DELETE /v1/projects/{p}/topics/{q}` (`200` → `true`, `404` → `false`) | Resolve `queueId`; if none → `false`; else `DELETE /20210201/queues/{id}` (`202`/`204` → `true`) + evict cache |
| `queue_exists(q)` | `GetQueueUrl({"QueueName": q})` (`200` → `true`, `NonExistentQueue` → `false`) | `GET /<acct>-queue/{q}?comp=metadata` (`200` → `true`, `404` → `false`) | `GET /v1/projects/{p}/topics/{q}` (`200` → `true`, `404` → `false`) | Resolve `queueId` via `GET /20210201/queues?compartmentId={c}&displayName={q}` + `GET /20210201/queues/{id}` |
| `queue_list()` | `ListQueues` (loop `NextToken`), extract queue name from each URL, sort | `GET /<acct>-queue?comp=list` (loop `NextMarker`), sort | `GET /v1/projects/{p}/topics` (loop `nextPageToken`), strip prefix, sort | `GET /20210201/queues?compartmentId={c}` (loop `opc-next-page`), filter `ACTIVE`, extract `displayName`, sort |
| `queue_send(q, body)` | `SendMessage({"QueueUrl": u, "MessageBody": wireBody})` → `MessageId` | `POST /<acct>-queue/{q}/messages` (`<QueueMessage><MessageText>base64(body)</MessageText></QueueMessage>`) → `MessageId` | `POST /v1/projects/{p}/topics/{q}:publish` (`{"messages":[{"data": base64(body)}]}`) → `messageIds[0]` | `POST /20210201/queues/{id}/messages` (`{"messages":[{"content": wireBody}]}`) → `messages[0].id` (as string) |
| `queue_receive(q, max, wait, vis)` | `ReceiveMessage({"QueueUrl": u, "MaxNumberOfMessages": max, "WaitTimeSeconds": wait, "VisibilityTimeout": vis})` | `GET /<acct>-queue/{q}/messages?numofmessages={max}&visibilitytimeout={vis}` (poll up to `wait`s if empty) | `POST /v1/projects/{p}/subscriptions/{q}:pull` (`{"maxMessages": max, "returnImmediately": wait==0}`) + `:modifyAckDeadline` if `vis != 30` | `GET /20210201/queues/{id}/messages?limit={max}&timeoutInSeconds={wait}&visibilityInSeconds={vis}` |
| `queue_ack(q, receipt)` | `DeleteMessage({"QueueUrl": u, "ReceiptHandle": receipt})` | `DELETE /<acct>-queue/{q}/messages/{msgId}?popreceipt={pop}` | `POST /v1/projects/{p}/subscriptions/{q}:acknowledge` (`{"ackIds": [receipt]}`) | `DELETE /20210201/queues/{id}/messages/{urlEscape(receipt)}` |
| `queue_nack(q, receipt, vis)` | `ChangeMessageVisibility({"QueueUrl": u, "ReceiptHandle": receipt, "VisibilityTimeout": vis})` | `PUT /<acct>-queue/{q}/messages/{msgId}?popreceipt={pop}&visibilitytimeout={vis}` | `POST /v1/projects/{p}/subscriptions/{q}:modifyAckDeadline` (`{"ackIds": [receipt], "ackDeadlineSeconds": vis}`) | `PUT /20210201/queues/{id}/messages/{urlEscape(receipt)}` (`{"visibilityInSeconds": vis}`) |

---

## 4. Portable Naming, Payload Encoding, and Parameter Rules

### 4.1 Portable Queue Naming Rules (Enforced Pre-Flight by All 4 Hosts)
- **Intersection of provider constraints:**
  - **Azure Queue Storage** is the strictest: 3–63 characters, lowercase ASCII letters, digits, and single hyphens (`-`); must start and end with a letter or digit; no consecutive hyphens (`--`).
  - **GCP Pub/Sub** topics/subscriptions: 3–255 chars, cannot start with `goog` (and we retain the `lmcloud` rule disallowing `google` / `g00gle` substrings for uniform validation across slices), must start with a letter on live GCP (`^[a-z]`).
  - **AWS SQS**: 1–80 chars (`[a-zA-Z0-9_-]`).
  - **OCI Queue**: `displayName` 1–255 chars.
- **Portable queue name rule (enforced pre-flight with `ErrorCode.INVALID_ARGUMENT`):**
  1. Length `3..63` bytes, starting with a lowercase ASCII letter `[a-z]`, ending with `[a-z0-9]`, and containing only `[a-z0-9-]`: RE2 pattern `^[a-z][a-z0-9-]{1,61}[a-z0-9]$`.
  2. Must **not** contain consecutive hyphens (`--`).
  3. Must **not** start with `goog` or contain `google` or `g00gle`.
  *(Note: Starting with `[a-z]` satisfies GCP Pub/Sub's requirement that topic/subscription IDs begin with a letter, while simultaneously satisfying Azure Queue Storage, AWS SQS, and OCI Queue.)*

### 4.2 Payload Encoding (Text & Binary Safety) and Portable Size Limit
- **`body` is an arbitrary byte-preserving `string`:**
  - Callers may send ASCII, UTF-8 (including CJK and emoji), or arbitrary binary bytes (including `\x00` and `0x80..0xFF`).
  - **Wire encoding per provider:**
    - **GCP Pub/Sub** natively requires base64 in JSON `messages[].data`.
    - **Azure Queue Storage** wraps `<MessageText>` in XML 1.0, which rejects raw `\x00` and invalid UTF-8 unless encoded; `lmazure` base64-encodes every payload into `<MessageText>` and base64-decodes on `queue_receive` (standard practice across official Azure Queue SDKs).
    - **AWS SQS** and **OCI Queue** transmit `MessageBody` / `content` as JSON strings, which reject invalid UTF-8 and control characters (`\x00`–`\x08`, `\x0B`, `\x0C`, `\x0E`–`\x1F`). To preserve human-readable UTF-8 payloads in simulators while supporting arbitrary binary bytes transparently, `lmaws` and `lmoci` send valid UTF-8 text (without XML/JSON-illegal control chars or the internal prefix) verbatim, and prefix-encode binary/control-char payloads as `"__lmcloud_b64__:" + base64(body)` (escaping any literal `"__lmcloud_b64__:"` prefix as `"__lmcloud_esc__:" + body`), decoding transparently in `queue_receive`.
- **Portable payload size limit: `49,152` bytes (`48 KiB`):**
  - Why `48 KiB` (`49,152` bytes)?
    - Azure Queue Storage limits `<MessageText>` to `64 KiB` (`65,536` bytes) of XML text; after base64 encoding (`4/3` expansion), `48 KiB` (`49,152` raw bytes) becomes `65,536` base64 bytes (`64 KiB`).
    - OCI Queue limits `content` to `64 KiB` (`65,536` bytes); a `48 KiB` binary payload encoded with `"__lmcloud_b64__:" + base64(body)` is `65,552` bytes (or for `48 KiB - 12` bytes, under `64 KiB`; for plain UTF-8 text up to `48 KiB`, it is `49,152` bytes).
    - AWS SQS allows `256 KiB` and GCP Pub/Sub allows `10 MiB`.
  - Therefore, all four hosts enforce a pre-flight limit of **`len(body) <= 49152` (`48 KiB`)** on `queue_send`: if `len(body) > 49152`, the host aborts immediately with `ErrorCode.INVALID_ARGUMENT` without making a network call. Empty string `""` (`len(body) == 0`) is permitted (`lmaws` encodes empty string as `"__lmcloud_b64__:"` because SQS rejects literal `""` `MessageBody` with `EmptyBatchRequest` / `InvalidParameterValue`, and decodes it back to `""` on receive).

### 4.3 `queue_receive` and `queue_nack` Parameter Bounds (Enforced Pre-Flight)
To guarantee identical behavior across all four clouds, all hosts validate these bounds pre-flight and abort with `ErrorCode.INVALID_ARGUMENT` if violated:
- `max_messages`: **`1 <= max_messages <= 10`** (SQS limits `MaxNumberOfMessages` to `1..10`; OCI and Azure allow `1..32`; Pub/Sub allows `1..1000`).
- `wait_seconds`: **`0 <= wait_seconds <= 20`** (SQS limits `WaitTimeSeconds` to `0..20`; OCI allows `0..20`).
- `visibility_timeout`: **`0 <= visibility_timeout <= 600`** (GCP Pub/Sub limits `ackDeadlineSeconds` to `0..600` seconds; SQS allows `0..43200`; Azure allows `0..604800`; OCI allows `0..43200`).
- `receipt` (in `queue_ack` / `queue_nack`): must be non-empty (`receipt != ""`), else `ErrorCode.INVALID_ARGUMENT`.

---

## 5. Delivery, Ordering, Idempotency, and Cooldown Semantics

1. **At-least-once delivery; unordered standard queues:**
   - All four providers provide **at-least-once** delivery.
   - Message ordering is **NOT** guaranteed (standard queues/topics, not FIFO). Conformance tests and user scripts must compare message sets/counts rather than assuming strict FIFO order, and must loop on `queue_receive` up to a bounded attempt count when collecting multiple messages (as SQS/Pub/Sub/OCI may return fewer than `max_messages` in a single call even when more messages are queued).
2. **Ack & Nack semantics:**
   - Once a message is received with `visibility_timeout > 0`, it is hidden from subsequent `queue_receive` calls until either:
     - `queue_ack(queue, receipt)` is called (permanently removing it),
     - `queue_nack(queue, receipt, 0)` is called (making it immediately eligible for redelivery), or
     - `visibility_timeout` seconds elapse without an ack.
   - **Invalid / fake receipt handle on `queue_ack` and `queue_nack`:**
     - Passing an empty receipt (`""`) aborts pre-flight with `ErrorCode.INVALID_ARGUMENT`.
     - Passing a bogus/corrupted or expired receipt on `queue_nack` aborts with `ErrorCode.INVALID_ARGUMENT` (or `NOT_FOUND` mapped to `INVALID_ARGUMENT` for receipt errors: SQS `ReceiptHandleIsInvalid`, Azure `400 InvalidQueryParameterValue` / `404 MessageNotFound`, Pub/Sub `400 INVALID_ARGUMENT`, OCI `400`/`404`). Note: on GCP Pub/Sub, `subscriptions.acknowledge` (`queue_ack`) is idempotent on unknown non-empty `ackIds` by specification unless the `ackId` format itself is rejected, so Scenario 08 tests invalid-receipt rejection via `queue_nack` (and empty-receipt validation on both `queue_ack` and `queue_nack`).
3. **Missing queue (`NOT_FOUND`) behavior:**
   - Calling `queue_send`, `queue_receive`, `queue_ack`, or `queue_nack` on a non-existent queue aborts with `ErrorCode.NOT_FOUND` (`[NOT_FOUND] ...`).
4. **SQS 60-second queue-name reuse cooldown (`QueueDeletedRecently`):**
   - On live AWS SQS, recreating a queue with the **same name** within 60 seconds of `DeleteQueue` fails with `AWS.SimpleQueueService.QueueDeletedRecently`.
   - Therefore, conformance tests and production scripts must **never** delete and recreate the same queue name within a run; each queue must use a distinct per-run name (`lmcloud-q-<scenario>-<run_id>-<suffix>`).

---

## 6. Explicit Exclusions (Not in Slice 2)

The following provider-specific features are **deliberately excluded** from the shared `lmcloud` Queue API:
1. **FIFO queues, message groups, and content-based deduplication** (Azure Queue Storage and OCI Queue lack FIFO message groups).
2. **Per-message delivery delay (`delay_seconds` on send)** (GCP Pub/Sub and OCI Queue do not support per-message visibility delay at publish time).
3. **Message attributes / custom key-value headers** (Azure Queue Storage messages have only `<MessageText>` with no separate header map; callers who need structured metadata encode JSON in `body`).
4. **Dead-letter queue (DLQ) redrive configuration** (configured via provider IAM/redrive policies that differ structurally across SQS, Azure, Pub/Sub, and OCI).
5. **`queue_purge` and approximate message counts** (SQS restricts `PurgeQueue` to once every 60 seconds and returns only eventual approximate counts; GCP Pub/Sub has no synchronous REST endpoint for subscription message count without querying Cloud Monitoring metrics).
6. **Push subscriptions / webhook endpoints** (Azure Queue Storage and OCI Queue are pull-only).

---

## 7. Open Questions (With Recommended Defaults)

1. **Portable payload size limit (`48 KiB` vs `64 KiB`):**
   - *Recommendation:* Keep **`48 KiB` (`49,152` bytes)** as the pre-flight limit on `queue_send(queue, body)` so `lmazure` can unconditionally base64-encode arbitrary binary/UTF-8 payloads into Azure's `64 KiB` `<MessageText>` XML element without data-dependent size failures.
2. **Method naming (`queue_ack` / `queue_nack` vs `queue_delete_message` / `queue_change_visibility`):**
   - *Recommendation:* Keep the concise **`queue_ack(queue, receipt)`** and **`queue_nack(queue, receipt, visibility_timeout)`** names in `schema/lmcloud.dsl.json` (where `visibility_timeout = 0` is an immediate nack/redelivery and `visibility_timeout > 0` extends visibility).
3. **`queue_ack` idempotency on already-acknowledged receipts:**
   - *Recommendation:* Treat `queue_ack` on an already-acknowledged receipt as idempotent (`void` no-op if a provider returns `404 MessageNotFound` on delete, matching Pub/Sub and SQS behavior), while `queue_nack` on an invalid/unknown receipt aborts with `ErrorCode.INVALID_ARGUMENT`.
