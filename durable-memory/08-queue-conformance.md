# 08 — `lmcloud` Queue Conformance Suite & Simulator Enhancements (Slice 2)

## 1. Conformance Runner Usage

The conformance runner [`tests/run-conformance.sh`](../tests/run-conformance.sh) supports selecting `object-storage`, `queue`, or `all` (default: `all`):

```bash
# Static compile/typecheck against schema/lmcloud.dsl.json:
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check object-storage
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check queue

# Execute against each provider + simulator once Go hosts are built:
./tests/run-conformance.sh /path/to/lmaws   http://127.0.0.1:4566 queue
./tests/run-conformance.sh /path/to/lmazure http://127.0.0.1:4577 queue
./tests/run-conformance.sh /path/to/lmgcp   http://127.0.0.1:4588 queue
./tests/run-conformance.sh /path/to/lmoci   http://127.0.0.1:4599 queue
```

### Naming, Polling & Isolation Rules
- Every queue conformance scenario generates queue names with `lmcloud-q<NN>-<run_id>-...`, satisfying `^[a-z][a-z0-9-]{1,61}[a-z0-9]$` with no `--` and no `goog`/`google`.
- Because live AWS SQS enforces a 60-second cooldown before recreating a recently deleted queue name (`AWS.SimpleQueueService.QueueDeletedRecently`), **no scenario ever deletes and recreates the same queue name**.
- Because SQS `ListQueues` and `DeleteQueue` visibility can be eventually consistent on live AWS (M3), Scenarios 01 and 02 use bounded polling loops when asserting list inclusion and post-delete disappearance.
- Because GCP Pub/Sub `queue_receive` pulls with `returnImmediately: false` under a `max(wait_seconds, 1)` deadline (H3) and `queue_nack(q, r, 0)` redelivery may take several seconds on Pub/Sub (M1), scenarios use `wait_seconds >= 1` for hidden/empty checks (L2) and bounded retry loops for redelivery.

---

## 2. The 13 Queue Conformance Scenarios (`tests/conformance/queue/`)

| # | File | Scenario | One-Line Expected Behavior |
|---|---|---|---|
| **01** | `01-queue-lifecycle.lms` | Queue create, exists, list, delete (with bounded poll, M3) | `queue_exists` is `false` before create; `queue_create` returns `true`; `queue_exists` is `true`; bounded poll of `queue_list()` is sorted and contains both created queues; `queue_delete` returns `true`; bounded poll of `queue_exists` is `false`. |
| **02** | `02-queue-idempotency.lms` | Idempotent `queue_create` and `queue_delete` (with bounded poll, M3) | Second `queue_create` on an existing queue returns `false`; `queue_delete` on a never-created queue and second `queue_delete` on a deleted queue (after bounded poll confirms deletion) both return `false` without error. |
| **03** | `03-message-send-receive-ack.lms` | Single message send, receive, and ack | `queue_send` returns a non-empty message `id`; `queue_receive(q, 1, 2, 30)` returns 1 `QueueMessage` with matching `body()` and non-empty `id()`/`receipt()`; `queue_ack(q, receipt)` removes it so a subsequent `queue_receive(q, 1, 1, 30)` returns `len() == 0` (L2). |
| **04** | `04-message-unicode-and-binary.lms` | Empty (`""`), sentinel-collision (`"__lmcloud_empty__"`), UTF-8, XML/JSON-special, and binary payloads (H2) | Payloads containing `""` (via portable `"__lmcloud_empty__"` wire sentinel), literal `"__lmcloud_empty__"` (escaped via `"__lmcloud_esc__:"`), UTF-8 (`"こんにちは世界 🚀 café"`), XML/JSON-sensitive chars, and raw binary bytes (`0001027f80feff41424300`) all round-trip byte-for-byte. |
| **05** | `05-message-batch-unordered.lms` | Multi-message send, unordered receive loop, and ack all | Sending 5 distinct messages and polling `queue_receive(q, 5, 1, 30)` in a bounded loop collects all 5 distinct message bodies regardless of delivery order; after acknowledging all 5, `queue_receive(q, 5, 1, 30)` returns `len() == 0`. |
| **06** | `06-visibility-timeout-and-nack.lms` | In-flight visibility hiding, chained `queue_nack` receipt rotation, and redelivery via `queue_nack(q, r2, 0)` (H1, M1, L2) | A message received with `visibility_timeout = 30` is hidden from `queue_receive(q, 1, 1, 30)`; calling `r2 = queue_nack(q, r1, 60)` and then `r3 = queue_nack(q, r2, 0)` using the returned receipt marks the message eligible for redelivery; bounded polling receives the redelivered message and `queue_ack` deletes it. |
| **07** | `07-visibility-extend-then-ack.lms` | Extend visibility with `queue_nack`, `queue_ack` using the returned receipt, and verify message does NOT come back (H1) | Receiving a message with `visibility_timeout = 2`, extending visibility via `new_rcpt = queue_nack(q, old_rcpt, 2)`, and calling `queue_ack(q, new_rcpt)` with the **new** receipt permanently deletes the message on all providers (including Azure where `PopReceipt` rotated) so polling past the 2s visibility window returns `0` messages. |
| **08** | `08-receive-empty-queue.lms` | Receive on empty queue (`1`-arg default and `4`-arg with `wait_seconds = 1`, H3) | Calling `queue_receive(q)` and `queue_receive(q, 5, 1, 30)` on an empty existing queue succeeds (`last_error().ok() == true`) and returns a `QueueMessageList` with `len() == 0`. |
| **09** | `09-ack-idempotency-and-invalid-receipt.lms` | Duplicate `queue_ack` idempotency and invalid `queue_nack` receipt rejection | Re-calling `queue_ack(q, receipt)` on an already-acknowledged message is a no-op, whereas `queue_nack(q, "invalid-receipt-handle-xyz", 15)` on an existing queue fails with `ErrorCode.INVALID_ARGUMENT`. |
| **10** | `10-queue-not-found-errors.lms` | Operations on a non-existent queue & `NOT_FOUND` precedence over malformed receipts (M5) | Calling `queue_send`, `queue_receive`, `queue_ack`, or `queue_nack` on a missing queue — including `queue_ack(missing_q, "malformed-not-base64!!!")` and `queue_nack(missing_q, "malformed-not-base64!!!", 10)` — fails with `ErrorCode.NOT_FOUND` (missing queue precedes receipt format validation, M5). |
| **11** | `11-queue-validation-guards.lms` | Pre-flight validation of queue names, receive/nack bounds, and empty receipts | Invalid queue names (`"ab"`, `"Bad_Queue"`, `"bad--double-hyphen"`, `"1starts-with-digit"`, `"goog-reserved-queue"`, `"my-google-queue"`), `max_messages` outside `1..10`, `wait_seconds` outside `0..20`, `visibility_timeout` outside `0..600`, and empty `receipt == ""` all fail pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`). |
| **12** | `12-queue-payload-size-guard.lms` | Boundary (`48 KiB` = `49,152` bytes) and over-limit (`49,153` bytes) for BOTH text and raw binary payloads (M2) | Both an exact `49,152`-byte ASCII payload and an exact `49,152`-byte raw binary payload (`\x00\xff\x7f\x80` repeated `12,288` times) succeed and round-trip byte-for-byte, while `49,153`-byte text and `49,153`-byte binary payloads both fail pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`). |
| **13** | `13-queue-auth-enforced-denial.lms` | Enforce-only (`# SKIP` in open mode) unauthenticated (`UNAUTHENTICATED`) vs unauthorized (`PERMISSION_DENIED`) queue access (M6) | Runs only against `<provider>sim --auth enforce` (emits TAP `# SKIP` in open mode): an unauthenticated pass (wrong secret/token) asserts `ErrorCode.UNAUTHENTICATED`, and a policy-denied pass (valid identity denied by policy) asserts `ErrorCode.PERMISSION_DENIED` on both `queue_create`/`queue_send` and `queue_exists` probes. |

---

## 3. Sim Enhancements (Evidence-Backed Findings Across the 4 Simulators)

Inspection of `/home/ubuntu/cloud/{awssim,azuresim,gcpsim,ocisim}` and `/home/ubuntu/cloud/lmoci` revealed the following concrete queue gaps and test omissions:

### 3.1 `awssim` (`/home/ubuntu/cloud/awssim`)
1. **`ChangeMessageVisibility` (and `PurgeQueue`) missing from `SUPPORTED.get("sqs")` in `--auth enforce` mode:**
   - **File / Lines:** `/home/ubuntu/cloud/awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java`, `SUPPORTED` map at lines **41–42**, and enforcement check at lines **116–118**:
     ```java
     // Lines 41–42:
     "sqs", Set.of("CreateQueue", "DeleteQueue", "GetQueueUrl", "GetQueueAttributes", "ListQueues",
         "SendMessage", "ReceiveMessage", "DeleteMessage", "TagQueue", "UntagQueue", "ListQueueTags"));
     // Lines 116–118:
     if (action == null || !SUPPORTED.get(service).contains(action.substring(action.indexOf(':') + 1))) {
         reject(ctx, xml, "AccessDenied", "Unsupported action in enforced mode"); return;
     }
     ```
   - **Evidence:** When `awssim` runs with `--auth enforce`, `AuthFilter.java:116–118` rejects any SQS action not listed in `SUPPORTED.get("sqs")` with `403 AccessDenied ("Unsupported action in enforced mode")`. Because `"ChangeMessageVisibility"` is omitted from `SUPPORTED.get("sqs")` at lines 41–42, `cloud.queue_nack(q, receipt, visibility_timeout)` fails with `403` in `--auth enforce` mode.
   - **Required Enhancement:** Add `"ChangeMessageVisibility"` (and `"PurgeQueue"`) to `SUPPORTED.get("sqs")` in `AuthFilter.java:41–42`, and add a test case in `scripts/test-auth.py`.
2. **Visibility timeout / `ChangeMessageVisibility` and `GetQueueUrl` missing-queue errors not covered in `awssim` integration tests:**
   - **File / Lines:** `/home/ubuntu/cloud/awssim/scripts/test-integration.py`, lines **108–118** (`test_sqs`).
   - **Evidence:** `test_sqs` tests `CreateQueue`, `SendMessage`, `ReceiveMessage`, `DeleteMessage`, `DeleteQueue`, and `ListQueues`, but does not test `ChangeMessageVisibility` (`VisibilityTimeout=0` redelivery) or `GetQueueUrl` on a non-existent queue.
   - **Required Enhancement:** Extend `test_sqs` in `scripts/test-integration.py` to exercise `ChangeMessageVisibility` (including `VisibilityTimeout=0` redelivery) and `GetQueueUrl` `NonExistentQueue` error status.

### 3.2 `azuresim` (`/home/ubuntu/cloud/azuresim`)
1. **`UpdateMessage` (`PUT /<account>-queue/<queue>/messages/<messageid>?popreceipt=...&visibilitytimeout=...`) and `GetQueueMetadata` (`?comp=metadata`) not covered in `azuresim` tests:**
   - **File / Lines:** `/home/ubuntu/cloud/azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java` lines **248–260** (`?comp=metadata` at line **250**; `PUT` → `"/write"` at line **256** and `action = prefix + "/messages" + operation` at line **259**) and `/home/ubuntu/cloud/azuresim/scripts/test-storage.py` lines **90–101**.
   - **Evidence:** `StorageAuth.java:250–259` maps `GET /<queue>?comp=metadata` to `Microsoft.Storage/storageAccounts/queueServices/queues/read` and `PUT /<queue>/messages/<messageid>` to `.../queues/messages/write`. However, `scripts/test-storage.py:90–101` only tests `PUT /<queue>`, `POST /<queue>/messages`, `GET /<queue>/messages`, `DELETE /<queue>/messages/<id>?popreceipt=...`, and `DELETE /<queue>`. It never tests `PUT /<queue>/messages/<id>?popreceipt=...&visibilitytimeout=...` (verifying `x-ms-popreceipt` rotation and redelivery, H1) or `GET /<queue>?comp=metadata` (required by `queue_exists`).
   - **Required Enhancement:** Add `GET /<account>-queue/<queue>?comp=metadata` and `PUT /<account>-queue/<queue>/messages/<id>?popreceipt=...&visibilitytimeout=...` (verifying that `azuresim`/`floci-az` returns an updated `x-ms-popreceipt` header, invalidates the old `popreceipt`, and honors `visibilitytimeout=0`) to `scripts/test-storage.py` and `scripts/test-auth.py`.

### 3.3 `gcpsim` (`/home/ubuntu/cloud/gcpsim`)
1. **Pub/Sub `:modifyAckDeadline` (`queue_nack`) not exercised in `gcpsim` integration or auth tests:**
   - **File / Lines:** `/home/ubuntu/cloud/gcpsim/src/main/java/ai/lmctl/gcpsim/PermissionFilter.java` line **112** (`: operation(suffix[1], "pull", "consume", "acknowledge", "consume", "modifyAckDeadline", "consume");`, with `Check` added at line **117**) and `/home/ubuntu/cloud/gcpsim/scripts/test-gcloud.py` lines **79–94**.
   - **Evidence:** `PermissionFilter.java:112` maps `POST /v1/projects/{p}/subscriptions/{s}:modifyAckDeadline` to `pubsub.subscriptions.consume`, which is supported by upstream `floci-gcp`. However, `scripts/test-gcloud.py:79–94` only tests topic create, subscription create, `:publish`, `:pull`, `:acknowledge`, and delete; it never tests `:modifyAckDeadline` (`ackDeadlineSeconds: 0` redelivery or invalid `ackIds` `400 INVALID_ARGUMENT`).
   - **Required Enhancement:** Add `:modifyAckDeadline` (`ackDeadlineSeconds: 30` and `ackDeadlineSeconds: 0` redelivery, plus invalid `ackId` rejection) to `scripts/test-gcloud.py` and `scripts/test-auth.py`.

### 3.4 `ocisim` (`/home/ubuntu/cloud/ocisim`) & Existing Java `lmoci` (`/home/ubuntu/cloud/lmoci`)
1. **OCI Queue `UpdateMessage` (`PUT /20210201/queues/{queueId}/messages/{messageReceipt}`) and invalid receipt handling not tested in `ocisim`:**
   - **File / Lines:** `/home/ubuntu/cloud/ocisim/src/main/java/ai/lmctl/ocisim/OciPolicyEngine.java` lines **645–647** (specifically line **646** mapping `"PUT"` to `"UpdateMessage"`) and `/home/ubuntu/cloud/ocisim/scripts/test-integration.py` lines **489–501**.
   - **Evidence:** `OciPolicyEngine.java:646` maps `PUT /20210201/queues/{id}/messages/{receipt}` to `"UpdateMessage"` (`QUEUE_UPDATE`), but `scripts/test-integration.py:489–501` only tests `POST /20210201/queues`, `POST .../messages`, `GET .../messages`, `DELETE .../messages/{receipt}`, and `DELETE /20210201/queues/{id}`.
   - **Required Enhancement:** Add `PUT /20210201/queues/{id}/messages/{receipt}` with `{"visibilityInSeconds": 0}` (verifying redelivery) and invalid receipt `400`/`404` status verification to `ocisim/scripts/test-integration.py`.
2. **OCI Queue `GET /20210201/queues?compartmentId=...&displayName=...` filter behavior:**
   - **File / Lines:** `/home/ubuntu/cloud/ocisim/scripts/test-integration.py` line **492** and existing Java host `/home/ubuntu/cloud/lmoci/src/main/java/ai/lmctl/lmoci/OciBackend.java` lines **874–893** (specifically `.displayName(name)` at lines **876** and **883**, followed by client-side `name.equals(q.getDisplayName())` filtering at line **888**).
   - **Evidence:** The existing Java `lmoci` host passes `.displayName(name)` on `ListQueuesRequest` (`OciBackend.java:883`) and also filters the returned items client-side (`OciBackend.java:888`). Verify that `ocisim` (`floci-oci`) honors the `displayName` query parameter on `GET /20210201/queues` in addition to the Go `lmoci` host filtering client-side by `displayName` and `lifecycleState == "ACTIVE"`.
