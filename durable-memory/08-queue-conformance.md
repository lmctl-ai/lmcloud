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

### Naming & Isolation Rules
- Every queue conformance scenario generates queue names with `lmcloud-q-<NN>-<run_id>` (plus `-a`/`-b` suffixes when a scenario uses multiple queues), satisfying `^[a-z][a-z0-9-]{1,61}[a-z0-9]$` with no `--` and no `goog`/`google`.
- Because live AWS SQS enforces a 60-second cooldown before recreating a recently deleted queue name (`AWS.SimpleQueueService.QueueDeletedRecently`), **no scenario ever deletes and recreates the same queue name**.
- Because standard queues across all four providers do **not** guarantee FIFO ordering or single-call batch completeness, multi-message scenarios loop on `queue_receive` up to a bounded iteration count and compare message sets/counts rather than order.

---

## 2. The 12 Queue Conformance Scenarios (`tests/conformance/queue/`)

| # | File | Scenario | One-Line Expected Behavior |
|---|---|---|---|
| **01** | `01-queue-lifecycle.lms` | Queue create, exists, list, delete | `queue_exists` is `false` before create; `queue_create` returns `true`; `queue_exists` is `true`; `queue_list()` is sorted and contains both created queues; `queue_delete` returns `true`; `queue_exists` is `false`. |
| **02** | `02-queue-idempotency.lms` | Idempotent `queue_create` and `queue_delete` | Second `queue_create` on an existing queue returns `false`; `queue_delete` on a never-created queue and second `queue_delete` on a deleted queue both return `false` without error. |
| **03** | `03-message-send-receive-ack.lms` | Single message send, receive, and ack | `queue_send` returns a non-empty message `id`; `queue_receive(q)` returns 1 `QueueMessage` with matching `body()` and non-empty `id()`/`receipt()`; `queue_ack(q, receipt)` removes it so a subsequent `queue_receive(q, 1, 0, 30)` returns `len() == 0`. |
| **04** | `04-message-unicode-and-binary.lms` | Empty, UTF-8, JSON, XML-special, and binary payloads | Payloads containing `""`, UTF-8 (`"こんにちは 🚀 café"`), XML/JSON-sensitive chars (`"<tag attr=\"v\">&</tag>"`), and binary bytes (`"bin\x00\x01\x02\xffend"`) round-trip byte-for-byte through `queue_send` and `queue_receive`. |
| **05** | `05-message-batch-unordered.lms` | Multi-message send, unordered receive loop, and ack all | Sending 5 distinct messages and polling `queue_receive(q, 5, 1, 30)` in a bounded loop collects all 5 distinct message bodies regardless of delivery order; after acknowledging all 5, the queue is empty. |
| **06** | `06-visibility-timeout-and-nack.lms` | In-flight visibility hiding and immediate redelivery via `queue_nack(q, r, 0)` | A message received with `visibility_timeout = 30` is hidden from an immediate second `queue_receive`; calling `queue_nack(q, receipt, 0)` makes the message immediately visible again so the next `queue_receive` redelivers it and `queue_ack` deletes it. |
| **07** | `07-receive-empty-queue.lms` | Receive on empty queue (`wait_seconds = 0` and `1`) | Calling `queue_receive(q)` and `queue_receive(q, 5, 1, 30)` on an empty existing queue succeeds (`last_error().ok() == true`) and returns a `QueueMessageList` with `len() == 0`. |
| **08** | `08-ack-idempotency-and-invalid-receipt.lms` | Duplicate `queue_ack` idempotency and invalid `queue_nack` receipt rejection | Re-calling `queue_ack(q, receipt)` on an already-acknowledged message is a no-op, whereas `queue_nack(q, "invalid-receipt-token", 10)` fails with `ErrorCode.INVALID_ARGUMENT`. |
| **09** | `09-queue-not-found-errors.lms` | Operations on a non-existent queue | Calling `queue_send`, `queue_receive`, `queue_ack`, or `queue_nack` on a missing queue aborts with `[NOT_FOUND]` (`ErrorCode.NOT_FOUND`). |
| **10** | `10-queue-validation-guards.lms` | Pre-flight validation of queue names and receive/nack bounds | Invalid queue names (`"ab"`, `"Bad_Queue"`, `"my--queue"`, `"google-queue"`, `"1starts-with-digit"`), `max_messages` outside `1..10`, `wait_seconds` outside `0..20`, `visibility_timeout` outside `0..600`, and empty `receipt == ""` all fail pre-flight with `ErrorCode.INVALID_ARGUMENT`. |
| **11** | `11-queue-payload-size-guard.lms` | Boundary payload (`48 KiB`) and oversized payload (`> 48 KiB`) | Sending an exact `49,152`-byte (`48 KiB`) payload succeeds and round-trips intact; sending a `49,153`-byte payload fails pre-flight with `ErrorCode.INVALID_ARGUMENT`. |
| **12** | `12-queue-auth-enforced-denial.lms` | Unauthenticated vs unauthorized queue access (`--auth enforce`) | Under `--auth enforce`, an unauthenticated request fails with `ErrorCode.UNAUTHENTICATED` (`401`), and a valid caller lacking queue permission fails with `ErrorCode.PERMISSION_DENIED` (`403`, or live OCI `404 NotAuthorizedOrNotFound` mapped by `lmoci` to `PERMISSION_DENIED`). |

---

## 3. Sim Enhancements (Evidence-Backed Findings Across the 4 Simulators)

Inspection of the four simulator repositories (`/home/ubuntu/cloud/{awssim,azuresim,gcpsim,ocisim}`) revealed the following concrete queue gaps and test omissions that should be addressed when implementing Slice 2:

### 3.1 `awssim` (`/home/ubuntu/cloud/awssim`)
1. **`ChangeMessageVisibility` (and `PurgeQueue`) missing from `SUPPORTED.get("sqs")` in `--auth enforce` mode:**
   - **File / Lines:** `/home/ubuntu/cloud/awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java`, lines 41–42:
     ```java
     "sqs", Set.of("CreateQueue", "DeleteQueue", "GetQueueUrl", "GetQueueAttributes", "ListQueues",
         "SendMessage", "ReceiveMessage", "DeleteMessage", "TagQueue", "UntagQueue", "ListQueueTags"),
     ```
   - **Evidence:** When `awssim` runs with `--auth enforce`, `AuthFilter.java` line 61 checks `SUPPORTED.getOrDefault(ra.service(), Set.of()).contains(ra.action())` and rejects any unlisted action with `403 AccessDenied ("Unsupported action in enforced mode: sqs:" + action)`. Because `"ChangeMessageVisibility"` is omitted from `SUPPORTED.get("sqs")`, `cloud.queue_nack(q, receipt, visibility_timeout)` will fail with `403` in `--auth enforce` mode!
   - **Required Enhancement:** Add `"ChangeMessageVisibility"` (and `"PurgeQueue"`) to `SUPPORTED.get("sqs")` in `AuthFilter.java` lines 41–42, and add a test case in `scripts/test-auth.py`.
2. **Visibility timeout / `ChangeMessageVisibility` and `ListQueues` pagination not covered in `awssim` integration tests:**
   - **File / Lines:** `/home/ubuntu/cloud/awssim/scripts/test-integration.py`, lines 108–118 (`test_sqs`).
   - **Evidence:** `test_sqs` tests `CreateQueue`, `SendMessage`, `ReceiveMessage`, `DeleteMessage`, `DeleteQueue`, and `ListQueues`, but does not test `ChangeMessageVisibility` (`VisibilityTimeout=0` immediate redelivery) or `GetQueueUrl` on a non-existent queue.
   - **Required Enhancement:** Extend `test_sqs` in `scripts/test-integration.py` to exercise `ChangeMessageVisibility` (with `VisibilityTimeout=0` redelivery) and `GetQueueUrl` `NonExistentQueue` error status.

### 3.2 `azuresim` (`/home/ubuntu/cloud/azuresim`)
1. **`UpdateMessage` (`PUT /<account>-queue/<queue>/messages/<messageid>?popreceipt=...&visibilitytimeout=...`) and `GetQueueMetadata` (`?comp=metadata`) not covered in `azuresim` tests:**
   - **File / Lines:** `/home/ubuntu/cloud/azuresim/src/main/java/ai/lmctl/azuresim/StorageAuth.java` lines 248–261 and `/home/ubuntu/cloud/azuresim/scripts/test-storage.py` lines 90–101.
   - **Evidence:** `StorageAuth.java` line 251 maps `PUT /<queue>/messages/<messageid>` (when `comp` is empty) to `Microsoft.Storage/storageAccounts/queueServices/queues/messages/write`, and line 258 maps `GET /<queue>?comp=metadata` to `.../queues/read`. However, `scripts/test-storage.py` lines 90–101 only tests `PUT /<queue>`, `POST /<queue>/messages`, `GET /<queue>/messages`, `DELETE /<queue>/messages/<id>?popreceipt=...`, and `DELETE /<queue>`. It never tests `PUT /<queue>/messages/<id>?popreceipt=...&visibilitytimeout=0` (required by `queue_nack`) or `GET /<queue>?comp=metadata` (required by `queue_exists`).
   - **Required Enhancement:** Add `GET /<account>-queue/<queue>?comp=metadata` and `PUT /<account>-queue/<queue>/messages/<id>?popreceipt=...&visibilitytimeout=0` (verifying immediate message redelivery and updated `PopReceipt`) to `scripts/test-storage.py` and `scripts/test-auth.py`, and ensure upstream `floci-az` honors `visibilitytimeout=0` on `PUT .../messages/<id>`.

### 3.3 `gcpsim` (`/home/ubuntu/cloud/gcpsim`)
1. **Pub/Sub `:modifyAckDeadline` (`queue_nack`) not exercised in `gcpsim` integration or auth tests:**
   - **File / Lines:** `/home/ubuntu/cloud/gcpsim/src/main/java/ai/lmctl/gcpsim/PermissionFilter.java` lines 118–119 and `/home/ubuntu/cloud/gcpsim/scripts/test-gcloud.py` lines 79–94.
   - **Evidence:** `PermissionFilter.java` line 119 maps `POST /v1/projects/{p}/subscriptions/{s}:modifyAckDeadline` to `pubsub.subscriptions.consume`, which is supported by upstream `floci-gcp`. However, `scripts/test-gcloud.py` lines 79–94 only tests topic create, subscription create, `:publish`, `:pull`, `:acknowledge`, and delete; it never tests `:modifyAckDeadline` with `ackDeadlineSeconds: 0` (immediate redelivery) or invalid `ackIds` error handling (`400 INVALID_ARGUMENT`).
   - **Required Enhancement:** Add `:modifyAckDeadline` (`ackDeadlineSeconds: 30` and `ackDeadlineSeconds: 0` redelivery, plus invalid `ackId` rejection) to `scripts/test-gcloud.py` and `scripts/test-auth.py`.

### 3.4 `ocisim` (`/home/ubuntu/cloud/ocisim`)
1. **OCI Queue `UpdateMessage` (`PUT /20210201/queues/{queueId}/messages/{messageReceipt}`) and invalid receipt handling not tested in `ocisim`:**
   - **File / Lines:** `/home/ubuntu/cloud/ocisim/src/main/java/ai/lmctl/ocisim/OciPolicyEngine.java` lines 645–647 and `/home/ubuntu/cloud/ocisim/scripts/test-integration.py` lines 489–501.
   - **Evidence:** `OciPolicyEngine.java` line 646 maps `PUT /20210201/queues/{id}/messages/{receipt}` to `"UpdateMessage"` (`QUEUE_UPDATE`), but `scripts/test-integration.py` lines 489–501 only tests `POST /20210201/queues`, `POST .../messages`, `GET .../messages`, `DELETE .../messages/{receipt}`, and `DELETE /20210201/queues/{id}`.
   - **Required Enhancement:** Add `PUT /20210201/queues/{id}/messages/{receipt}` with `{"visibilityInSeconds": 0}` (verifying immediate redelivery) and invalid receipt `400`/`404` status verification to `ocisim/scripts/test-integration.py`.
2. **OCI Queue `GET /20210201/queues?compartmentId=...&displayName=...` filter behavior:**
   - **File / Lines:** `/home/ubuntu/cloud/ocisim/scripts/test-integration.py` line 492 and `/home/ubuntu/cloud/lmoci/src/main/java/ai/lmctl/lmoci/OciBackend.java` line 1482.
   - **Evidence:** `lmoci` resolves queue names by listing `/20210201/queues?compartmentId=...` and matching `displayName`. Verify that `ocisim` (`floci-oci`) honors the optional `displayName` query parameter on `GET /20210201/queues` (in addition to `lmoci` filtering client-side by `displayName` and `lifecycleState == "ACTIVE"`).
