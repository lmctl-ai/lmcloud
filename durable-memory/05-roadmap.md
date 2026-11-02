# 05 — `lmcloud` 10-Slice Roadmap & Simulator Epics

## 1. Guiding Principles

1. **Use the real thing when it is cheap and local; use a sim only to emulate a cloud's API:** When a workload's data plane is an open, lightweight local server (such as Valkey), run the **real** server locally (`docker run` on a free loopback port, or a GitHub Actions service container in CI). Mocking an open-source protocol engine that starts in milliseconds has no value (like mocking SQLite). Reserve simulators strictly for emulating proprietary cloud APIs and control planes.
2. **Simulators are the primary test target for cloud APIs:** Cloud-API conformance tests execute first against our four local emulators (`awssim` on `:4566`, `azuresim` on `:4577`, `gcpsim` on `:4588`, `ocisim` on `:4599`) — fast, deterministic, zero cloud cost, no cloud account required, and runnable in GitHub Actions from checksum-pinned release binaries.
3. **One program runs everywhere:** The **exact same** `lmscript` conformance programs later execute against live AWS, Azure, GCP, and OCI clouds by changing only the endpoint/credentials configuration.
4. **Simulators are ours and evolve with the schema:** All four simulators are overlay builds over pinned, checksum-verified upstreams (`awssim` 0.2.0 on `floci` 2.3.0; `azuresim` 0.2.0 on `floci-az` 0.15.0; `gcpsim` 0.2.0 on `floci-gcp` 0.11.0; `ocisim` 0.1.0 on `floci-oci` 0.5.0). When a slice requires simulator capabilities or auth-map coverage, we enhance the simulator rather than watering down `lmcloud`.
5. **Customizable simulator behavior via `lmcode` SAM rules (and `lmmock` front-proxy evaluation):** Simulator behavior (throttling, fault injection, latency, pagination caps, OCI `403`→`404` denial mapping, and regional response quirks) is customizable via `lmcode` SAM rule methods (`Interceptor` / `Responder` on `sim_rules_v1`; see [`06-sim-rules.md`](06-sim-rules.md)). In parallel, `lmctl-ai/lmmock` is being evaluated as an alternative or complementary programmable front proxy (`--upstream` selective passthrough + audit log).

---

## 2. The 10 Target Areas

| Area | Cloud Equivalents (AWS / Azure / GCP / OCI) | Existing Host Exposure (`lmaws` / `lmazure` / `lmgcp` / `lmoci`) | Portability | Cost & Live-Cloud Risk |
|---|---|---|---|---|
| **Storage** | S3 / Blob Storage / Cloud Storage (GCS) / Object Storage | Covered (16 `s3_*`) / Covered (`Run.container`) / Covered (13 `storage_*`) / Covered (9 obj ops) | **HIGH** — CRUD maps 1:1; normalized pagination tokens, metadata keys, and bucket naming | Low; guarded by run ledgers + cost caps |
| **Queue** | SQS / Queue Storage / Pub/Sub / OCI Queue | Covered (6) / Covered (`Run.queue`) / Covered (11 `pubsub_*`) / Covered (3) | **MED-HIGH** — Pub/Sub topic+subscription mapped onto portable queue send/receive/ack/nack | Low; 64 KiB billing units |
| **Perf & Cost** | Cost Explorer + CloudWatch / Cost Mgmt / Billing + Monitoring / Cost Analysis | `Spend` (8) + `fleet_costs`, `spot_prices`, `cpu_credits` / `cost_report`, `estimated_cost` / 6 cost/evidence + `monitoring_*` / `cost_summary`, `estimated_cost`, `runtime` budget | **HIGH** — Cross-cutting host-side ledger, embedded price tables, and budget caps; zero simulator dependency | Zero API risk (embedded price tables; live CE paid queries gated) |
| **Permissions** | IAM / Entra + RBAC / Cloud IAM / OCI IAM | Extensive (20 `Cloud` + 53 `Policy` builder/lint/simulate/attach) / Absent / Read-only ×3 / Read + `analyze_policy` lint | **MED-LOW** — Statement model (AWS/OCI) vs role bindings (GCP) vs role assignments (Azure) | Low cost, **HIGH blast radius**; mutations strictly gated to run-owned resources |
| **Tables** | DynamoDB / Table Storage + Cosmos NoSQL / Firestore / OCI NoSQL | Partial (4 item ops) / Inventory-only / Partial (5 `firestore_*`) / Absent | **MEDIUM** — Key-value CRUD + prefix/partition scan portable; secondary indexes/TTL diverge | Low–medium |
| **Userpool** | Cognito User Pools / Entra External ID / Identity Platform (Firebase Auth) / OCI Identity Domains | Absent across all four hosts | **MEDIUM** — Pool/user create, admin auth, and token verify map cleanly; custom triggers/JWKS differ | Low (generous free tiers) |
| **VM** | EC2 / Azure VMs / Compute Engine / OCI Compute | Covered (18 + 17 Spot) / Inventory-only / Covered (9, shape allowlist) / Absent | **LOW-MED** — Control-plane metadata slice only (shapes, images, lifecycle); no Docker instance boot | **HIGHEST** on live clouds (hourly billing, orphan leaks; requires durable journals, sweepers, $0.25 caps) |
| **Container** | ECS·EKS·ECR / ACI·AKS·ACR / Cloud Run·GKE·AR / OKE | Inventory `clusters` / Registries + AKS inventory / `run_*` ×7 + `gke`/`ar` read / `clusters` list | **LOW** — Mock control-plane & service/cluster metadata slice | Medium–high on live clouds (GKE/OKE hourly if leaked) |
| **Lambda / Functions** | Lambda / Azure Functions / Cloud Functions / OCI Functions | Covered (5 + `Lambda`/`Serverless` types) / Inventory-only / Absent / Partial (list + `Run.application`) | **LOW-MED** — Control-plane only (`create`/`get`/`list`/`delete` without `invoke`, as invocation requires Docker) | Very low |
| **Valkey / Cache** | ElastiCache / Azure Cache for Redis / Memorystore / OCI Cache | Absent across all four hosts | **HIGH** data plane (real `valkey/valkey` container), **MED** cloud control plane | Medium on live clouds (node-hourly) |

---

## 3. Adopted Slice Implementation Order

Lead has fixed the delivery order across the 10 slices as follows:

1. **Slice 1 — Object Storage** *(`02-object-storage-design.md`, `03-object-storage-conformance.md`, `schema/lmcloud.dsl.json`)*:
   - Bucket `create`/`delete`/`exists`/`list` and Object `put`/`get`/`head`/`delete`/`list`/`list_all` with metadata and content-type. All four sims (`awssim`, `azuresim`, `gcpsim`, `ocisim`) run in-process today.
2. **Slice 2 — Queue** *(`07-queue-design.md`, `08-queue-conformance.md`, `schema/lmcloud.dsl.json`)*:
   - Portable queue lifecycle (`queue_create`, `queue_delete`, `queue_exists`, `queue_list`) and messaging (`queue_send`, `queue_receive`, `queue_ack`, `queue_nack`) over SQS, Azure Queue Storage, GCP Pub/Sub (auto-managed topic+subscription pair), and OCI Queue. All four sims support queues in-process today.
3. **Slice 3 — Perf & Cost (Cross-Cutting)**:
   - Host-side cost estimation, operation counters, per-run budget caps (`$0.05` default, `$0.25` ceiling), durable pre-request resource ledgers, and LIFO teardown across all four hosts with zero external simulator dependency.
4. **Slice 4 — Permissions**:
   - Portable policy/binding inspection, offline policy lint/validation, and run-scoped role/policy attachment, backed by each simulator's `--auth enforce` policy engine.
5. **Slice 5 — Tables**:
   - Portable key-value / document table CRUD (`table_create`, `table_delete`, `item_put`, `item_get`, `item_delete`, `item_query`) over DynamoDB (`awssim`), Azure Table/Cosmos (`azuresim`), Firestore (`gcpsim`), and OCI NoSQL (`ocisim` upstream epic).
6. **Slice 6 — Userpool**:
   - User pool creation, user registration, password/token authentication, and group/claim lookup over Cognito (`awssim`), Entra (`azuresim`), Identity Platform / Firebase Auth (`gcpsim`), and OCI Identity Domains (`ocisim`).
7. **Slice 7 — VM (Control-Plane Only)**:
   - Instance lifecycle metadata (`vm_create`, `vm_get`, `vm_list`, `vm_stop`, `vm_delete`) against mock/control-plane simulator endpoints without launching Docker containers.
8. **Slice 8 — Container**:
   - Cluster/service/registry control-plane operations over ECS/EKS (`awssim`), AKS/ACR (`azuresim`), Cloud Run/GKE (`gcpsim`), and OKE (`ocisim`).
9. **Slice 9 — Lambda / Functions (Control-Plane Only, Without Invoke)**:
   - Function registration, configuration, listing, and deletion (`fn_create`, `fn_get`, `fn_list`, `fn_delete`), explicitly excluding runtime invocation (`invoke` requires Docker executors on all sims).
10. **Slice 10 — Valkey / Cache (Last)**:
    - **Valkey data plane is NOT mocked.** Data-plane operations are tested against a **real `valkey/valkey` container** (`docker run` on a free loopback port locally, and a GitHub Actions `services:` container in CI). The cloud-API side (`create`/`describe`/`delete` managed cache cluster) is covered by the simulators' control planes (`awssim` ElastiCache answers today), returning the loopback endpoint of the real `valkey/valkey` container behind it.

---

## 4. Simulator Enhancement Epics

### Cross-Simulator: Programmable Rules (`06-sim-rules.md`)
- **All four sims (`awssim`, `azuresim`, `gcpsim`, `ocisim`):** Embed `sim_rules_v1` SAM rule execution (`--rules FILE.dslb` / `SIM_RULES`) for deterministic fault injection, retry/throttling, pagination caps, and response rewriting; evaluate `lmctl-ai/lmmock` (`--upstream` passthrough + `Handler` SAM entries) as an alternative or complementary front proxy.

### `awssim` (`floci` 2.3.0 + overlay)
- **Slice 1 (Storage, S):** Verify `HeadBucket`/`HeadObject` route resolution and raw percent-encoded special-character key comparison in `AuthFilter.java`.
- **Slice 2 (Queue, S):** Add `ChangeMessageVisibility` (and `PurgeQueue`) to `SUPPORTED.get("sqs")` in `AuthFilter.java` so `queue_nack` works under `--auth enforce`, and add visibility-timeout / pagination coverage to `scripts/test-integration.py`.
- **Slice 4 (Permissions, M):** Extend `AuthFilter.java` `SUPPORTED` action map and tests to cover IAM policy/role operations in `--auth enforce` mode (167 IAM ops already exist in-process upstream).
- **Slice 6 (Userpool, S):** Certify upstream in-process Cognito IDP (86 operations, no Docker) and add enforce-mode route mapping.
- **Slice 7 (VM, S):** Enable and certify upstream EC2 mock control-plane mode without starting the wildcard IMDS listener or Docker containers.
- **Slice 8 & 9 (Container & Lambda, S):** Certify upstream ECS mock and Lambda control-plane operations (without Docker invocation).
- **Slice 10 (Valkey control plane, S):** Certify existing `awssim` ElastiCache control-plane (`CreateCacheCluster`/`DescribeCacheClusters`/`DeleteCacheCluster`) in `--auth enforce` mode and wire its returned endpoint to the local `valkey/valkey` container port.

### `azuresim` (`floci-az` 0.15.0 + overlay)
- **Slice 1 (Storage, S):** Allow `%25` (percent-encoded `%`) in blob names in `StorageAuth.java` (`--auth enforce`) and add pagination + `x-ms-meta-*` tests in `scripts/test-storage.py`.
- **Slice 2 (Queue, S):** Verify and test `PUT /<account>-queue/<queue>/messages/<messageid>?popreceipt=...&visibilitytimeout=...` (`UpdateMessage` for `queue_nack`) and `GET /<account>-queue/<queue>?comp=metadata` in `scripts/test-storage.py`.
- **Slice 4 (Permissions, M):** Add RBAC-lite role-assignment overlay on top of `StorageAuth.java`.
- **Slice 5 (Tables, S/M):** Certify upstream in-process Azure Table Storage (and optional embedded Cosmos NoSQL) and extend `StorageAuth.java` action mappings.
- **Slice 6 (Userpool, M):** Harden upstream Entra token issuance / userpool endpoints in `azuresim` without Docker.
- **Slice 7–9 (VM / Container / Functions, M):** Certify ARM control-plane handlers for VMs, AKS/ACR, and Functions metadata without Docker.
- **Slice 10 (Valkey control plane, S):** Add ARM `Microsoft.Cache/redis` control-plane handler returning the local `valkey/valkey` container endpoint.

### `gcpsim` (`floci-gcp` 0.11.0 + overlay)
- **Slice 1 (Storage, S):** Verify single-request `uploadType=multipart` binary + JSON metadata handling and `maxResults`/`pageToken` pagination in `scripts/test-lifecycle.py`.
- **Slice 2 (Queue, S):** Add `:modifyAckDeadline` (`queue_nack` / immediate redelivery with `ackDeadlineSeconds=0`) and `topics.list` pagination tests to `scripts/test-gcloud.py` and `scripts/test-auth.py`.
- **Slice 4 (Permissions, M):** Extend `PermissionFilter.java` to permit scoped IAM policy inspection/mutation in `--auth enforce` mode.
- **Slice 5 (Tables, M):** Certify upstream in-process Firestore REST endpoints and add `PermissionFilter.java` rules.
- **Slice 6 (Userpool, M):** Certify upstream in-process Firebase Auth / Identity Platform REST endpoints.
- **Slice 7 (VM, M):** Certify upstream Compute Engine control-plane endpoints in mock mode.
- **Slice 8 & 9 (Container & Lambda, S):** Certify Cloud Run / GKE mock control planes and Cloud Functions control plane (excluding Docker invoke).
- **Slice 10 (Valkey control plane, S):** Add Memorystore for Redis/Valkey REST control-plane endpoints (`projects.locations.instances`) returning the local `valkey/valkey` container endpoint.

### `ocisim` (`floci-oci` 0.5.0 + overlay)
- **Slice 1 (Storage, S):** Emit `opc-error-code` header on `OciAuthFilter.reject()` for `HEAD` requests and add `opc-meta-*` + `ListObjects` pagination tests to `scripts/test-integration.py`.
- **Slice 2 (Queue, S):** Add `PUT /20210201/queues/{queueId}/messages/{messageReceipt}` (`UpdateMessage` for `queue_nack`) and `displayName` filter / pagination tests to `scripts/test-integration.py`.
- **Slice 4 (Permissions, S):** Extend `OciPolicyEngine.java` operation resolvers as new slices are added.
- **Slice 5 (Tables, L — upstream epic):** Implement in-process OCI NoSQL Database REST service in `floci-oci` (currently absent upstream; blocks 4-cloud parity for Slice 5).
- **Slice 6 (Userpool, L — upstream epic):** Implement in-process OCI Identity Domains users/groups/auth subset in `floci-oci`.
- **Slice 7 (VM, L — upstream epic):** Implement OCI Compute control-plane (`instances`, `shapes`, `images`) in `floci-oci`.
- **Slice 8 & 9 (Container & Lambda, S):** Certify existing `floci-oci.services.oke.mock=true` and `floci-oci.services.functions.mock=true` control planes without Docker (`fnserver`/`k3s`).
- **Slice 10 (Valkey control plane, S):** Add OCI Cache (`redisClusters`) control-plane endpoints in `floci-oci` returning the local `valkey/valkey` container endpoint.
