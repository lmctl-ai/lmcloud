# 15 — `lmcloud` Permissions Design (Slice 4: portable IAM-like policies)

## 1. Goals & Architectural Alignment

Slice 4 extends `schema/lmcloud.dsl.json` **additively** with a provider-neutral authorization model: policy statements (`Allow`/`Deny` over portable actions and resources), attachment of policies to bucket/queue/table resources or to principals, a **reference evaluation** call, and offline lint (incl. least-privilege findings). No existing Slice 1/2/3/5 signature is modified.

1. **Local emulators (primary conformance target):** `awssim :4566`, `azuresim :4577`, `gcpsim :4588`, `ocisim :4599`, each in `--auth enforce` mode as the *enforcement* ground truth for data-plane probes (scenarios 12–13); `policy_check` itself is a portable reference evaluation (§3.4).
2. **Real clouds:** credentials/endpoint rules from `02-object-storage-design.md`; live-mode authority chain per `14-live-safety.md` (double opt-in, `live-policy.json`, journal-first, ownership fencing). The `--live` profile **excludes** this slice; additionally every attach/mutation on a live-routed endpoint fails closed until the native-mapping certification matrix (§5.2) is signed off (design-time rule: mutation routes require sim/offline/`ref`).

### 1.1 Endpoint Resolution
Service name **`"permissions"`** in the canonical precedence table (`02-object-storage-design.md` §3.3): `cloud.set_endpoint("permissions", url)` / `LMCLOUD_PERMISSIONS_ENDPOINT` / `LM<PROVIDER>_PERMISSIONS_ENDPOINT` → provider-native IAM endpoints. Loopback-only `http://` rules apply unchanged.

---

## 2. Portable Policy Model

### 2.1 Two-tier input handling (the single contract)

- **Tier 1 — strict *syntax* in the builder/parse path.** `policy.statement(effect, actions, resources)` and `policy_parse(document)` reject only *malformed* inputs pre-flight (`INVALID_ARGUMENT`, `http_status()==0`): bad effect spelling (not `Allow`/`Deny`, case-insensitive-normalized), action strings not matching the shape `^[a-z]+(\.[a-z]+){2}$`, resource strings not matching `<slice>:<type>:<rest>` with legal charsets, oversized elements, malformed JSON in `policy_parse`. Tier 1 knows the *grammar*, not the *vocabulary*.
- **Tier 2 — semantic lint.** Well-formed-but-unknown or forbidden vocabulary (e.g. `storage.object.bogusverb`, `permissions.policy.write`) is ACCEPTED into the in-memory policy and reported by `policy_lint` with error findings. Policies with any `severity=="error"` finding are **non-executable**: `policy_attach*` refuses them pre-flight (`INVALID_ARGUMENT`). Lint-clean policies (errors=0; warnings allowed) are executable.
- Attach validation is never relaxed to make lint tests run — the tiering above is the fix (formerly contradictory strict-builder rules are removed).

### 2.2 Action vocabulary (exhaustive; Appendix A is the matrix)

Action = `<slice>.<type>.<op>`; ops are **per resource type** (not one global verb list):

| Resource | Legal ops |
|---|---|
| `storage.bucket` | `create`, `read` (head/exists), `list` (listBuckets), `delete` |
| `storage.object` | `read` (get/head), `write` (put), `list` (list objects), `delete` |
| `queue.queue` | `create`, `read` (metadata), `list`, `delete`, `send`, `receive`, `ack`, `nack` |
| `tables.table` | `create`, `read` (get/query metadata), `list`, `write` (put/update/delete items), `delete` |

`permissions.*` (and any management/identity namespaces, e.g. `iam.*`, `identity.*`, `userpool.*`) do **not** exist in the portable namespace. Bare `*` or partial wildcards in actions are **never legal** (even Tier 1 flags findable cases — see matrix notes in Appendix A); unknown-but-well-formed triples → lint `UNKNOWN_ACTION`.

### 2.3 Resource grammar

`<slice>:<type>` = `[a-z]+` each; `<name>` = the owning slice's portable name charset (buckets/queues/tables rules — e.g. bucket `[a-z0-9-]` 3..63); the `/...` suffix (object scopes only) uses the object-key charset from `02-object-storage-design.md` §4 rules. `*` is a **trailing byte-prefix wildcard** allowed only after `/` and only inside `storage.object` scopes (`storage:object:<bucket>/logs/*`). Whole-class wildcards like `storage:bucket:*` are syntactically legal but raise lint `WILDCARD_SCOPE` and are **not attachable at identity side** (§4.3). Names follow the owning slice's portable naming rules. Matching is **literal byte** matching — no URL-decoding/normalization layer; resource keys containing literal `*`, control chars, or `%` sequences never alias; a literal `*` inside a key is not addressable by a policy resource (documented constraint).
Existence **anchors**: object-scoped references anchor on their parent bucket; queue/table references anchor on the entity itself. (Hypothetical children never gate checks or attaches.)

### 2.4 Statements, effects, evaluation

- Effects: `Allow`, `Deny`. Evaluation: explicit **Deny anywhere wins**; absence of any matching Allow ⇒ **denied** (default deny). Deterministic, provider-independent.
- **Effective policy** for a principal = the union of all journaled attachments naming that principal (both resource-scoped and principal-scoped kinds), evaluated over statement sets. (This union is evaluated by the portable reference evaluator, §3.4.)
- **Deny portability:** Deny is enforced by the reference evaluator and by all four sim enforcement layers (`ocisim`'s `OciPolicyEngine` implements deny-overrides). **Native Deny** is NOT certified anywhere except AWS IAM native policies; per §5.2 attach containing Deny is **refused** on live Azure/GCP/OCI today (Azure customer-managed deny assignments are not GA; GCP deny policies bind at org/folder/project scope, outside our ownership boundary; live OCI has no Deny).

### 2.5 Principals

- `principal_current() -> string`: the caller's identity string from credentials (provider-shaped); information-only accessor (may resolve locally; never used to infer auth mode).
- Principal strings are Tier-1 validated: `^[A-Za-z0-9_+=,.@:/-]{1,256}$`; longer or out-of-charset → pre-flight `INVALID_ARGUMENT`.
- Principals are referenced, not provisioned (identity provisioning out of scope; Slice 6). Conformance uses configured test identities: scenarios read `LMCLOUD_TEST_PRINCIPAL` or `LM<PROVIDER>_SIM_PRINCIPAL` (default `arn:aws:iam::000000000000:role/lmcloud-test`) and never hard-code provider identities into shared logic. Enforcement-fixture principals come from dedicated env pairs (`LMCLOUD_ENFORCE_GRANTED_PRINCIPAL` beside `LMCLOUD_ENFORCE_GRANTED_<P>_*` credentials) so grant targets are always *the identity the auth layer actually maps those credentials to* — never invented strings (scenario 13).

---

## 3. Schema Surface

### 3.1 Types

#### `Policy` (mutable builder locally; canonicalized for wire/journal)
| Method | Signature | Description |
|---|---|---|
| `statement` | `(effect: string, actions: StrList, resources: StrList) -> self` | Tier-1 validated; appends. |
| `document` | `() -> string` | Canonical JSON per §3.5 (byte-identical across hosts). |
| `len` | `() -> int` | Statement count (`0..32`). |

#### `LintReport` / `LintFinding`
| Type | Methods |
|---|---|
| `LintReport` | `ok() -> bool` (true iff zero `severity()=="error"`), `len() -> int`, `at(int) -> LintFinding` (deterministic order: statement index, then rule code, §3.5) |
| `LintFinding` | `severity() -> string` (`"error"`/`"warning"`), `code() -> string`, `message() -> string` |

**Lint rules (§3.3):** `EMPTY_POLICY`(e), `UNKNOWN_ACTION`(e), `UNKNOWN_RESOURCE`(e), `EFFECT_INVALID`(e, defensive), `ESCALATION_NAMESPACE`(e), `STATEMENT_COUNT`(e), `WILDCARD_SCOPE`(w), `OVERBROAD_COMBINATION`(w).

### 3.2 `Cloud` methods

| Method | Semantics |
|---|---|
| `principal_current() -> string` | §2.5. |
| `policy_new() -> Policy` / `policy_parse(document: string) -> Policy` | Tier-1 build/parse. |
| `policy_lint(Policy) -> LintReport` | Offline; deterministic finding order. |
| `policy_attach(resource, principal, Policy) -> void` | Attach document to the **owned** target resource for `principal`. Statement resources must be within the target's scope (§4.3 fences). Lint-error policy → `INVALID_ARGUMENT` pre-flight. Missing target → `NOT_FOUND`; existing-foreign → `PERMISSION_DENIED`. Identity semantics per §4.2 (idempotent same-doc; different doc = replace). |
| `policy_attach_principal(principal, Policy) -> void` | Identity-side attach; every statement resource must exist-and-be-owned, or be an in-scope subpath of one; whole-class wildcards fail closed (`INVALID_ARGUMENT`). Same identity/replace rules. |
| `policy_detach(resource, principal) -> void` / `policy_detach_principal(principal) -> void` | Remove the attachment for the exact pair; idempotent (`OK` when nothing attached). Only journaled owned attachments are ever touched (§4). |
| `policy_check(principal, action, resource) -> bool` | **Portable reference evaluation** over the journaled portable attachment state (§3.4): grammar errors → `INVALID_ARGUMENT` (`http_status()==0`); anchored target missing → `NOT_FOUND`; else effective allow/deny per §2.4. It never claims what native IAM would do. |

### 3.4 Reference evaluator (chosen authority)

`policy_check` is the *same* provider-neutral evaluator on all four hosts: input = journaled attachment state (§4.1) + the (principal, action, resource) triple; evaluation = statement-set union, prefix matching per §2.3, Deny precedence. Ambient/native grants never affect it; native simulate APIs (`SimulatePrincipalPolicy`, `testIamPermissions`) are deliberately **not** used (both are caller-scoped or IAM-identity-scoped and cannot answer for arbitrary portable principals). Native *enforcement* is verified separately by data-plane probes (conformance scenario 13, against sim enforce layers after epics A-P1/A-P2/A-P3/A-P4).

### 3.5 Canonical document format, bounds & finding order (P2)

- Envelope: `{"v":1,"statements":[{"effect":"Allow|Deny","actions":[..],"resources":[..]}, ...]}`. Unknown fields and duplicate keys in `policy_parse` input → `INVALID_ARGUMENT`. Canonical output = UTF-8, no insignificant whitespace, object keys in the fixed order shown; `actions`/`resources` sorted ascending UTF-8 bytes; statements keep insertion order.
- Bounds: document ≤ **8192 bytes**; statements ≤ 32; actions per statement ≤ 64; resources per statement ≤ 64; each action ≤ 128 bytes; each resource ≤ 512 bytes. Cross-host canonical bytes are pinned by a golden-document conformance fixture (scenario 01).
- Lint finding order: statement index, then rule code ascending.
- Attachments ≤ **128 per run**; per-(target,principal) document ≤ 8192 canonical bytes.

---

## 4. Ownership, Authority, Identity & Durability Contract

1. **Attachment identity & semantics (single contract — no accumulation/replacement duality):**
   - Key = `(scope-fingerprint, run_id, kind∈{resource,principal}, target, principal)`.
   - Same key + identical canonical document → idempotent no-op (`OK`). Same key + different document → **replace** the contribution of that attachment. Detach removes exactly that attachment's contribution. Contributions from different keys (resource-side and principal-side, different principals/targets) **combine by union** during evaluation; Deny precedence applies across the union. Foreign/pre-existing native policy entries are never touched (§4.4).
2. **Journal-backed durable state (replayable):** every attach/detach intends a journaled record containing: scope fingerprint (provider+account/project/namespace), run id, attachment key, kind, **full canonical document** (bounded ≤ 8 KiB — hash alone is NOT the replay source), 128-bit ownership token, generation counter, native identifiers (bucket-policy etag / role-definition+assignment ids / binding etag / policy OCID, where the provider keeps them), and every native child object created (recorded as journaled children with reserved teardown). Replay after child-process exit reconstructs the evaluator + pending intents from the journal alone; ambiguous lost replies → `retained`, never adopted or assumed absent (14-live-safety §3 rules apply).
3. **Scope fences at attach:** resource-side attaches require every statement resource to be the target itself or a subpath within it. Identity-side attaches: each statement resource must be an owned existing entity (bucket/queue/table) or a subpath of one; whole-class wildcards (e.g. `storage:bucket:*`) fail closed at attach (`INVALID_ARGUMENT`) rather than expanding to project/account scope.
4. **Shared-native-document preservation:** where attach maps to a shared native document/binding list (AWS bucket policy JSON, GCP `setIamPolicy` bindings, Azure assignments), the adapter merge-perserves other principals'/non-lmcloud entries (read-modify-write under native etag/condition where supported); detach removes only entries carrying our ownership token/record keys. Entries not provably ours are never adopted (retained on ambiguity).
5. **Metering:** attach/detach/check plus every hidden physical sub-op (ownership reads, policy reads/writes, role-definition writes, assignment writes, pages, polls, retries, cleanup) go through the Slice-3 attempt-level `CostMeter` reservations settled by attempt ID (distinct from native idempotency tokens). Overruns surface `COST_CAP_EXCEEDED` (already in the shared `ErrorCode` enum on main). Dry runs register explicit Dry slots: attach/detach are mutators with zero native writes and a scoped preview the later `policy_check` sees; builder/parse/lint are local-only.
6. **No unbounded reads:** no tenant-wide policy listing exists; check/detach are point operations.
7. **Escalation containment:** management namespaces excluded (§2.2); lint `ESCALATION_NAMESPACE` errors make such policies non-executable; attaches fence ownership.

## 5. Per-Provider Mapping & Certified Subset (§5.2 refuses everything not listed)

### 5.1 Reference layer (all providers, sim-first)
The journaled attachment store + reference evaluator + lint are identical everywhere; on sims it's the primary path and it never depends on provider semantics.

### 5.2 Native mapping certification matrix (per action/effect — everything else is refused pre-flight today)

| Portable | AWS (iam/s3) | Azure (RBAC) | GCP (IAM) | OCI (policies) |
|---|---|---|---|---|
| `storage.object.read` on `storage:object:<b>/*` Allow | `s3:GetObject` on `arn:aws:s3:::<b>/*` (bucket-policy statement) | **pending A-P2** (data-action `.../blobs/read` at container scope) | **pending A-P3** (`storage.objects.get`, resource-level binding) | `read` on `objects in bucket <b>` (condition-constrained; **pending** live review) |
| …(each matrix row from Appendix A gets an exact native line before that row is live-certified) | AWS native Deny allowed | Azure native Deny refused (service-managed only) | GCP native Deny refused (org/folder scope) | OCI native Deny refused (no Deny) |
| Deny effect (native attach) | allowed | **refused** | **refused** | **refused** (evaluate-only) |

Attach on a native route with an unsupported mapping fails `INVALID_ARGUMENT` *before any network call* (fail-closed). Sim/loopback attach routes that exist but are **not yet mapped/implemented** fail the same way, and the canonical classification is `last_error().provider_code() == "UNSUPPORTED_MAPPING"` — this specific code is the only sanctioned "route unmapped" skip reason in conformance scenarios (everything else, including `INTERNAL`, fails the scenario). The sim/loopback and offline routes implement the full portable model regardless; **native/live routes additionally require the row above to be certified** plus Slice-14's double opt-in gate. Safe shared-document concurrency on providers lacking native conditional writes is a certification prerequisite (etag-free read/modify/write alone is not sufficient against concurrent foreign edits).

### 5.3 Simulator gaps (epics; evidence in 16 §3)
- **A-P1 `awssim`:** `AuthFilter.SUPPORTED` has no `iam` key and the `s3` set lacks `PutBucketPolicy`/`GetBucketPolicy`/`DeleteBucketPolicy`; add both + enforce tests.
- **A-P2 `azuresim`:** add RBAC-lite (role definitions + assignments at storage scopes, data-action evaluation) in `StorageAuth.java`.
- **A-P3 `gcpsim`:** add resource `setIamPolicy` binding mutation + `testIamPermissions` evaluation for GCS/PubSub in `PermissionFilter.java`.
- **A-P4 `ocisim`:** extend `OciPolicyEngine` resolvers: policy CRUD (`/20160918/policies`) and application of resource-scoped attached statements to OS/Queue decisions in enforce mode.

## 6. Error Model (shared codes; COST_CAP_EXCEEDED included)

| `ErrorCode` | When |
|---|---|
| `INVALID_ARGUMENT` | Tier-1 grammar failures; lint-error policy at attach; scope-fence violations (foreign-scope wildcard expansion, out-of-target statements); unsupported native/sim mapping (with `provider_code() == "UNSUPPORTED_MAPPING"`); all pre-flight (`http_status()==0`) |
| `NOT_FOUND` | attach/detach/check whose anchored target (§2.3) is missing |
| `CONFLICT` | foreign collision/journal races (14-live-safety) |
| `PRECONDITION_FAILED` | native etag mismatch on shared-document merge |
| `UNAUTHENTICATED` | bad credentials; live not enabled |
| `PERMISSION_DENIED` | existing-but-foreign target; enforce-mode policy denial |
| `COST_CAP_EXCEEDED` | attempt admission/settlement over the run cap (Slice-3 code; explicitly listed) |
| `INTERNAL` | transient/unknown |

## 7. Excluded from v1
1. Native simulate APIs as the check backend (§3.4). 2. Native Deny mapping except AWS (§2.4/§5.2). 3. Identity provisioning (users/roles/groups/members). 4. Condition keys/context. 5. Cross-account grants. 6. `NotAction`/`NotResource`. 7. Tenant-wide policy listing/audit export. 8. Permission boundaries/SCP. 9. Versioned policy history. 10. Managed/named reusable policies (inline documents only).

## 8. Decisions (D1–D6)
1. Tier-1 (syntax) vs Tier-2 (semantic lint) separated; non-executable policies rejected at attach (single consistent contract; fixes the earlier strict-builder contradiction).
2. Per-resource-type op vocabulary + exhaustive appendix matrix; no management namespaces.
3. `policy_check` = provider-neutral evaluator over journaled state (never native simulate); native enforcement verified separately via data-plane probes against sim enforce layers.
4. Attachment replace-per-key with union-across-keys evaluation and exact detach; Deny precedence across the union.
5. Durable full-document journal records + native IDs + per-child teardown reservation; retained-on-ambiguity; no adoption.
6. Golden canonical documents + hard bounds + deterministic finding order pin cross-host byte equality.

## Appendix A — Exhaustive action/resource compatibility matrix

| Action | Legal resources | Attach side allowed |
|---|---|---|
| `storage.bucket.create` | `storage:bucket:<name>` | both |
| `storage.bucket.read` | `storage:bucket:<name>` | both |
| `storage.bucket.list` | `storage:bucket:<name>` | both (note: list op is caller-scope filtered by providers) |
| `storage.bucket.delete` | `storage:bucket:<name>` | both |
| `storage.object.read` | `storage:object:<b>/k`, `storage:object:<b>/prefix*`, `storage:object:<b>/*` | both |
| `storage.object.write` | same | both |
| `storage.object.list` | same | both |
| `storage.object.delete` | same | both |
| `queue.queue.create` | `queue:queue:<name>` | both |
| `queue.queue.read` | `queue:queue:<name>` | both |
| `queue.queue.list` | `queue:queue:<name>` | both |
| `queue.queue.delete` | `queue:queue:<name>` | both |
| `queue.queue.send` | `queue:queue:<name>` | both |
| `queue.queue.receive` | `queue:queue:<name>` | both |
| `queue.queue.ack` | `queue:queue:<name>` | both |
| `queue.queue.nack` | `queue:queue:<name>` | both |
| `tables.table.create` | `tables:table:<name>` | both |
| `tables.table.read` | `tables:table:<name>` (covers item get/query/scan) | both |
| `tables.table.list` | `tables:table:<name>` | both |
| `tables.table.write` | `tables:table:<name>` (covers item put/update/delete) | both |
| `tables.table.delete` | `tables:table:<name>` | both |

Everything not listed here is `UNKNOWN_ACTION` (lint error) and non-executable.
