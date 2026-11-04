# 15 — `lmcloud` Permissions Design (Slice 4: portable IAM-like policies)

## 1. Goals & Architectural Alignment

Slice 4 extends `schema/lmcloud.dsl.json` **additively** with a provider-neutral **authorization model**: policy statements (`Allow`/`Deny` over portable actions and resources), attachment of policies to **bucket/queue/table resources** or to **principals**, an evaluation/check call, and offline lint (incl. least-privilege findings). No existing Slice 1/2/3/5 signature is modified.

1. **Local emulators (primary conformance target):** `lmaws`↔`awssim :4566`, `lmazure`↔`azuresim :4577`, `lmgcp`↔`gcpsim :4588`, `lmoci`↔`ocisim :4599` — each sim runs in `--auth enforce` mode as the ground truth for enforcement; the slice's own scenarios exercise those enforce paths (scenario 12) against each sim's policy/auth layer.
2. **Real clouds** — credentials/endpoint rules from `02-object-storage-design.md`; **Stage-1 live safety** (`14-live-safety.md`) applies verbatim when attach/mutate operations ever run live: double opt-in, `live-policy.json`, journal-first, ownership fencing. The `--live` conformance profile currently **excludes** this slice (no live naming/ownership profile for policies yet).

### 1.1 Endpoint Resolution
Policy operations use service name **`"permissions"`** in the canonical precedence table (`02-object-storage-design.md` §3.3): `cloud.set_endpoint("permissions", url)` / `LMCLOUD_PERMISSIONS_ENDPOINT` / `LM<PROVIDER>_PERMISSIONS_ENDPOINT`, natives: `AWS_ENDPOINT_URL_IAM`/`AWS_ENDPOINT_URL`, `AZURE_*` (ARM), `IAM` endpoints on GCP, `OCI_ENDPOINT`. Loopback-only `http://` rules apply unchanged.

---

## 2. Portable Policy Model

### 2.1 Statements & Effects
A `Policy` is an ordered list of **statements**. Each statement (built via `policy.statement(effect, actions, resources)`):
- `effect`: exactly `"Allow"` or `"Deny"` (case-insensitive input is normalized; anything else fails pre-flight `INVALID_ARGUMENT`, `http_status()==0`).
- `actions`: `StrList` of portable action strings (§2.2).
- `resources`: `StrList` of portable resource references (§2.3).

**Evaluation semantics (portable core, all four providers agree):** *explicit Deny wins over Allow*; default with no matching Allow is **deny**. (AWS explicit-deny, GCP deny policies, Azure deny assignments all override; OCI IAM **has no native Deny** — see §5.4: on live OCI a Deny statement is evaluate-only; `policy_attach` of a policy containing Deny fails `INVALID_ARGUMENT` on live OCI with `provider_code` note, while `ocisim`'s enforce engine *does* implement deny-overrides, so sim conformance covers Deny end-to-end.)

### 2.2 Portable action grammar `<slice>.<resourcetype>.<verb>`
Verbs: `create | read | write | delete | list` only (no `manage`-class verbs — privilege containment, §4). Slices covered in v1: `storage`, `queue`, `tables` (`tables.table.<verb>`). Examples: `storage.bucket.create`, `storage.object.read`, `storage.object.write`, `queue.queue.send`, `tables.table.read`. Unknown slice/type/verb fails pre-flight `INVALID_ARGUMENT`; bare `"*"` actions fail pre-flight (least-privilege: v1 grammar requires full triples; narrow wildcards are lint findings, see §3.3). **`permissions.*` actions do not exist in the portable namespace** — permission management is never grantable through portable policies (anti-escalation, §4.2).

### 2.3 Portable resource grammar `<slice>:<resourcetype>:<name>[/[subpath*]]`
- `storage:bucket:<name>`, `storage:object:<bucket>/<key-or-prefix*>`, `queue:queue:<name>`, `tables:table:<name>`.
- `*` only as a **trailing** sub-path marker on object-key prefixes (`storage:object:<b>/logs/*`); whole-name wildcards (`storage:bucket:*`) parse but raise a **lint finding** (`WILDCARD_SCOPE`); non-trailing `*` fails pre-flight.
- Names must be the portable names of the target slice (bucket rules, queue rules, table rules); invalid → `INVALID_ARGUMENT`.
- The empty/malformed grammar (missing type, unknown type, bad chars) fails pre-flight before any call.

### 2.4 Principals
- `cloud.principal_current() -> string`: the caller's provider-shaped identity string (AWS IAM ARN / Azure object-id-ish / GCP member / OCI OCID; sims return the configured test identity). Non-empty; identical across calls in one run.
- **Principals are referenced, not provisioned** — portable v1 never creates real users/roles/service-accounts (identity provisioning is out of scope; userpool is Slice 6). A principal string is opaque beyond charset validation (`[A-Za-z0-9_+=,.@:/-]{1,256}`) and provider-shape normalization at the adapter. "Roles" appear as principals targeted by `policy_attach_principal`.

---

## 3. Schema Surface (Added to `schema/lmcloud.dsl.json`)

### 3.1 Domain Types

#### `Policy` (builder; immutable-on-wire)
| Method | Signature | Description |
|---|---|---|
| `statement` | `(effect: string, actions: StrList, resources: StrList) -> self` | Appends a normalized statement. Validates `effect∈{Allow,Deny}`, non-empty validated action/resource lists (§2.2/§2.3) pre-flight. |
| `document` | `() -> string` | Canonical JSON serialization (stable key order), provider-neutral; round-trips through `policy_parse`. |
| `len` | `() -> int` | Statement count (`0 <= len() <= 32`). |

#### `LintReport` / `LintFinding`
| Type | Methods |
|---|---|
| `LintReport` | `ok() -> bool` (no `severity=="error"` findings), `len() -> int`, `at(int) -> LintFinding` |
| `LintFinding` | `severity() -> string` (`"error"`/`"warning"`), `code() -> string` (§3.3), `message() -> string` |

#### `Lint` rule set (offline, portable; no provider call)
| Code | Severity | Trigger |
|---|---|---|
| `EMPTY_POLICY` | error | 0 statements |
| `UNKNOWN_ACTION` | error | action triple not in the portable namespace |
| `UNKNOWN_RESOURCE` | error | resource does not match §2.3 |
| `EFFECT_INVALID` | error | (defensive; statement() already rejects) |
| `ESCALATION_NAMESPACE` | error | action in a permissions/management namespace (§4.2) |
| `WILDCARD_SCOPE` | warning | whole-resource-class wildcards (`storage:bucket:*`) |
| `OVERBROAD_COMBINATION` | warning | `write`+`delete` on a wildcard scope |
| `STATEMENT_COUNT` | error | >32 statements |

### 3.2 `Cloud` methods (`context cloud: Cloud`)

| Method | Signature | Semantics |
|---|---|---|
| `principal_current` | `() -> string` | Caller's identity string (§2.4). |
| `policy_new` | `() -> Policy` | Empty builder. |
| `policy_parse` | `(document: string) -> Policy` | Parses/validates the canonical JSON; malformed → `INVALID_ARGUMENT` (`http_status()==0`). |
| `policy_lint` | `(policy: Policy) -> LintReport` | Offline lint per §3.3; never calls the provider. |
| `policy_attach` | `(resource: string, principal: string, policy: Policy) -> void` | Attaches `policy` scoped to `resource` for `principal` (resource policy on AWS/OCI; role-assignment-equivalent scope on Azure/GCP). **Ownership fence:** resource must exist and be run-owned (journal proof per `14-live-safety.md`); missing → `NOT_FOUND`, existing-but-foreign → `PERMISSION_DENIED`. Lint-error policies (`!lint.ok()`) are refused with `INVALID_ARGUMENT`. Idempotent: identical re-attach is a no-op success. |
| `policy_attach_principal` | `(principal: string, policy: Policy) -> void` | Identity-side attach (AWS managed/inline policy equivalent, GCP project/member binding, Azure role assignment at scope implied by statement resources). Same lint/ownership rules (statement resources must be run-owned). |
| `policy_detach` | `(resource: string, principal: string) -> void` | Removes the caller's attach; idempotent (`OK` when nothing was attached). Journal-marked detach only for journal-proven attachments. |
| `policy_detach_principal` | `(principal: string) -> void` | Identity-side counterpart; idempotent. |
| `policy_check` | `(principal: string, action: string, resource: string) -> bool` | Evaluates effective authorization for `(principal, action, resource)` from the current attached state (native simulate where available: AWS `SimulatePrincipalPolicy`; GCP `testIamPermissions`; Azure/OCI host-side evaluator over recorded attachments; sims in enforce mode are the runtime ground truth). Grammar errors → `INVALID_ARGUMENT` (`http_status()==0`); missing resource → `NOT_FOUND`. Returns `true` iff allowed (Deny precedence applied). |

---

## 4. Ownership, Authority & Escalation Guards (Sol lessons applied)

1. **Journal-backed attach authority (state & spend):** every `policy_attach*` first appends a journaled intent (target, principal, canonical document hash, 128-bit tokens) **before** the provider call; `Confirm`/`Retain` follow the `14-live-safety.md` journal discipline; sweep/detach acts only on journal-proven attachments; ambiguous post-crash attach state is `retained` (never silently assumed absent). Physical admission (per-attempt cost reservation) reuses the Slice-3 `CostMeter` path — attach/detach/check are metered operations like any other.
2. **Anti-escalation:** the portable namespace has **no** `permissions.*` (or `iam.*`-class) actions; lint turns any management-namespace action into an `error`; hosts additionally refuse escalation-shaped policies at attach (belt & braces: lint-clean requirement at attach boundary). A policy can never widen the caller's own authority because attachments are fenced to run-owned resources and portable actions only cover data-plane verbs of `storage`/`queue`/`tables`.
3. **Resource ownership fence:** attach/detach require the target to exist AND be run-owned (ownership metadata/journal entry); foreign → `PERMISSION_DENIED`, missing → `NOT_FOUND` (order: validation → existence → ownership; matches Slice-5 precedence discipline — malformed grammar `INVALID_ARGUMENT` before missing-resource `NOT_FOUND`).
4. **Fail-closed on live:** without the double opt-in + `live-policy.json`, all `policy_attach*` fail `UNAUTHENTICATED`/disabled (mode resolution per `14-live-safety.md`); `policy_check` on live runs in read-only evaluator/simulate mode only.
5. **No unbounded reads:** there is no `policy_list` enumeration of all tenant policies in v1 (excluded); check/lint are point operations; detach is by exact (resource, principal) pair.

## 5. Per-Provider Mapping & Simulator Evidence

### 5.1 Mapping

| `lmcloud` | AWS IAM (`awssim`) | Azure RBAC/ARM (`azuresim`) | GCP IAM (`gcpsim`) | OCI IAM (`ocisim`) |
|---|---|---|---|---|
| Policy document | IAM JSON policy (Statement/Effect/Action/Resource) — portable grammar compiles to AWS action/resource ARNs under the sim's account | Role-assignment tuple (principal, permission set, scope) — portable Allow statement compiles to data-action grants at resource scope (`Microsoft.Storage.../blobs/read` etc.) | Binding tuple (member, role) — portable statement maps to a per-resource binding with granular permissions (`storage.objects.get`, …) | Policy statement `Allow … to <verb> <resource-type>` mapped to inspect/read/use/manage verbs; **live OCI Deny unsupported** (§2.1); `ocisim` engine implements allow+deny |
| `policy_check` | `SimulatePrincipalPolicy` (`EvalDecision`) | host-side evaluator over recorded role-assignments (no Azure simulate API) | `testIamPermissions` at the resource | host-side evaluator over recorded policies (`ocisim`: `OciPolicyEngine` evaluation path) |
| `policy_attach` (resource) | `PutBucketPolicy`-style resource policy body with `Principal` | role assignment `PUT …/roleAssignments/{id}` at scope | `setIamPolicy` add binding at resource | `CreatePolicy` scoped to run-owned compartment |
| Enforcement ground truth (sim) | `AuthFilter` enforce map (s3/sqs/dynamodb sets) | `StorageAuth.java` overlay (blob/queue; table pending A2) | `PermissionFilter.java` (GCS/PubSub; Firestore pending G2) | `OciPolicyEngine` (full policy verbs incl. Deny) |

### 5.2 Simulator gaps (evidence-backed, for the conformance doc)
- **A-P1 `awssim`:** `AuthFilter.SUPPORTED` (awssim `src/main/java/ai/lmctl/awssim/AuthFilter.java` SUPPORTED map, s3/dynamodb/sqs only) has **no `iam` set** — `SimulatePrincipalPolicy`/`PutBucketPolicy`/policy CRUD calls fail closed with `AccessDenied` in enforce mode. Epic: add `iam` + `s3` bucket-policy actions to the map and a tests leg (upstream Floci IAM has ~167 ops in-process incl. simulate family).
- **A-P2 `azuresim`:** `StorageAuth.java` covers blob/queue routes only; RBAC role-assignment surface absent → epic: RBAC-lite (role definitions + assignments at resource scope) so attach/check works in enforce mode.
- **A-P3 `gcpsim`:** `PermissionFilter.java` maps GCS/PubSub → permissions; epic: generic binding mutation + `testIamPermissions` route mapping for storage/queue resource types used here.
- **A-P4 `ocisim`:** `OciPolicyEngine` already evaluates Allow/Deny with verb hierarchy (see ocisim `durable-memory/auth-wave11-2026-10-29.md`); epic: resolver mapping for `policy`-service endpoints used by attach (`/20160918/policies`) and resource-scoped statement application to buckets/queues.
- All four: conformance scenario 12 (enforce denial) runs today **only where the sim's auth layer covers the permission API**; per-provider legs self-SKIP until epics land (same pattern as tables/14).

## 6. Error Model (shared 8 codes; new mappings)

| `ErrorCode` | When |
|---|---|
| `INVALID_ARGUMENT` | Malformed action/resource/effect/grammar; wildcard outside allowed position; lint-error policy at attach; Deny-attach on live OCI; token/principal charset violations (all pre-flight, `http_status()==0`) |
| `NOT_FOUND` | attach/detach/check on a missing target resource |
| `CONFLICT` | journal/ownership race (foreign collision per `14-live-safety.md`) |
| `PRECONDITION_FAILED` | reserved (not used in v1) |
| `UNAUTHENTICATED` | bad creds; live mode not enabled |
| `PERMISSION_DENIED` | policy-denied call in enforce mode; attach to existing-but-foreign resource |
| `INTERNAL` | transient/unknown |

## 7. Deliberately Excluded (v1)
1. Named/managed persistent policies (attach carries inline documents only). 2. Provisioning identities (users/roles/groups/members) — referenced only. 3. Condition keys (`IpAddress`, dates, tags). 4. Cross-account grants. 5. `NotAction`/`NotResource` inverse forms. 6. Policy listing/enumeration of a tenant. 7. Permission boundaries & SCPs. 8. Deny-attach on live OCI (evaluate-only there). 9. Versioned policy history/rollback.

## 8. Decisions (D1–D6)
1. **Statements carry no principals; principals appear at attach time** (`policy_attach(resource, principal, policy)` / `policy_attach_principal(principal, policy)`) — the only shape that maps onto both resource-policy providers (AWS/OCI) and role-binding providers (Azure/GCP).
2. **Portable action/resource grammar is triple-noun and point-scoped** (§2.2/§2.3) with wildcards restricted to trailing object prefixes; management namespaces are excluded wholesale (containment, D2/T-lesson).
3. **Deny is in the model** (three providers support it; `ocisim` engine supports it; live OCI degrades to evaluate-only with a documented attach refusal).
4. **Lint is offline & mandatory at attach** — `policies` with lint errors can't attach; warnings never block (least-privilege hints: `WILDCARD_SCOPE`, `OVERBROAD_COMBINATION`).
5. **Check = point evaluation, not enumeration** (no tenant-wide listing anywhere, per §4.5); native simulate where it exists, host evaluator otherwise, sim enforce mode as ground truth.
6. **Journal-first attach/detach with idempotent semantics and retained-on-ambiguity** (Slice-3/14-live-safety authority & recovery rules applied to policy state).
