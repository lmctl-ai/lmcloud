# 16 — `lmcloud` Permissions Conformance Suite & Simulator Enhancements (Slice 4)

## 1. Runner Usage & Gates

The conformance runner [`tests/run-conformance.sh`](../tests/run-conformance.sh) accepts `permissions` (or `all`):

```bash
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check permissions
./tests/run-conformance.sh /path/to/lmaws http://127.0.0.1:4566 permissions
```

- Every scenario carries `# Requires: permissions`; `tests/capabilities.conf` marks **all hosts + reference host `pending(go-permissions-adapter)`** until the host-side `Permissions` adapter lands and passes this suite (honesty rule per 13 §1). The `permissions` slice is excluded from the `--live` profile wholesale (policies have no live naming/ownership profile yet; see 14-live-safety.md and design 15 §4.4).
- Naming: buckets used by scenarios follow the existing object-storage hyphenated rule (`lmcloud-p<NN>-<run_id>-...`); queues `lmcloud-p<NN>-<run_id>-...`; tables `lmtp<NN><run_id>...` (alnum rule). Principal strings in scenarios are opaque test identities (`arn:aws:iam::000000000000:role/<name>`-shaped inputs are accepted in sims).
- Embedded-compile gate: scenario `_lmcode_` bodies are compiled by the runner's gate (outer `--check` + spliced-body compile + negative control) — all 12 scenarios pass it.
- Error/abort conventions: default abort mode + `[CODE]` prefix; inspection via `set_abort_on_error(false)` and `last_error()`, identical to existing slices.

## 2. The 12 Permissions Conformance Scenarios (`tests/conformance/permissions/`)

| # | File | Expected behavior (one line) |
|---|---|---|
| **01** | `01-policy-build-and-document.lms` | Two-statement policy builds; `document()` canonical JSON round-trips: `policy_parse(p.document()).document() == p.document()`; `len()==2`; malformed effect/action rejected pre-flight with `INVALID_ARGUMENT` (`http_status()==0`). |
| **02** | `02-policy-lint-clean-pass.lms` | A least-privilege policy (exact actions, exact named resource) lints `ok()==true`, zero findings. |
| **03** | `03-policy-lint-findings.lms` | Wildcard action triple / whole-class wildcard resource (`storage:bucket:*`) / write+delete on wildcard / `permissions.*`-style management action produce findings with expected codes (`UNKNOWN_ACTION`, `WILDCARD_SCOPE`, `OVERBROAD_COMBINATION`, `ESCALATION_NAMESPACE`), severities (`error`/`warning`) — and `ok()==false` when any error exists. |
| **04** | `04-principal-current.lms` | `principal_current()` returns a non-empty stable string (two calls equal) per provider/sim identity. |
| **05** | `05-attach-resource-grants-check.lms` | Run-owned bucket created; `policy_attach(storage:bucket:<b>, <pr>, allow storage.object.read on <b>/*)`; then `policy_check(<pr>, storage.object.read, storage:object:<b>/k)` is `true`, unrelated principal is `false`; cleanup detaches. |
| **06** | `06-deny-overrides-allow.lms` | Allow + Deny on same action/resource → check `false` (Deny precedence); deny on a *narrower* object prefix leaves other keys allowed (`true`). |
| **07** | `07-attach-principal-identity.lms` | `policy_attach_principal(<pr>, policy listing storage:bucket:<b>)` → `policy_check(<pr>, storage.bucket.list…` on `<b>` `true`; check against a second bucket `false` (statement-resource scoping). |
| **08** | `08-detach-revokes.lms` | attach → check `true` → `policy_detach` → check `false`; second detach idempotent (`OK`). |
| **09** | `09-ownership-and-escalation-guards.lms` | attach to never-created resource → `NOT_FOUND`; attach to existing-but-foreign resource → `PERMISSION_DENIED`; attaching a policy with lint errors (e.g. management-namespace action) → pre-flight `INVALID_ARGUMENT`. |
| **10** | `10-check-validation-notfound.lms` | `policy_check` with malformed action (`"bogus"`) or malformed resource (`"bogus"`) → `INVALID_ARGUMENT` (`http_status()==0`); well-formed grammar on missing bucket → `NOT_FOUND`. |
| **11** | `11-attach-idempotency.lms` | identical re-attach succeeds (no-op); attaching a *changed* document over an existing attachment replaces it (post-change check reflects the new effect); detach of a never-attached pair is `OK`. |
| **12** | `12-perms-auth-enforced-denial.lms` | Enforce-only (`SKIP` in open mode): wrong creds → `UNAUTHENTICATED` on `policy_attach`/`policy_check`; restricted principal (denied on `*denied*` resources, per sims' auth configs) → `PERMISSION_DENIED` on both. Azure leg self-SKIPs until epic A-P2 (RBAC-lite) lands; oci leg is runner-skipped while its mapping epic (A-P4) is pending. |

## 3. Simulator Enhancements (evidence-backed)

Evidence from prior review probes plus source inspection (see 15 §5.2):
1. **A-P1 `awssim`** — extend `AuthFilter.SUPPORTED` (currently `s3`/`dynamodb`/`sqs` only, `awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java:36-43`) with an `iam` set (`AttachRolePolicy`/`DetachRolePolicy`/`CreatePolicy`/`DeletePolicy`/`SimulatePrincipalPolicy`/`SimulateCustomPolicy`/`GetPolicy*`) plus S3 bucket-policy actions (`PutBucketPolicy`, `GetBucketPolicy`, `DeleteBucketPolicy`), and add an allow/deny test leg to `scripts/test-auth.py`.
2. **A-P2 `azuresim`** — add an RBAC-lite overlay to `StorageAuth.java`: role-definition table + role-assignment CRUD at storage scopes + data-action evaluation for blob/queue(/table after slice-5 A2) so `policy_attach`/`policy_check` execute under `--auth enforce`; tests in `scripts/test-auth.py`.
3. **A-P3 `gcpsim`** — extend `PermissionFilter.java` with generic binding mutation (`setIamPolicy`) and `testIamPermissions` evaluation routes for `storage.buckets/objects`, `pubsub.topics/subscriptions` resources used by this slice.
4. **A-P4 `ocisim`** — extend `OciPolicyEngine.java` resolvers to map `/20160918/policies` (policy CRUD) and to apply *resource-scoped* attached statements to object-storage/queue authorization decisions in enforce mode.

> **Execution status:** the 12 programs pass the runner's full static gate (outer `--check`, embedded-body compile, negative control intact). Runtime execution awaits the Go hosts' Permissions adapters (all `pending(...)` in `tests/capabilities.conf`); the sim enforce paths above are the certified ground truth once epics A-P1..A-P4 land.
