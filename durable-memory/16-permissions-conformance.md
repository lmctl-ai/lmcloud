# 16 — `lmcloud` Permissions Conformance Suite & Simulator Enhancements (Slice 4)

## 1. Runner Usage & Gates

The conformance runner [`tests/run-conformance.sh`](../tests/run-conformance.sh) accepts `permissions` (or `all`):

```bash
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check permissions
./tests/run-conformance.sh /path/to/lmaws http://127.0.0.1:4566 permissions
```

- Every scenario carries `# Requires: permissions`; `tests/capabilities.conf` marks **all hosts + reference host `pending(...)`** until the host-side `Permissions` adapter lands AND passes this suite (honesty rule per 13 §1). The `permissions` slice is excluded from the `--live` profile wholesale (and additionally, design 15 §5.2: live routes refuse attach until the native certification matrix is signed off).
- Static gates: outer `--check` plus the embedded `_lmcode_` compile gate (negative control retained).
- Test principals come from `LMCLOUD_TEST_PRINCIPAL` (cross-provider override) or `LM<PROVIDER>_SIM_PRINCIPAL`, with a well-formed fallback default; scenarios never hard-code provider identities (design 15 §2.5).
- Two-tier input contract reminder for scenario authors (design 15 §2.1): builder/parse reject only malformed *syntax*; unknown-but-well-formed vocabulary is lint-level and cannot attach.

## 2. The 13 Permissions Conformance Scenarios (`tests/conformance/permissions/`)

| # | File | Expected behavior (one line) |
|---|---|---|
| **01** | `01-policy-build-and-document.lms` | Two-statement policy builds; `document()` equals the **golden canonical fixture** (byte-exact envelope, sorted arrays, insertion-ordered statements); `parse(document()).document()==document()`; Tier-1 rejects malformed effect/action/resource/JSON (`INVALID_ARGUMENT`, `http_status()==0`) and accepts well-formed unknown vocabulary for lint. |
| **02** | `02-policy-lint-clean-pass.lms` | Least-privilege policy (exact actions incl. `queue.queue.receive`/`queue.queue.ack`, exact resources) lints `ok()==true`, zero findings. |
| **03** | `03-policy-lint-findings.lms` | Findings appear with expected codes/severities: `EMPTY_POLICY`(e) on an empty policy; `UNKNOWN_ACTION`(e), `ESCALATION_NAMESPACE`(e), `WILDCARD_SCOPE`(w), `OVERBROAD_COMBINATION`(w) on a combined policy; `ok()==false` iff an error finding exists (valid bucket-name fixture). |
| **04** | `04-principal-current.lms` | `principal_current()` returns a non-empty, stable string (information-only accessor). |
| **05** | `05-attach-resource-grants-check.lms` | Run-owned bucket; `policy_attach(storage:bucket:<b>, <pr>, allow read <b>/*)` → `policy_check` true for <pr>, false for an unrelated principal (default deny); detach cleanup. |
| **06** | `06-deny-overrides-allow.lms` | Single-document Allow+Deny over the same attachment key: Deny wins regardless of statement order (both orders exercised via document *replacement* on the same key); narrow `/secret/*` deny blocks only its sub-path. |
| **07** | `07-attach-principal-identity.lms` | Identity-side attach scopes to listed resources only (listed bucket true, other bucket false). |
| **08** | `08-detach-revokes.lms` | attach → check true → detach → check false; re-detach idempotent OK. |
| **09** | `09-ownership-and-escalation-guards.lms` | Lint-error policy refused at attach (`INVALID_ARGUMENT` pre-flight); missing target → `NOT_FOUND` (both attach forms); with fixture env `LMCLOUD_FOREIGN_BUCKET` set (operator-provisioned, non-own) → `PERMISSION_DENIED` (leg self-reports skipped when unset). |
| **10** | `10-check-validation-notfound.lms` | `policy_check` malformed action/resource → `INVALID_ARGUMENT`; anchored target missing → `NOT_FOUND` (object refs anchor on their parent bucket per design §2.3). |
| **11** | `11-attach-idempotency.lms` | Identical re-attach = no-op OK; **changed document replaces** the attachment contribution (read grant replaced by write grant); detach of a never-attached pair OK. (These exercise observable semantics only; journal crash/authority properties are acceptance criteria in §4, not proven here.) |
| **12** | `12-perms-auth-enforced-denial.lms` | Enforce-only (SKIP in open). Mode probe is an authenticated op (`bucket_create` with bogus creds → `UNAUTHENTICATED`); Pass 2 uses a seeded owned target with a restricted principal → `PERMISSION_DENIED` on `policy_attach` and `policy_check`. Azure leg self-SKIPs pending A-P2; OCI runner-skips. |
| **13** | `13-perms-data-plane-probes.lms` | **Real enforcement proof:** after an attach, a granted restricted identity performs a real `object_get` through the sim's auth engine (must succeed), and an unrelated identity is denied at the data plane. Legs self-SKIP (with reason) where native attach routes are unmapped (A-P1..A-P4) or the auth fixture lacks a grantee identity. |

## 3. Simulator Enhancements (evidence-backed; unchanged set, restated with files)

1. **A-P1 `awssim`** — `src/main/java/ai/lmctl/awssim/AuthFilter.java` (`SUPPORTED` map at lines 36–43: only `s3`/`dynamodb`/`sqs`): add an `iam` set (policy CRUD + `Simulate*`) and `s3` bucket-policy actions (`PutBucketPolicy`/`GetBucketPolicy`/`DeleteBucketPolicy`) + allow/deny test legs in `scripts/test-auth.py`.
2. **A-P2 `azuresim`** — `src/main/java/ai/lmctl/azuresim/StorageAuth.java`: RBAC-lite overlay (role definitions + assignments at storage scopes + data-action evaluation) + tests.
3. **A-P3 `gcpsim`** — `src/main/java/ai/lmctl/gcpsim/PermissionFilter.java`: resource `setIamPolicy` mutation + `testIamPermissions` evaluation for GCS/PubSub routes.
4. **A-P4 `ocisim`** — `src/main/java/ai/lmctl/ocisim/OciPolicyEngine.java`: resolver mappings for `/20160918/policies` CRUD and application of resource-scoped attached statements to Object-Storage/Queue decisions in enforce mode.

## 4. Implementation Acceptance Criteria (not proven by these .lms programs)

When `go-permissions-adapter` lands, the following must be demonstrated with fixtures before the capability entries flip to `supported` (design 15 §4):
1. **Crash/replay:** attach → kill −9 mid-campaign → journal replay restores evaluator state and pending intents; ambiguous lost replies surface `retained`, never assumed absent/adopted.
2. **Foreign preservation:** native documents/bindings containing other principals' entries are preserved verbatim across our replace/detach (etag-guarded where supported).
3. **Cross-attachment deny:** resource-side Deny beats principal-side Allow (union evaluation, Deny precedence across kinds).
4. **Stale replacement/detach fencing:** only generation-matched owned attachments are replaced/detached; concurrent opposite ops produce deterministic outcomes.
5. **Interrupted cleanup:** partial teardown of native children resumes from journal with attempt-level reservation settlement; no double-delete errors.
6. **Bounded documents:** document >8192 bytes / statements >32 / attachments >128 per run fail pre-flight.
7. **Queue and table enforcement probes** (same pattern as scenario 13's storage leg) once A-P1..A-P4 cover those routes; immediate check/revoke vs eventual native propagation timing is pinned per provider.
8. **Scenario 09 foreign leg** exercised with `LMCLOUD_FOREIGN_BUCKET` against a real operator-provisioned resource in live-qualification runs.

**Honest coverage note (R2 follow-up):** scenarios today cover bucket/object resources end-to-end; queue/table attaches share the vocabulary but their native-route probes are acceptance criteria §4.7, pending the sim epics. No runtime behavior is certified until adapters + epics land; all hosts stay capability-pending.
