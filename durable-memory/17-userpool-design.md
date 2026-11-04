# 17 — `lmcloud` Userpool Design (Slice 6: portable user directory / identity pool)

## 1. Goals & Architectural Alignment

Slice 6 extends `schema/lmcloud.dsl.json` **additively** with a provider-neutral **user directory**: user pool (directory) lifecycle, user CRUD with portable attributes, password set/verify with policy, enable/disable, sign-in producing an opaque session token with claims and expiry, token verification, groups/membership, and bounded pagination. No existing Slice 1–5 signature is modified.

1. **Local emulators (primary conformance target):** `lmaws`↔`awssim :4566` (Cognito IDP), `lmazure`↔`azuresim :4577` (Entra/B2C — *gap*), `lmgcp`↔`gcpsim :4588` (Identity Platform / Firebase Auth), `lmoci`↔`ocisim :4599` (Identity Domains — *absent, pending epic*).
2. **Real clouds:** same credential/endpoint rules (02 §3.2); **fail-closed live** — `--live` conformance excludes the slice, and additionally every pool/user/group mutation on a live route is refused until the slice passes native certification (design-time rule, same posture as Slice-4 §5.2).
3. Sims' enforce mode is the runtime ground truth for the auth-denied scenario (11); reference behaviors elsewhere.

### Endpoint Resolution
Service name **`"userpool"`** in the canonical precedence table (02 §3.3): `cloud.set_endpoint("userpool", url)` / `LMCLOUD_USERPOOL_ENDPOINT` / `LM<PROVIDER>_USERPOOL_ENDPOINT` → provider-native endpoints. Loopback-only `http://` rules apply unchanged.

---

## 2. Portable Model

### 2.1 Pools, Users, Groups
- **Pool** (`userpool`): a logical user directory. Portable name `^[a-z][a-z0-9]{2,31}$` (Azure/B2C-strict intersection, like Slice-5 table names). Lifecycle create/delete/exists/list; list returns **all pages followed, ascending** (pools are few; matches `bucket_list`/`table_list` discipline) — bounded by nothing user-supplied, and pools are run-owned few.
- **User**: keyed by `username` (`^[a-z][a-z0-9_]{2,63}$`, lowercase). Fields: `username`, `enabled: bool`, `status` (`"CONFIRMED" | "FORCE_CHANGE_PASSWORD"` — see §2.3), `created_at` (epoch seconds), `attributes` (flat portable map).
- **Attributes:** names `^[a-z][a-z0-9_]{0,62}$`; reserved `sub`/`username`/`groups` reject pre-flight; values UTF-8 strings ≤ **2048 bytes**; ≤ **32 attributes/user**. Pre-flight `INVALID_ARGUMENT`, `http_status()==0`.
- **Groups:** group names `^[a-z][a-z0-9_]{2,63}$`; membership ops are **idempotent**; `group_list`/`user_groups` return sorted full lists (bounded only by 64 groups/64 memberships-per-user caps, §4.4).

### 2.2 Passwords & Policy (portable floor)
- `user_set_password(pool, user, password)` sets a **permanent** password; temporary/force-change flows are excluded (v1).
- Fixed portable password policy: **8–128 bytes UTF-8, containing at least one ASCII letter and one ASCII digit** (no provider policy knobs in v1 — excluded). Violations fail pre-flight `INVALID_ARGUMENT` before dispatch.
- Passwords are **write-only**: there is no read-back; failure/success signals never carry the secret (§2.6 redaction).

### 2.3 Sign-in, Tokens, Verification
- `user_sign_in(pool, username, password) -> Session`: wrong password / disabled user / missing user → `UNAUTHENTICATED` with a **generic** message (no which-part-wrong detail). Fresh sign-in immediately after create/set/enable is asserted directly (sims are strong); live note in §6.
- `Session`: `access_token() -> string` (opaque, non-empty; sims issue RS256 JWT-style tokens or equivalent), `expires_in() -> int` (portable cap: `1..3600`), `claims() -> StrMap` (string-valued; guaranteed keys: `sub`, `username`, `iat`, `exp`; group membership is read via `user_groups`, not claims, in v1).
- `user_verify_token(pool, token) -> Session`: verifies signature + `exp` + pool audience/issuer binding; invalid signature / expired / foreign pool → `UNAUTHENTICATED`. On success returns a fresh `Session` view of the same token (claims available). No refresh tokens in v1 (§5 exclusions).

### 2.4 Pagination & listing discipline (bounded, no unbounded reads)
- `user_list(pool) -> UserPage` / `user_list(pool, max_items, page_token)`: `max_items` `0`=default 100, `1..500`; token invariant `has_more() == (str_len(next_token()) > 0)`; ordering = ascending `username` (byte order); short/empty pages with continuation are legal and followed (Slice-5 rule).
- `userpool_list()`, `group_list(pool)`, `user_groups(pool, username)` return complete sorted `StrList`s (bounded by the §4.4 caps like Slice-2 queue_list).

### 2.5 Error/abort semantics
Unchanged from prior slices: default abort with `[CODE]` prefix; probes (`userpool_exists`, `user_get` on missing user) return `false`/`exists()==false` with `OK`; delete ops are idempotent; operations on a missing pool → `NOT_FOUND`.

### 2.6 Secrets handling (hard contract)
- Passwords and tokens are **write-only secrets**: they must never appear in `last_error().message()`, abort frames, logs, journals, evidence output, or conformance output. Hosts register every password/token string via `hostkit.ErrorState.AddRedaction` the moment it crosses the boundary (Slice-14 §3.3 mechanism), so even provider echoes are scrubbed (`[create-token]`-style redaction).
- Sign-in failures are generic (`NotAuthorizedException`-class message without echoing username/password correctness detail).
- Conformance scenarios assert redaction: a tampered-token error must not contain the token string; a wrong-password error must not contain the password.

---

## 3. Schema Surface (added; additive-only)

New types: **`User`** (`exists/username/enabled/status/attributes/attribute/created_at`), **`UserPage`** (`len/at/has_more/next_token`), **`Session`** (`access_token/expires_in/claims`).

New `Cloud` methods (19 names): pool — `userpool_create(name)->bool`, `userpool_delete(name)->bool`, `userpool_exists(name)->bool`, `userpool_list()->StrList`; user — `user_create(pool,username[,attrs])->User`, `user_get(pool,username)->User`, `user_delete(pool,username)->void`, `user_set_enabled(pool,username,bool)->void`, `user_set_password(pool,username,password)->void`, `user_list(pool[,max,token])->UserPage`; session — `user_sign_in(pool,username,password)->Session`, `user_verify_token(pool,token)->Session`; groups — `group_create(pool,name)->bool`, `group_delete(pool,name)->bool`, `group_list(pool)->StrList`, `group_add_user(pool,group,username)->void`, `group_remove_user(pool,group,username)->void`, `user_groups(pool,username)->StrList`.

Missing pool/user semantics: ops on missing pool → `NOT_FOUND`; `user_get` missing user in existing pool → `exists()==false` `OK`; `user_delete` idempotent; `group_add_user`/`group_remove_user` idempotent; membership of a missing user/group → `NOT_FOUND`.

---

## 4. Per-Provider Mapping (native vs sim — explicitly separated)

| `lmcloud` | AWS Cognito IDP (`awssim`) | Azure (Entra External ID / B2C) (`azuresim`) | GCP Identity Platform / Firebase Auth (`gcpsim`) | OCI Identity Domains (`ocisim`) |
|---|---|---|---|---|
| Pool | `CreateUserPool` (+ `CreateUserPoolClient`) | *no GA equivalent in sim*: upstream floci-az has Entra **token issuance** endpoints only; user directory CRUD absent → sim epic AZ-UP1 | project-scoped `identitytoolkit` tenant-less directory (gcpsim: Firebase Auth endpoints exist upstream, uncertified) | **absent upstream** → epic O-UP1 (pending) |
| User create/get/list/delete | `AdminCreateUser` / `AdminGetUser` / `ListUsers` (paginated) / `AdminDeleteUser` | epic | `accounts:signUp`-admin/lookup/batchGet/delete | epic |
| Password set | `AdminSetUserPassword` (Permanent=true) | epic (no GA password-write in sim; native Azure password write is Graph-only and restricted) | `accounts:update` password | epic |
| Sign-in → token | `AdminInitiateAuth` `USER_PASSWORD_AUTH` (or `InitiateAuth`) → JWTs | epic | `accounts:signInWithPassword` | epic |
| Token verify | signature via sim JWKS/discovery (per upstream docs) or host-held key; exp/iss check | epic | Firebase ID token verify (via sim cert/JWKS) | epic |
| Groups | `CreateGroup`/`AdminAddUserToGroup`/`AdminListGroupsForUser`/... | epic (B2C groups are GA but absent in sim) | **native gap:** Firebase has no groups; mapping = host-managed custom-attribute emulation on sim route, **refused on live GCP** (like Slice-4 native Deny refusals) | epic |

### 4.1 Simulator status evidence (from prior live probes + docs)
- **awssim (floci 2.3.0):** Cognito IDP + Cognito-Identity compiled in-process, ~86 IDP ops + JWKS/discovery/OAuth token endpoints (`awssim` upstream `docs/services/cognito.md`); no Docker unless Lambda triggers are wired (we never wire them). Enforce gap: `AuthFilter.SUPPORTED` has no cognito set (epic A-UP1).
- **gcpsim (floci-gcp 0.11.0):** Firebase Auth / Identity Platform compiled in, wire-compatible with the official emulator, uncertified in gcpsim's gate (epic G-UP1 certify + `PermissionFilter` mapping).
- **azuresim (floci-az 0.15.0):** Entra token issuance exists; **user directory CRUD + password sign-in path absent** → upstream epic AZ-UP1 (Azure leg is `pending(...)`).
- **ocisim (floci-oci 0.5.0):** Identity Domains explicitly "not implemented" upstream → epic O-UP1; OCI tables-blocker precedent applies (`pending(oci-identity-domains-epic)`).

### 4.2 Ownership/journal & authority (Sol lessons applied)
- Pools are run-owned journaled resources exactly like buckets/queues/tables (intent→create→confirm, owner nonce + create token, LIFO teardown, retained-on-ambiguity, never adopt foreign). Users/groups inside a pool are **child resources** journaled under the pool; `userpool_delete` fences on children-deleted-first (bounded metered sweeps; async-deletion polling where native).
- **Async fencing:** native pool provisioning may be asynchronous (OCI Identity Domains, Azure tenant-scoped objects); `userpool_create` polls until usable/ACTIVE (≤60 s deadline, `WaitLoop` discipline) before returning `true`; `userpool_delete` = deletion accepted; post-delete disappearance asserted via bounded poll (sims are synchronous; live semantics documented).
- **Per-physical-attempt admission:** pool/user/group/session calls and every hidden probe/poll/page are metered via Slice-3 attempt reservations settled by attempt ID; cleanup headroom is reserved before creation (per Slice-3/14-live-safety campaign rules). Overruns → `COST_CAP_EXCEEDED`.
- Reserved logical names rejected pre-flight: pool named `lmcloudmeta` (catalog collision), any `__*__`-wrapped names.
- No unbounded native reads: pool/user/group listing only via the §2.4 contract (bounded page sizes; full-list helpers follow all pages by bounded loops).

---

## 5. Deliberately Excluded (v1)
1. Refresh tokens / session refresh. 2. Temporary/force-change password flows and invite emails. 3. MFA / SMS flows. 4. Custom password policy knobs (fixed portable policy only). 5. Social/enterprise IdP federation (Okta/SAML/log-in-with-X). 6. Custom/signed-JWT claims authoring. 7. Import/export/migration tooling. 8. Cognito Identity Pools (federated cloud credentials) — this slice is user directories only. 9. Cross-provider groups mapping on live GCP (emulation on sim route only, §4.1). 10. Self-service sign-up/password-reset endpoints (admin-driven model only).

## 6. Consistency & Failure Semantics
- Sims are in-memory/synchronous: sign-in right after create/password-set/disable is asserted directly at runtime.
- Live clouds: Cognito admin writes are read-after-write consistent; Identity Platform strongly consistent for account reads; eventual spots (group claims propagation, indexing) are covered by bounded polls in scenarios that assert aggregates (§2.4) — same discipline as previous slices; `user_verify_token` never depends on propagation (verifies bytes the program already holds).
- Failure precedence: validation `INVALID_ARGUMENT` → missing pool/user `NOT_FOUND` → auth `UNAUTHENTICATED`/`PERMISSION_DENIED` — matching earlier slices.

## 7. Decisions (D1–D7)
1. **Admin-model portable directory** (no self-service flows) with fixed password policy (8–128 bytes, ≥1 letter + ≥1 digit).
2. **Opaque access tokens only**, `expires_in ≤ 3600`, claims = minimal guaranteed keys; groups via membership APIs, not claims.
3. **`user_verify_token` is a host call** (signature + exp + iss/aud via sim discovery keys or host-held test key on reference route); never a network round-trip to a "verify" RPC that doesn't exist on some providers.
4. **Groups exist in the portable model**; GCP live refuses group ops (`INVALID_ARGUMENT` + `provider_code == "UNSUPPORTED_MAPPING"` — same classification rule as Slice-4 §5.2); sim route emulates via membership records.
5. **All creates wait usable / all deletes are accepted-then-polled** (async fencing).
6. **Every secret-bearing call redacts** via `AddRedaction` at the boundary + generic auth errors (scenarios 05/11 assert it).
7. **Azure & OCI legs pending sim epics** (AZ-UP1 / O-UP1) — capability rows stay pending; nothing ships half-mapped.

## 8. Error Model (shared codes)
| `ErrorCode` | When |
|---|---|
| `INVALID_ARGUMENT` | name/attr/username/group/password validation (incl. reserved names), pagination bounds, token shape garbage input (all `http_status()==0`) |
| `NOT_FOUND` | ops on missing pool; membership ops on missing user or group |
| `CONFLICT` | foreign collision/journal race |
| `PRECONDITION_FAILED` | (reserved; unused in v1) |
| `UNAUTHENTICATED` | bad password/disabled/missing user at sign-in; invalid/expired/foreign-pool token at verify; bogus sim credentials |
| `PERMISSION_DENIED` | enforce-mode authorization denial on directory admin operations |
| `COST_CAP_EXCEEDED` | admission over run cap |
| `INTERNAL` | transient/unknown |
