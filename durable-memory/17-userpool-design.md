# 17 — `lmcloud` Userpool Design (Slice 6: portable user directory / identity pool)

## 1. Goals & Architectural Alignment

Slice 6 extends `schema/lmcloud.dsl.json` **additively** with a provider-neutral **user directory**: per-pool isolated directories, user CRUD with portable attributes, password set/verify, enable/disable, sign-in → session token, token verify, groups/membership, bounded authoritative pagination. No existing signature is modified.

1. **Sims are the primary target;** reference model (catalog + evaluator + redaction plumbing) is hostkit-shared. Live: `--live` profile excludes the slice **and** every userpool operation (including sign-in/verify, which carry secrets/discovery traffic) is refused on live-routed endpoints until the native certification matrix lands (`UNSUPPORTED_MAPPING` classification, same rule as Slice-4 §5.2).
2. The slice inherits the pooled authority rules: Slice-13 capability honesty, Slice-3 per-attempt cost admission, Slice-14 journal/ownership fencing (now extended to directories).

### Endpoint Resolution
Service name **`"userpool"`**; `cloud.set_endpoint("userpool", url)` / `LMCLOUD_USERPOOL_ENDPOINT` / `LM<PROVIDER>_USERPOOL_ENDPOINT` → native endpoints; loopback-only `http://` rules unchanged. `user_verify_token` performs **no** token-supplied endpoint discovery (§3.2).

## 2. Portable Model

### 2.1 Pools, users, groups — names and bounds
| Object | Rule |
|---|---|
| pool name | `^[a-z][a-z0-9]{2,31}$`; reserved `lmcloudmeta`/`__*__` rejected pre-flight |
| username | `^[a-z][a-z0-9_]{2,63}$` |
| group name | `^[a-z][a-z0-9_]{2,63}$` |
| password | 8–128 **bytes** UTF-8, printable ASCII excluding space (`0x21..0x7E`), ≥1 ASCII letter AND ≥1 ASCII digit (true native intersection: Cognito rejects whitespace, etc.) |
| attribute name | `^[a-z][a-z0-9_]{0,19}$` (bound chosen to be legal for any future native schema mapping); reserved names `sub`, `username`, `groups` rejected pre-flight |
| attribute value | UTF-8 ≤ **2048 bytes** |
| counts | ≤32 attributes/user; ≤64 groups/pool; ≤64 memberships/user; ≤2000 users/pool (§4.2 ordering authority); pools ≤128/run |

Out-of-rule inputs fail pre-flight `INVALID_ARGUMENT` (`http_status()==0`) before any I/O. Reserved logical names (`lmcloudmeta`, `__*__`) are refused.

### 2.2 Attribute storage honesty (uniform host-managed side profile — fixed for native quotas)

Native mapping cannot host portable attributes: Cognito custom schema attributes are ≤20-char names, **≤50 per pool, permanent (never freed)** — 32 disjoint names over two users would already exhaust or corrupt a pool's schema allocation; Firebase custom claims are ≤1000 bytes total and are not profile storage. Therefore the slice uses a **uniform host-managed profile side store** on every provider: attributes live in catalog-linked, journaled per-user profile records keyed by the native UID (projection: username/sub/status), never in token claims and never in provider permanent schema. Native directories hold only authentication state (credentials/keys/status); profile reads join side-store records with metered reads; `user_delete` cascades the side record in the same child-teardown scope; foreign users' profiles are never read or touched. (§4.2 catalog covers authority.)

### 2.3 Users, statuses, and duplicate create
- `user_create` returns `User` with `exists()==true`. A second create of the same username fails **`CONFLICT`** (whether attributes match or differ; no silent upsert). A passwordless new user has `status()=="FORCE_CHANGE_PASSWORD"`; after `user_set_password`, `status()=="CONFIRMED"`.
- `attribute(name)` on an absent attribute returns `""` (presence: `attributes()` map contains only set keys).
- `user_delete` is idempotent; `user_set_enabled`/`user_set_password` on missing user → `NOT_FOUND`; on missing pool → `NOT_FOUND` (pool precedes user: §6 precedence).
- Group ops: `group_add_user`/`group_remove_user` idempotent; missing user or missing group → `NOT_FOUND`; missing membership (remove) → `OK`. `group_delete` succeeds while membered; memberships of the deleted group disappear from all views.

### 2.4 Secrets handling (hard contract, strengthened)
- Hosts **never persist secrets** (passwords, tokens, client secrets, private keys) in journals, catalogs, reports, logs, or errors. Passwords/tokens are write-only inputs or immediately-consumed returns.
- Storage rule (host fake/reference/sim-plumbing backends and any catalog): **no plaintext or fast-hash or reversible password storage anywhere** — host-side reference stores use a salted KDF (PBKDF2-HMAC-SHA256, ≥600,000 iterations, random 16-byte salt, ≥256-bit derived key) **or** the provider's native storage. Simulators are test fixtures, *not* a credential-security boundary; sim-side password storage is explicitly synthetic-only (current sims: awssim upstream `CognitoService.java:5081` uses plain SHA-256 `passwordHash`; floci-gcp `FirebaseAuthService.java:34` keeps a `fakeHash` dev fixture — acceptable only for synthetic test passwords, called out so no one treats sim storage as real protection). Conformance scenarios use only synthetic passwords.
- Error/redaction contract: error messages and abort frames are built from fixed templates that never interpolate secrets; **before** any diagnostic path can observe a returned token, the host registers it (exact + JSON-escaped variants) with `hostkit.ErrorState.AddRedaction`. Bounded redaction state: >256 registrations must not silently drop coverage — the host caps secret registrations by keeping the *current* token/password set per session bounded (registration of a new secret evicts only already-consumed ones; short inputs — password <8 bytes or token fragments — never appear in errors because the failure path is template-constructed; conformance canaries: escaped-representation, short-invalid-input, provider-echo, >256-operations, failure-path, abort-path (acceptance criteria 18 §4).

### 2.5 Pagination with authority (fix for P1.5)
- Native backends (Cognito `ListUsers` ≤60/page, no global order; Identity Platform pages likewise unordered) cannot serve globally-ordered pages directly: the host maintains a **pool-scoped username index snapshot** (projection: username + UID + status only — never full profiles; ≤2000 entries ≈ ≤256 KiB, catalog-linked, journaled, refreshed via metered projected native pages), globally sorts the *index*, and returns the requested page (≤500 entries, ≤1 MiB profiles joined from index hits; the ≤2 MiB bound applies to the projected index, so sorting is provably global, never a sorted native window).
- Page tokens: opaque, ≤512 bytes, HMAC-signed host token binding `(endpoint, caller-scope fingerprint, pool physical id + incarnation, ordering=username-asc, max_items, index cursor)`; expiry 300 s; signature key = run-state random key persisted as a `0600` file in the run state dir (**never in the journal**) and rotated on reopen; malformed/tampered/expired → `INVALID_ARGUMENT`; wrong caller/scope or stale pool incarnation → `INVALID_ARGUMENT` (structure-class) / missing pool → `NOT_FOUND`; empty pages with continuation are followed; token invariant `has_more() == (str_len(next_token()) > 0)`; no-progress/looping tokens → `INTERNAL`.
- `userpool_list`/`group_list`/`user_groups` return complete sorted lists (bounded by §2.1 caps).

### 2.6 Token & verification contract (fix for P1.2)
- **Algorithms:** RS256 from the pool-bound key set only; `alg=none` or any other algorithm → reject before parsing claims. Header/claim duplicate-field rejection; token ≤ **8192 bytes**; header/payload JSON each ≤ 4096 bytes; JWKS document ≤ 256 KiB, ≤16 keys.
- **Trusted source:** JWKS fetched only from the *pool-bound native issuer* recorded at pool creation (loopback sim discovery path or the live issuer) — never from token-supplied `iss`/`jku`; key cache ≤1 h with explicit rotation handling; injected test clock (`hostkit` clock).
- **Expiry policy (single exact rule, integer epoch seconds):** STRICT expiry, zero expiry leeway — a token is temporally valid **iff `now < exp`** (at `exp == now` it is invalid; both sides integer epoch seconds). Clock-skew leeway applies ONLY to issuance freshness: `iat > now + 60` → invalid; `iat <= now + 60` accepted. `exp` claim is mandatory. `expires_in()`: on `user_sign_in` = issued TTL (`1..3600`); on `user_verify_token` = `exp - now` in whole seconds (guaranteed `>= 1` for any token that verifies, by the strict rule).
- **Canonical claim mapping:** portable claims always include `sub` (native UID), `username`, `iat`, `exp`, `sgen` (session generation, §below). Cognito access tokens: require `token_use == "access"` and binding to the pool's own app client (`client_id` claim; no `aud` without a resource server — the slice uses `client_id` binding). Firebase ID tokens: issuer is **project-level** (`https://securetoken.google.com/<project>`) with `aud == <project>`; the **tenant binding is the signed `firebase.tenant` claim, whose value must equal the catalog-recorded tenant ID** for the pool (project issuer + tenant-claim binding, mirroring the official SDK's two-step check); `user_id` → `sub`, and `username` is normalized from the pool's UID mapping record. A simulator must NOT invent a tenant-suffixed issuer format (would hide a native mismatch).
- **Token taxonomy:** structural garbage (segment count ≠ 3, non-base64url, undecodable JSON, oversize tokens, duplicate claims) → `INVALID_ARGUMENT`; trust failures (disallowed algorithm incl. `none`/empty signature, bad signature, expired, future-iat, wrong pool/client/tenant binding, revoked) → `UNAUTHENTICATED`. Precedence in `user_verify_token`: structure (`INVALID_ARGUMENT`) → pool existence (`NOT_FOUND`) → trust (`UNAUTHENTICATED`).
- **Revocation via durable session generation (exact same-second rule):** the journaled catalog keeps a per-user monotonic **`session_generation`**; `user_set_password`, `user_set_enabled(false)`, and `user_delete` bump it. Every issued token embeds `sgen`; verify requires token `sgen ==` current generation — *not* a timestamp comparison — so a disable/reset/delete in the same epoch second still revokes (equality on an integer that already advanced), and a same-second **new** sign-in carries the new generation and remains fully usable. (`tokens_valid_after` is a native optimization input only — Cognito `TokenValidityUnits` / Firebase `tokensValidSinceTime` — never the authority.) Post-delete verification therefore always fails.
- Sessions return the token via `access_token()` **by explicit design** (a deliberately secret-bearing return); the prohibition is on *incidental* leakage (logs/errors/journals/evidence), not on the declared API return.

## 3. Schema Surface
Types added: `User`, `UserPage`, `Session`. **18** `Cloud` method names added:
`userpool_create/delete/exists/list`; `user_create(2/3 args)/get/delete/set_enabled/set_password/list(1 or 3 args)`; `user_sign_in`; `user_verify_token`; `group_create/delete/list/add_user/remove_user/user_groups`.
Semantics per §2; precedence: validation `INVALID_ARGUMENT` → missing pool `NOT_FOUND` → missing user/group `NOT_FOUND` → auth failures (`user_verify_token` internally orders structural `INVALID_ARGUMENT` → pool `NOT_FOUND` → trust `UNAUTHENTICATED`, §2.6). **Sign-in special case:** missing/disabled/wrong-password all share the exact same `UNAUTHENTICATED` template message (enumeration protection precedes NOT_FOUND on the auth path). Verification does not consult network/native discovery on the reference/sim route: authoritative revocation state is the journaled per-user `session_generation` (a consistent local read, metered), so "offline verify" is by-design authoritative, not a stale snapshot.

## 4. Pool Isolation & Lifecycle Contract (fix for P1.1, P1.6)

### 4.1 Per-pool physical isolation (native unit per pool)
| Provider | Native pool unit | Notes |
|---|---|---|
| AWS | one Cognito User Pool **per pool** + one app client per pool (no secret, `ALLOW_ADMIN_USER_PASSWORD_AUTH`) | real isolation; issuer = userPoolId |
| GCP | one Identity Platform **tenant per pool** (tenant-aware endpoints/sign-in; issuer carries tenantId) | catalog maps pool→tenantID; sim epic G-UP1 adds tenants + signed tokens |
| Azure | pending AZ-UP1 (eventual unit: a directory tenant/user-flow scope explicitly recorded, never the whole shared tenant as a disposable resource) | pending |
| OCI | pending O-UP1 (eventual unit: Identity Domain instance recorded) | pending |

### 4.2 Authoritative pool catalog (journaled, fenced)
Catalog record per pool (reserved host-controlled table/collection `lmcloudmeta`, never user-visible): `{pool_name, scope fingerprint, physical ids (UserPoolId / tenantId / clientId), incarnation (128-bit uuid), owner_token, state: creating|active|deleting|quarantined, tokens_valid_after per-user map reference, generation, run link}`. Rules:
- **Duplicate create:** identical pool name with matching owner_token → `false`; foreign/different-incarnation physical target → `CONFLICT` (never adopt). Writer generation/lease serializes catalog mutation.
- **Ownership before every child operation:** child ops (user/group/membership/sign-in) verify the catalog entry is `active` + owned by this run, and the physical incarnation matches.
- **Recreation quarantine:** after `userpool_delete`, the name+incarnation stay tombstoned/quarantined until authoritative terminal deletion is confirmed (bounded metered polling); recreate of the same name during quarantine → `CONFLICT`. Tokens from a prior incarnation never verify (issuer/keys change with the new incarnation + `tokens_valid_after` per-user state is reset with the new catalog record; envelope binds pool incarnation).
- **Username namespace per pool:** the same logical username exists independently in two pools with distinct passwords/subs (native per-pool/per-tenant keying; conformance scenario `tests/conformance/userpool/13-pool-isolation.lms` exercises sign-in per pool plus cross-pool token rejection, and deeper native-level cases are in the acceptance criteria 18 §4).
- **Exact delete scope:** pool teardown deletes exactly the journaled children (users, groups, memberships, clients) in child order (memberships→users→groups→client→pool), each as a metered journaled attempt with its own reserved cleanup; foreign children (not in journal) are preserved and block final deletion (`retained`, sweep-visible).
- **Cost authority:** pool create reserves pool-level cleanup; every child create reserves its own cleanup before dispatch; JWKS/discovery/client/status-poll/page/retry attempts are each metered with durable attempt IDs; sign-in/password ops are non-idempotent at the admission layer (never retried blindly; ambiguous replies → classify via bounded probe, else `INTERNAL`).

### 4.3 Dry runs & live refusal
- Dry mode: attach-style mutations zero-write preview; `user_sign_in` fails closed in dry mode (`INVALID_ARGUMENT`, "dry mode does not authenticate") — zero SDK calls; `user_verify_token` is a pure local operation and works on tokens the run already holds... in dry there are none; returns `INVALID_ARGUMENT` for unseen tokens (no network).
- Live routes: **all** userpool methods refuse until certified (`INVALID_ARGUMENT` + `UNSUPPORTED_MAPPING`); independent of runner exclusion.

## 5. Deliberately Excluded (v1)
Refresh tokens; temporary-password/invite flows (AdminCreateUser always uses `MessageAction=SUPPRESS`; pools created with no email/SMS triggers, MFA off, auto-verify off); MFA/SMS; custom policy knobs; federation/social IdPs; custom-claims authoring (tokens carry only guaranteed claims); Cognito Identity Pools (federated AWS creds); user self-service sign-up/reset; importing/exporting users; group claims inside tokens (use `user_groups`).

## 6. Consistency & Failure Semantics + Sim Mapping Evidence

### 6.1 Consistency
Sims are in-memory/synchronous — direct asserts at runtime. Live notes: Cognito admin writes read-after-write consistent; Identity Platform strong for direct id reads; aggregate listing views via bounded polls (Slice-5 discipline); token verify never depends on propagation.

### 6.2 Simulator & upstream evidence (exact file:line where verified)
- **awssim (floci 2.3.0):** Cognito IDP present in-process (JWKS/discovery/OAuth endpoints per upstream `docs/services/cognito.md`; password store seen at upstream `.../services/cognito/CognitoService.java:5081` using plain SHA-256 `passwordHash` — synthetic-test-only by §2.4). Epic **A-UP1:** certify the IDP op subset + signed-token issuance config + `AuthFilter.SUPPORTED` cognito-idp set + enforce tests.
- **gcpsim (floci-gcp 0.11.0):** Firebase Auth present, **materially incomplete for this slice**: upstream `.../services/firebaseauth/FirebaseJwt.java:11`–`:22` mints `alg:none` with empty signature, `FirebaseAuthService.java:34`–`:38` uses a `fakeHash` dev fixture. Epic **G-UP1:** RS256 signing + pool/tenant-scoped JWKS/issuers + tenant units + `PermissionFilter` mapping — *until then the GCP leg refuses verification* (`UNSUPPORTED_MAPPING`), we never accept unsigned emulator tokens as satisfying this contract.
- **azuresim (floci-az 0.15.0):** supporting reads show upstream Graph membership endpoints + a directory store (`.../graph/GraphServiceHandler.java:24`–`:38`, `:84`–`:101`) but `.../entra/PasswordGrant.java:8`–`:9` accepts password grants **without checking the password**. Epic **AZ-UP1:** directory CRUD validated + password-checked sign-in + tenant-scoped issuance + enforce mapping.
- **ocisim (floci-oci 0.5.0):** Identity Domains listed as not-implemented upstream (README; runtime listing independently probed earlier — `/20190828/...` style requests return 404; the identity-domain surface was not re-verified in this round). Epic **O-UP1.**

### 6.3 Error Model (shared codes)
| `ErrorCode` | When |
|---|---|
| `INVALID_ARGUMENT` | name/attr/username/group/password validation (incl. reserved names); token **structural** garbage (segment count≠3, non-base64url, undecodable JSON, oversize(>8192 B), duplicate claims); pagination bounds/tokens (malformed/expired/wrong-scope); over-capacity growth (2001st user); dry-mode auth attempt; uncertified route refusal (`provider_code=="UNSUPPORTED_MAPPING"`) — `http_status()==0` for pre-flight |
| `NOT_FOUND` | missing pool; missing user/group on admin ops; stale/incarnation-mismatched page token |
| `CONFLICT` | duplicate `user_create` of same username; foreign/quarantined duplicate pool; journal race |
| `PRECONDITION_FAILED` | unused v1 |
| `UNAUTHENTICATED` | wrong/disabled/missing-user sign-in (generic identical message); token **trust** failures (disallowed algorithm incl. `none`/empty signature, bad signature, expired under the strict `now < exp` rule, future-iat beyond +60 s, wrong pool/client/tenant binding, revoked via `sgen` mismatch); bogus credentials |
| `PERMISSION_DENIED` | enforce-mode authorization denial on directory admin ops |
| `COST_CAP_EXCEEDED` | admission over run cap |
| `INTERNAL` | transient/unknown |

## 7. Decisions (D1–D8)
1. Per-pool native isolation unit everywhere (Cognito pool / GCIP tenant / recorded directory scope) + journaled catalog incl. incarnation — recreations never accept old-incarnation tokens.
2. Token verify = strict offline check against pool-bound discovery (RS256 only), never token-supplied endpoints; revocation via `tokens_valid_after`; unsigned-emulator paths refused, not "certified anyway".
3. Salted-KDF storage rule for all host-side password persistence; sims declared synthetic-only fixtures; secrets never persisted outside providers and never echoed diagnostically (template-constructed errors + bounded pre-registered redaction incl. escaped forms).
4. Authoritative bounded pagination: ≤2000 users/pool (catalog-enforced), metered aggregation sort, signed bound tokens with expiry.
5. Duplicate create = `CONFLICT`; passwordless status FORCE_CHANGE_PASSWORD; precedence fixed (validation → missing pool → missing user/group → auth; sign-in path uses generic UNAUTHENTICATED).
6. Exact child-teardown order + quarantine window + foreign-children refusal; every create reserves its cleanup.
7. Dry-mode sign-in/verify fail closed; live routes fully refuse until certified.
8. Attributes: 20-char names, side-store on GCP (never custom claims), Cognito custom schema on AWS.
