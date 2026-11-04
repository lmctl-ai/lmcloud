# 18 — `lmcloud` Userpool Conformance Suite & Simulator Enhancements (Slice 6)

## 1. Runner Usage & Gates

```bash
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check userpool
./tests/run-conformance.sh /path/to/lmaws http://127.0.0.1:4566 userpool
```

- Every scenario carries `# Requires: userpool`; `tests/capabilities.conf` marks **all hosts + reference host `pending(...)`** (adapter/ epic-specific reasons) until the adapter lands AND passes this suite.
- `userpool` is excluded from the `--live` profile (runner slice-dir rule); design 17 §1.2 additionally refuses mutations on live routes until native certification.
- Static gates: outer `--check` + embedded `_lmcode_` compile gate (negative control retained).
- Naming: pools `lmu<NN><run_id>` + letter suffix (`^[a-z][a-z0-9]{2,31}$`); users `user<NN>_<run_id>_<suffix>`; groups `grp<NN>_<run_id>_<suffix>` (alnum+underscore rules).
- Aggregate assertions (`userpool_list`, `group_list`, `user_groups`, `user_list` walks) use bounded restart-per-poll loops (≤10) per Slice-5 discipline; point operations on sims assert directly (documented live caveat, design 17 §6).
- **Secrets:** conformance scenarios never echo passwords or tokens into output/evidence; scenario 05 asserts the error message does not contain the wrong password; scenario 07 asserts a tamper error does not contain the token.

## 2. The 12 Userpool Conformance Scenarios (`tests/conformance/userpool/`)

| # | File | Expected behavior |
|---|---|---|
| **01** | `01-pool-lifecycle.lms` | create `true` → exists `true` → `userpool_list` (bounded poll) contains it sorted → delete `true` → bounded-poll disappearance; delete again `false`. |
| **02** | `02-pool-idempotency.lms` | second `userpool_create` → `false`; delete of a never-created pool → `false` + `OK`. |
| **03** | `03-user-crud-attributes.lms` | `user_create` (with attributes incl. unicode) → `get` round-trips username/enabled/attributes/`status`; missing user `exists()==false`+OK; delete idempotent. |
| **04** | `04-user-password-and-signin.lms` | set permanent password; `user_sign_in` → `Session` with non-empty `access_token()`, `expires_in` in `1..3600`, `claims()` carrying `sub`/`username`/`iat`/`exp`; two sign-ins both valid. |
| **05** | `05-user-bad-password-redaction.lms` | wrong password → `UNAUTHENTICATED`; the error message must **not** contain the wrong password string (redaction asserted); missing user sign-in → `UNAUTHENTICATED` too (no user-enumeration leak via distinct messages — assert both messages equal). |
| **06** | `06-user-enable-disable.lms` | sign-in OK → disable → sign-in `UNAUTHENTICATED` → enable → sign-in OK again. |
| **07** | `07-token-verify.lms` | `user_verify_token` accepts a fresh token and returns its claims (`sub`/`username` match); tampered token (last char flipped) → `UNAUTHENTICATED` with a message not containing the token; token from pool A verified under pool B → `UNAUTHENTICATED` (audience isolation). |
| **08** | `08-user-list-pagination.lms` | five users; `user_list(pool, 2, tok)` token walk; five distinct usernames ascending, no gaps/dups; final token `""`; empty pool page legal. |
| **09** | `09-userpool-validation-guards.lms` | invalid pool names (`"Up"`, hyphen, 2-char, 33-char); invalid username (`"A"`, `"a-"`, `"_x"`); reserved/invalid attribute names (`"sub"`, `"Bad-Key"`); oversize attr value (>2048 B); weak password (`"short1"`); `max_items` outside `0..500`; all pre-flight `INVALID_ARGUMENT` with `http_status()==0`. |
| **10** | `10-groups-membership.lms` | `group_create` true/false-duplicate; add user idempotent; `user_groups` sorted contains group; group_list sorted; remove idempotent; missing user/group membership ops → `NOT_FOUND`; group delete while membered OK + membership gone. |
| **11** | `11-userpool-auth-enforced-denial.lms` | Enforce-only (SKIP in open, probed via authenticated `userpool_create` attempt with bogus creds): Pass 1 → `UNAUTHENTICATED`; Pass 2 restricted-but-valid identity → `PERMISSION_DENIED` on `userpool_create`/`user_create`. Azure leg self-SKIPs pending AZ-UP1; GCP pending G-UP1; OCI runner-skips (`oci-identity-domains-epic`). |
| **12** | `12-userpool-notfound-errors.lms` | All user/group/sign-in/verify ops on a missing pool → `NOT_FOUND` (abort-mode `[NOT_FOUND]` + inspection mode); probes return false/`exists()==false` with OK. |

## 3. Simulator Enhancements (evidence-backed)

1. **A-UP1 `awssim`** — certify upstream in-process Cognito IDP surface used by the slice (`CreateUserPool`, `CreateUserPoolClient`, `AdminCreateUser/SetUserPassword/AddUserToGroup/DeleteUser/GetUser`, `ListUsers` with `PaginationToken`, `CreateGroup`, `AdminListGroupsForUser`, `AdminInitiateAuth` USER_PASSWORD_AUTH, `AdminGlobalSignOut` n/a) and token verification via upstream JWKS/discovery (~86 ops per upstream docs); extend `AuthFilter.SUPPORTED` with a `cognito-idp` action set for `--auth enforce` + tests in `scripts/test-auth.py`.
2. **AZ-UP1 `azuresim`** — upstream floci-az epic: Entra-style user directory CRUD + password sign-in (ROPC-equivalent) on the existing Entra token-issuance base (currently token issuance only; directory absent); then `StorageAuth`-adjacent route mapping for enforce mode.
3. **G-UP1 `gcpsim`** — certify upstream Identity Toolkit slice (`accounts:signUp`/`signInWithPassword`/`lookup`/`delete`/`query`, `setAccountInfo` for attrs) + `PermissionFilter.java` enforcement mapping; document the **groups-on-GCP gap** (host-managed membership records on sim route; refused natively per design 17 §4.1/D4).
4. **O-UP1 `ocisim`** — upstream floci-oci epic: in-process OCI Identity Domains subset (SCIM-style users/groups + OAuth token endpoint) + `OciPolicyEngine` resolvers; blocks only the OCI leg (capability `pending(oci-identity-domains-epic)`).

> **Execution status:** all 12 programs pass the runner's static gates. Runtime awaits the Go hosts' `Userpool` adapter (pending in `tests/capabilities.conf`); no runtime behavior is claimed. Sims: AWS operationally present (needs certification + enforce mapping), GCP present-but-uncertified, Azure/OCI need upstream epics — the slices' conformance stays 4-provider-uniform with loud capability SKIPs.
