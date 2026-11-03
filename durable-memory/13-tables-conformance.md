# 13 — `lmcloud` Tables Conformance Suite & Simulator Enhancements (Slice 5)

## 1. Conformance Runner Usage

[`tests/run-conformance.sh`](../tests/run-conformance.sh) now accepts `object-storage`, `queue`, `tables`, or `all` (default `all`):

```bash
# Static compile/typecheck against schema/lmcloud.dsl.json:
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check
LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript ./tests/run-conformance.sh --check tables

# Execute against each provider + simulator once Go hosts are built:
./tests/run-conformance.sh /path/to/lmaws   http://127.0.0.1:4566 tables
./tests/run-conformance.sh /path/to/lmazure http://127.0.0.1:4577 tables
./tests/run-conformance.sh /path/to/lmgcp   http://127.0.0.1:4588 tables
./tests/run-conformance.sh /path/to/lmoci   http://127.0.0.1:4599 tables
```

### Naming, Polling & Capability-Skip Rules
- Table names are `lmt<NN><run_id><suffix>` matching the portable rule `^[a-z][a-z0-9]{2,31}$` (no hyphens — Azure Table is alnum-only, design 12 §4.1). Every scenario embeds a per-run `run_id` (`ARGV[2]`).
- Portable consistency floor is **eventual** (design 12 §4.5): point reads (`item_get`) assert directly; `table_list` / `item_query` counts / `item_scan` sets / post-delete disappearance assert with bounded polls (`<= 10`).
- **Capability skip mechanism (new, explicit, never silent):**
  1. `tests/capabilities.conf` maps `host-name:slice -> supported|pending(<reason>)`. Host name is derived from the host binary basename (`lmaws`/`lmazure`/`lmgcp`/`lmoci`/`lmcloud-ref`). **Honesty rule:** a host's `tables` entry stays `pending(...)` until its Go `Tables` adapter exists *and* passes this suite against its sim; today that means **all four hosts + the reference host are `pending`** (`go-tables-adapter`; OCI additionally `oci-nosql-epic`). Simulator readiness (§3) is separate: AWS/Azure sims are operationally ready, GCP needs Firestore gRPC certification (G1/G3), OCI needs the upstream NoSQL epic (O1).
  2. Every scenario file's first 3 lines carry a `# Requires:` header (`tables` for all 14 here).
  3. The runner matches scenario `Requires` against `capabilities.conf` **before executing**: a `pending(...)` capability prints `ok N - tables/NN-... # SKIP <reason>` (TAP) and counts as `skip`, never `pass` and never silently absent — so `all` stays honest about partial coverage.
  4. The existing in-program `SKIP: ...` mechanism (`run-conformance.sh` exit-0-with-SKIP-output) remains for runtime conditions the runner cannot know (e.g. `--auth` open vs enforce, per-provider enforce gaps).

## 2. The 14 Tables Conformance Scenarios (`tests/conformance/tables/`)

| # | File | Scenario | One-Line Expected Behavior |
|---|---|---|---|
| **01** | `01-table-lifecycle.lms` | key-only + sorted create, exists, list (sorted), delete, post-delete poll | One key-only and one sorted table: `table_exists` `false` before; `table_create` `true`; `exists` `true`; bounded-poll `table_list` contains both sorted; `table_delete` `true`; bounded-poll disappearance `false`. |
| **02** | `02-table-idempotency-and-schema-conflict.lms` | idempotent create; layout mismatch | Second `table_create` (same layout) returns `false`; `table_create` of the same name with the **other** layout fails `CONFLICT` (abort-mode probe both directions). |
| **03** | `03-item-put-get-delete.lms` | CRUD on both layouts; all 4 value types; unicode; empty string; int64 min/max (exact VM arithmetic); integral float keeps `number` tag | `item_put` + `item_get` round-trip `string/int/float/bool/""`/UTF-8 attrs on both layouts incl. `set_number(5.0)` → `type_of == "number"`; `item_delete` then `get` → `exists()==false`; second delete idempotent OK. |
| **04** | `04-item-conditional-put.lms` | only-if-absent and only-if-version | `item_put(t, it, "")` succeeds once, second → `CONFLICT`; version put: read `version()`, `item_put(t, it2, v)` → stored with **changed** version; stale `v` → `PRECONDITION_FAILED`; if-version on missing item → `NOT_FOUND`. |
| **05** | `05-item-update-partial.lms` | item update partial merge| `item_update` sets only stated attrs (other attrs survive — Azure `MERGE` parity), works on both layouts, missing item → `NOT_FOUND`, `version()` changes. |
| **06** | `06-item-query-partition.lms` | query one partition, sk-ascending | 4 items (pk=P, sk a..d) + 1 foreign (pk=Q): `item_query(t, "P")` returns exactly the 4 in ascending `sk` order; key-only table query returns the single item. |
| **07** | `07-item-query-sort-range.lms` | half-open `[sk_from, sk_to)` range | `[b, d)` on the seeded partition yields `{b, c}` only; empty bounds = whole partition; `sk_from >= sk_to` (both non-empty) → pre-flight `INVALID_ARGUMENT`; non-empty range on a key-only table → `INVALID_ARGUMENT`. |
| **08** | `08-item-query-pagination.lms` | `max_items=2` token walk | 5 items in one partition: walk pages of 2 while `has_more()`; assert 5 distinct items, ascending order, no duplicates/gaps; final `next_token() == ""`. |
| **09** | `09-item-scan-bounded.lms` | bounded unordered scan with restart-per-poll, dedup, empty-page-with-token tolerance, tiny pages | 6 items across 2 partitions: polls **restart** the full `item_scan` walk each attempt (no partial-page accumulation across retries; scans are not snapshots) and dedupe by key until the exact set appears; `max_items=1` tiny-page walk completes; `max_items 501`/`-1` fail pre-flight. |
| **10** | `10-item-notfound-errors.lms` | missing table errors; missing-item probes | On a missing table: `item_get`/`item_put`/`item_update`/`item_delete`/`item_query`/`item_scan` → `ErrorCode.NOT_FOUND` (and `[NOT_FOUND]` abort in default mode); on an existing table: missing-item `item_get` → `exists()==false` + OK; `item_delete` of missing item → OK; `item_update` of missing item → `NOT_FOUND`. |
| **11** | `11-item-validation-guards.lms` | pre-flight guards | Invalid names (`"Bad_Name"`, `"ab"`, 33-char, `"bad-hyphen-x"`), invalid keys (`""`, `"/bad"`, `"has#hash"`, `256B`), invalid attr names (`"Bad"`, `"x-y"`, `"__lmv"`), `set_number` NaN/Inf, out-of-range `max_items`/reversed range/empty `sk` on sorted ops: all → `INVALID_ARGUMENT` with `http_status()==0`. |
| **12** | `12-item-value-boundaries.lms` | portable boundary values & sizes | int64 min/max (exact VM arithmetic); floats incl. range extrema `1e-130` / `9.999e125` (via `math_pow`) and pre-flight rejection of `1e126`/`1e-131`; bool; `255`-byte keys; per-string cap **32768 UTF-16 units** measured correctly: BMP `雪`×32768 fit / ×32769 fail, astral `🚀`×16384 (32768 units) fit / ×16385 fail; distributed user-attribute budget 7×32768+32688 = 262144 user bytes exactly (+1 byte → `INVALID_ARGUMENT`); 240 user attrs OK / 241st → `INVALID_ARGUMENT`. |
| **13** | `13-item-scan-key-only-table.lms` | scan on a key-only table (restart-per-poll, dedup, empty-page tolerance) | 3 key-only items collected exactly via restart-style walks with dedup; scan needs no sort key; returned items carry non-empty version tokens. |
| **14** | `14-tables-auth-enforced-denial.lms` | enforce-only auth matrix | Emits `SKIP` in open auth mode. In `--auth enforce`: (a) wrong secret/token → `UNAUTHENTICATED` on `table_create` and `item_put`; (b) restricted principal → `PERMISSION_DENIED` on `item_put` and on `table_exists` probe (never masked as `false`/OK). Azure & GCP legs emit `SKIP` until sim enhancements A2/G2 land; OCI is runner-level capability SKIP. |

---

## 3. Sim Enhancements (evidence-backed; all four sims inspected + live-probed 2026-11-02)

### 3.1 `awssim` (`/home/ubuntu/cloud/awssim`) — DynamoDB fully slice-ready
- **Verified live (open mode):** CreateTable (HASH / HASH+RANGE) `200`; duplicate `400 ResourceInUseException`; typed `PutItem` incl. empty string; conditional puts (`attribute_not_exists`, `__lmv = :v`) → `400 ConditionalCheckFailedException`; `UpdateItem SET` with `__lmv+1` arithmetic; `Query` sorted-by-sk with `BETWEEN`, `Limit`/`LastEvaluatedKey`; `Scan` `Limit`/`ExclusiveStartKey`; `DeleteItem` idempotent; `DeleteTable`; `ListTables`; missing table → `400 ResourceNotFoundException`.
- **Enforce mode:** `AuthFilter.java:39-40` `SUPPORTED.get("dynamodb")` = `CreateTable, DescribeTable, DeleteTable, ListTables, PutItem, GetItem, DeleteItem, UpdateItem, Query, Scan, TagResource, UntagResource, ListTagsOfResource` — **covers the entire slice** (contrast: queue slice needed `ChangeMessageVisibility` added previously).
- **A1 (small, optional):** add a DynamoDB leg to `scripts/test-auth.py` enforce matrix (allow vs deny on `PutItem` + `DescribeTable`), and an empty-string / number-type round trip to `scripts/test-integration.py`.
- **A3 (small, contract-relevant):** certify `ConsistentRead=true` on `GetItem`/`Query` and **`ReturnValuesOnConditionCheckFailure=ALL_OLD`** on conditional writes (design 12 §4.4 — hosts classify `CONFLICT` vs `PRECONDITION_FAILED` vs `NOT_FOUND` atomically when the failure body carries the old item; without it the host falls back to a bounded probe with ambiguity → `INTERNAL`). Also cover `sk BETWEEN` inclusive-bounds semantics and short `Limit` pages in `scripts/test-integration.py`.

### 3.2 `azuresim` (`/home/ubuntu/cloud/azuresim`) — Table Storage works, needs enforce mapping + tests
- **Verified live (open mode, route prefix `/{account}-table/`, OData JSON):** `POST /Tables` `201` / dup `409 TableAlreadyExists`; typed insert (`Edm.Int64`, double, bool, empty string `""`); dup keys `409 EntityAlreadyExists`; point GET with `odata.etag`; `PUT` replace `204`; `MERGE` preserves unstated props; `If-Match` ETag `204` on match / `412 UpdateConditionNotSatisfied` on mismatch; `DELETE If-Match:*` `204` / missing `404 ResourceNotFound`; `$filter` `PartitionKey eq … and RowKey ge … lt …` verified; `$top=2` + `x-ms-continuation-NextPartitionKey/NextRowKey` pagination verified; `DELETE /Tables('name')` `204`.
- **Sim-vs-live laxness (documented; host pre-flight compensates):** accepts empty `RowKey` and hyphenated table names (live Azure rejects both). Keep: not fidelity-critical; hosts validate first.
- **A2 (S):** extend `StorageAuth.java` action mapping & route prefix recognition to `/{account}-table/` (table + entity read/write/delete actions) so `--auth enforce` accepts table traffic, then add table cases to `scripts/test-auth.py`; add `MERGE` + `If-Match` + `$top`/continuation cases to `scripts/test-storage.py`.
- **A4 (S):** confirm Table query pages may be **empty while continuation headers are present** (Azure-documented; hosts must follow the token, design 12 §4.3) and keep `MERGE`/`PUT` `If-Match:*` on missing entities as `404` in enforce mode after A2 lands.

### 3.3 `gcpsim` (`/home/ubuntu/cloud/gcpsim`) — Firestore gRPC present, needs certification + auth mapping
- **Verified live:** REST `/v1/projects/.../documents` returns `404` (not routed); raw gRPC `google.firestore.v1.Firestore/GetDocument` on the shared `:4588` port (ALPN) answers `grpc-status: 5` + `grpc-message: Document not found` (real gRPC path works). Upstream `floci-gcp-0.11.0` `services/firestore/` implements the full gRPC surface (`getDocument:93`, `runQuery:156`, `listDocuments:218`, `updateDocument:239`, `deleteDocument:262`, `createDocument:279`, `listCollectionIds:301`, `batchWrite`, transactions, streaming write/listen) and is `enabled: true` in `application.yml` (lines ~82–83) — but **uncertified** by gcpsim's gate and **unmapped** in `PermissionFilter.java`.
- **G1 (M):** add `scripts/test-firestore.py` certifying the slice's gRPC subset: create/get/update/delete doc with field types, `listDocuments` pagination (`page_size`/`page_token`), and `runQuery` with `__name__` ordering + range + cursor (the design's query path, design 12 §3.2/§6-D6 — verify ordering support; if absent upstream, small upstream patch). Note: host listing is catalog-driven (`lmcloudmeta`), so `listCollectionIds` is *not* on the critical path for empty-table listing.
- **G2 (S):** extend `PermissionFilter.java` with Firestore methods → permission mappings (`datastore.entities.create/get/update/delete/list`, `datastore.databases.listCollectionIds`) for `--auth enforce` + tests.
- **G3 (S):** verify `runQuery` `__name__` ordering/range/cursor behavior on flat collections and correct behavior on empty/absent user collections (catalog-registered empty tables); verify `Precondition` (`exists`, `updateTime`) failure codes (`FAILED_PRECONDITION`, `ALREADY_EXISTS`, `NOT_FOUND`) surface as specified in design 12 §5.

### 3.4 `ocisim` (`/home/ubuntu/cloud/ocisim`) — NoSQL absent (upstream epic)
- **Verified live:** `POST /20190828/tables` and `GET /20190828/tables` → `404 {"code":"NotFound"}` on ocisim v0.1.0; upstream `floci-oci 0.5.0` has no `nosql` package; `lmoci` pins no `oci-java-sdk-nosql` artifact.
- **O1 (L — upstream epic):** implement in-process OCI NoSQL `20190828` REST plane in `floci-oci` — `CreateTable/DeleteTable/GetTable/ListTables`, row `Put/Get/Delete` with `If-Match` conditional, paginated `Query` (pk + sk range) and `Scan` — following the upstream `services/queue` pattern; add `OciPolicyEngine.java` resolvers for enforce mode. **OCI is an explicit capability SKIP (`oci-nosql-epic`) in every tables conformance run until O1 lands.**

> **Execution status:** all 14 `.lms` programs pass `lmscript --check` **and** a no-dispatch embedded-compilation gate (each `_lmcode_` body compiled against `schema/lmcloud.dsl.json`). **Runtime** execution awaits the `Tables` adapter in the Go hosts (09-hostkit.md v5 plan); every host's `tables` capability is marked `pending(...)` in `tests/capabilities.conf` until its adapter lands and passes this suite. Simulator readiness: awssim DynamoDB and azuresim Table are operationally ready (verified live, §3); gcpsim needs Firestore gRPC certification (G1/G3) and auth mapping (G2); ocisim needs the upstream NoSQL epic (O1). **OCI mapping remains unverified against live OCI** (key/type/conditional/capacity policy) — four-provider tables is a design target, not a delivered claim. Firestore gRPC additionally needs its own deadline/retry/credential interception (the HTTP `RetryPolicy`/loopback router do not cover gRPC; see 09-hostkit.md v5 note).
