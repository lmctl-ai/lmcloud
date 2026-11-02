# 12 — `lmcloud` Tables Design (Slice 5: DynamoDB-like key/value tables)

## 1. Goals & Architectural Alignment

Slice 5 extends `schema/lmcloud.dsl.json` **additively** with a provider-neutral, DynamoDB-like **key/value table API** on the existing `cloud` (`Cloud`) context object. **No existing Slice 1/2 signature is modified.** Every `lmscript` tables program runs unchanged against:

1. **Local emulators (primary conformance target):**
   - `lmaws` ↔ `awssim` (`http://127.0.0.1:4566`, S3 + DynamoDB + SQS)
   - `lmazure` ↔ `azuresim` (`http://127.0.0.1:4577`, Blob + Queue + **Table Storage**)
   - `lmgcp` ↔ `gcpsim` (`http://127.0.0.1:4588`, GCS + Pub/Sub + **Firestore gRPC** on the same port via ALPN)
   - `lmoci` ↔ `ocisim` (`http://127.0.0.1:4599`, Object Storage + OCI Queue; **NoSQL PENDING — see §9**)
2. **Real clouds (`aws`, `azure`, `gcp`, `oci`)** using the same credential chains and endpoint configuration rules defined in [`02-object-storage-design.md`](02-object-storage-design.md).

### Endpoint Resolution for Tables (L1)
Tables endpoint resolution follows the **single canonical precedence table in [`02-object-storage-design.md` §3.3](02-object-storage-design.md#L123-L135)**, with service name **`"tables"`**:
- `cloud.endpoint("tables")` returns the effective sanitized tables endpoint URL (control plane and data plane).
- `cloud.set_endpoint("tables", url)` (or `cloud.set_endpoint("all", url)`) overrides it at runtime.
- On GCP, the same loopback URL carries both REST and gRPC (Firestore) — `gcpsim` terminates both on one port via ALPN; `lmgcp` uses the **Firestore gRPC endpoint** for tables.

---

## 2. Schema Surface (Added to `schema/lmcloud.dsl.json`)

### 2.1 Domain Types

#### `TableItem`
A mutable, in-program item value (typed attribute map plus logical key) built via `cloud.item_new(pk)` / `cloud.item_new(pk, sk)`, passed to `item_put`, and returned (server-populated) by `item_put`/`item_get`/`item_update`/`item_query`/`item_scan`. Attribute values are a **flat map** of `name -> (string | int | float | bool)` (value model in §4.2).

| Method | Signature | Description |
|---|---|---|
| `set_string` | `(name: string, value: string) -> self` | Sets attribute `name` to a UTF-8 `string` (empty strings allowed, verified portable; ≤32768 UTF-16 code units per value, §4.2). |
| `set_int` | `(name: string, value: int) -> self` | Sets attribute `name` to a 64-bit signed integer (maps to DynamoDB `N`, Azure `Edm.Int64`, Firestore `integerValue`, OCI NoSQL `LONG`). |
| `set_number` | `(name: string, value: float) -> self` | Sets attribute `name` to a finite IEEE-754 double within the portable range (`x==0` or `1e-130 <= |x| <= 1e126`, §4.2). **NaN / ±Inf / out-of-range fail pre-flight** (`INVALID_ARGUMENT`). |
| `set_bool` | `(name: string, value: bool) -> self` | Sets attribute `name` to `BOOL`/`Edm.Boolean`/`booleanValue`. |
| `remove` | `(name: string) -> self` | Removes attribute `name` from this **local** item only (no server effect). |
| `has` | `(name: string) -> bool` | `true` if the item currently carries attribute `name`. |
| `type_of` | `(name: string) -> string` | `"string"`, `"int"`, `"number"`, `"bool"`, or `""` when absent (never aborts). |
| `get_string` / `get_int` / `get_number` / `get_bool` | `(name: string) -> string/int/float/bool` | Typed attribute getter. Missing attribute or wrong type fails locally with `ErrorCode.INVALID_ARGUMENT` (`http_status() == 0`). |
| `names` | `() -> StrList` | Attribute names in ascending lexicographical order (does **not** include the logical keys or `version`). |
| `len` | `() -> int` | Number of attributes (`0 <= len() <= 240`). |
| `pk` / `sk` | `() -> string` | Logical partition/sort key **values** carried by this item (`sk() == ""` on key-only items). |
| `version` | `() -> string` | Opaque provider-managed optimistic-concurrency token: `""` on locally-built or `exists()==false` items; non-empty on items returned by `item_put`/`item_get`/`item_update`/`item_query`/`item_scan`. Compare only with `==`/`!=`, only within the same provider and table (§4.4). |
| `exists` | `() -> bool` | `true` for items known to exist server-side (successful `item_put`/`item_update`, or `item_get` on a present item); `false` for locally-built items and for `item_get` results on missing items. |

#### `TablePage` (result of `item_query` / `item_scan`; iterable via `for (it in page) { ... }` backed by `len`/`at`)
| Method | Signature | Description |
|---|---|---|
| `len` | `() -> int` | Items on this page (`0 <= len() <= max_items`). |
| `at` | `(int) -> TableItem` | Item at index `i` (`0 <= i < len()`). |
| `has_more` | `() -> bool` | `true` iff `str_len(next_token()) > 0` (token invariant, same as Slice 1 M7). |
| `next_token` | `() -> string` | Opaque continuation token; `""` on the last page. |

### 2.2 `Cloud` Table Methods (`context cloud: Cloud`)

| Method | Signature(s) | Semantics |
|---|---|---|
| `item_new` | `(pk: string) -> TableItem`<br>`(pk: string, sk: string) -> TableItem` | Builds a local `TableItem` bound to partition key `pk` (and sort key `sk`). Keys are validated pre-flight (§4.1) at the time of `item_new`. |
| `table_create` | `(name: string) -> bool`<br>`(name: string, sorted: bool) -> bool` | Ensures table `name` exists. 1-arg form creates a **partition-key-only** table; 2-arg form with `sorted=true` creates a **partition+sort-key** table (`sorted=false` ≡ 1-arg). Returns `true` if newly created, `false` if it already existed **with the same key layout**; fails with `ErrorCode.CONFLICT` if a table with that name exists but with the **other** key layout (§3, per-provider key-layout detection). |
| `table_delete` | `(name: string) -> bool` | Deletes table `name` (deleting a non-empty table is allowed). Returns `true` if deleted, `false` if it did not exist (`404`). |
| `table_exists` | `(name: string) -> bool` | Probe: `true` if `name` exists and is accessible, `false` on `404`. Auth failures abort (Slice-1 H1/H2 rules unchanged). |
| `table_list` | `() -> StrList` | All caller-visible table names in the active scope, all pages followed, ascending lexicographical order. Reserved host-meta tables/collections (§3.5) are filtered. |
| `item_put` | `(table: string, item: TableItem) -> TableItem`<br>`(table: string, item: TableItem, expect_version: string) -> TableItem` | 2-arg: unconditional put (insert or full-item overwrite), returns the stored item with a fresh `version()`. 3-arg: **conditional put** (§4.4): `expect_version == ""` = **only-if-absent** (existing item → `CONFLICT`); `expect_version != ""` = **only-if-version** (missing item → `NOT_FOUND`; version mismatch → `PRECONDITION_FAILED`). On a **sorted table**, `item` must have been built with `sk`; omitting a required `sk` or supplying one on a key-only table fails pre-flight `INVALID_ARGUMENT`. |
| `item_get` | `(table: string, pk: string) -> TableItem`<br>`(table: string, pk: string, sk: string) -> TableItem` | Point read. Missing item in an existing table → `TableItem` with `exists() == false` and `last_error == OK`; missing table → `NOT_FOUND`. |
| `item_delete` | `(table: string, pk: string) -> void`<br>`(table: string, pk: string, sk: string) -> void` | Idempotent remove: `OK` whether the item existed or not when the table exists; missing table → `NOT_FOUND`. |
| `item_update` | `(table: string, pk: string, changes: TableItem) -> TableItem`<br>`(table: string, pk: string, sk: string, changes: TableItem) -> TableItem` | Partial merge: **sets** the attributes carried by `changes`, preserves all others, bumps `version`. Missing item → `NOT_FOUND` (enforced pre-flight via conditional update where the provider would otherwise upsert, §3.4). Returns the stored item. |
| `item_query` | `(table: string, pk: string) -> TablePage`<br>`(table: string, pk: string, sk_from: string, sk_to: string, max_items: int, page_token: string) -> TablePage` | Items with partition key `pk`, **ascending `sk` order** (sorted tables). 6-arg form: half-open range `[sk_from, sk_to)` (`""` = unbounded on that side), `max_items` bound (`0` = default `100`, `1..500`), opaque `page_token` (`""` = first page). On a **key-only** table the 6-arg form with non-empty range bounds fails pre-flight `INVALID_ARGUMENT`; `2-arg` on a key-only table returns the 0-or-1 item for `pk`. |
| `item_scan` | `(table: string) -> TablePage`<br>`(table: string, max_items: int, page_token: string) -> TablePage` | **Bounded whole-table scan, unordered** (test programs must compare sets, not sequences). Same `max_items`/`page_token` rules as `item_query`. |

---

## 3. Per-Provider Mapping (with live sim evidence gathered 2026-11-02)

### 3.1 Model Fit

| Concern | AWS DynamoDB (`awssim` `:4566`) | Azure Table Storage (`azuresim` `:4577`) | GCP Firestore (`gcpsim` `:4588`) | OCI NoSQL (`ocisim`) |
|---|---|---|---|---|
| Native shape | table, items keyed (`HASH`[, `RANGE`]) attrs typed `S/N/BOOL` | table, entities always keyed (`PartitionKey`,`RowKey`), flat typed properties | collections → documents, dynamically typed fields | table, rows, typed columns |
| `lmcloud` key-only table | `KeySchema=[pk HASH]` | entity `RowKey` = reserved sentinel `"-"` (§4.1; verified: live Azure requires non-empty RowKey, sim happens to accept empty) | document id `enc(pk)` in collection `{name}` | *pending* |
| `lmcloud` sorted table | `KeySchema=[pk HASH, sk RANGE]` | `PartitionKey=pk`, `RowKey=sk` | document id `enc(pk) + "#" + enc(sk)` (single flat collection, `#`=`0x23` sorts before every legal first key char (`-`=`0x2D`); ordering & ranges via `__name__`) | *pending* |
| Key-layout/existence authority | `DescribeTable.KeySchema` (authoritative) | **catalog table `lmcloudmeta`** (one entity per logical table; §3.5) | **catalog collection `lmcloudmeta`** (one doc per logical table, id = plain table name; §3.5) | *pending* |
| `version()` | reserved string attribute `__lmcloud_v` set to a fresh random 128-bit token on every write, under `ConditionExpression` for conditional modes | `odata.etag` per entity | document `updateTime` | *pending* |

### 3.2 Operation Mapping Table

| `lmcloud` | AWS DynamoDB | Azure Table Storage | GCP Firestore (gRPC) | OCI NoSQL |
|---|---|---|---|---|
| `table_create(name)` / `(name, sorted)` | `CreateTable` (`AttributeDefinitions` `pk[,sk]` S; `KeySchema` HASH[, RANGE]; `BillingMode=PAY_PER_REQUEST`); wait `DescribeTable` ACTIVE (≤60 s); `ResourceInUseException` → `DescribeTable` compare → `false` or `CONFLICT` | `POST /{acct}-table/Tables {"TableName":name}` (`201`); **conditional catalog claim** (insert meta entity with `If-None-Match: *` semantics via insert-only; existing record → compare layout/scope → `false`/`CONFLICT`, §3.5) | **conditional catalog claim**: `createDocument` on collection `lmcloudmeta`, id `{name}` → `ALREADY_EXISTS` → compare stored layout/scope → `false`/`CONFLICT` (§3.5) | *pending* |
| `table_delete(name)` | `DeleteTable` (`ResourceNotFoundException` → `false`) — deletion is *accepted*; `table_exists`/list disappearance may lag (poll) | tombstone state in catalog → bounded child deletion → `DELETE /Tables('{name}')` (`204`; `404` → `false` if no catalog record) → catalog tombstone deleted **last** (§3.5) | tombstone state in catalog → bounded metered child deletes (`listDocuments` + `deleteDocument` loops) → catalog tombstone deleted **last** (§3.5); `false` when no catalog record | *pending* |
| `table_exists(name)` | `DescribeTable` (`200`/`ResourceNotFoundException`) | **catalog entity `GET`** (`lmcloudmeta`, PK=`tables`, RK=`{name}`) — authoritative even for empty tables | **catalog doc `getDocument`** (`lmcloudmeta/{name}`) — authoritative even for empty tables (`5 NOT_FOUND` → `false`) | *pending* |
| `table_list()` | `ListTables` loop `LastEvaluatedTableName` | **catalog query** on `lmcloudmeta` partition `tables` (loop continuation headers), sorted | **catalog `listDocuments` on `lmcloudmeta`** (loop `nextPageToken`), sorted (works for empty tables; no `listCollectionIds` dependence) | *pending* |
| `item_put(t, item)` (Unconditional) | `PutItem` with fresh `__lmcloud_v` random token; request content identical across retries → retry of an ambiguous reply is safe (same token, same bytes) | `PUT` (replace) `/Customers(PartitionKey=…,RowKey=…)` (upsert; ETag refreshed) | `updateDocument` full field replace (precondition none) | *pending* |
| — conditional-failure classification (AWS) | `ReturnValuesOnConditionCheckFailure=ALL_OLD` on conditional writes (atomic, no probe race; sim-verification A3 §3.6); fallback = one bounded `GetItem` probe, ambiguity → `INTERNAL` | native `409`/`412`/`404` per call | native gRPC codes per call | *pending* |
| `item_put(t, item, "")` only-if-absent | `PutItem` `ConditionExpression="attribute_not_exists(pk)"`; `ConditionalCheckFailedException` + probe → `CONFLICT` | `POST /{table}` insert-only: `409 EntityAlreadyExists` → `CONFLICT` | `createDocument` (precondition exists=false): `ALREADY_EXISTS(6)` → `CONFLICT` | *pending* |
| `item_put(t, item, ver)` only-if-version | `PutItem` `ConditionExpression="__lmcloud_v = :v"`; failure + probe → `PRECONDITION_FAILED` (exists) / `NOT_FOUND` (absent) | `PUT` with `If-Match: {ver}`: `412 UpdateConditionNotSatisfied` → `PRECONDITION_FAILED`; `404` → `NOT_FOUND` | `updateDocument` with `Precondition.updateTime = ver`: `FAILED_PRECONDITION(9)` → `PRECONDITION_FAILED`, `NOT_FOUND(5)` → `NOT_FOUND` | *pending* |
| `item_get` | `GetItem` | `GET /{table}(PartitionKey=…,RowKey=…)` (`404 ResourceNotFound` → `exists=false`/OK) | `getDocument` (`NOT_FOUND(5)` → exists=false/OK; **table-missing distinction via meta** §3.5) | *pending* |
| `item_delete` | `DeleteItem` (200 whether present or not) | `DELETE` + `If-Match: *`; `404` on missing entity when table exists → OK | `deleteDocument`; `NOT_FOUND(5)` on missing doc (table exists) → OK | *pending* |
| `item_update` | `UpdateItem SET ...` with `ConditionExpression="attribute_exists(pk)"` (missing → `ConditionalCheckFailedException` + probe → `NOT_FOUND`); bumps `__lmcloud_v` | `MERGE` with `If-Match: *` (missing → `404`); partial by construction | `updateDocument` with field mask + `Precondition.exists=true` (missing → `NOT_FOUND(5)`) | *pending* |
| `item_query(t, pk[, range, max, token])` | `Query` `KeyConditionExpression="pk = :p AND sk BETWEEN :a AND :b"` (pk equality + one sk condition; `BETWEEN` is inclusive-both, so the host drops any returned `sk == sk_to` row client-side and compensates page boundaries via the host-bound token, §4.3), `Limit=max_items`, `ExclusiveStartKey=token`, `ScanIndexForward=true`, `ConsistentRead=true` (§4.5) | `$filter=PartitionKey eq 'pk' [and RowKey ge 'a' and RowKey lt 'b']`, `$top=max_items`, continuation headers as token | `runQuery` structured: `__name__ >= start AND __name__ < end` on collection `{name}`, `orderBy __name__`, limit/cursor token | *pending (epic must include runQuery)* |
| `item_scan(t[, max, token])` | `Scan` `Limit=max_items`, `ExclusiveStartKey=token` | `$top=max_items` without `$filter`, continuation headers | `listDocuments(pageSize,pageToken)` on collection | *pending* |

### 3.3 Live Simulator Evidence (driven with `scripts/sim.sh` + curl, 2026-11-02)

- **awssim v0.2.0 (DynamoDB, in-process, no Docker):** `CreateTable` (HASH and HASH+RANGE) `200` with full `TableDescription`; duplicate create → `400 ResourceInUseException`; `PutItem` with `S/N/BOOL` incl. **empty string `""` accepted**; conditional puts verified end-to-end (`attribute_not_exists(pk)` and `__lmv = :v` version match/stale → `400 ConditionalCheckFailedException`); `UpdateItem SET` with `__lmv + 1` increment verified (`N=1→2→3`); `Query` returns items **sorted by sk**, honours `BETWEEN`, `Limit` + `LastEvaluatedKey` → `ExclusiveStartKey` pagination verified across pages; `Scan` with `Limit`/`ExclusiveStartKey` verified; `DeleteItem` idempotent `200`; `DeleteTable` + `ListTables` round trip `{"TableNames":[]}`; ops on missing table → `400 ResourceNotFoundException`. Enforce-mode op map (`awssim/src/main/java/ai/lmctl/awssim/AuthFilter.java:39-40`) already includes `CreateTable, DescribeTable, DeleteTable, ListTables, PutItem, GetItem, DeleteItem, UpdateItem, Query, Scan, TagResource, UntagResource, ListTagsOfResource` — **the whole slice surface**.
- **azuresim v0.2.0 (Azure Table Storage over OData JSON, route prefix `/{account}-table/`, in-process, no Docker):** `POST /Tables` `201`, dup → `409 TableAlreadyExists`, `GET /Tables` list `200`; typed inserts incl. `Edm.Int64` annotation, double, bool, **empty string**; duplicate key insert → `409 EntityAlreadyExists`; point `GET` `200` with `odata.etag`; `PUT` replace `204`; `MERGE` partial `204` preserving unstated properties (**verified** Name survives Score-only merge); `If-Match` correct ETag → `204`, wrong ETag → **`412 UpdateConditionNotSatisfied`**; `DELETE ... If-Match:*` → `204`, missing entity → `404 ResourceNotFound`; `$filter=PartitionKey eq …` and `… and RowKey ge 'b' and RowKey lt 'd'` range verified (results sorted by `(PartitionKey,RowKey)`); `$top=2` → continuation headers `x-ms-continuation-NextPartitionKey/NextRowKey` verified; `DELETE /Tables('name')` `204`. **Quirks vs live Azure:** sim accepts empty `RowKey` and hyphenated table names (live Azure rejects both) — host pre-flight rules (§4.1) close this gap. **Enforce mode:** `StorageAuth.java` maps only `blob|queue` (verified: no `table` mapping), so table routes fail closed in `--auth enforce` (see §3.6 enhancement A2).
- **gcpsim v0.2.0 (Firestore, gRPC-only on shared `:4588` via ALPN; REST `/v1/.../documents` returns `404`):** raw gRPC probe `google.firestore.v1.Firestore/GetDocument` answered `grpc-status: 5` with percent-encoded `grpc-message: Document not found` (live-verified). Upstream `floci-gcp 0.11.0` (`build/floci-gcp-*/src/main/java/io/floci/gcp/services/firestore/`) implements **gRPC-only**: `getDocument` (line 93), `batchGetDocuments`, `runQuery` (156), `beginTransaction`, `updateDocument` (239), `deleteDocument` (262), `createDocument` (279), `listCollectionIds` (301), `listDocuments` (218), `batchWrite`, `runAggregationQuery`, streaming `Write`/`Listen`. **Firestore is *not* certified in gcpsim's release gate and has no `PermissionFilter.java` route mapping** (enhancements G1/G2).
- **ocisim v0.1.0:** **No NoSQL service** — `POST /20190828/tables` and `GET /20190828/tables` both return `404 {"code":"NotFound"}` (live-verified); upstream `floci-oci 0.5.0` `services/` contains no nosql package. **OCI portion of Slice 5 is PENDING** (§9).

### 3.4 Update/Conditional-Write Semantics by Provider

| Semantic | AWS | Azure | GCP | OCI |
|---|---|---|---|---|
| Unconditional `item_put` overwrite | `PutItem` (replaces whole item; host writes attributes + fresh `__lmcloud_v`) | `PUT` entity replace + `If-Match` omitted (upsert; host merges preserved attrs only for `item_update`) | `updateDocument` without mask | pending |
| only-if-absent | `attribute_not_exists(pk)` | insert-only `POST` (`409`) | `createDocument` (`ALREADY_EXISTS`) | pending |
| only-if-version | `__lmcloud_v = :v` `ConditionExpression` | `If-Match: <etag>` (`412`) | `Precondition.updateTime` (`FAILED_PRECONDITION`) | pending |
| `item_update` missing-item guard | `attribute_exists(pk)` | `If-Match: *` on `MERGE` (missing → `404`) | `Precondition.exists = true` | pending |

### 3.5 Catalog, Key Layout & Lifecycle Authority (replaces earlier lazy-meta note; addresses empty tables, concurrency, crash rules)

Providers differ on whether table existence/key layout is discoverable server-side:
- **AWS DynamoDB:** `DescribeTable.KeySchema` is authoritative (no catalog on AWS).
- **Azure Table Storage & GCP Firestore:** existence and key layout are client conventions, so the hosts maintain a **reserved catalog** that is the **authoritative registry** for `table_exists` / `table_list` / layout arbitration — for empty tables too:
  - Azure: table **`lmcloudmeta`**, entity `PartitionKey="tables"`, `RowKey=<name>` (alnum, matches §4.1 rule; `table_list` shows catalog rows, and filters the catalog table itself).
  - GCP: collection **`lmcloudmeta`** (plain alnum — never `__lmcloud_meta__`, which matches Firestore's forbidden `__..__` ID pattern), document id = **plain table name** (one component, never `<literal>/<name>`).
  - OCI NoSQL: pending; DDL is authoritative once epic O1 lands.

**Catalog record:** `{layout: "key"|"sorted", scope: <account/project fingerprint>, token: <128-bit create token>, state: "active"|"deleting", created: <epoch>}`. Immutable after claim except `state`.

- **Claim (create):** conditional create-only write of the catalog record (`lmazure`: insert-only `POST` on `lmcloudmeta`, `409 EntityAlreadyExists` → read record; `lmgcp`: `createDocument`, `ALREADY_EXISTS` → read). If the existing record matches layout+scope → `false` (idempotent). Layout mismatch or foreign scope/token → **`CONFLICT`**; no auto-adoption of foreign, pre-existing resources. This makes concurrent opposite-layout creates safe: exactly one claim wins; the loser reports `CONFLICT` without overwriting (no upsert anywhere in the lifecycle).
- **Delete lifecycle & crash recovery:** `table_delete` → set catalog record `state="deleting"` (tombstone) → bounded child deletion (Azure: delete entities by partition scan; Firestore: `listDocuments` + per-doc `deleteDocument` in pages, **Firestore child deletion is metered per-document — not one free teardown**) → provider table delete where applicable (Azure `DELETE /Tables('{name}')`) → **delete the catalog record last**. A crash with the tombstone present: recovery treats `state="deleting"` as "delete in progress", resumes child deletion, and never presents the table as existing. The journal of tombstone records is the recovery source.
- **Ownership:** the catalog (`lmcloudmeta` table/collection) is **host-shared infrastructure owned by the adapter scope**, never considered run-owned and never swept by run teardown/sweepers. Run-owned tables live one catalog record each; sweepers may only tombstone+delete catalog records they can prove belong to their expired run (token/age checks, existing rules).

### 3.6 Sim Enhancements Required (details + evidence in [`13-tables-conformance.md`](13-tables-conformance.md) §3)

- **A1 `awssim`:** optional — verify `TagResource`-on-create and `DescribeTable` in `scripts/test-auth.py` enforce matrix (map already covers all slice actions; conformance currently exercises open + enforce).
- **A3 `awssim`:** certify `ConsistentRead=true` on `GetItem`/`Query` (accepted and honored — in-memory sim is strongly consistent anyway) and `ReturnValuesOnConditionCheckFailure=ALL_OLD` on conditional writes (returns old item on failed condition; used for atomic `CONFLICT`/`PRECONDITION_FAILED`/`NOT_FOUND` classification, §4.4). Verify `sk BETWEEN` inclusive-bounds behavior and short/empty `Limit` pages in `scripts/test-integration.py`.
- **A2 `azuresim`:** add Table Storage routes to `StorageAuth.java` action mapping (`/{account}-table` prefix → table/entity actions) so `--auth enforce` table traffic works; add entity `If-Match`/`$top` continuation coverage to `scripts/test-storage.py`. (Cosmos NoSQL embedded engine exists upstream but is **not** targeted by this slice.)
- **A4 `azuresim`:** confirm `$top`-driven pages may return empty-with-continuation on Table queries and that `MERGE`/`PUT If-Match:*` on missing entities stays `404` in enforce mode too (after A2).
- **G1 `gcpsim`:** certify the Firestore **gRPC** subset used here (`createDocument`/`getDocument`/`updateDocument`/`deleteDocument`/`listDocuments`/collection-listing equivalent and `runQuery` incl. `__name__` ordering + range + cursor pagination) in `scripts/`; **G2:** extend `PermissionFilter.java` with Firestore route mappings for `--auth enforce`.
- **G3 `gcpsim`:** verify `runQuery` supports `__name__` ordering/ranges and cursor tokens on the flat catalog/user collections, and behavior on empty collections (catalog-driven listing must still report empty-but-registered tables).
- **O1 `ocisim` (upstream epic):** implement in-process OCI NoSQL `20190828` plane (tables + row CRUD + query/scan pagination + conditional ops) in `floci-oci`; until it lands, all OCI table runs are explicit capability SKIPs (§9; `tests/capabilities.conf`).

---

## 4. Portable Naming, Key, Value, Size, and Pagination Rules

### 4.1 Table Names & Keys (pre-flight, `INVALID_ARGUMENT`, `http_status() == 0`)

- **Table names** must match `^[a-z][a-z0-9]{2,31}$` (3–32 chars, lowercase alnum, start letter) — the intersection of DynamoDB (`3..255`, `[a-zA-Z0-9._-]`), Azure Table (`^[A-Za-z][A-Za-z0-9]{2,62}$`, **no hyphens**), Firestore collection ids (any UTF-8 sans `/`, not `.`/`..`/`__*__`), OCI NoSQL (`^[A-Za-z][A-Za-z0-9._-]{0,255}$` roughly). Conformance table names: `lmt<NN><run_id><suffix>` (alnum-only run suffix).
- **Partition key / sort key values** must match `^[A-Za-z0-9._~-]{1,255}$` each (1–255 bytes) **and** must not be `.` or `..` and must not be wrapped in double underscores (`^__..__$`) — the last three are legal per the charset but are **forbidden Firestore document ids**, so they fail pre-flight for portability. This charset is identity-encoded on every provider (no percent-encoding needed): valid Firestore document id component, valid Azure `RowKey` (excludes `/ \ # ?`), valid DynamoDB key value. **Unicode/arbitrary keys are out of scope for v1** (§8 exclusion 6). Conformance covers reserved-looking keys (`"__x__"`, `"."`, `".."`) via pre-flight rejection and prefix-neighbor partitions (e.g. pk `"a"` vs `"ab"` must not bleed ranges).
- **Reserved RowKey sentinel:** key-only tables map to Azure with `RowKey = "-"` (single legal character, guaranteed never to collide because a key-only table never admits a user sort key; the sim accepting *empty* RowKey is a sim-only laxness the host never relies on).
- **`sk` on `item_new`/`item_get`/`item_delete`:** empty `sk` (`""`) fails pre-flight when a sort key is expected; `sk` must not be supplied for key-only operations (arity does this).

### 4.2 Item Value Model (portable JSON subset)

- **Flat attributes only:** `name -> string | int | float | bool`. **Nested lists/maps, binary, sets, and explicit null are excluded** (Azure Table has no arrays/maps/null; common denominator). Absence of an attribute is the portable "null".
- **Attribute names:** `^[a-z][a-z0-9_]{0,62}$`; names starting `__lm` are reserved for host-managed metadata (`__lmcloud_v`, `__lmt` on DynamoDB) and fail pre-flight. Names `pk`/`sk` are also reserved (they are the key attribute aliases on DynamoDB) and fail pre-flight.
- **Per-string value limit (portable floor):** a string attribute value may be at most **32768 UTF-16 code units** (Azure `Edm.String` caps at 64 KiB of UTF-16). Hosts count code units pre-flight (a `雪` counts 1, an astral char counts 2) and reject over-limit values with `INVALID_ARGUMENT` even when their UTF-8 byte length is small. Scenario 12 covers ASCII at-limit, +1-unit, and unit-vs-byte counting.
- **Numbers:** `set_int` = exact signed 64-bit (serialized as decimal text end-to-end; SDKs must not float-convert); `set_number` = finite IEEE-754 double with the **portable range restriction** `x == 0.0` or `1e-130 <= |x| <= 1e126` (DynamoDB `N` accepts nonzero magnitudes only down to ~1E-130 and up to ~1E126); **NaN/±Inf and out-of-range finite doubles rejected pre-flight**. Providers may normalize numeric text (`1.50` → `1.5`), so conformance asserts with `==` for ints/bools/strings and `assert_close` for floats.
- **Int vs float tag preservation:** Azure (`Edm.Int64` vs `Edm.Double` via `@odata.type` annotation), Firestore (`integerValue` vs `doubleValue`), and OCI NoSQL (`LONG`/`DOUBLE`) carry the distinction natively. **DynamoDB does not** (`N` normalizes `0.1`/`5.0`/integer lookalikes), so the DynamoDB adapter additionally writes a reserved string attribute **`__lmt`** per item listing the names of float-valued attributes (`"score,pi"`; integral floats like `5.0` included). `__lmt` counts toward the 240-attribute cap and the size budget; adapters read it to answer `type_of`/`get_int`/`get_number` exactly (an untagged `N` is `"int"` only if integral-text; any float-tagged attr is `"number"`). Conformance scenario 03 pins the `set_number(5.0)` → `type_of == "number"` case.
- **Empty strings** are portable (verified on DynamoDB, Azure Table; Firestore supports them).
- **Attribute count:** `<= 240` per item (Azure's `252`-property ceiling minus `PartitionKey`/`RowKey`/`Timestamp`, with margin; DynamoDB `__lmt`/`__lmcloud_v` consume budget on AWS).
- **Item size (canonical measure, testable):** `item_bytes = sum(utf8_len(name) + utf8_len(value_bytes)) + 8 * attribute_count` over all attributes; **`item_bytes <= 262144` (256 KiB)** enforced pre-flight on all hosts, where int values count as 8 bytes, float as 8 bytes, bool as 1 byte, strings as their UTF-8 byte length. (Scenario 12 distributes the exact budget across eight legal properties: 7×32768-byte strings + one 32688-byte string + names/overhead = 262144 exactly; +1 byte fails pre-flight.) Under DynamoDB's `400 KB` item cap with margin, under Azure's `1 MB` entity cap and Firestore's `1 MiB` document cap.

### 4.3 Pagination (token rules)

- `max_items`: `0` = default **`100`**; `1..500` valid; out of range fails pre-flight `INVALID_ARGUMENT`. (Provider page ceilings — DynamoDB evaluates at most `1 MB` per `Query`/`Scan` call — mean a provider page may hold fewer than `max_items` items; callers loop on `has_more()`, never assume full pages — same M7 rule as Slice 1.)
- **Empty pages with continuation are legal** (Azure explicitly returns them; DynamoDB `ConsistentRead`/`Limit` pages can also be short): an empty page that still has `has_more() == true` MUST be followed, never treated as completion. Conformance walks use tiny-page (`max_items=1`) and boundary fixtures (scenarios 08/09/13).
- **Token binding & validation:** `page_token` is an opaque host-encoded blob bound to `(provider endpoint, table, key layout, partition key, range bounds, max_items)`; a token replayed against a mismatched table/layout/range fails `INVALID_ARGUMENT`; undecodable tokens fail `INVALID_ARGUMENT`; a stalled/looping provider token (no progress) fails `INTERNAL` (consistent with Slice 1's `ListAll` stall rule). All failures above are pre-flight/local (`http_status()==0` for malformed/mismatch).
- **Token invariant:** `has_more() == (str_len(next_token()) > 0)`; `""` = first page on input, `""` = last page on output.
- **Half-open range mapping where the backend is inclusive-both (AWS):** DynamoDB `BETWEEN :a AND :b` includes both endpoints, so the host filters out any returned row with `sk == sk_to` when `sk_to != ""`. The trim is applied *inside* the page the host returns (pages may therefore be shorter than `max_items`); the host's continuation token always advances past the trimmed row so no duplicate or missed row occurs. (AWS grammar: pk equality plus **one** sk condition — `BETWEEN` qualifies; `sk >= :a AND sk < :b` is not expressible natively.)
- Ordering: `item_query` returns ascending `sk` order within the partition; `item_scan` is **unordered** across all providers (DynamoDB `Scan` is unordered; Azure happens to be `(PK,RK)`-sorted; spec deliberately weaker; whole-table scans are *not* snapshots — late/mutating rows are tolerated by the restart-style polling pattern in scenarios 09/13).

### 4.4 Versioning & Conditional Puts (portable subset)

- **Write modes (adapter-explicit):** the schema's 2-arg `item_put` maps to mode **Unconditional**; 3-arg with `expect_version == ""` maps to **IfAbsent**; 3-arg with `expect_version != ""` maps to **IfVersion**. The adapter interface carries an explicit mode enum so these are never conflated (see 09-hostkit.md v5 plan).
- **Version allocation:** every server write stamps a **fresh, random, non-repeating 128-bit token** (`__lmcloud_v` on DynamoDB; native `odata.etag`/`updateTime` pass-through elsewhere; OCI ETag when O1 lands). Tokens are generated **once per logical call** and reused verbatim across retries, so a retried unconditional write is byte-identical and harmless. Random-per-write means a delete/recreate sequence produces a different token (no ABA), and stale-token conditional writes fail cleanly even after intermediate deletes.
- **Conditional semantics:**
  - IfAbsent (`expect_version == ""`): item exists → `CONFLICT`.
  - IfVersion: item exists with a different version → `PRECONDITION_FAILED`; item absent → `NOT_FOUND`.
  - **No blind retry of conditional writes after an ambiguous (post-commit-possible) failure.** On AWS the adapter classifies conditional failures atomically with `ReturnValuesOnConditionCheckFailure=ALL_OLD` where available (returns the old item on a failed conditional write; sim-verification item A3 — awssim/Floci support must be certified; fallback: one bounded `GetItem` probe, unresolved ambiguity → `INTERNAL`, never reclassify a retry's conflict as the original outcome).
- `version()` is comparable only within the same provider+table+item lineage; programs must not compare versions across providers.

### 4.5 Consistency & Control-Plane Lifecycle (strong point/partition reads; eventual scans/lists)

- **Strong reads are the contract** for `item_get` and `item_query` (immediate post-write assertions are valid), achieved per provider:
  - **AWS DynamoDB:** `ConsistentRead=true` on `GetItem` and `Query` (strongly consistent; small extra RCU cost on live AWS; Scan has no strong mode → stays eventual).
  - **Azure Table Storage:** reads are strong by default (single-region, no consistency knob needed).
  - **GCP Firestore:** document reads and queries are strongly consistent by default.
  - **OCI NoSQL:** per-request `Consistency=ABSOLUTE` (when epic O1 lands).
- **`item_scan` and `table_list` remain evental-consistency-class:** DynamoDB `Scan` is always eventual, and list operations may lag on live clouds. Conformance scenarios use **restart-per-poll with deadline-bounded attempts** (≤12 attempts; each poll restarts the full walk and dedupes by key set — never accumulates partial pages across retries): scenarios 09/13. `table_list` assertions use the same bounded poll as slices 1–2 (≤10 polls).
- **`table_create` waits until usable** before returning `true`: DynamoDB `CreateTable` is asynchronous — the host polls `DescribeTable` until `ACTIVE` (≤60 s deadline, jittered backoff, same `WaitLoop` discipline as Slice 2); OCI NoSQL create is likewise asynchronous (poll until ACTIVE) when implemented; Azure/Firestore catalog claims are synchronously visible (strong per §3.5), then item traffic begins. **`table_delete` means *deletion accepted***: post-delete `table_exists` disappearance is asserted via bounded poll everywhere (DynamoDB deletion is async; Azure table-name reuse after delete can lag on live Azure — conformance uses unique per-run names and never reuses a deleted name).
- Conformance immediate assertions (`item_get` right after `item_put`, partition `item_query` right after seeding) rely on the strong-read contract above; the ≤10 bounded polls kept around *aggregate* reads stay as belt-and-braces for sims.

---

## 5. Error Model (reuses the shared 8 `ErrorCode`s)

| `ErrorCode` | DynamoDB (`awssim`) | Azure Table (`azuresim`) | Firestore (`gcpsim`, gRPC status) | OCI NoSQL (planned) |
|---|---|---|---|---|
| `INVALID_ARGUMENT` | `ValidationException` (`400`) | `InvalidInput` / `PropertiesNeedValue` / `InvalidValueType` (`400`) | `INVALID_ARGUMENT (3)` | `InvalidParameter` (`400`) |
| `NOT_FOUND` | `ResourceNotFoundException` (`400`) | `TableNotFound`, `ResourceNotFound` (`404`) | `NOT_FOUND (5)` | `TableNotFound` (`404`) |
| `CONFLICT` | `ResourceInUseException` (`400`); conditional-failure + probe when item exists | `TableAlreadyExists`, `EntityAlreadyExists` (`409`) | `ALREADY_EXISTS (6)` | `TableAlreadyExists` (`409`) |
| `PRECONDITION_FAILED` | conditional-failure + probe (existing item, wrong version) | `UpdateConditionNotSatisfied` (`412`) | `FAILED_PRECONDITION (9)` | `IfMatchFailed` (`412`) |
| `UNAUTHENTICATED` | `InvalidSignatureException` / missing auth (`400/403`) | `AuthenticationFailed` (`403`) | `UNAUTHENTICATED (16)` | `NotAuthenticated` (`401`) |
| `PERMISSION_DENIED` | `AccessDeniedException` (`400/403`) | `AuthorizationPermissionMismatch` (`403`) | `PERMISSION_DENIED (7)` | `NotAuthorizedOrNotFound` (`403`/`404`, H1 rule from design 02 §5.1 applies) |
| `INTERNAL` | `InternalServerError` (`500`) | `OperationTimedOut` (`500`) | `INTERNAL (13)`, `UNAVAILABLE (14)`→retry | `InternalServerError` (`500`) |

Notes: (a) DynamoDB signals most client faults as HTTP `400` with `__type` discriminator — hosts map by `__type`, never by status alone. (b) The Slice-1/Slice-2 abort format, `set_abort_on_error` semantics, retry policy (429/5xx exponential backoff), and redaction rules apply unchanged.

---

## 6. Decisions (D1–D7)

1. **Key layout as create-time choice:** `table_create(name)` = partition-key-only; `table_create(name, sorted:bool)`. Key attribute names are fixed logicals (`pk`, `sk`); users never name key attributes. (`Decided`: overload form, matching Slice-1/2 flat-style; alternative `table_create_sorted` rejected for symmetry with `object_put` overloads.)
2. **`version()` is an opaque, random-per-write provider string** (§4.4), **not** a portable integer or counter — Azure/Firestore/OCI pass through provider tokens; DynamoDB stamps a fresh `__lmcloud_v` UUID-hex per logical write (retry-identical). No cross-worker counter arithmetic, no ABA after delete/recreate.
3. **Conditional put via single 3-arg overload** with `expect_version == ""` meaning only-if-absent; the adapter interface carries explicit `Unconditional`/`IfAbsent`/`IfVersion` modes (09-hostkit.md v5 plan). Conditional classification on AWS uses `ReturnValuesOnConditionCheckFailure=ALL_OLD` (certify in sim, A3); ambiguity falls back to bounded probe → `INTERNAL`. Conditional `item_update` excluded in v1.
4. **Scan is unordered + bounded** (`max_items <= 500`, default `100`) and **eventual-everywhere**; scenarios restart the full walk per poll and dedupe by key (no partial-page accumulation). Whole-table scans are not snapshots.
5. **Batch operations excluded in v1** (`BatchWriteItem`/entity group transactions/`bulkWriter` differ on atomicity: Azure EGTs are atomic-only-within-partition, DynamoDB batch is non-atomic with partial-failure items — no portable contract worth schema surface yet).
6. **Firestore mapping uses document-id key encoding** (`enc(pk)` / `enc(pk)#enc(sk)`, `#`=`0x23` sorts before every legal first key char) + `__name__`-range queries (no composite indexes); **catalog collection `lmcloudmeta`** (never `__..__`-wrapped, doc id = plain table name) is the authoritative existence/layout registry including empty tables (§3.5).
7. **OCI is explicitly pending** for Slice 5 (§9): no half-mapped surface ships; OCI joins when the ocisim NoSQL epic (O1) lands.
8. **Strong point/partition reads are portable and required** (`ConsistentRead=true` DynamoDB; native strength Azure/Firestore; `ABSOLUTE` OCI), so immediate get/query assertions in conformance are contractual; scans and lists remain poll-bounded (§4.5).
9. **`table_create` waits for usable state** (≤60 s `DescribeTable`-ACTIVE poll on DynamoDB/OCI; synchronous catalog claim on Azure/Firestore); `table_delete` = accepted, disappearance polled (§4.5).
10. **DynamoDB range = `BETWEEN`(inclusive) + host trim of `sk == sk_to`**, with host-bound tokens advancing past trimmed rows (§4.3), because DynamoDB's KeyConditionExpression grammar admits one sort-key condition and `BETWEEN` is inclusive-both.

## 7. Consistency With Existing Slices

- Schema identity rules (design 02 §1.1): `lmcloud.dsl.json` stays raw domain-only; the four hosts embed byte-identical bytes; CI `cmp -s` gate unchanged.
- Endpoint precedence: `"tables"` slots into design 02 §3.3 (env: `LMCLOUD_TABLES_ENDPOINT`, `LM<PROVIDER>_TABLES_ENDPOINT`, then natives `AWS_ENDPOINT_DYNAMODB`/`AWS_ENDPOINT_URL`, `AZURE_TABLES_ENDPOINT`/`AZURE_STORAGE_ENDPOINT`, `FIRESTORE_EMULATOR_HOST`, `OCI_NOSQL_ENDPOINT`/`OCI_ENDPOINT`).
- Ownership/ledger/cost: hosts apply the existing run-owned naming/ledger discipline; tables carry no extra cost categories on sims; on live clouds this slice is metadata-and-item I/O only (PAY_PER_REQUEST/on-demand where the provider requires a capacity mode — capacity/billing mode parameters are excluded, §8).

## 8. Deliberately Excluded From Slice 5

1. Secondary indexes (GSI/LSI), projection queries, and non-key filtering (`FilterExpression`).
2. TTL / time-to-live attributes. 3. Streams / change feeds / CDC. 4. Transactions (`TransactWriteItems`, Azure EGT, Firestore multi-doc transactions). 5. Batch/bulk write APIs (§6 D5). 6. Unicode/arbitrary key strings (key charset `^[A-Za-z0-9._~-]{1,255}$`). 7. Nested lists/maps, binary, explicit null attribute values. 8. Strong/consistency-level options (portable floor is eventual). 9. Capacity & billing mode knobs (`PROVISIONED`, RU/s, storage caps) — sims accept on-demand defaults. 10. Cross-partition sorted queries / `begins_with` on `sk` alone. 11. Cosmos DB NoSQL as a distinct Azure backend (Table Storage is the Azure mapping; Cosmos Table API is wire-compatible and noted only). 12. `table_describe` (key layout introspection) — `table_create` CONFLICT covers the mismatch case in v1.

## 9. OCI Pending Plan (explicit)

- **State:** `ocisim` (floci-oci 0.5.0) has no NoSQL service (verified §3.3); `lmoci` pins no `oci-java-sdk-nosql`.
- **Plan:** upstream epic **O1** in `floci-oci`: in-process `20190828` NoSQL plane (`CreateTable`/`DeleteTable`/`ListTables` + row `Put/Get/Delete`+conditional ops + paginated `Query`/`Scan`), Quarkus JAX-RS following the existing `services/queue` pattern, with `OciPolicyEngine.java` resolver extension so it participates in `--auth enforce`. Stop-gap alternative (only if O1 stalls): `lmmock` scripted SAM handler fronting ocisim — rejected as default because a scripted mock cannot keep pagination/conditional-write fidelity.
- **Conformance today:** `tests/capabilities.conf` marks `lmoci` `tables=pending(oci-nosql-epic)`; every tables scenario enumerates as `ok N - tables/NN-... # SKIP oci-nosql-epic` for OCI runs — the slice is never silently partial.
