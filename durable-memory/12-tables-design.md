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
| `set_string` | `(name: string, value: string) -> self` | Sets attribute `name` to a UTF-8 `string` (empty strings allowed, verified portable). |
| `set_int` | `(name: string, value: int) -> self` | Sets attribute `name` to a 64-bit signed integer (maps to DynamoDB `N`, Azure `Edm.Int64`, Firestore `integerValue`, OCI NoSQL `LONG`). |
| `set_number` | `(name: string, value: float) -> self` | Sets attribute `name` to a finite IEEE-754 double (maps to DynamoDB `N`, Azure `Edm.Double`, Firestore `doubleValue`, OCI NoSQL `DOUBLE`). **NaN / ±Inf fail pre-flight** (`INVALID_ARGUMENT`). |
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
| `lmcloud` sorted table | `KeySchema=[pk HASH, sk RANGE]` | `PartitionKey=pk`, `RowKey=sk` | document id `enc(pk) + "#" + enc(sk)` (single flat collection, `#` sorts before any legal sk; ordering & ranges via `__name__`) | *pending* |
| Key-layout detection for `table_create` CONFLICT | `DescribeTable.KeySchema` (authoritative) | host-owned meta entity (§3.5) | host-owned meta doc (§3.5) | *pending* |
| `version()` | reserved numeric attribute `__lmcloud_v` incremented under `ConditionExpression` on every write | `odata.etag` per entity | document `updateTime` | *pending* |

### 3.2 Operation Mapping Table

| `lmcloud` | AWS DynamoDB | Azure Table Storage | GCP Firestore (gRPC) | OCI NoSQL |
|---|---|---|---|---|
| `table_create(name)` / `(name, sorted)` | `CreateTable` (`AttributeDefinitions` `pk[,sk]` S; `KeySchema` HASH[, RANGE]; `BillingMode=PAY_PER_REQUEST`); `ResourceInUseException` → `DescribeTable` compare → `false` or `CONFLICT` | `POST /{acct}-table/Tables {"TableName":name}` (`201` → `true`; `409 TableAlreadyExists` → meta compare → `false`/`CONFLICT`) | implicit on first doc / meta-doc create (§3.5); exists → meta compare → `false`/`CONFLICT` | *pending* |
| `table_delete(name)` | `DeleteTable` (`ResourceNotFoundException` → `false`) | `DELETE /{acct}-table/Tables('{name}')` (`204` → `true`; `404` → `false`) + delete meta entity | delete meta doc + delete docs discovered by `listDocuments` (bounded loops; empty-after-delete tolerated) | *pending* |
| `table_exists(name)` | `DescribeTable` (`200`/`ResourceNotFoundException`) | `GET /{acct}-table/Tables('{name}')` or meta-entity `GET` | meta-doc `getDocument` (`5 NOT_FOUND` → `false`) | *pending* |
| `table_list()` | `ListTables` loop `LastEvaluatedTableName` | `GET /{acct}-table/Tables` loop continuation headers | `listCollectionIds` loop `nextPageToken`, filter reserved | *pending* |
| `item_put(t, item)` | `PutItem` (+ host sets `__lmcloud_v` = prev+1 via `ConditionExpression`-free read-modify? No: unconditional put = `PutItem` with fresh `__lmcloud_v` computed from last read known to the host, or atomic `ADD` trick via `UpdateItem`; see §6 decision D2) | `PUT` (replace) `/Customers(PartitionKey=…,RowKey=…)` (upsert; ETag refreshed) | `updateDocument` full field replace (precondition none) | *pending* |
| `item_put(t, item, "")` only-if-absent | `PutItem` `ConditionExpression="attribute_not_exists(pk)"`; `ConditionalCheckFailedException` + probe → `CONFLICT` | `POST /{table}` insert-only: `409 EntityAlreadyExists` → `CONFLICT` | `createDocument` (precondition exists=false): `ALREADY_EXISTS(6)` → `CONFLICT` | *pending* |
| `item_put(t, item, ver)` only-if-version | `PutItem` `ConditionExpression="__lmcloud_v = :v"`; failure + probe → `PRECONDITION_FAILED` (exists) / `NOT_FOUND` (absent) | `PUT` with `If-Match: {ver}`: `412 UpdateConditionNotSatisfied` → `PRECONDITION_FAILED`; `404` → `NOT_FOUND` | `updateDocument` with `Precondition.updateTime = ver`: `FAILED_PRECONDITION(9)` → `PRECONDITION_FAILED`, `NOT_FOUND(5)` → `NOT_FOUND` | *pending* |
| `item_get` | `GetItem` | `GET /{table}(PartitionKey=…,RowKey=…)` (`404 ResourceNotFound` → `exists=false`/OK) | `getDocument` (`NOT_FOUND(5)` → exists=false/OK; **table-missing distinction via meta** §3.5) | *pending* |
| `item_delete` | `DeleteItem` (200 whether present or not) | `DELETE` + `If-Match: *`; `404` on missing entity when table exists → OK | `deleteDocument`; `NOT_FOUND(5)` on missing doc (table exists) → OK | *pending* |
| `item_update` | `UpdateItem SET ...` with `ConditionExpression="attribute_exists(pk)"` (missing → `ConditionalCheckFailedException` + probe → `NOT_FOUND`); bumps `__lmcloud_v` | `MERGE` with `If-Match: *` (missing → `404`); partial by construction | `updateDocument` with field mask + `Precondition.exists=true` (missing → `NOT_FOUND(5)`) | *pending* |
| `item_query(t, pk[, range, max, token])` | `Query` `KeyConditionExpression="pk = :p"` (+ `sk >= :a AND sk < :b`), `Limit=max_items`, `ExclusiveStartKey=token`, `ScanIndexForward=true` | `$filter=PartitionKey eq 'pk' [and RowKey ge 'a' and RowKey lt 'b']`, `$top=max_items`, continuation headers as token | `runQuery` structured: `__name__ >= start AND __name__ < end` on collection `{name}`, `orderBy __name__`, limit/offset cursor token | *pending (epic must include runQuery)* |
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

### 3.5 Key-Layout Discovery & Reserved Meta Storage (M6)

Providers differ on whether table key layout is discoverable server-side:
- **AWS DynamoDB:** `DescribeTable.KeySchema` is authoritative (no meta needed).
- **Azure Table Storage & GCP Firestore:** layouts are client conventions, so the hosts persist a **reserved meta record per table** (`sorted: bool`, plus future slice flags):
  - Azure: entity in reserved table **`lmcloudmeta`** (`PartitionKey="tables"`, `RowKey=<name>`; created lazily, upserted by `table_create`, read by `table_create`/`item_query` pre-flight, deleted with the table). `table_list` filters `lmcloudmeta` (it matches the §4.1 naming rule but is reserved).
  - GCP: document in reserved collection **`__lmcloud_meta__`**, doc id `tables/{name}`; `table_list` (= `listCollectionIds`) filters names starting `__lm`.
- **OCI NoSQL:** pending; when implemented upstream, table DDL carries key columns, so `DescribeTable`-equivalent is authoritative (no meta).

### 3.6 Sim Enhancements Required (details + evidence in [`13-tables-conformance.md`](13-tables-conformance.md) §3)

- **A1 `awssim`:** optional — verify `TagResource`-on-create and `DescribeTable` in `scripts/test-auth.py` enforce matrix (map already covers all slice actions; conformance currently exercises open + enforce).
- **A2 `azuresim`:** add Table Storage routes to `StorageAuth.java` action mapping (`/{account}-table` prefix → `Microsoft.Storage/storageAccounts/tableServices/tables/entities/*` style actions) so `--auth enforce` table traffic works; add entity `If-Match`/`$top` continuation coverage to `scripts/test-storage.py`. (Cosmos NoSQL embedded engine exists upstream but is **not** targeted by this slice.)
- **G1 `gcpsim`:** certify the Firestore **gRPC** subset used here (`get/create/update/delete/listDocuments/listCollectionIds/runQuery` incl. `__name__` ordering and cursor pagination) in `scripts/`; **G2:** extend `PermissionFilter.java` with Firestore route mappings for `--auth enforce`.
- **O1 `ocisim` (upstream epic):** implement in-process OCI NoSQL `20190828` plane (tables + row CRUD + query/scan pagination) in `floci-oci`; until it lands, all OCI table runs are explicit capability SKIPs (§9; `tests/capabilities.conf`).

---

## 4. Portable Naming, Key, Value, Size, and Pagination Rules

### 4.1 Table Names & Keys (pre-flight, `INVALID_ARGUMENT`, `http_status() == 0`)

- **Table names** must match `^[a-z][a-z0-9]{2,31}$` (3–32 chars, lowercase alnum, start letter) — the intersection of DynamoDB (`3..255`, `[a-zA-Z0-9._-]`), Azure Table (`^[A-Za-z][A-Za-z0-9]{2,62}$`, **no hyphens**), Firestore collection ids (any UTF-8 sans `/`, not `.`/`..`/`__*__`), OCI NoSQL (`^[A-Za-z][A-Za-z0-9._-]{0,255}$` roughly). Conformance table names: `lmt<NN><run_id><suffix>` (alnum-only run suffix).
- **Partition key / sort key values** must match `^[A-Za-z0-9._~-]{1,255}$` each (1–255 bytes). This charset is identity-encoded on every provider (no percent-encoding needed): valid Firestore document id component, valid Azure `RowKey` (excludes `/ \ # ?`), valid DynamoDB key value. **Unicode/arbitrary keys are out of scope for v1** (§8 exclusion 6).
- **Reserved RowKey sentinel:** key-only tables map to Azure with `RowKey = "-"` (single legal character, guaranteed never to collide because a key-only table never admits a user sort key; the sim accepting *empty* RowKey is a sim-only laxness the host never relies on).
- **`sk` on `item_new`/`item_get`/`item_delete`:** empty `sk` (`""`) fails pre-flight when a sort key is expected; `sk` must not be supplied for key-only operations (arity does this).

### 4.2 Item Value Model (portable JSON subset)

- **Flat attributes only:** `name -> string | int | float | bool`. **Nested lists/maps, binary, sets, and explicit null are excluded** (Azure Table has no arrays/maps/null; common denominator). Absence of an attribute is the portable "null".
- **Attribute names:** `^[a-z][a-z0-9_]{0,62}$`; names starting `__lm` are reserved for host-managed metadata (`__lmcloud_v` on DynamoDB) and fail pre-flight.
- **Numbers:** `set_int` = exact signed 64-bit; `set_number` = finite IEEE-754 double; **NaN/±Inf rejected pre-flight**; providers may normalize the textual form (`1.50` → `1.5`), so conformance asserts with `==` for ints/bools/strings and `assert_close` for floats.
- **Empty strings** are portable (verified on DynamoDB, Azure Table; Firestore supports them).
- **Attribute count:** `<= 240` per item (Azure's `252`-property ceiling minus `PartitionKey`/`RowKey`/`Timestamp`, with margin).
- **Item size (canonical measure, testable):** `item_bytes = sum(utf8_len(name) + utf8_len(value_bytes)) + 8 * attribute_count` over all attributes; **`item_bytes <= 262144` (256 KiB)** enforced pre-flight on all hosts, where int values count as 8 bytes, float as 8 bytes, bool as 1 byte, strings as their UTF-8 byte length. (A single attribute `"v"` with a `262135`-byte value is exactly at budget; `262136` fails pre-flight — scenario 12.) Under DynamoDB's `400 KB` item cap with margin, under Azure's `1 MB` entity cap and Firestore's `1 MiB` document cap.

### 4.3 Pagination (token rules)

- `max_items`: `0` = default **`100`**; `1..500` valid; out of range fails pre-flight `INVALID_ARGUMENT`. (Provider page ceilings — DynamoDB evaluates at most `1 MB` per `Query`/`Scan` call — mean a provider page may hold fewer than `max_items` items; callers loop on `has_more()`, never assume full pages — same M7 rule as Slice 1.)
- `page_token` is an opaque host-encoded provider token (base64url of provider token or key cursor); `""` = first page; **token invariant:** `has_more() == (str_len(next_token()) > 0)`.
- Ordering: `item_query` returns ascending `sk` order within the partition; `item_scan` is **unordered** across all providers (DynamoDB `Scan` is unordered; Azure happens to be `(PK,RK)`-sorted; spec deliberately weaker).

### 4.4 Versioning & Conditional Puts (portable subset)

- Every server-stored item carries `version()` (opaque string): DynamoDB → decimal string of host-maintained `__lmcloud_v` numeric attribute (atomically bumped under the same write's `ConditionExpression`); Azure → `odata.etag`; Firestore → document `updateTime`; OCI → planned row `ETag`.
- `item_put(t, item, "")` = only-if-absent → `CONFLICT` when the item exists.
- `item_put(t, item, v)` (`v != ""`) = only-if-version → `PRECONDITION_FAILED` when the item exists with a different version, `NOT_FOUND` when absent.
- On DynamoDB both failure kinds surface as the single `ConditionalCheckFailedException`; the host issues a point `GetItem` probe after a failed conditional write to classify `CONFLICT` vs `PRECONDITION_FAILED` vs `NOT_FOUND` (documented race: an interleaved delete between the two calls yields `NOT_FOUND`, acceptable).
- `version()` is comparable only within the same provider+table+item lineage; programs must not compare versions across providers.

### 4.5 Consistency (portable floor)

- Portable guarantee = **eventual consistency**. Sims are in-process/in-memory and answer immediately; live DynamoDB is eventual by default (reads after writes may lag), live OCI NoSQL defaults to `EVENTUAL`, Azure Table and Firestore doc reads are strong.
- Conformance tests therefore assert point reads (`item_get`) directly after writes, but use **bounded poll loops** (Slice-2 M3 pattern, `<= 10` polls) for aggregate assertions (`table_list`, `item_query` counts, scan sets, post-delete disappearance). Strong-per-request read variants are deliberately excluded (§8).

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
2. **`version()` is an opaque provider string** (per §4.4), **not** a portable integer — Azure/Firestore/OCI use provider-managed ETags/`updateTime`; DynamoDB emulates with host-maintained `__lmcloud_v`. Programs treat versions as compare-only tokens.
3. **Conditional put via single 3-arg overload** with `expect_version == ""` meaning only-if-absent — avoids a fourth method name and keeps only-if-absent/only-if-version as the complete portable conditional subset; conditional `item_update` excluded in v1.
4. **Scan is unordered + bounded** (`max_items <= 500`, default `100`); no whole-table unbounded reads in v1.
5. **Batch operations excluded in v1** (`BatchWriteItem`/entity group transactions/`bulkWriter` differ on atomicity: Azure EGTs are atomic-only-within-partition, DynamoDB batch is non-atomic with partial-failure items — no portable contract worth schema surface yet).
6. **Firestore mapping uses document-id key encoding** (`enc(pk)` / `enc(pk)#enc(sk)`, `#` sorts before every legal sk char) + `__name__`-range queries, avoiding any composite-index requirement; meta collection `__lmcloud_meta__` stores key layout (§3.5).
7. **OCI is explicitly pending** for Slice 5 (§9): no half-mapped surface ships; OCI joins when the ocisim NoSQL epic (O1) lands.

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
