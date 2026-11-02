# 09 — Shared Go host kit (`hostkit`) and the provider adapter contract

Module `github.com/lmctl-ai/lmcloud` (Go 1.26, sole dependency `lmctl-ai/lmcode-go`
pinned in `go.mod` and `sdk.lock` at `77932bf7134a`). Everything a script can observe is decided
once here; a provider port is **schema pin + adapter + endpoint/signing**.

| Package | Contents | Imports lmcode? |
|---|---|---|
| `schema` | `schema.Bytes`: the exact raw `schema/lmcloud.dsl.json` (embed). Serve it verbatim for `--lmcode-schema [--json]`. | no |
| `hostkit` | error enum + `CloudError` + abort format + `ErrorState`; `RetryPolicy`; endpoint policy (`ValidateEndpoint`, `EndpointResolver`, redirect policy, `NewHTTPClient`); redaction; validation + limits + key escaping + `ReadBounded`; queue codec; `ListAll`; `WaitLoop`, `ReceiptPrecedence`; adapter interfaces. No provider names, no globals. | no |
| `hostkit/invoke` | `ParseArgs` (`--lmcode/--first/--last`, standard manifest via `LMCODE_INVOCATION_FILE`), `Runner` (one terminal frame). Copied from lmgcp `internal/invoke` @4ba074b with attribution. | yes |
| `hostkit/cloudhost` | `Host` (all 24 Cloud methods / 27 overloads, real + dry), `Register` (every method with an explicit Dry slot), `Program.Main` (CLI). | yes |
| `hostkit/fakeadapter` | In-memory `ObjectStore`+`Queue`, optional JSON state file with flock (multi-process scenarios), enforce-mode auth, call counters. | no |
| `hostkit/cmd/lmcloud-ref` | Reference host = cloudhost + fakeadapter. `lmcloud-ref [cloud] --lmcode FILE`. | yes |

## Provider port in ten lines

```go
func main() {
	os.Exit(cloudhost.Program{
		Name: "lmxyz", Version: version, Schema: schema.Bytes,
		NewConfig: func(dry bool) (cloudhost.Config, error) {
			a, err := xyz.NewAdapter(dry) // credentials/signing; skip network setup when dry
			return cloudhost.Config{Provider: "xyz", Store: a, Queue: a,
				Endpoints: &hostkit.EndpointResolver{Prefix: "LMXYZ", Native: xyz.NativeEnv, Default: xyz.LiveEndpoints}}, err
		},
	}.Main(os.Args[1:]))
}
```

## Adapter contract (`hostkit.ObjectStore`, `hostkit.Queue`)

The host has already validated every argument (names, keys, content type, metadata, sizes,
bounds, empty receipt) and resolved + validated the endpoint, attached to `ctx`
(`hostkit.EndpointFrom(ctx)`; `""` means the provider's live default). The adapter:

1. **Returns `*hostkit.CloudError` classified onto the 8 shared codes** (`hostkit.ProviderError`).
   Anything else is reported as `INTERNAL`. Never invent codes (no UNAVAILABLE/RATE_LIMITED/ALREADY_EXISTS).
2. **Uses `hostkit.RetryPolicy` (or `DoHTTP`) for every HTTP call and disables SDK retries.** After the
   last attempt classify with `FinalStatusError` (429/5xx → `INTERNAL` with final http + provider code).
3. **Builds clients with `hostkit.NewHTTPClient`** (no env proxy, same-origin redirects only) and never
   sends ambient live credentials to a loopback override (design 02 §3.2).
4. **Reads bodies with `hostkit.ReadBounded(limit)`** — fail above the limit, never truncate.
5. **Reports NOT_FOUND only for a genuine absence**, and qualifies it with `WithAbsent(bucket|object|queue|message)`
   when the provider says which. Ambiguous "not authorized or not found" answers are `PERMISSION_DENIED`.
   If the qualifier is missing the host probes (`HeadBucket` / `LookupQueue`) to disambiguate.
6. **Never fabricates success**: no invented message IDs or receipts, no "409 means mine", no fail-open
   on undecodable 2xx bodies — return `INTERNAL`.

| Method | Must return | Host adds |
|---|---|---|
| `CreateBucket` | `(true,nil)` new; `(false,nil)` if it can prove ownership itself (e.g. probe-before-put); else `CONFLICT` | on `CONFLICT`, `HeadBucket` → accessible ⇒ `false/OK`, else `CONFLICT` |
| `DeleteBucket` | `nil`, `NOT_FOUND`, or `CONFLICT` when non-empty (add a pre-check where the provider deletes non-empty containers) | `NOT_FOUND` ⇒ `false/OK` |
| `HeadBucket` | `nil` exists; `NOT_FOUND` absent | `bucket_exists`, disambiguation probes |
| `ListBuckets`/`ListQueues` | one page + next token | `ListAll`: all pages, stall/cycle/limit ⇒ `INTERNAL`, sorted, de-duplicated |
| `PutObject` | metadata (ETag may be quoted) | size/bucket/key fill-in, ETag normalisation |
| `GetObject(limit)` | bytes ≤ limit or error | second 16 MiB check |
| `HeadObject` | metadata, or qualified `NOT_FOUND` | missing key in existing bucket ⇒ `exists()==false/OK` |
| `DeleteObject` | `nil` or qualified `NOT_FOUND` | missing key in existing bucket ⇒ OK; missing bucket ⇒ `NOT_FOUND` |
| `ListObjects(max)` | ≤ max items, next token (`""` last) | sort, token invariant, repeated-token ⇒ `INTERNAL` |
| `QueueCaps` | `LongPoll`, `TextOnlyWire` | wait loop (`WaitLoop`, 250 ms) when no long poll; `__lmcloud_b64__` envelope when text-only |
| `CreateQueue` | `(true,nil)` / `(false,nil)` | — |
| `DeleteQueue`/`LookupQueue` | `nil` / `NOT_FOUND` | `false/OK` on `NOT_FOUND` |
| `Send(wire)` | non-empty ID | encodes body with `EncodeQueueBody` (empty sentinel, `__lmcloud_` escape) |
| `Receive` | ≤ max raw messages with ID + receipt | decodes wire, rejects missing ID/receipt |
| `Ack` | `nil`; `NOT_FOUND`+`AbsentMessage` for already-gone; `INVALID_ARGUMENT` for a malformed receipt | `ReceiptPrecedence`: missing queue ⇒ `NOT_FOUND` first; re-ack ⇒ OK |
| `Nack` | the receipt valid from now on (rotated or same) | same precedence; message gone ⇒ `INVALID_ARGUMENT` |

## Dry policy (one place, `cloudhost`)

The invocation's dry flag comes only from the standard manifest (`invoke.ParseArgs`). Every Cloud
method is registered with an explicit Dry slot:
- **Mutators** (`bucket_create/delete`, `object_put/delete`, `queue_create/delete/send/receive/ack/nack`)
  never call adapter mutators. They run full validation (including body bounds) and read-only
  existence probes, and record a **dry overlay** so later reads in the same dry run see the previewed
  state (`object_get` returns the previewed body, `bucket_exists` sees the previewed bucket, lists
  merge previews). `queue_receive` previews an empty batch (receiving consumes).
- **Reads** (`*_exists`, `object_get/head/list*`, `bucket_list`, `queue_list`) are real reads merged with
  the overlay. `object_list` with no overlay changes for that bucket is the real page.
- **Local state and snapshots** (`set_endpoint`, `set_abort_on_error`, `last_error`, accessors) are identical.
- Zero mutator calls is proven by `TestDryRunMakesZeroMutatorCalls` and end to end through
  `lmscript --dry-run` (`TestDryRunThroughCompilerMakesNoMutations`).
- **SDK limitation (lmcode-go 77932bf):** `validateDryResult` has no enum case, so a dry run reaching
  `CloudError.code()` fails with `dry callback for ErrorCode returned string` (without a slot the
  dry-null comparison fails too). Needs an lmcode-go fix; scripts that inspect `.code()` cannot dry-run yet.

## Conventions

- `provider()`, `abort_on_error()`, `last_error()` do not modify `last_error`; every operation sets it.
- Abort message: `[CODE] op (target): message (http=N, provider_code=X|none)`; preflight
  `[INVALID_ARGUMENT] op: reason` with `http=0`, `provider_code=""`. Targets and messages are redacted.
- Endpoint precedence: `set_endpoint(svc)` > `set_endpoint(all)` > `LMCLOUD_<SVC>_ENDPOINT` >
  `<PREFIX>_<SVC>_ENDPOINT` > `LMCLOUD_ENDPOINT` > `<PREFIX>_ENDPOINT` > native service/global vars >
  default. Every source is validated; an invalid env value is `INVALID_ARGUMENT` naming the variable.
- Extra provider name rules plug in via `hostkit.Validator{BucketRules,QueueRules,KeyRules}` and may only narrow.

## Verification

`scripts/test-hostkit.sh` = gofmt + `go vet ./...` + `go test -race -count=3 ./...` with
`LMSCRIPT_BIN` set, which includes the reference-host e2e: conformance open mode 25/25 (2 auth
SKIP), enforce mode 25/25 (0 SKIP, allow/deny credentials via `LMCLOUD_REF_*`), dry-run zero
mutations, and schema/signature parity with `lmscript`.
With `LMCLOUD_REF_PAGE_SIZE=2`, `object-storage/07` fails because it reads all 4 keys from one 2-arg
`object_list` page; that scenario assumes a provider page holds ≥4 keys (spec M7 allows short pages).

## hostkit v2 (branch `hostkit-v2`) — additive changes from the lmoci port

All existing exported identifiers keep their names and signatures; v2 only adds. Two behaviour
changes are deliberate and listed under "Behaviour changes".

### Additions
| Package | Addition | Purpose |
|---|---|---|
| `hostkit` | `NilIfTyped(err) error` | A typed-nil `*CloudError` returned through `error` is success. `AsCloudError` uses it; `cloudhost` wraps every adapter so all adapter errors pass through it. |
| `hostkit` | `Router{Pick}`, `Backend`, `EndpointRoutes{Offline,Sim,Live,UseLive,Unavailable}.Pick`, `CapsFor` | One forwarding implementation of both adapter interfaces; a port writes one `Pick` instead of 17 routing methods. `EndpointRoutes`: no endpoint → Offline (or Live when `UseLive()`), loopback → Sim, other → Live; a missing backend returns `Unavailable(route)`. |
| `hostkit` | `QueueCapsProvider{QueueCapsFor(ctx, queue)}` | Per-call/per-queue caps; preferred over the global `QueueCaps()` (kept). `Router` implements it from the routed backend. |
| `hostkit` | `BucketCreationTimer`, `QueueCreationTimer` | Optional creation times to resolve CONFLICT-after-our-own-create (below). |
| `hostkit` | `Attempt.NotSent`, `RequestNotSent(err)`, `IdempotentMethod(method)` | Retry safety for non-idempotent requests. |
| `hostkit` | `ReadBoundedResponse(resp, limit)` | `ReadBounded` that records the response status in the error. |
| `hostkit/invoke` | `Hooks.AfterRun` | Runs after each slot's `Program.Run` (watchdog stopped). |
| `hostkit/cloudhost` | `Program.Hooks`, `Program.Init`, `Program.Help`, `Program.Notices`, `Program.Commands`; `Signatures(withoutStd)` | `Main` now handles no args/`--help`/`-h`, `--version`/`-V`, `--notices`, `--lmcode-schema [--json]`, `--lmcode-signatures [--without-std]`, host commands, and a leading `cloud` word. `Init` (e.g. memory budget) failing is CLI_USAGE exit 2. |

### Behaviour changes
1. **Retry idempotency.** `RetryPolicy.Do/DoHTTP(ctx, idempotent, …)`: the bool now governs
   *all* retries, not only transport errors. 429 is always retried (refused before processing);
   500/502/503/504 and in-flight transport errors only when `idempotent`; transport errors with
   `NotSent` (dial/DNS failure) always. Pass `IdempotentMethod(req.Method)`; pass `true` for a POST
   only when it carries a client token the provider de-duplicates (e.g. an idempotency key on a
   message send). Before v2 a POST create was retried on 5xx and could turn a server-side success
   into a 409.
2. **Create idempotency decision.** When `CreateBucket`/`CreateQueue` reports CONFLICT and the
   resource is accessible (`HeadBucket`/`LookupQueue`), the host returns `created=true` only if the
   adapter implements the creation timer and the server-side creation time is at or after the start
   of this call (an earlier attempt of the same call committed). Otherwise — no timer, timer error,
   older creation time — it returns `false` ("already existed"): the host never claims a create it
   cannot prove. Server/client clock skew can only turn a true into a false. `CreateQueue` CONFLICT
   for a queue that is not accessible stays CONFLICT (previously any queue CONFLICT failed).

### Port checklist (v2)
- Replace hand-written routing with `hostkit.Router{Pick: hostkit.EndpointRoutes{...}.Pick}`.
- Return per-route caps with `QueueCapsFor` when backends differ (e.g. offline fake vs long poll).
- Build requests with `DoHTTP(ctx, client, hostkit.IdempotentMethod(method), …)`.
- Implement `BucketCreatedAt`/`QueueCreatedAt` when the provider reports creation times.
- Move CLI extras into `Program{Hooks, Init, Help, Notices, Commands}`.
- After the lmcode-go pin includes `Registry.Enum` (proposed patch below), `cloudhost.Register`
  should declare `reg.Enum("ErrorCode", codes)` so dry runs can evaluate `last_error().code()`.

### lmcode-go dry enum limitation — proposed patch
Repro (lmcode-go 77932bf): a host callback whose return type is an enum returns the constant
name as a string (the wire form). In a dry run `validateDryResult` accepts only primitives or
objects, so a `Dry` callback returning `String("OK")` for `ErrorCode` fails with
`dry callback for ErrorCode returned string`; without a slot the dry-null dummy cannot be compared
with `ErrorCode.OK`. Proposed patch (not pushed): `Registry.Enum(name, values)` declares a schema
enum; a dry result for a declared enum must be one of its constant strings; the no-slot dummy is
the first constant; undeclared types stay strict. Branch `dry-enum-string` commit `23ff76b` in the
scratch clone `lmcode-go-dryenum`, patch file `lmcode-go-dry-enum-patch/0001-*.patch`, with tests
`dry_enum_test.go`; `go test -race ./...` passes there.

> **Update (v0.1.0):** `Registry.Enum` is merged upstream (lmcode-go `06cd9ae`, PR #1). hostkit's `go.mod`
> now pins that commit and carries NO `replace`; hosts must also drop their `replace` of lmcode-go
> (and, once they require a tagged `github.com/lmctl-ai/lmcloud`, their `replace` of lmcloud). The v3
> text below describing the temporary local patch is kept for history.

## hostkit v3 (branch `hostkit-v3`) — SolReviewer cross-host review, risks 7–10

Additive again: no exported identifier was renamed or removed. Deprecated (kept, no longer used by
the host): `BucketCreationTimer`, `QueueCreationTimer`.

### 1. Dry runs can evaluate `last_error().code()` (risk 7) — needs a go.mod line in every host
`cloudhost.Register` declares `ErrorCode` through lmcode-go `Registry.Enum` when the linked SDK has
it (interface assertion; `cloudhost.EnumsDeclared()` reports it). Upstream lmcode-go 77932bf does
not, so hostkit's go.mod carries a **temporary** replace to `../lmcode-go-patched` (a clone of the
unpublished branch `dry-enum-string`, commit 23ff76b, proposed patch from v2).
**Replace directives do not propagate to dependents.** Each host that wants the fix adds, next to its
existing `replace github.com/lmctl-ai/lmcloud => ../lmcloud`:

```
// TEMPORARY: lmcode-go Registry.Enum (dry enum results) is not published yet.
// Remove when it is merged upstream and the lmcode-go pin is bumped.
replace github.com/lmctl-ai/lmcode-go => ../lmcode-go-patched
```

Without it the host still builds (hostkit calls `Enum` only if present) and keeps the old
limitation: a dry run reaching `last_error().code()` fails with
`dry callback for ErrorCode returned string`. **Removal condition:** when `Registry.Enum` (or an
equivalent enum-aware dry check) is merged into github.com/lmctl-ai/lmcode-go and the lmcode-go pin
in hostkit and every host go.mod + sdk.lock is bumped to a commit that contains it, delete the
replace lines; `EnumsDeclared()` then becomes true everywhere without local patches.

### 2. Offline receive timing follows the route (risk 8)
- `fakeadapter.Options.LongPoll` (honour `waitSeconds` inside Receive), `BinaryWire`, `PollInterval`;
  the fake implements `QueueCapsFor`. Default caps stay short-poll/text-only, so the host's
  `WaitLoop` makes an empty offline `queue_receive(q, 1, 1, 30)` take ~1 s.
- With `Router{Pick: EndpointRoutes{Offline: fake, Sim: ..}.Pick}` the caps of the **routed**
  backend are used per call. Hosts must not advertise their remote route's `LongPoll=true` from a
  global `QueueCaps()` while routing to the fake (Sol: OCI/AWS/GCP did); use `Router`/`QueueCapsFor`.
- `WaitLoop` now returns an INTERNAL error when its context ends before the requested wait;
  earlier versions turned a cancellation into an empty successful receive.

### 3. Dry previews are scoped per endpoint (risk 9)
The dry overlay is keyed by the per-service resolved endpoint attached to ctx (`""` = offline/live
default route). A preview at endpoint A is invisible at B and still visible when switching back to A.
Provider scope that is not part of the endpoint (account/project chosen by env) is not separated.

### 4. Create ownership after CONFLICT: token proof only (risk 10)
v2 accepted "server creation time ≥ call start" as proof; that is unsound (a server clock ahead of
the client, or a concurrent creator, satisfies it). **v3 decision:** when `CreateBucket`/`CreateQueue`
returns CONFLICT and the resource is accessible, the host returns `created=true` **only** if the
adapter implements `BucketCreateTokenReader`/`QueueCreateTokenReader` and reads back this call's
`hostkit.CreateToken(ctx)` — a random 128-bit token the host attaches per call, which the adapter
must store **atomically in the create request itself** (tag/label/metadata of the create call). Any
other case — no reader, read error, missing or different token — returns `false`. Timers are ignored.

Provider notes (adapter work, not done in hostkit): GCS bucket labels, S3 `CreateBucket` has no tag
parameter (tagging is a second request, so it is NOT atomic — S3 cannot prove), Azure container
metadata on `PUT ?restype=container` (atomic), OCI `freeformTags` in `CreateBucket`/`CreateQueue`
body (atomic); SQS `CreateQueue` tags (atomic), Pub/Sub labels on topic/subscription create.

**Limitation vs spec.** Design 02 §2.1 says `bucket_create` returns `true` "if newly created". With a
lost reply after a committed create (or a retried create), a host whose provider cannot store an
atomic token will return `false` although this call created the bucket. Nothing is lost (the bucket
exists, `last_error` is OK), but the boolean is "created and proven by this call".
**Proposed amendment to design 02 §2.1 / §6.1 (for the design owner, not applied):**
> `bucket_create`/`queue_create` return `true` when this call is known to have created the resource:
> a direct success response, or — after a conflict — a provider-stored creation token written by this
> call. A conflict on an accessible resource without such proof returns `false` with `ErrorCode.OK`.
> Scripts must not treat `false` as "someone else created it"; use it only as "no new resource was
> proven".

### 5. Error-typed bounded reads
`ReadBoundedErr(r, limit)` and `ReadBoundedResponseErr(resp, limit)` return `([]byte, error)` with a
nil interface on success. **Footgun:** `ReadBounded`/`ReadBoundedResponse` return `*CloudError`;
`data, e := ReadBounded(..); return data, e` in a function returning `error` is a non-nil error on
success. Use the `Err` variants in adapter methods (hostkit still neutralises typed nils at the
boundary via `NilIfTyped`).

### 6. HTTP guard rails
- `NewHTTPClient(timeout)` is the constructor to use (pass it to provider SDKs); `timeout<=0` now means
  `DefaultHTTPTimeout` (60 s).
- `EnforceClient(c)` returns a hardened copy of any client (same-origin redirects only, a timeout, no
  environment proxy). An existing `CheckRedirect` is kept and runs after the same-origin check, so an
  adapter's stricter hook (lmazure strips `Authorization` on every redirect) still applies. **`DoHTTP` applies it to every client it is given**, so an adapter that builds
  its own `http.Client` cannot forward credentials cross-origin through `DoHTTP` by accident. SDK
  pipelines that bypass `DoHTTP` must be given `NewHTTPClient`/`EnforceClient` explicitly.
- `hostkit/httpguard`: fault-injecting loopback server for adapter tests —
  `New(t)`, `Script(steps...)`, steps `Status`, `RetryAfter`, `Oversize`, `Delay`, `RedirectTo`,
  `HangUp` (request received, connection closed: a possibly committed POST), and
  `Requests/Count/AssertCount/AssertNoCredentials`. hostkit's own HTTP path is tested with it: 503
  retried 3×, POST 429 retried, POST 5xx and post-commit hang-up not retried, PUT hang-up retried,
  deadline, oversize with http status, cross-origin redirect refused for hostkit, plain and nil
  clients with no credentials reaching the foreign origin.

### Also fixed
`Router` rejects a typed-nil backend from `Pick` (error instead of a panic).

### Verification (v3)
`scripts/test-hostkit.sh` (gofmt, vet, `go test -race -count=3 ./...` incl. reference-host conformance
25/25 open + 25/25 enforce and a compiler dry run evaluating `last_error().code()`), plus a four-host
proof on scratch copies of each host's `hostkit-port` branch with only the two replace lines changed
(lmcloud → hostkit-v3 worktree, lmcode-go → lmcode-go-patched): build, vet, `go test -race`, and an
`lmscript --dry-run` whose program compares `last_error().code()` with `ErrorCode` constants
(`{"dry":true,"ok":true}`). Without the lmcode-go replace every host still builds and shows the old
`dry callback for ErrorCode returned string`. Invoke hosts as `HOST cloud --lmcode FILE` (lmgcp's
top-level schema is not the shared one).

## hostkit v4 (branch `hostkit-v4`) — create tokens never reach diagnostics

SolReviewer (sol-final risk 5): provider errors can echo the create token (e.g. in a message that
quotes the request's tags), and `last_error`/abort text carried it on all four hosts. v4 adds one
central redaction; tokens stay fully usable inside adapters (`hostkit.CreateToken(ctx)` unchanged,
same 32-hex format, so host tag/label code is unaffected).

- **Format redaction (all diagnostics):** `RedactText` — used by every `CloudError` constructor
  (`ProviderError`, `Preflightf`, `AsCloudError`), `FormatAbort` and `ErrorState.Fail` — and
  `RedactURL`/`RedactTarget` replace any 32-hex token-format string with `[create-token]`
  (`hostkit.CreateTokenMarker`, `hostkit.RedactCreateTokens`). Side effect: other 32-hex values in
  error text (an MD5-style ETag or request id) are replaced too; error text is diagnostic only.
- **Exact redaction (last_error and aborts):** `ErrorState.AddRedaction(secret)` registers exact
  strings (cloudhost registers each create token it issues, bounded to the last 256). `Fail` replaces
  them in message, provider_code, op and target before storing `last_error` and formatting the abort
  message, so an echo in a non-hex form (encoded, prefixed, adapter-built struct literal) is caught too.
- `fakeadapter.Options.EchoCreateToken` (and `LMCLOUD_REF_ECHO_TOKEN=1` on the reference host) makes
  creates fail with the token in message and provider code, bypassing the constructors.
- Tests: hostkit unit (format + exact + bounded list + constructors), cloudhost (bucket and queue,
  non-abort and abort), reference-host end-to-end through lmscript (`message()`, `provider_code()`,
  abort frame contain `[create-token]`, no 32-hex string anywhere in the output).
- Not covered: provider-side copies (the token is a tag/label/metadata value on the resource,
  visible to anyone authorized to read it), and adapter-private logging outside hostkit.

## hostkit v5 (planned, design only — DO NOT implement) — Slice 5 `Tables` adapter

Design doc: `12-tables-design.md`. Additive again: no existing identifier changes; the `Tables`
adapter interface sits next to `ObjectStore` and `Queue`, and `Router`/`EndpointRoutes` gain a
`Tables` route the same way. Planned shape:

```go
type Tables interface {
    CreateTable(ctx, name string, sorted bool) (created bool, err error) // CONFLICT only on layout mismatch (host probes)
    DeleteTable(ctx, name string) error                                   // NOT_FOUND -> false/OK
    HeadTable(ctx, name string) error                                     // nil / NOT_FOUND
    ListTables(ctx, max int, token string) (names []string, next string, err error) // ListAll applies
    PutItem(ctx, t string, it Item, expect string) (stored Item, err error)         // expect=="" absent; else version
    GetItem(ctx, t, pk, sk string) (Item, error)                          // NOT_FOUND item -> AbsentItem-qualified
    DeleteItem(ctx, t, pk, sk string) error                               // idempotent within existing table
    UpdateItem(ctx, t, pk, sk string, changes Item) (Item, error)         // NOT_FOUND on missing item
    Query(ctx, t, pk, skFrom, skTo string, max int, token string) (TablePage, error) // half-open range, asc sk
    Scan(ctx, t string, max int, token string) (TablePage, error)         // unordered, bounded
}
```

- `Item` = hostkit value type: `map[string]Attr` with `Attr{S *string, I *int64, N *float64, B *bool}`,
  plus `PK/SK/Version` strings and `Exists bool`. Validation (name/attr regexes, key charset, NaN/Inf,
  240-attr and 262144-byte canonical budget with the 8-byte-per-attr rule) lives in hostkit pre-flight,
  identical across providers — adapters receive only valid values.
- Version plumbing: adapters for Azure/Firestore/OCI pass through the provider token; **DynamoDB**
  adapters maintain `__lmcloud_v` (atomic bump under `ConditionExpression`) and classify
  `ConditionalCheckFailedException` via a point `GetItem` probe (design 12 §4.4).
- Key-layout state: DynamoDB via `DescribeTable`; Azure/Firestore read a reserved meta record
  (`lmcloudmeta` table entity / `__lmcloud_meta__` collection doc) — fakeadapter keeps it in memory;
  the host lists filter reserved names (`table_list`).
- Pagination tokens: reuse the existing opaque-token helper (`ListAll` + token invariant);
  `max_items` bounds (`0..500`, default 100) enforced once in `cloudhost`.
- Dry runs: table/table-item mutators get explicit Dry slots with overlay previews (same pattern as
  buckets/queues); `item_query`/`item_scan` merge overlays over real pages.
- Conditional-write abort codes: missing item under only-if-version = `NOT_FOUND`; existing with wrong
  version = `PRECONDITION_FAILED`; only-if-absent on existing = `CONFLICT` (all probe-backed, no invented codes — contract rule 6).
- Cost ledger: add `tables` category entries so the cross-cutting slice can meter per-op estimates.
- Verification additions to `scripts/test-hostkit.sh`: conformance `tables` 14/14 open on the
  reference host, auth scenario 14 against fakeadapter enforce mode (allow/deny credentials), and a
  dry-run zero-mutator proof for the 14 programs.
