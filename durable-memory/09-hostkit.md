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
