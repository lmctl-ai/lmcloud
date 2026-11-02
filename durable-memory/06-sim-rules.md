# 06 — Shared Simulator Rules (`sim_rules_v1`) & `lmmock` Front-Proxy Evaluation

*(Design by SolReviewer from `scratchpad/sim-rules-design.md`, adopted by Lead; with `lmscript` `.dslb` compilation status and `lmctl-ai/lmmock` evaluation note.)*

All APIs below are proposals unless identified as existing.
Reference paths: `C=/home/ubuntu/cloud`; `R=/tmp/claude-1000/-home-ubuntu-cloud/63980a51-1418-4bdf-becd-29d8f0bb5418/scratchpad/ref`.

## 1. Evidence and Choice

- **Follow `lmmock`'s startup binding and selected-entry dispatch, not wholesale HTTP replacement:** `R/lmmock/README.md:49–99`; `internal/mock/mock.go:81–133, 189–209`; `internal/mock/schema.json:298–308`.
- **Single-registration startup body:** Its body registers routes once; duplicate annotations, missing bindings, or wrong interfaces fail startup; each request calls its selected entry index. Faults use counters, delay, and disconnect; state survives across requests (`examples/faults.lms:1–20`; `examples/stateful.lms:1–13`).
- **SAM is a schema signature, not a Java interface implementation:** Annotation duplicates are language-legal, so the simulator must reject ambiguous bindings (`R/lmcode/spec/schema.md:120–144`; `language.md:395–424`; `grammar.md:31, 104`; `bytecode.md:79–102`).
- **Go sample reference:** Demonstrates independent entries, including never-called and duplicate annotations (`examples/rule-entries.lms:1–24`); `main.go:130–165` dispatches; `host.go:76–86, 245–250` registers explicit typed callbacks.
- **Java runtime (`lmcode-java`) inspected at `HEAD=8b2d16312dea695492b8213e52df46fb031f5960`:** `Program.java:21–35, 79–85` exposes `entries()` and `call(index, Context, Registry, List<Value>)`, validates schema SHA, and binds imports.
- **Worker isolation requirement (`Registry.java`):** `Registry.java:3–5, 18, 26–40` uses callbacks without reflection or dynamic loading, **but prohibits overlapping runs on one `Registry`**. Use an isolated loaded `Program` + `Registry` per bounded worker; never share one bound program across concurrent workers.
- **SDK pin convergence:** `lmaws/sdk.lock:1–6` and `lmoci/sdk.lock:1–6` pin an older `3ff5ca5e` commit; source embedding is established (`lmaws/pom.xml:5`; `lmoci/pom.xml:147–176`). Do not assume that older pin has every inspected `HEAD` behavior; choose and verify one new common pin.

---

## 2. Contract and Selection

- **One byte-identical schema:** Ship one byte-identical `sim_rules_v1` schema with every simulator binary; provider differences live in Java adapters. Export via `<sim> serve --rules-schema` (prints schema and exits).
- **Client/server independence:** Rules are independent of the `lmcode` cloud-client program: the client talks HTTP; the simulator runs its own compiled `.dslb`.
- **Startup registration:** Startup body calls `bind(phase, service, operation, annotation)`; `phase` is `"before"` or `"after"`, `service` and `operation` are canonical identifiers or `"*"`. No Go `ServeMux` semantics are copied.
- **Canonical starter identifiers:**
  - Services: `object`, `queue`, `table`
  - Operations: `object.bucket.create`, `object.write`, `object.read`, `object.list` (and queue/table equivalents as slices roll out)
  - Expose `native_service` / `native_operation` separately on `Request`.
- **Specificity resolution:** Resolve once per request: exact `service`+`operation` > exact `service` > global (`"*"`); reject duplicate equal-specificity selectors at startup. A binding selects **ONE** annotation and **ONE** phase; never run all entries, and never run both a `before` and an `after` entry on one request.
- **Pass-through defaults:** Unmatched requests pass through. A `before` rule returning without a terminal action passes; an `after` rule returning preserves the response. To combine behaviors, put them in the selected function or inline helpers.
- **Execution boundaries & auth invariants:**
  - `before` runs after authentication/authorization and route metadata resolution, before handler side effects.
  - `after` runs before response commitment, including tagged auth aborts. `after` does not undo handler side effects.
  - A `before` binding on an auth-rejected request is skipped. An `after` binding may change only a tagged authorization denial into another denial (e.g., OCI `403`→`404`); authentication failures and denial→success transitions are immutable.
  - Bindings are startup-only; request methods/state/clock are request-only. Compile-time schema typing plus host phase checks enforce these boundaries.

---

## 3. `dsl.schema` 2 JSON Sketch (`sim_rules_v1`)

This is a valid JSON shape, intentionally compact; method overload arrays and named SAM parameters follow `R/lmcode/spec/schema.md:26–37, 63–78`:

```json
{
 "dsl.schema":2,"name":"sim_rules_v1",
 "types":{
  "Exchange":{"methods":{
   "request":[{"params":[],"returns":"Request"}],"response":[{"params":[],"returns":"Response"}],
   "state":[{"params":[],"returns":"State"}],"clock":[{"params":[],"returns":"Clock"}],"random":[{"params":[],"returns":"Random"}],
   "pass":[{"params":[],"returns":"void"}],"delay":[{"params":["int"],"returns":"void"}],
   "throttle":[{"params":["int"],"returns":"void"}],"not_found":[{"params":[],"returns":"void"}],
   "denied":[{"params":[],"returns":"void"}],"server_error":[{"params":[],"returns":"void"}],
   "drop_connection":[{"params":[],"returns":"void"}],"page_cap":[{"params":["int"],"returns":"void"}]
  }},
  "Request":{"methods":{
   "method":[{"params":[],"returns":"string"}],"path":[{"params":[],"returns":"string"}],"raw_path":[{"params":[],"returns":"string"}],
   "header":[{"params":["string"],"returns":"string"}],"query":[{"params":["string"],"returns":"string"}],"body":[{"params":[],"returns":"string"}],
   "service":[{"params":[],"returns":"string"}],"operation":[{"params":[],"returns":"string"}],
   "native_service":[{"params":[],"returns":"string"}],"native_operation":[{"params":[],"returns":"string"}],
   "account":[{"params":[],"returns":"string"}],"tenant":[{"params":[],"returns":"string"}],"region":[{"params":[],"returns":"string"}],
   "identity":[{"params":[],"returns":"Identity"}],"resource_key":[{"params":[],"returns":"string"}]
  }},
  "Identity":{"methods":{"principal":[{"params":[],"returns":"string"}],"verified":[{"params":[],"returns":"bool"}],"auth_mode":[{"params":[],"returns":"string"}]}},
  "Response":{"methods":{
   "status":[{"params":[],"returns":"int"},{"params":["int"],"returns":"void"}],"code":[{"params":[],"returns":"string"}],
   "header":[{"params":["string"],"returns":"string"}],"body":[{"params":[],"returns":"string"}],
   "set_header":[{"params":["string","string"],"returns":"void"}],"remove_header":[{"params":["string"],"returns":"void"}],
   "replace":[{"params":["int","string","string"],"returns":"void"}]
  }},
  "State":{"methods":{
   "increment":[{"params":["string"],"returns":"int"}],"get_int":[{"params":["string","int"],"returns":"int"}],
   "put_int":[{"params":["string","int"],"returns":"void"}],"get":[{"params":["string","string"],"returns":"string"}],
   "put":[{"params":["string","string"],"returns":"void"}],"erase":[{"params":["string"],"returns":"void"}]
  }},
  "Clock":{"methods":{"now_ms":[{"params":[],"returns":"int"}]}},
  "Random":{"methods":{"uniform":[{"params":["int"],"returns":"int"}]}}
 },
 "functions":{"bind":[{"params":["string","string","string","string"],"returns":"void"}]},
 "context":{},"enums":{},"conversions":[],
 "interfaces":{
  "Interceptor":{"params":[{"name":"x","type":"Exchange"}],"returns":"void"},
  "Responder":{"params":[{"name":"x","type":"Exchange"}],"returns":"void"}
 }
}
```

### Read, Mutation, Action, State, Clock & Determinism Rules
- **Read access:** `Request` is an immutable snapshot; decoded `path` and `raw_path` remain distinct; `body` is a byte-preserving string, lazily buffered/replayed. `resource_key` is a collision-free `provider/account/tenant/container/key` identifier.
- **Headers & query:** Headers are case-insensitive, query is decoded; scalar getters return first value or `""`; **production schema should add `count`/`at` accessors for repeated header/query values before freezing v1**. Redact `Authorization`/cookies/signatures; expose sanitized `Identity`, never credentials.
- **`Request` immutability in v1:** `method`/`path`/`query`/`body`/`service`/`operation`/`account`/`tenant`/`identity` are **NOT** mutable in v1: changing signed routing after auth is unsafe and changes operation meaning. Add a separately authenticated rewrite stage only if later required.
- **`Response` access:** Available only in `after`; `status`/`code` reflect the original native result until changed; `replace(status, content_type, bytes)` replaces body and status. Native code parsing belongs to each adapter, including `HEAD` responses.
- **Actions & terminal action rule:** `pass` is the explicit default; `delay` sets a cancellable response delay, never sleeping an event loop. `throttle(seconds)`, `not_found()`, `denied()`, and `server_error()` are terminal native failures; **`drop_connection()` closes the transport without an HTTP error payload**.
- **Single terminal action enforcement:** First terminal action wins; **a second terminal action is a rule error**. Return after a terminal branch via `if`/`else` structure; do not assume arbitrary early returns. `page_cap` and `delay` are non-terminal.
- **`page_cap`:** `before`-only and lowers the effective native handler limit; preserve normal ordering, continuation token, and next-page headers. **Never truncate the serialized page and discard items.**
- **`State`:** Host-owned per process/run, shared across entries, namespaced by `scenario+resource` where needed, reset by restart; no hidden persistence. `increment` is atomic; `get`+`put` sequences require serial test requests or a future transaction primitive.
- **`Clock` & `Random`:** Deterministic `epoch + admission_ordinal * tick` (default `epoch=0`, `tick=100ms`); snapshot per request, independent of wall-clock waits/auth timestamps. Optional `real` mode uses monotonic elapsed time. `uniform(n)` is `[0, n)`, seeded by `run_seed + ordinal` with a specified portable PRNG; `n <= 0` fails.
- **Determinism:** Requires a fixed request admission order; concurrent client arrival order is not reproducible. Physical delay and client retry scheduling remain wall-clock effects.

---

## 4. Provider Adapters and Integration

Add shared `SimRulesEngine`/`Schema`/`State` plus per-sim `RulesFilter` and `NativeErrors`/`OperationAdapter` under `src/main/java/ai/lmctl/<sim>/` (proposed filenames, not existing files):
- **AWS (`awssim`):** `AuthFilter.java:28–29` is priority `950` after upstream account/region `900`; add matched `RulesFilter` at request priority `3000`, after auth, before handlers. Extract service/action mapping from `AuthFilter.java:50–55, 115–124` so `open` mode also has metadata (currently returns early at `:48`).
- **Azure (`azuresim`):** `StorageAuth.java:100–103` is `preMatching` auth at priority `1000`; add matched `RulesFilter` after it, reuse/extract target resolution (`:112, 136–145`) even when `config == null`. Publish verified principal as a request property.
- **GCP (`gcpsim`):** `PermissionFilter.java:22, 32–53` authorizes at `AUTHORIZATION=2000`; add `RulesFilter` at `3000` and extract map (`:53–115`). REST first; gRPC is a separate interceptor project, explicitly not covered (`README.md:117–119`).
- **OCI (`ocisim`):** `OciAuthFilter.java:32, 79–95` authenticates at `1001` and resolves policy operation; add `RulesFilter` at `3000`, reuse `OciPolicyEngine.resolveOperation`, publish tenancy/principal and denial tags. `:209–210` currently renders `403 NotAuthorizedOrNotFound`.

### Filter, Buffering, Error Mapping, CLI & Sandbox Details
- **Quarkus abort-path proof:** Each `RulesFilter` also supplies a global response filter for selected `after` bindings, including request-filter aborts. **Prove Quarkus abort-path invocation/order in delivery step 2**; if bypassed, call the same response adapter explicitly from the auth rejection boundary, with an **exactly-once guard**.
- **Streaming & buffer bounds:** Use a writer interceptor / Vert.x response adapter where serialized bytes are required: `ContainerResponseFilter` alone sees Java entities, not necessarily wire bytes. Bound buffering; **initially reject `after`-body rules for streaming/oversized operations, while pass-through remains streaming**.
- **`NativeErrors` protocol + operation selection:** `NativeErrors` must select **protocol AND operation**: S3 XML + `HEAD` rules, DynamoDB/SQS AWS JSON, Azure Storage XML/`x-ms-error-code`, GCP REST JSON, OCI JSON/`opc-request-id`. Preserve request IDs, content type, and provider retry headers; recalculate `Content-Length`/checksums, strip stale encodings.
- **Action-to-error mapping:** Map `throttle` to the operation's native throttling status/code (**S3 `SlowDown` may be `503`**, other APIs `429`/`400`); `server_error` is `500` with native envelope. `not_found` selects `NoSuchKey`/`NoSuchBucket`, `ResourceNotFound` variants, or OCI `NotAuthorizedOrNotFound` as applicable; `denied` preserves existing provider denial semantics.
- **Fixture verification & `drop_connection`:** Exact per-operation mappings beyond the inspected auth errors are unverified: **fixture-test them with actual `lmcode` host SDK retry/error parsers before declaring support**. `drop_connection` needs Vert.x connection close (HTTP/2 stream reset later); **never substitute status 500**.
- **CLI & Env precedence:** `<sim> serve --rules FILE.dslb`; env `SIM_RULES`. Add `SIM_RULES_SEED`/`--rules-seed` (default `0`), `SIM_RULES_CLOCK`/`--rules-clock` (`logical|real`, default `logical`); versioned config can later expose `epoch`/`tick`/budgets.
- **Precedence & duplicate flags:** **Explicit CLI > `<PROVIDER>SIM_RULES` alias > `SIM_RULES`; reject duplicate flags.** Match existing OCI aliases (`Main.java:68–69`); align Azure `SIM_AUTH` fallback in the same compatibility pass (`Azure Main.java:32–33` currently only reads `AZURESIM_AUTH*`).
- **Pre-listener startup validation (exit 2):** No `--rules` means unchanged execution. Validate file size, bytecode version, schema SHA, allowed imports, all entries/interfaces, unique annotations/selectors, provider operation capabilities, and bounds **before opening any listener**. **Invalid config exits `2` with no secrets.**
- **Initialization before `Quarkus.run`:** Run body once in startup-only registry mode, freeze bindings; call selected entry only on requests. Native startup validation belongs before `Quarkus.run`: `AWS Main.java:33–38, 101`; `Azure :52–69`; `GCP :51–78`; `OCI :48–54, 122`.
- **Auth & loopback restriction:** Enable with both `open` and `enforce` auth; **loopback listeners only when rules are enabled, rejecting wildcard/public listeners**. Enforce mode remains useful for OCI denial fidelity; no rule can bypass failed authentication or authorize a denied operation.
- **Security sandbox:** Use `new Registry(false)` plus explicit pure standard callbacks and domain methods. **Default `Registry` includes file helpers (`Registry.java:18`; `Stdlib.java:11–14`), so DO NOT use it.** Reject file/network/env/process imports at load, including unused-entry imports; no cloud SDK clients or dynamic loading.
- **Resource budgets:** Defaults: `1 MiB` `.dslb`, `1 MiB` inspected body, `4 MiB` output, `10k` state keys / `4 MiB` state, `100k` VM instructions / `8 MiB` VM budget, max delay `5s`, bounded `16` workers / `64` pending requests. Account host allocations too; current `Context.java:7–10` budgets alone do not cap every callback allocation.
- **VM runtime errors:** **Request VM errors discard buffered changes, emit native `500` plus redacted diagnostic, and fail the CI scenario**; after-stage errors cannot roll back prior handler side effects. Bound initialization similarly; reject unsupported capabilities at startup rather than silently no-op.

---

## 5. CI, Native Images, and `.dslb` Compilation

- **Rule compilation & `savedsl` retirement (open dependency):**
  - `savedsl` is **RETIRED** (a static `--check` error in current `lmscript`).
  - Inspection of `/home/ubuntu/lmctl-mono/lmscript/bin/lmscript --help` and `~/lmctl-mono/lmscript/durable-memory/lmscript_language_reference.md` (§"lmcode programs") confirms that `lmscript` compiles `_lmcode_` blocks to DSLB v6 bytecode in memory and materializes `$DSLFILE` only as a private temporary file during `run_lmcode` / `lmcode_build` (which requires the spawned command to emit a valid `lmcode` JSON result envelope), and notes that *"Low-level compiler APIs remain available for fixture generation"*.
  - **Open dependency:** The current `lmscript` CLI does **not** yet expose a standalone CLI flag to write a `.dslb` file directly to disk without running a host envelope. Before simulator rule tests run in CI, either:
    1. `lmscript` adds an explicit CLI flag (or `lmcode` fixture-export mode) to write compiled `.dslb` bytecode to a target path against `<sim> serve --rules-schema`, **or**
    2. `<sim>` exposes a small `compile-rules` / `--lmcode` helper mode invoked via `run_lmcode(rule_prog, {command:[sim_bin, "compile-rules", "--lmcode", "$DSLFILE", "--out", out_dslb]})` that validates and persists `$DSLFILE` and prints `{ok:true, result:out_dslb}`.
  - Native simulator binaries need neither the `lmscript` compiler nor a JVM at runtime.
- **Fixtures & bytecode versions:** Keep readable `.lms` fixtures and optionally cache/prepublish `.dslb` with schema SHA/compiler/runtime provenance; reject stale hashes. No per-scenario GraalVM build. Client bytecode is separately pinned (`gcpsim/examples/templates.lms:37–44` explicitly needs v5; rules runtime here is v6).
- **Existing test drivers:** Extend current `lmscript`/template drivers: AWS `examples/templates.lms:10–44` generates JSON payload/auth files; Azure `:65–71` checks denied SDK status; GCP `:33–51` and OCI `:258–269` assert client errors. Add rules-file startup and black-box host assertions there.
- **Source overlay build:** Embed a checksum-pinned `lmcode-java` source subset/shared adapter release via `sdk.lock`, following `lmaws`/`lmoci`. Simulator build scripts overlay Java into pinned upstream trees (`AWS scripts/build.py:36–53`, `Azure :37–54`, `GCP :36–47`, `OCI :41–49, 79–83`); copy shared sources **and** exact schema resource there.
- **Native image reachability:** Native feasibility has source evidence: JDK-only interpreter, no reflection/dynamic code loading (`Java README.md:30–34, 46–52`; `Registry.java:3`). Avoid pulling CLI/conformance runners and file libraries into reachability.
- **Binary size / RSS / build-time overhead is UNMEASURED:** **Binary-size/RSS/build-time delta is UNMEASURED; do not promise negligible overhead.** Measure stripped bytes, cold idle RSS/start time, 16-worker loaded RSS, and throughput against identical native build flags on Linux, then existing five-platform matrices. Budget target, not evidence: `<5 MiB` executable and `<16 MiB` idle RSS increase.

---

## 6. Six Concrete Scripts and Caveats

Each numbered block is its own `.lms` fixture wrapped in `program = _lmcode_ schema="sim-rules.schema.json"; ... end _lmcode_;` and compiled to `.dslb` via the CLI/helper mechanism in §5. Proposed APIs; scripts were not compiled:

```text
# 1. First three calls throttle; SDK receives native error and Retry-After: 1.
@retry fn retry(x: Exchange) -> void implements Interceptor {
 if (x.state().increment("retry:"+x.request().resource_key()) <= 3) { x.throttle(1); } else { x.pass(); }
}
bind("before","object","object.read","retry");

# 2. Inject native 500 on a key pattern, pass other reads; portable string helper.
@fault fn fault(x: Exchange) -> void implements Interceptor {
 if (str_contains(x.request().resource_key(),"fault-500/")) { x.server_error(); } else { x.pass(); }
}
bind("before","object","object.read","fault");

# 3. Add 150ms response latency; hide successful reads for 300 logical ms after a successful write.
@lag fn lag(x: Exchange) -> void implements Responder {
 let k = "visible:"+x.request().resource_key();
 x.delay(150);
 if (x.request().operation()=="object.write" && x.response().status()>=200 && x.response().status()<300) {
   x.state().put_int(k,x.clock().now_ms()+300);
 } else {
   if (x.request().operation()=="object.read" && x.response().status()==200 && x.clock().now_ms()<x.state().get_int(k,0)) { x.not_found(); }
 }
}
bind("after","object","object.write","lag"); bind("after","object","object.read","lag");

# 4. OCI: preserve native denial payload/code, change authorization-denial 403 to real-cloud 404.
@oci404 fn oci404(x: Exchange) -> void implements Responder {
 if (x.response().status()==403 && x.response().code()=="NotAuthorizedOrNotFound") { x.response().status(404); }
}
bind("after","object","*","oci404");

# 5. Five created objects must arrive as pages of 2,2,1 with native continuation tokens.
@pages fn pages(x: Exchange) -> void implements Interceptor { x.page_cap(2); }
bind("before","object","object.list","pages");

# 6. AWS us-east-1 own-bucket re-create response compatibility.
@east fn east(x: Exchange) -> void implements Responder {
 if (x.request().region()=="us-east-1" && x.response().status()==409 && x.response().code()=="BucketAlreadyOwnedByYou") {
   x.response().replace(200,"application/xml",""); x.response().remove_header("x-amzn-errortype");
 }
}
bind("after","object","object.bucket.create","east");
```

### Per-Example Caveats
- **#3 (`@lag`):** Covers read-after-write visibility only, for serial isolated resources; list visibility needs a handler-level visibility adapter, and overwrite tests need version-aware state. It does **not** claim full eventual consistency.
- **#4 (`@oci404`):** Matches documented OCI `404` ([Oracle API errors](https://docs.oracle.com/en-us/iaas/Content/API/References/apierrors.htm)); current `ocisim` intentionally uses `403` (`ocisim/README.md:51–54`). Keep this opt-in.
- **#6 (`@east`):** Emulates the response distinction only: AWS also resets ACLs ([CreateBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html)). Full ACL parity needs an adapter mutation; never turn `BucketAlreadyExists`/foreign ownership into success. Existing simulator `409` behavior itself was not verified against a running binary.

---

## 7. Incremental Delivery, Estimates, and Risks

1. **Step 1 (2–3 engineer-days):** `ocisim` only, one `before` hook, one `@retry` rule, OCI native throttle helper, fixed schema subset, CLI/load validation, and pinned Java embed.
   - *Acceptance:* Prebuilt native binary + `lmoci` `lmscript` driver makes three injected throttles then a real successful read; raw requests verify `Retry-After`/code, unselected sentinel stays untouched, no-rules baseline passes.
2. **Step 2 (2–4 engineer-days):** Worker isolation/limits/state/clock, `after` hook, and Quarkus abort-path proof.
   - *Acceptance:* Signed valid-but-denied OCI call is `403` normally, `404` only with rule; wrong signature remains `401`; invalid schema/entry/import exits before opening port; parallel requests do not trigger `Registry` active errors.
3. **Step 3 (4–7 engineer-days):** AWS/Azure/GCP REST adapters and native error fixtures; run all six scenarios through actual host SDKs, including page traversal/no duplicates and failed-write visibility.
   - *Risks:* Upstream filter ordering, route metadata in `open` mode, protocol-specific SDK retry classification, transport close semantics.
4. **Step 4 (3–5 engineer-days):** Handler-level pagination caps, bounded serialized response rewriting, native resource/size regression gates, and five-platform CI/release artifacts. Streaming/gRPC/full ACL mutations remain explicitly unsupported until separate acceptance work.

- **Total initial supported REST rollout:** Roughly **11–19 engineer-days**, contingent on upstream adapter access; full fidelity adds work. Do not publish provider-wide support from one service's fixtures.
- **Defaults:** Loopback-only, both auth modes, compile rules in CI, deterministic logical clock, state reset per process.

---

## 8. Evaluation Note: `lmctl-ai/lmmock` as an Alternative / Complement Front Proxy

Alongside in-simulator `sim_rules_v1` filters, **`lmctl-ai/lmmock`** (`/home/ubuntu/cloud/lmmock`) is being evaluated as an alternative or complementary programmable front proxy in front of `<provider>sim` (spike by DeepseekCoder pending in `scratchpad/lmmock-spike.md`):

- **Existing `lmmock` capabilities:**
  - Scripted HTTP request/response interception via `lmcode` `Handler` SAM entries (`@name fn h(req: Request, res: Response) -> void implements Handler`).
  - Built-in protocol servers (`redis`, `kafka`, `mongodb`, `postgres`, `mqtt`, `smtp`, `imap`, `amqp`) and wire layers (`ws`, `http2`, `grpc`).
  - **`--upstream` selective passthrough + audit log:** `lmmock` can sit in front of `awssim` (`:4566`), `azuresim` (`:4577`), `gcpsim` (`:4588`), or `ocisim` (`:4599`), intercepting only matched routes while forwarding all other requests untouched to the upstream simulator and recording a full request/response audit log.
