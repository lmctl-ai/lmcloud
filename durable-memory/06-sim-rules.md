# 06 — Shared Simulator Rules (`sim_rules_v1`) & `lmmock` Front-Proxy Evaluation

*(Design by SolReviewer, adopted by Lead; with evaluation note on `lmctl-ai/lmmock`.)*

## 1. Evidence and Architectural Choice

- **Startup binding and selected-entry dispatch:** Follow `lmmock`'s startup binding and selected-entry dispatch model rather than wholesale HTTP handler replacement (`lmmock/README.md:49–99`; `internal/mock/mock.go:81–133, 189–209`; `internal/mock/schema.json:298–308`).
- **Single-registration body:** A rule program's top-level body registers route bindings once at startup; duplicate annotations, missing bindings, or wrong SAM interfaces fail startup immediately; each incoming request invokes only its selected entry index. Faults use stateful counters, logical or real delays, and transport disconnects; state survives across requests (`examples/faults.lms:1–20`; `examples/stateful.lms:1–13`).
- **SAM is a schema signature, not a Java interface implementation:** Annotation duplicates are legal in `lmscript` (`lmcode/spec/schema.md:120–144`; `language.md:395–424`; `grammar.md:31, 104`; `bytecode.md:79–102`), so the simulator host must reject ambiguous bindings at startup.
- **Reference dispatch model:** `lmcode-go-sample` demonstrates independent SAM entries, including never-called and duplicate annotations (`examples/rule-entries.lms:1–24`; `main.go:130–165`; `host.go:76–86, 245–250`).
- **Java runtime integration (`lmcode-java`):** At inspected `HEAD=8b2d16312dea695492b8213e52df46fb031f5960`, `Program.java:21–35, 79–85` exposes `entries()` and `call(index, Context, Registry, List<Value>)`, validates the schema SHA, and binds imports. `Registry.java:3–5, 18, 26–40` uses explicit callbacks without reflection or dynamic classloading, making it GraalVM native-image safe, **but prohibits overlapping runs on a single `Registry` instance**. Each simulator must therefore maintain an isolated loaded `Program` + `Registry` per bounded worker and never share a single bound instance across concurrent workers.
- **Pin convergence:** `lmaws/sdk.lock` and `lmoci/sdk.lock` currently pin an older `3ff5ca5e` commit with source embedding (`lmaws/pom.xml:5`; `lmoci/pom.xml:147–176`). All four simulators should converge on one verified common `lmcode-java` commit that includes `entries()` / indexed `call()`.

---

## 2. Contract and Selection Semantics

- **One shared schema:** Ship a byte-identical `sim_rules_v1` schema across all four simulator binaries (`awssim`, `azuresim`, `gcpsim`, `ocisim`), exported via `<sim> serve --rules-schema` (prints JSON schema and exits). Provider protocol differences live inside each simulator's Java adapter.
- **Client/server independence:** Simulator rules are completely independent of the `lmcloud` client program: the `lm<provider>` client speaks standard cloud HTTP to the simulator, while the simulator executes its own compiled `.dslb` rule bytecode.
- **Binding call:** Top-level startup code calls `bind(phase, service, operation, annotation)`:
  - `phase`: `"before"` or `"after"`
  - `service`: canonical service identifier (`"object"`, `"queue"`, `"table"`, ...) or `"*"`
  - `operation`: canonical operation identifier (`"object.bucket.create"`, `"object.write"`, `"object.read"`, `"object.list"`, `"queue.create"`, `"queue.send"`, `"queue.receive"`, `"queue.ack"`, `"queue.nack"`, ...) or `"*"`
  - Provider-specific service/operation names remain inspectable on `Request` via `native_service()` and `native_operation()`.
- **Deterministic specificity resolution:** Resolved once per request:
  1. Exact `service` + exact `operation`
  2. Exact `service` + `"*"`
  3. `"*"` + `"*"`
  Duplicate bindings at the same specificity fail startup. A binding selects **at most one** annotation and **one** phase per request (never run all entries; never run both a `before` and an `after` entry on the same request).
- **Pass-through defaults:** Unmatched requests pass through unchanged. A `before` rule that returns without invoking a terminal action passes through to the simulator handler; an `after` rule that returns without mutating the response preserves the handler's response.
- **Execution boundaries & auth invariants:**
  - `before` runs **after** authentication/authorization and route metadata resolution, and **before** handler side effects. If a request is rejected by authentication/authorization, `before` rules are skipped.
  - `after` runs **before** response commitment, including tagged authorization aborts, and does not undo handler side effects.
  - An `after` rule may transform a tagged authorization denial into another denial representation (e.g., OCI `403 NotAuthorizedOrNotFound` → `404 NotAuthorizedOrNotFound`), but **authentication failures (`401`) and denial→success transitions are immutable**.
  - `bind(...)` is startup-only; `Exchange`, `State`, `Clock`, and `Random` are request-only.

---

## 3. `sim_rules_v1` Schema (`dsl.schema` v2)

```json
{
  "dsl.schema": 2,
  "name": "sim_rules_v1",
  "types": {
    "Exchange": {
      "methods": {
        "request": [{ "params": [], "returns": "Request" }],
        "response": [{ "params": [], "returns": "Response" }],
        "state": [{ "params": [], "returns": "State" }],
        "clock": [{ "params": [], "returns": "Clock" }],
        "random": [{ "params": [], "returns": "Random" }],
        "pass": [{ "params": [], "returns": "void" }],
        "delay": [{ "params": ["int"], "returns": "void" }],
        "throttle": [{ "params": ["int"], "returns": "void" }],
        "not_found": [{ "params": [], "returns": "void" }],
        "denied": [{ "params": [], "returns": "void" }],
        "server_error": [{ "params": [], "returns": "void" }],
        "drop_connection": [{ "params": [], "returns": "void" }],
        "page_cap": [{ "params": ["int"], "returns": "void" }]
      }
    },
    "Request": {
      "methods": {
        "method": [{ "params": [], "returns": "string" }],
        "path": [{ "params": [], "returns": "string" }],
        "raw_path": [{ "params": [], "returns": "string" }],
        "header": [{ "params": ["string"], "returns": "string" }],
        "query": [{ "params": ["string"], "returns": "string" }],
        "body": [{ "params": [], "returns": "string" }],
        "service": [{ "params": [], "returns": "string" }],
        "operation": [{ "params": [], "returns": "string" }],
        "native_service": [{ "params": [], "returns": "string" }],
        "native_operation": [{ "params": [], "returns": "string" }],
        "account": [{ "params": [], "returns": "string" }],
        "tenant": [{ "params": [], "returns": "string" }],
        "region": [{ "params": [], "returns": "string" }],
        "identity": [{ "params": [], "returns": "Identity" }],
        "resource_key": [{ "params": [], "returns": "string" }]
      }
    },
    "Identity": {
      "methods": {
        "principal": [{ "params": [], "returns": "string" }],
        "verified": [{ "params": [], "returns": "bool" }],
        "auth_mode": [{ "params": [], "returns": "string" }]
      }
    },
    "Response": {
      "methods": {
        "status": [
          { "params": [], "returns": "int" },
          { "params": ["int"], "returns": "void" }
        ],
        "code": [{ "params": [], "returns": "string" }],
        "header": [{ "params": ["string"], "returns": "string" }],
        "body": [{ "params": [], "returns": "string" }],
        "set_header": [{ "params": ["string", "string"], "returns": "void" }],
        "remove_header": [{ "params": ["string"], "returns": "void" }],
        "replace": [{ "params": ["int", "string", "string"], "returns": "void" }]
      }
    },
    "State": {
      "methods": {
        "increment": [{ "params": ["string"], "returns": "int" }],
        "get_int": [{ "params": ["string", "int"], "returns": "int" }],
        "put_int": [{ "params": ["string", "int"], "returns": "void" }],
        "get": [{ "params": ["string", "string"], "returns": "string" }],
        "put": [{ "params": ["string", "string"], "returns": "void" }],
        "erase": [{ "params": ["string"], "returns": "void" }]
      }
    },
    "Clock": {
      "methods": {
        "now_ms": [{ "params": [], "returns": "int" }]
      }
    },
    "Random": {
      "methods": {
        "uniform": [{ "params": ["int"], "returns": "int" }]
      }
    }
  },
  "functions": {
    "bind": [{ "params": ["string", "string", "string", "string"], "returns": "void" }]
  },
  "context": {},
  "enums": {},
  "conversions": [],
  "interfaces": {
    "Interceptor": {
      "params": [{ "name": "x", "type": "Exchange" }],
      "returns": "void"
    },
    "Responder": {
      "params": [{ "name": "x", "type": "Exchange" }],
      "returns": "void"
    }
  }
}
```

### Key Runtime Semantics
- **`Request` snapshot:** Immutable; `path()` (decoded) and `raw_path()` (percent-encoded wire path) are distinct; `resource_key()` is a canonical collision-free `provider/account/tenant/container/key` identifier. Credentials (`Authorization`, cookies, signatures) are redacted; only sanitized `Identity` is exposed.
- **`Response` access:** Available only in `after` rules. `replace(status, content_type, body)` replaces status and body and recalculates `Content-Length`.
- **Actions:** `pass()` is the explicit default; `delay(ms)` and `page_cap(n)` are non-terminal (`page_cap` is `before`-only and lowers the effective native handler page size while preserving continuation tokens); `throttle(retry_after_seconds)`, `not_found()`, `denied()`, `server_error()`, and `drop_connection()` are terminal actions (at most one terminal action per rule execution).
- **`State`, `Clock`, `Random`:** `State` is in-memory per simulator process (`increment` is atomic). `Clock` defaults to a deterministic logical clock (`epoch + admission_ordinal * 100ms`, overridable via `--rules-clock real`). `Random.uniform(n)` uses a deterministic PRNG seeded by `--rules-seed` + request ordinal.

---

## 4. Provider Adapters & Security Bounds

- **Filter placement:**
  - `awssim`: `AuthFilter` runs at priority `950`; `RulesFilter` runs at `3000` (extracting service/action metadata so `--auth open` also populates `service()` / `operation()`).
  - `azuresim`: `StorageAuth` runs at `1000`; `RulesFilter` runs after it, reusing target resolution in both `open` and `enforce` modes.
  - `gcpsim`: `PermissionFilter` runs at `2000`; `RulesFilter` runs at `3000` over REST routes.
  - `ocisim`: `OciAuthFilter` runs at `1001`; `RulesFilter` runs at `3000`, reusing `OciPolicyEngine.resolveOperation`.
- **CLI & Env:** `<sim> serve --rules FILE.dslb` (or `<PROVIDER>SIM_RULES` / `SIM_RULES`), plus `--rules-seed` (`SIM_RULES_SEED`, default `0`) and `--rules-clock` (`SIM_RULES_CLOCK`, `logical|real`, default `logical`).
- **Sandbox & resource bounds:** Loopback listeners only when rules are enabled. Use `new Registry(false)` with explicit pure callbacks (never the default `Registry`, which exposes file I/O helpers). Enforce caps: `1 MiB` `.dslb`, `1 MiB` inspected body, `4 MiB` output, `10,000` state keys / `4 MiB` state, `100,000` VM instructions / `8 MiB` VM memory, max delay `5s`, bounded `16` workers / `64` pending requests.

---

## 5. Six Canonical Rule Examples

Each block below is wrapped in `program = _lmcode_ schema="sim-rules.schema.json"; ... end _lmcode_;` and compiled to `.dslb` during test setup:

```text
# 1. First three calls throttle; SDK receives native error and Retry-After: 1.
@retry fn retry(x: Exchange) -> void implements Interceptor {
  if (x.state().increment("retry:" + x.request().resource_key()) <= 3) { x.throttle(1); } else { x.pass(); }
}
bind("before", "object", "object.read", "retry");

# 2. Inject native 500 on a key pattern, pass other reads.
@fault fn fault(x: Exchange) -> void implements Interceptor {
  if (str_contains(x.request().resource_key(), "fault-500/")) { x.server_error(); } else { x.pass(); }
}
bind("before", "object", "object.read", "fault");

# 3. Add 150ms response latency; hide successful reads for 300 logical ms after a successful write.
@lag fn lag(x: Exchange) -> void implements Responder {
  let k = "visible:" + x.request().resource_key();
  x.delay(150);
  if (x.request().operation() == "object.write" && x.response().status() >= 200 && x.response().status() < 300) {
    x.state().put_int(k, x.clock().now_ms() + 300);
  } else {
    if (x.request().operation() == "object.read" && x.response().status() == 200 && x.clock().now_ms() < x.state().get_int(k, 0)) {
      x.not_found();
    }
  }
}
bind("after", "object", "object.write", "lag");
bind("after", "object", "object.read", "lag");

# 4. OCI: preserve native denial payload/code, change authorization-denial 403 to real-cloud 404.
@oci404 fn oci404(x: Exchange) -> void implements Responder {
  if (x.response().status() == 403 && x.response().code() == "NotAuthorizedOrNotFound") { x.response().status(404); }
}
bind("after", "object", "*", "oci404");

# 5. Five created objects must arrive as pages of 2, 2, 1 with native continuation tokens.
@pages fn pages(x: Exchange) -> void implements Interceptor { x.page_cap(2); }
bind("before", "object", "object.list", "pages");

# 6. AWS us-east-1 own-bucket re-create response compatibility (200 instead of 409 BucketAlreadyOwnedByYou).
@east fn east(x: Exchange) -> void implements Responder {
  if (x.request().region() == "us-east-1" && x.response().status() == 409 && x.response().code() == "BucketAlreadyOwnedByYou") {
    x.response().replace(200, "application/xml", "");
    x.response().remove_header("x-amzn-errortype");
  }
}
bind("after", "object", "object.bucket.create", "east");
```

---

## 6. Evaluation Note: `lmctl-ai/lmmock` as an Alternative / Complement Front Proxy

Alongside in-simulator `sim_rules_v1` filters, **`lmctl-ai/lmmock`** (`/home/ubuntu/cloud/lmmock`) is being evaluated as an alternative or complementary programmable front proxy in front of `<provider>sim` (spike by DeepseekCoder pending in `scratchpad/lmmock-spike.md`):

- **Existing `lmmock` capabilities:**
  - Scripted HTTP request/response interception via `lmcode` `Handler` SAM entries (`@name fn h(req: Request, res: Response) -> void implements Handler`).
  - Built-in protocol servers (`redis`, `kafka`, `mongodb`, `postgres`, `mqtt`, `smtp`, `imap`, `amqp`) and wire layers (`ws`, `http2`, `grpc`).
  - **`--upstream` selective passthrough + audit log:** `lmmock` can sit in front of `awssim` (`:4566`), `azuresim` (`:4577`), `gcpsim` (`:4588`), or `ocisim` (`:4599`), intercepting only matched routes (for fault injection, throttling, latency, or OCI `403`→`404` status rewriting) while forwarding all other requests untouched to the upstream simulator and recording a full request/response audit log.
- **Trade-off under evaluation:**
  - `lmmock --upstream` requires **zero Java/GraalVM modifications** to the four simulator binaries for basic HTTP fault injection, header/status rewriting, and transport drops (`res.drop()`).
  - In-simulator `sim_rules_v1` retains an advantage only where a rule must inspect post-auth resolved IAM/policy state (`Identity`, tagged auth denials) or mutate internal handler pagination limits (`page_cap(n)`) without re-parsing provider wire protocols.
