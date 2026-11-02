# Cloud Simulator Harness

Local multi-cloud test harness for `lmcloud` using standalone native emulator binaries for AWS, Azure, GCP, and OCI.

## Pinned Simulator Binaries

All simulators are standalone native executables (Quarkus / GraalVM native image builds based on Floci engines) distributed via GitHub Releases under `lmctl-ai`. Checksums for all supported platforms (`linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64`, `windows-x64`) are pinned in [`scripts/sims.lock`](../scripts/sims.lock).

| Simulator | Release | Upstream Engine | Default Port | Health / Readiness Probe |
|---|---|---|---|---|
| **awssim** | `v0.2.0` | Floci 2.3.0 | `4566` | `GET /_floci/health` (HTTP 200) |
| **azuresim** | `v0.2.0` | Floci-AZ 0.15.0 | `4577` | `GET /_floci/health` (HTTP 200) |
| **gcpsim** | `v0.2.0` | floci-gcp 0.11.0 | `4588` | `GET /health` (HTTP 200) |
| **ocisim** | `v0.1.0` | floci-oci 0.5.0 | `4599` | `GET /_floci-oci/health` (HTTP 200) |

## Pinned Client Binaries

Legacy released client binaries are pinned in [`scripts/clients.lock`](../scripts/clients.lock) for cross-platform execution:

| Client | Release | Upstream Repo | Native Platform Assets |
|---|---|---|---|
| **lmaws** | `v0.1.27` | `lmctl-ai/lmaws` | `linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64` |
| **lmazure** | `v0.1.5` | `lmctl-ai/lmazure` | `linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64`, `windows-x64.exe` |
| **lmgcp** | `v0.1.9` | `lmctl-ai/lmgcp` | `linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64`, `windows-x64.exe` |
| **lmoci** | `v0.1.0` | `lmctl-ai/lmoci` | `linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64`, `windows-x64.exe` |

## Harness Scripts

### 1. `scripts/sims.lock` & `scripts/clients.lock`
JSON manifests recording repository, release tag, version, and platform-specific SHA-256 digests for all simulator and client release binary assets.

### 2. `scripts/fetch-sims.sh` & `scripts/fetch-clients.sh`
Downloads the simulator and client binaries for the current host architecture (`uname -s` and `uname -m`) into `$LMCLOUD_SIM_DIR` (default `.cache/sims/`) and `$LMCLOUD_CLIENT_DIR` (default `.cache/clients/`).
- Idempotent and offline-friendly: skips download if binary exists and SHA-256 checksum matches.
- Validates SHA-256 against lockfiles and fails loudly on mismatch.
- Marks binaries executable (`chmod +x`) and symlinks canonical shorthand names.

### 3. `scripts/sim.sh`
Manages the background server lifecycle for each simulator:
```bash
scripts/sim.sh start <aws|azure|gcp|oci> [--name NAME] [--port N] [--free-port] [--data-dir D] [--timeout S]
scripts/sim.sh stop <aws|azure|gcp|oci> [--name NAME]
scripts/sim.sh status <aws|azure|gcp|oci> [--name NAME]
scripts/sim.sh url <aws|azure|gcp|oci> [--name NAME]
```

Key features and lifecycle semantics:
- **Same-Provider Concurrency (`--name NAME` / `$LMCLOUD_SIM_NAME`):**
  Each instance runs in an isolated directory (`.cache/sims/run/<provider>/<name>/`), allowing parallel tests to run multiple instances of the same simulator concurrently on separate ports without collision.
- **Idempotent Start:**
  Calling `start` for an instance that is already healthy and running simply prints its existing loopback URL and exits 0 without spawning duplicate processes.
- **Data Directory Lifecycle & Residue Policy:**
  - *Default:* When no `--data-dir` is specified, an ephemeral directory (`$SIM_RUNDIR/data`) is used. It is automatically purged when the simulator stops to ensure a clean slate.
  - *Custom (`--data-dir PATH`):* When an explicit directory is provided by the caller, the harness preserves it after `stop`. This allows post-mortem inspection of sqlite/file state and enables persistent state reuse across runs.
- **Log Truncate-on-Start:**
  Starting a simulator truncates `$SIM_RUNDIR/sim.log` (rather than appending) so diagnostic output always corresponds strictly to the current instance run.
- **Process Group Isolation (`setsid`):**
  Simulators run in their own process group via `setsid` (with python `os.setsid` fallback on BSD/macOS). Termination signals target the negative PID group (`-$pid`), ensuring all child threads and sub-processes are terminated cleanly.
- **PID Reuse Protection:**
  Pidfiles record `PID=<pid>`, `EXE=<sim_bin>`, and start timestamp token `START=<lstart>` (via `ps -o lstart=`). Before `status` or `stop` acts on a PID, it verifies that `/proc/<pid>/cmdline` (or `ps -o comm=`) and start time match the recorded identity. If the process has died and the OS reused the PID for another process, `sim.sh` refuses to kill it, removes the stale pidfile, and reports status accurately.
- **Signal Handling & Clean Exit Codes:**
  Signal handlers trap `INT` (exits 130), `TERM` (exits 143), and `ERR` (exits `$ec`). All traps perform process group cleanup before exiting.
  > [!NOTE]
  > CI workflow runners often launch backgrounded subshells with `SIGINT` ignored. CI step teardown must explicitly call `sim.sh stop` (e.g. via `if: always()`) rather than relying on inherited signal propagation.

### 4. `scripts/smoke-sim-wire.sh`
Internal simulator wire smoke test (not the lmscript acceptance test). Executes end-to-end provider-native object storage round trips with plain `curl` against all 4 simulators:
```bash
scripts/smoke-sim-wire.sh [aws|azure|gcp|oci...]
```
All 4 pass cleanly (bucket create, object put, get & byte comparison, object delete, bucket delete).

### 5. `scripts/test-sims-lmscript.sh`
The primary LMScript harness runner. Per provider, starts the simulator, runs an LMScript program via the client using mono LMScript (`LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript`) and the CURRENT API (`load_schema` / `_lmcode_` / `run_lmcode`), and stops the simulator:
```bash
scripts/test-sims-lmscript.sh [--strict] [aws|azure|gcp|oci...]
```
- **Exit Codes:**
  - *Default:* Exits `0` if all evaluated providers are either `PASS` or expected `PENDING-GO-PORT`. Exits `1` only if an unexpected failure (`FAIL`) occurs.
  - *Strict (`--strict`):* Exits `1` if any provider is `PENDING-GO-PORT` or `FAIL`. Useful for CI enforcement once modern clients are deployed.
- **Machine-Readable Output:**
  Emits standard TAP (Test Anything Protocol) lines (`1..N`, `ok 1 - aws # PENDING-GO-PORT ...`) and provider summary lines (`PROVIDER <name> <status>`).

---

## Portability & macOS Compatibility

All scripts are written to run portably on macOS (bash 3.2 / BSD userland) and Linux (Ubuntu bash 5 / GNU userland):
- **No Bash 4+ Associative Arrays:** Replaced all `declare -A` constructs with POSIX-compatible indexed parallel arrays.
- **Template-Required `mktemp`:** Uses `mktemp -d "${TMPDIR:-/tmp}/lmcloud.XXXXXX"` compatible with BSD `mktemp`.
- **Millisecond Timestamps:** Uses `python3 -c 'import time; print(int(time.time() * 1000))'` rather than GNU-specific `date +%s%N`.
- **Strict Linting:** All scripts pass `shellcheck` with zero warnings.

---

## Current Compiler Compatibility & Provider Status

The current mono LMScript compiler (`lmscript 0.2.38`) implements the modern `lmcode` specification:
- Generates **bytecode version 6** (loader rejects any other version).
- Modern host discovery requires the host binary to support `load_schema(cli=...)` via CLI flags `--lmcode-schema --json`.
- The execution contract (`run_lmcode`) requires the host binary to emit an execution return frame bounded by `LMCODE_RETURN_BEGIN` and `LMCODE_RETURN_END` framing lines.
- Legacy directives (`savedsl`, `dsl_cli`, `_dsl_`) are removed.

All four pinned released clients (`lmaws v0.1.27`, `lmazure v0.1.5`, `lmgcp v0.1.9`, `lmoci v0.1.0`) were built against legacy compiler `0.2.420` (bytecode v5, `--dsl` execution flags). Consequently, none can be driven by the current mono compiler, and all are marked **`PENDING-GO-PORT`**.

### Provider Status Matrix

| Provider | Client Version | Status | Primary Diagnostic / Failure Mode |
|---|---|---|---|
| **aws** | `lmaws v0.1.27` | **PENDING-GO-PORT** | Rejects bytecode v6 (`LOAD_BAD_BYTECODE`); lacks `--lmcode-schema`; missing return frame delimiters |
| **azure** | `lmazure v0.1.5` | **PENDING-GO-PORT** | Rejects bytecode v6 (`LOAD_BAD_BYTECODE`); lacks `--lmcode-schema`; missing return frame delimiters |
| **gcp** | `lmgcp v0.1.9` | **PENDING-GO-PORT** | Rejects bytecode v6 (`LOAD_BAD_BYTECODE`); lacks `--lmcode-schema`; missing return frame delimiters |
| **oci** | `lmoci v0.1.0` | **PENDING-GO-PORT** | Wire frame protocol mismatch (`frame is not terminal`: no `LMCODE_RETURN_BEGIN/END`); lacks `--lmcode-schema` |

### Detailed Failure Evidence

#### 1. AWS (`lmaws v0.1.27`)
- **Direct schema discovery attempt:**
  ```bash
  /home/ubuntu/lmctl-mono/lmscript/bin/lmscript -e 's = load_schema(cli="lmaws");'
  ```
  **Error output:**
  ```
  error:<inline>:1:5: _lmcode_: schema host exited 2: lmaws 0.1.27 — AWS SDK for Java v2 scripting host
  usage: lmaws [--dry-run] [--apply] --dsl FILE | --dsl-schema [--json] | --dsl-signatures [--without-std]
  ```
  *Cause:* `lmaws` does not recognize `--lmcode-schema`.
- **Execution attempt via schema file + `run_lmcode`:**
  ```bash
  lmaws --dsl-schema --json > schema.json
  # Compiled _lmcode_ block with aws.region("us-east-1")
  run_lmcode(p, {command: ["lmaws", "--dsl", "$DSLFILE"]})
  ```
  **Error output:**
  ```
  unsupported bytecode version 6 (this runtime reads version 5)
  {"ok": false, "phase": "run", "code": "LOAD_BAD_BYTECODE", "message": "unsupported bytecode version 6 (this runtime reads version 5)"}
  error: run_lmcode: lmcode host exited with code 3: lmcode return frame: frame is not terminal
  ```

#### 2. Azure (`lmazure v0.1.5`)
- **Direct schema discovery attempt:**
  ```bash
  /home/ubuntu/lmctl-mono/lmscript/bin/lmscript -e 's = load_schema(cli="lmazure");'
  ```
  **Error output:**
  ```
  error:<inline>:1:5: _lmcode_: schema host exited 2: invalid arguments; use --help
  ```
  *Cause:* `lmazure` does not recognize `--lmcode-schema`.
- **Execution attempt via schema file + `run_lmcode`:**
  ```bash
  lmazure --dsl-schema --json > schema.json
  run_lmcode(p, {command: ["lmazure", "--dsl", "$DSLFILE"]})
  ```
  **Error output:**
  ```
  {"ok": false, "phase": "load", "code": "LOAD_BAD_BYTECODE", "message": "unsupported bytecode version 6 (this runtime reads version 5)"}
  error: run_lmcode: lmcode host exited with code 3: lmcode return frame: frame is not terminal
  ```

#### 3. GCP (`lmgcp v0.1.9`)
- **Direct schema discovery attempt:**
  ```bash
  /home/ubuntu/lmctl-mono/lmscript/bin/lmscript -e 's = load_schema(cli="lmgcp");'
  ```
  **Error output:**
  ```
  error:<inline>:1:5: _lmcode_: schema host exited 2: usage: lmgcp --version | --help | --notices | --dsl-schema [--json] ...
  ```
  *Cause:* `lmgcp` does not recognize `--lmcode-schema`.
- **Execution attempt via schema file + `run_lmcode`:**
  ```bash
  lmgcp --dsl-schema --json > schema.json
  run_lmcode(p, {command: ["lmgcp", "--dsl", "$DSLFILE"]})
  ```
  **Error output:**
  ```
  {"ok": false, "phase": "load", "code": "LOAD_BAD_BYTECODE", "message": "unsupported bytecode version 6 (this runtime reads version 5)"}
  error: run_lmcode: lmcode host exited with code 3: lmcode return frame: frame is not terminal
  ```

#### 4. OCI (`lmoci v0.1.0`)
- **Direct schema discovery attempt:**
  ```bash
  /home/ubuntu/lmctl-mono/lmscript/bin/lmscript -e 's = load_schema(cli="lmoci");'
  ```
  **Error output:**
  ```
  error:<inline>:1:5: _lmcode_: schema host exited 2: lmoci 0.1.0 — Oracle Cloud Infrastructure SDK for Java scripting host
  usage: lmoci [--dry-run] [--apply] [--live] [--profile NAME] [--region NAME] [--endpoint URL] --dsl FILE
  ```
  *Cause:* `lmoci` does not recognize `--lmcode-schema`.
- **Execution attempt via schema file + `run_lmcode`:**
  ```bash
  lmoci --dsl-schema --json > schema.json
  run_lmcode(p, {command: ["lmoci", "--dsl", "$DSLFILE"]})
  ```
  **Error output:**
  ```
  {"ok": true, "result": null}
  error: run_lmcode: lmcode return frame: frame is not terminal
  ```
  *Cause:* `lmoci` prints raw JSON instead of the `LMCODE_RETURN_BEGIN` and `LMCODE_RETURN_END` framing required by `lmscript/dist/lmcode-frame.js`.

---

## Proposed Simulator Enhancements & Compatibility Findings

### Verified Supported Capabilities (False Proposals Removed)
During live verification on the release binaries, several features previously assumed missing were confirmed fully operational in current releases:
- **`azuresim v0.2.0` Health Endpoint:**
  `azuresim` already supports `GET /_floci/health` returning HTTP 200 `{"status":"UP","version":"dev","edition":"floci-az-always-free"}`. The harness probe was updated accordingly.
- **`awssim v0.2.0` S3 Multipart, Versioning & Copy:**
  Live wire testing confirmed that `POST /<bucket>/<key>?uploads` initializes multipart uploads (`InitiateMultipartUploadResult`), `PUT /<bucket>?versioning` configures bucket versioning, and `PUT /<bucket>/<target>` with `x-amz-copy-source` performs S3 object copies cleanly.
- **`gcpsim v0.2.0` Delete Status Code:**
  DELETE object and bucket requests consistently return HTTP 204 No Content per Google Cloud Storage JSON API specifications.

### Proposed Simulator Enhancements
1. **`ocisim` (`lmctl-ai/ocisim`, `src/main/java/io/flo/oci/lif/EmulatorLifecycle.java`):**
   - **Health route path alias:** `ocisim v0.1.0` serves its health endpoint only at `GET /_floci-oci/health`, while `GET /_floci/health` returns 404:
     ```bash
     $ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4599/_floci/health
     404
     $ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4599/_floci-oci/health
     200
     ```
   - **Proposal (Cosmetic):** Add route alias `GET /_floci/health` in `EmulatorLifecycle.java` matching `awssim` and `azuresim`, allowing harnesses to use a uniform probe path across all Floci-based simulators.
