# Cloud Simulator Harness

Local multi-cloud test harness for `lmcloud` using standalone native emulator binaries for AWS, Azure, GCP, and OCI.

## Pinned Simulator Binaries

All simulators are standalone native executables (Quarkus / GraalVM native image builds based on Floci engines) distributed via GitHub Releases under `lmctl-ai`. Checksums for all supported platforms (`linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64`, `windows-x64`) are pinned in [`scripts/sims.lock`](../scripts/sims.lock).

| Simulator | Release | Upstream Engine | Default Port | Health / Readiness Probe |
|---|---|---|---|---|
| **awssim** | `v0.2.0` | Floci 2.3.0 | `4566` | `GET /_floci/health` (HTTP 200) |
| **azuresim** | `v0.2.0` | Floci-AZ 0.15.0 | `4577` | `GET /devstoreaccount1?comp=list` (HTTP 200) |
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
scripts/sim.sh start <aws|azure|gcp|oci> [--port N] [--free-port] [--data-dir D] [--timeout S]
scripts/sim.sh stop <aws|azure|gcp|oci>
scripts/sim.sh status <aws|azure|gcp|oci>
scripts/sim.sh url <aws|azure|gcp|oci>
```
- **Lifecycle & Process Management:** Starts process in background (`serve --port <port> --data-dir <data_dir>`), writes PID and port to `.cache/sims/run/<provider>/`, captures stdout and stderr to `sim.log`, and prints the loopback URL on stdout once healthy.
- **Port Selection:** Uses the provider default port if available, or dynamically selects an unused loopback port (`--free-port` or when default port is busy).
- **Graceful Shutdown:** `stop` sends `SIGTERM`, waits up to 5 seconds for clean exit, and escalates to `SIGKILL` only if the process fails to terminate.
- **Orphan Prevention:** Uses bash error and termination traps (`ERR`, `INT`, `TERM`) during startup to ensure no zombie processes remain if startup or readiness polling fails.

### 4. `scripts/smoke-sim-wire.sh`
Internal simulator wire smoke test (not the lmscript acceptance test). Executes end-to-end provider-native object storage round trips with plain `curl` against all 4 simulators:
```bash
scripts/smoke-sim-wire.sh [aws|azure|gcp|oci...]
```
All 4 pass cleanly (bucket create, object put, get & byte comparison, object delete, bucket delete).

### 5. `scripts/test-sims-lmscript.sh`
The primary LMScript harness runner. Per provider, starts the simulator, runs an LMScript program via the client using mono LMScript (`LMSCRIPT_BIN=/home/ubuntu/lmctl-mono/lmscript/bin/lmscript`) and the CURRENT API (`load_schema` / `_lmcode_` / `run_lmcode`), and stops the simulator.

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

## Proposed Simulator Enhancements

Based on real observations from building the harness, inspecting the simulator sources, and driving wire/client operations:

1. **`azuresim` (`lmctl-ai/azuresim`, `src/` / routing filter):**
   - **Missing standard health endpoint:** Unlike `awssim` (`/_floci/health`), `gcpsim` (`/health`), and `ocisim` (`/_floci-oci/health`), `azuresim` has no dedicated HTTP GET endpoint to probe readiness without making a functional Blob or Queue storage call.
   - **Proposal:** Add a lightweight `GET /_floci/health` route returning HTTP 200 `{"status": "UP"}` to eliminate the need for functional resource list queries (`/devstoreaccount1?comp=list`) during harness startup polling.

2. **`ocisim` (`lmctl-ai/ocisim`, `src/main/java/io/flo/oci/lif/EmulatorLifecycle.java`):**
   - **Health route path consistency:** `ocisim` serves health at `GET /_floci-oci/health`.
   - **Proposal:** Add an alias route `GET /_floci/health` (consistent with `awssim`) so multi-cloud harnesses can use a unified health check path across all simulators.

3. **`awssim` (`lmctl-ai/awssim`, `src/` & `durable-memory/auth-2026-10-30.md`):**
   - **S3 Advanced APIs:** S3 multipart upload (`InitiateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`), S3 object copy (`CopyObject`), and bucket versioning are deferred.
   - **Proposal:** Implement mock multipart upload and object copy in Floci S3 service handlers so object storage conformance tests covering large uploads or server-side copying can run locally.

4. **`gcpsim` (`lmctl-ai/gcpsim`, `src/`):**
   - **Delete Object Return Codes:** Ensure DELETE object media requests consistently return HTTP 204 No Content according to Google Cloud Storage JSON API specifications, and implement stubbed bucket lifecycle and uniform bucket-level access configuration endpoints for future conformance suites.
