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

## Harness Scripts

### 1. `scripts/sims.lock`
JSON manifest recording repository, release tag, version, and platform-specific SHA-256 digests for all release binary assets.

### 2. `scripts/fetch-sims.sh`
Downloads the simulator binaries for the current host architecture (`uname -s` and `uname -m`) into `$LMCLOUD_SIM_DIR` (or `.cache/sims/`).
- Idempotent and offline-friendly: skips download if binary exists and SHA-256 checksum matches.
- Validates SHA-256 against `scripts/sims.lock` and fails loudly on mismatch.
- Marks binaries executable (`chmod +x`) and symlinks canonical shorthand names (e.g. `awssim`, `azuresim`, `gcpsim`, `ocisim`).

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

### 4. `scripts/test-sims.sh`
Executes end-to-end provider-native object storage round trips with plain `curl` against all 4 simulators:
```bash
scripts/test-sims.sh [aws|azure|gcp|oci...]
```
For each simulator:
1. Starts the simulator via `sim.sh start`.
2. Creates a bucket or container using the provider's native HTTP API.
3. Uploads binary payload via `PUT` or `POST`.
4. Retrieves the object and verifies byte equality against the uploaded file using `cmp`.
5. Deletes the object and bucket/container.
6. Stops the simulator via `sim.sh stop`.
7. Reports `PASS` or `FAIL`.

## Provider Wire Shapes & Curl Patterns (Open Mode)

All simulators operate in `--auth open` by default. Every provider supports full object storage CRUD operations via standard `curl` commands without external SDKs:

### AWS (`awssim`) — S3 Path-Style REST
- **Create Bucket:** `curl -f -X PUT http://127.0.0.1:4566/<bucket>` (HTTP 200)
- **Put Object:** `curl -f -X PUT --data-binary "@file" http://127.0.0.1:4566/<bucket>/<key>` (HTTP 200)
- **Get Object:** `curl -f http://127.0.0.1:4566/<bucket>/<key> -o output` (HTTP 200)
- **Delete Object:** `curl -f -X DELETE http://127.0.0.1:4566/<bucket>/<key>` (HTTP 204)
- **Delete Bucket:** `curl -f -X DELETE http://127.0.0.1:4566/<bucket>` (HTTP 204)

### Azure (`azuresim`) — Blob Storage REST
- **Account:** Default local storage account is `devstoreaccount1`.
- **Create Container:** `curl -f -X PUT "http://127.0.0.1:4577/devstoreaccount1/<container>?restype=container"` (HTTP 201)
- **Put Block Blob:** `curl -f -X PUT -H 'x-ms-blob-type: BlockBlob' --data-binary "@file" http://127.0.0.1:4577/devstoreaccount1/<container>/<blob>` (HTTP 201)
- **Get Blob:** `curl -f http://127.0.0.1:4577/devstoreaccount1/<container>/<blob> -o output` (HTTP 200)
- **Delete Blob:** `curl -f -X DELETE http://127.0.0.1:4577/devstoreaccount1/<container>/<blob>` (HTTP 202)
- **Delete Container:** `curl -f -X DELETE "http://127.0.0.1:4577/devstoreaccount1/<container>?restype=container"` (HTTP 202)

### GCP (`gcpsim`) — Cloud Storage JSON API
- **Project:** Default local project is `gcpsim-local`.
- **Create Bucket:** `curl -f -X POST -H 'Content-Type: application/json' -d '{"name": "<bucket>"}' "http://127.0.0.1:4588/storage/v1/b?project=gcpsim-local"` (HTTP 200)
- **Upload Media:** `curl -f -X POST -H 'Content-Type: application/octet-stream' --data-binary "@file" "http://127.0.0.1:4588/upload/storage/v1/b/<bucket>/o?uploadType=media&name=<object>"` (HTTP 200)
- **Download Media:** `curl -f "http://127.0.0.1:4588/storage/v1/b/<bucket>/o/<object>?alt=media" -o output` (HTTP 200)
- **Delete Object:** `curl -f -X DELETE "http://127.0.0.1:4588/storage/v1/b/<bucket>/o/<object>"` (HTTP 204)
- **Delete Bucket:** `curl -f -X DELETE "http://127.0.0.1:4588/storage/v1/b/<bucket>"` (HTTP 204)

### OCI (`ocisim`) — Object Storage REST
- **Namespace:** Resolved dynamically via `GET http://127.0.0.1:4599/n/` (defaults to `"floci-local"`).
- **Tenancy Compartment:** Default tenancy OCID is `ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000`.
- **Create Bucket:** `curl -f -X POST -H 'Content-Type: application/json' -d '{"name": "<bucket>", "compartmentId": "<tenancy>"}' http://127.0.0.1:4599/n/<ns>/b/` (HTTP 200)
- **Put Object:** `curl -f -X PUT -H 'Content-Type: application/octet-stream' --data-binary "@file" http://127.0.0.1:4599/n/<ns>/b/<bucket>/o/<object>` (HTTP 200)
- **Get Object:** `curl -f http://127.0.0.1:4599/n/<ns>/b/<bucket>/o/<object> -o output` (HTTP 200)
- **Delete Object:** `curl -f -X DELETE http://127.0.0.1:4599/n/<ns>/b/<bucket>/o/<object>` (HTTP 204)
- **Delete Bucket:** `curl -f -X DELETE http://127.0.0.1:4599/n/<ns>/b/<bucket>` (HTTP 204)

## Simulator Quirks & Operational Notes

1. **`awssim`:**
   - In open mode, SigV4 authorization headers are completely optional; path-style S3 requests succeed anonymously.
   - Sockets after shutdown may remain briefly in TCP `TIME_WAIT`. The harness sets `SO_REUSEADDR` when checking or binding ports.
2. **`azuresim`:**
   - Lacks a dedicated `/_floci/health` route. Readiness is signalled by the first HTTP 200 response (e.g. `GET /devstoreaccount1?comp=list`).
   - Azure REST conventions require `?restype=container` on container operations, and the header `x-ms-blob-type: BlockBlob` on blob PUT requests.
   - Azure returns HTTP `201 Created` for resource creation and `202 Accepted` for deletions.
3. **`gcpsim`:**
   - Object creation uses the `/upload/storage/v1/b/...` path with query parameter `uploadType=media&name=<object>`.
   - Object content retrieval requires the query parameter `?alt=media`; omitting `alt=media` returns the JSON object metadata instead of the payload bytes.
4. **`ocisim`:**
   - In open mode, standard curl requests work without `Authorization` or `Date` headers.
   - Object storage paths require the namespace prefix `/n/<namespace>/b/<bucket>/o/<object>`.
   - Bucket creation requires specifying `compartmentId` in the JSON request body.
