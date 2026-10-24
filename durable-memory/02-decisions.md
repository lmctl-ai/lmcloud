# Decisions and Architecture

## 1. Upstream Base: OpenTofu v1.13.2

Tag `v1.13.2` is selected as the stable base. Upstream files are preserved unmodified wherever possible.

## 2. In-Process Execution via `internal/command`

Rather than implementing low-level graph traversal or spawning external CLI binaries, `internal/lmhost` calls directly into OpenTofu's `command.Meta` and command implementations (`InitCommand`, `ValidateCommand`, `PlanCommand`, `ApplyCommand`, `OutputCommand`, `ShowCommand`, `FmtCommand`):
- Clean abstraction matching upstream CLI semantics.
- Virtual `terminal.Streams` backed by OS pipes capture all stdout and stderr streams.
- `last_error()` retrieves captured error output on non-zero exit codes.

## 3. Schema Design

Context:
```json
"context": {
  "tofu": "Tofu"
}
```

Types:
- `Tofu`:
  - `init(dir: string) -> bool`
  - `validate(dir: string) -> bool`
  - `fmt(text: string) -> string`
  - `plan(dir: string) -> Plan`
  - `apply(dir: string) -> bool`
  - `destroy(dir: string) -> bool`
  - `output(dir: string, name: string) -> string`
  - `var(name: string, value: string) -> void`
  - `show_state(dir: string) -> string`
  - `last_error() -> string`
- `Plan`:
  - `add() -> int`
  - `change() -> int`
  - `destroy() -> int`
  - `summary() -> string`
  - `save(path: string) -> bool`

## 4. Exit Codes & Results

Follows sibling host convention (`lmfilament`, `lmvideo`):
- `0`: OK (`{"ok": true, "result": ...}`)
- `2`: Usage error (flag syntax, missing arguments)
- `3`: Load / verify / runtime bytecode error (`{"ok": false, "phase": ..., "code": ..., "message": ...}`)
- `4`: Application fatal failure (`APP_FAIL`)

## 5. Automated Releases

Automatic semantic releases on every push to `main` via `.github/workflows/ci.yml`:
- Version: `0.1.<run_number>`.
- Artifacts: binaries for `linux-x64`, `linux-arm64`, `macos-arm64`, `macos-x64`, and `windows-x64`, plus `SHA256SUMS`.
