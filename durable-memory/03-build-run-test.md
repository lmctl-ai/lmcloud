# Build, Run, Test

## Toolchain Requirements

- Go 1.26 or Go 1.27 (`GOTOOLCHAIN=auto` handles minor toolchain transitions automatically).
- CGO is disabled (`CGO_ENABLED=0`).
- `lmscript` on PATH (installed via `npm i -g @lmctl-ai/lmctl@0.2.420`).

## Build

Compile the single static executable:
```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ./bin/lmcloud ./cmd/lmcloud
```

Binary inspection:
```bash
file ./bin/lmcloud
# ./bin/lmcloud: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
ldd ./bin/lmcloud
# not a dynamic executable
```

Binary size: ~106MB (includes the entire OpenTofu runtime, HCL parsers, providers, encryption subsystem, and state backends).

## Test Suite

Run the full verification script:
```bash
./test.sh
```

Checks performed (38/38 checks):
1. Binary exists and executable
2. Static linking verification (`ldd`)
3. `--version` output matches `lmcloud X.Y.Z`
4. `--version` contains a single version number (`grep -Eo '[0-9]+\.[0-9]+\.[0-9]+'`)
5. Host signatures parity against `lmscript --dsl-signatures schema/lmcloud.dsl.json`
6. Host-only signatures parity against `lmscript --dsl-signatures schema/lmcloud.dsl.json --without-std`
7. Embedded schema byte-identity (`cmp <(./bin/lmcloud --dsl-schema --json) schema/lmcloud.dsl.json`)
8. Schema summary text formatting
9-26. All 18 examples (`examples/01-fmt-and-validate.lms` .. `examples/18-module-composition.lms`)
27. Implicit std and testing helpers (`assert_close`, `print`) compile and run
28. Invalid CLI flags return exit code 2
29. Corrupted bytecode rejected with exit code 3 (`LOAD_BAD_BYTECODE`)
30. Non-existent directory handling in plan
31. Uninitialized directory handling in apply
32. Unknown output key or post-`destroy` output query returns empty string, populates `last_error()`, and emits nothing on `stderr`
33. `tofu.var()` values persist in `<dir>/.terraform/lmcloud-vars.json` across separate cleanup processes
34. Formatting invalid HCL returns original string and records `last_error()`
35. `fmt_check` distinguishes formatted from unformatted HCL
36. `state_list` and `import` against missing dir handle error cleanly
37. `go test ./internal/builtin/providers`
38. `go test ./internal/lmhost`

Compiler >=0.2.420 is capability-probed against an empty schema; the existing host-only schema is unchanged, with default SDK std and full/`--without-std` parity checked alongside a std-only runtime probe.
