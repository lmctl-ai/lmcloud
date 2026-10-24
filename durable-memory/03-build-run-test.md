# Build, Run, Test

## Toolchain Requirements

- Go 1.26 or Go 1.27 (`GOTOOLCHAIN=auto` handles minor toolchain transitions automatically).
- CGO is disabled (`CGO_ENABLED=0`).
- `lmscript` on PATH (installed via `npm i -g @lmctl-ai/lmctl@0.2.401`).

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

Checks performed (19/19 checks):
1. Binary exists and executable
2. Static linking verification (`ldd`)
3. `--version` output matches `lmcloud X.Y.Z (opentofu 1.13.2)`
4. Host signatures parity against `lmscript --dsl-signatures schema/lmcloud.dsl.json`
5. Embedded schema byte-identity (`cmp <(./bin/lmcloud --dsl-schema --json) schema/lmcloud.dsl.json`)
6. Schema summary text formatting
7. `examples/01-fmt-and-validate.lms`
8. `examples/02-plan-inspection.lms`
9. `examples/03-lifecycle.lms`
10. `examples/04-variables-and-locals.lms`
11. `examples/05-count-and-for-each.lms`
12. `examples/06-local-module.lms`
13. Invalid CLI flags return exit code 2
14. Corrupted bytecode rejected with exit code 3 (`LOAD_BAD_BYTECODE`)
15. Non-existent directory handling in plan
16. Uninitialized directory handling in apply
17. Unknown output key handling (returns empty string and populates `last_error()`)
18. Formatting invalid HCL returns original string and records `last_error()`
19. In-process Go unit tests (`go test -v ./internal/lmhost`)
