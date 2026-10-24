# Purpose and Place

lmcloud is a native `lmscript` `_dsl_` host: a single, statically linked, dependency-free binary that runs LMScript `_dsl_` bytecode (via SDK `github.com/lmctl-ai/lmcode-go`) and embeds the OpenTofu v1.13.2 engine in-process to expose infrastructure operations (init, validate, fmt, plan, apply, destroy, output, state inspection) as typed objects to DSL scripts.

```
LMScript (.lms) --lmscript--> DSL bytecode (.dslb) --lmcloud --dsl--> In-Process OpenTofu Engine
                  schema/lmcloud.dsl.json  (SHA-256 bound to bytecode)
```

## Licensing & Fork Rationale

HashiCorp Terraform >= 1.6 transitioned to the Business Source License (BUSL-1.1), which is non-open-source and restricts competing hosted and embedded infrastructure offerings.

lmcloud is built upon **OpenTofu** (`github.com/opentofu/opentofu`, MPL-2.0, the open source community fork of Terraform):
- MPL-2.0 is an OSI-approved open source copyleft license allowing in-process inclusion and distribution.
- OpenTofu maintains identical HCL syntax, provider protocols, and state file schemas.
- Go enforces that packages under `internal/` cannot be imported from outside the module. OpenTofu's core engine, CLI commands, state manager, and configuration loaders reside under `internal/`. Therefore, lmcloud is maintained as a fork under module path `github.com/opentofu/opentofu` in `github.com/lmctl-ai/lmcloud`.

## License Split

- **Upstream OpenTofu files:** Unchanged, under MPL-2.0. Upstream `README.md` is preserved at `UPSTREAM-README.md`. Upstream `LICENSE` (MPL-2.0) remains at repository root.
- **Our added files:** Under MIT (`// SPDX-License-Identifier: MIT`). Added locations include `cmd/lmcloud/`, `internal/lmhost/`, `schema/`, `examples/`, `durable-memory/`, `test.sh`, `scripts/`, and `.github/workflows/ci.yml`.
- **Modified upstream files:** `go.mod` and `go.sum` (required `github.com/lmctl-ai/lmcode-go`). Documented in `durable-memory/04-gotchas.md`.

## Key Capabilities (v1)

- **Zero Network Execution:** All v1 operations work entirely offline without network access using the built-in provider `terraform.io/builtin/terraform` (`terraform_data` resource), `locals`, `variables`, `outputs`, `check` blocks, `count`, `for_each`, and local file-system modules.
- **In-Process Engine Execution:** No child processes (`os/exec` calling a `tofu` CLI binary) are spawned. All operations invoke OpenTofu's `internal/command` in-process with virtualized terminal pipes and UI views.
- **Static Binary:** Builds with `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"` into a single dependency-free executable.
