# lmcloud

**Drive OpenTofu infrastructure operations from LMScript with one static executable.**

lmcloud is a native host for the lmscript `_dsl_` statement. It embeds the [OpenTofu](https://github.com/opentofu/opentofu) v1.13.2 engine in-process and exposes it through [`schema/lmcloud.dsl.json`](schema/lmcloud.dsl.json). Scripts can initialize, format, validate, plan, apply, destroy, and inspect state using typed objects with zero runtime dependencies.

```lms
p = _dsl_ cli="lmcloud" install="github:lmctl-ai/lmcloud@latest";
let ok_init = tofu.init("infra/production");
let plan = tofu.plan("infra/production");
let adds = plan.add();
let ok_apply = tofu.apply("infra/production");
let endpoint = tofu.output("infra/production", "api_endpoint");
let state_json = tofu.show_state("infra/production");
let ok_destroy = tofu.destroy("infra/production");
end _dsl_
```

## What it does (and does not)

- **Real in-process engine:** All operations (`init`, `validate`, `fmt`, `plan`, `apply`, `destroy`, `output`, `show_state`) run within the process through OpenTofu's core `internal/command` subsystem with captured I/O streams. No child processes (`tofu` or `terraform` binaries) are spawned.
- **Zero-network offline operations:** v1 operates completely offline with zero network access using the built-in provider `terraform.io/builtin/terraform` (`terraform_data` resource), `locals`, `variables`, `outputs`, `check` blocks, `count`, `for_each`, and local filesystem modules.
- **Third-party cloud providers:** External cloud providers (AWS, Azure, GCP, Kubernetes) operate as separate gRPC plugin executables. In OpenTofu, downloading them requires network during `init`. A future version may embed selected providers.
- **Single static executable:** Built with `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"` into a standalone binary with no dynamic library dependencies.

## Example Gallery

All examples live in [`examples/`](examples) and run completely offline:

| **01-fmt-and-validate** | **02-plan-inspection** | **03-lifecycle** |
| --- | --- | --- |
| <img src="docs/images/01-fmt-and-validate.png" width="290"> | <img src="docs/images/02-plan-inspection.png" width="290"> | <img src="docs/images/03-lifecycle.png" width="290"> |
| Canonical HCL formatting and syntax validation in memory without cloud dependencies.<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmcloud/main/examples/01-fmt-and-validate.lms` | In-process planning, reading change counts (`plan.add()`, `plan.change()`, `plan.destroy()`), and saving binary plan files.<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmcloud/main/examples/02-plan-inspection.lms` | Complete lifecycle: initialize directory, plan, apply, retrieve outputs, inspect state JSON, and destroy.<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmcloud/main/examples/03-lifecycle.lms` |

| **04-variables-and-locals** | **05-count-and-for-each** | **06-local-module** |
| --- | --- | --- |
| <img src="docs/images/04-variables-and-locals.png" width="290"> | <img src="docs/images/05-count-and-for-each.png" width="290"> | <img src="docs/images/06-local-module.png" width="290"> |
| Programmatic variable injection via `tofu.var()` before plan/apply, evaluating computed local expressions.<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmcloud/main/examples/04-variables-and-locals.lms` | Multi-resource iteration and scaling using HCL `count` and `for_each` on `terraform_data`.<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmcloud/main/examples/05-count-and-for-each.lms` | Hierarchical module composition using local directory modules (`source = "./modules/subservice"`).<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmcloud/main/examples/06-local-module.lms` |

| **lmcloud CLI & Schema** | **tofu.plan Summary** |
| --- | --- |
| <img src="docs/images/lmcloud-cli.png" width="450"> | <img src="docs/images/tofu-plan.png" width="450"> |
| Version, embedded OpenTofu engine version, and DSL schema method signatures.<br>`lmcloud --version && lmcloud --dsl-schema` | Structured plan inspection, change counts, and binary plan persistence.<br>`tofu.plan(dir).summary()` |

## Licensing & Fork Rationale

HashiCorp Terraform >= 1.6 adopted the Business Source License (BUSL-1.1), which is non-open-source and restricts commercial and competitive use.

lmcloud is built upon **OpenTofu** (`github.com/opentofu/opentofu`, MPL-2.0), the open source, community-governed Terraform fork. OpenTofu maintains complete HCL compatibility, identical provider protocols, and state file interoperability.

### License Split

- **Upstream OpenTofu files:** Unchanged and governed by Mozilla Public License 2.0 (MPL-2.0). Upstream documentation is preserved at [`UPSTREAM-README.md`](UPSTREAM-README.md); upstream [`LICENSE`](LICENSE) remains untouched.
- **Our added files:** Governed by the MIT License (`// SPDX-License-Identifier: MIT`). Added paths:
  - `cmd/lmcloud/`
  - `internal/lmhost/`
  - `schema/`
  - `examples/`
  - `durable-memory/`
  - `scripts/`
  - `test.sh`
  - `.github/workflows/ci.yml`
- **Modified upstream files:**
  - `go.mod`: Added `github.com/lmctl-ai/lmcode-go` dependency.
  - `go.sum`: Checksums for `github.com/lmctl-ai/lmcode-go`.
  - `.gitignore`: Added `build/` and `dist/` directories.

## Build and Test

### Prerequisites

- Go 1.26 or Go 1.27
- `lmscript` (installed via `npm i -g @lmctl-ai/lmctl@0.2.401`)

### Build Static Executable

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ./bin/lmcloud ./cmd/lmcloud
```

Verify static linking:
```bash
file ./bin/lmcloud
# ./bin/lmcloud: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
ldd ./bin/lmcloud
# not a dynamic executable
```

### Run Tests

```bash
./test.sh
```

Verifies static linkage, schema byte-identity, signature parity against `lmscript --dsl-signatures`, all 6 zero-network examples, error handling paths (invalid flags, corrupt bytecode, missing directory, uninitialized apply, unknown output name, invalid HCL), and Go unit tests.
