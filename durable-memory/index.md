# lmcloud durable memory

Technical documentation, architecture notes, and operational procedures for `lmcloud` (OpenTofu in-process DSL host).
Repository: https://github.com/lmctl-ai/lmcloud.

## Overview
lmcloud embeds OpenTofu core in-process to provide infrastructure management directly within lmscript.

## Document map

| File | Contents |
| --- | --- |
| [01-purpose-and-place.md](01-purpose-and-place.md) | Mission, architecture, and distinction from standalone tofu/terraform |
| [02-decisions.md](02-decisions.md) | Architectural and design decisions |
| [03-build-run-test.md](03-build-run-test.md) | Building the Go binary, running tests, and schema verification |
| [04-gotchas.md](04-gotchas.md) | OpenTofu internals, state locks, and concurrency lessons |
| [05-open-items.md](05-open-items.md) | Planned features and roadmap |
| [rebase-upstream.md](rebase-upstream.md) | Upstream OpenTofu synchronization and rebasing procedures |

## Adding an example or function

### Adding an example
1. Create `examples/<name>.lms` using `_dsl_ cli="lmcloud" install="github:lmctl-ai/lmcloud@latest"`.
2. Provide local HCL configuration under an accompanying subfolder or self-contained `terraform_data` resource.
3. Test locally: `PATH=$PWD/bin:$PATH lmscript examples/<name>.lms <output>.dslb`.
4. Capture output to `docs/images/src/<name>.txt` and render `docs/images/<name>.png`.
5. Add test coverage in `test.sh` and update `README.md` gallery with `<img src="...">` and `lmctl autorun` caption.

### Adding a host function/method
1. Declare in `schema/lmcloud.dsl.json`.
2. Implement in `internal/lmhost/registry.go` using `lmcode.Registry`.
3. Verify `./test.sh` passes and schema signatures match.

## Releases
Releases are built and published automatically on every push to `main` across Linux, macOS, and Windows.
