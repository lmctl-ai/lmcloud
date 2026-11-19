# lmcloud

Documentation: [Quick reference](https://www.lmctl.com/tools/lmcloud/) · [LLM skill](https://www.lmctl.com/tools/lmcloud/skill.html) · [Guide](https://www.lmctl.com/tools/lmcloud/guide.html) · [Reference](https://www.lmctl.com/tools/lmcloud/reference.html)

Script any cloud from lmscript with one procedural, provider-neutral API: a shared
lmcode schema (object storage, queue) implemented by `lmaws`, `lmazure`, `lmgcp`
and `lmoci`, and tested against the local emulators `awssim`, `azuresim`,
`gcpsim` and `ocisim`.

Built on `lmctl-ai/lmcode-go` (`lmcode_std_v3`, 226 standard signatures + 10 standard
REST/CLI interfaces: `RestGet`..`RestOptions`, `RestHandler`, `CliCommand`, `CliOption`,
`rest_config`, `rest_route`, `rest_serve`, `rest_stop`, `rest_cli`).

lmcloud replaces the declarative OpenTofu approach (archived as
`lmctl-ai/lmtofu`) with procedural lmscript programs.

Status: bootstrap. See [durable-memory/index.md](durable-memory/index.md).
