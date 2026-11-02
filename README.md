# lmcloud

Script any cloud from lmscript with one procedural, provider-neutral API: a shared
lmcode schema (object storage, queue) implemented by `lmaws`, `lmazure`, `lmgcp`
and `lmoci`, and tested against the local emulators `awssim`, `azuresim`,
`gcpsim` and `ocisim`.

lmcloud replaces the declarative OpenTofu approach (archived as
`lmctl-ai/lmtofu`) with procedural lmscript programs.

Status: bootstrap. See [durable-memory/index.md](durable-memory/index.md).
