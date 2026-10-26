# Open Items

## Post-v1 Enhancements

1. **External Cloud Providers (`aws`, `google`, `azurerm`, etc.):**
   Six utility providers (`random`, `null`, `local`, `time`, `archive`, `tls`) plus `terraform_data` are embedded in-process via `bufconn` gRPC for zero-network execution. External cloud providers (`hashicorp/aws`, `hashicorp/google`, `hashicorp/azurerm`, etc.) are resolved and downloaded automatically by `tofu.init(dir)` via `meta.ProviderSource` (`registry.opentofu.org`, `.tofurc` / `TF_CLI_CONFIG_FILE` mirrors, `terraform.d/plugins`, and `TF_PLUGIN_CACHE_DIR`), locked in `.terraform.lock.hcl`, and executed as managed `go-plugin` gRPC child processes (`plugin.CleanupClients()`).

2. **Concurrent Directory Execution:**
   Currently, `runCommand` holds a host mutex lock because `os.Chdir()` alters the working directory of the entire OS process. If parallel execution across distinct configurations is required in future versions, thread-safe virtual filesystem abstractions or separate workdir scoping within OpenTofu command packages could be evaluated.

3. **Detailed JSON Plan Export (Resolved):**
   `Plan.json() -> string` and `tofu.plan_json(dir: string) -> string` expose the full machine-readable JSON representation produced by `tofu show -json <planfile>`.
