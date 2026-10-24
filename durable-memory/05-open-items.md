# Open Items

## Post-v1 Enhancements

1. **Embedded / Pre-bundled Cloud Providers:**
   In v1, zero network execution is guaranteed by relying exclusively on the built-in `terraform_data` provider, locals, outputs, checks, variables, and local modules. External cloud providers (AWS, Azure, GCP, Cloudflare) operate as separate gRPC plugin processes and require network downloads during `tofu init`. A future version could embed selected popular provider plugins directly into the binary or vendor them in a cache.

2. **Concurrent Directory Execution:**
   Currently, `runCommand` holds a host mutex lock because `os.Chdir()` alters the working directory of the entire OS process. If parallel execution across distinct configurations is required in future versions, thread-safe virtual filesystem abstractions or separate workdir scoping within OpenTofu command packages could be evaluated.

3. **Detailed JSON Plan Export:**
   `Plan.summary()` returns the standard human-readable change summary (`Plan: X to add, Y to change, Z to destroy.`). A future method `Plan.json() -> string` could expose the full machine-readable JSON representation produced by `tofu show -json <planfile>`.
