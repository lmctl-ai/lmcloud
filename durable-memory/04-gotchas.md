# Gotchas & Modified Upstream Files

## Modified Upstream Files

Per the fork guidelines, upstream OpenTofu files must remain untouched wherever possible. The following files are the only modified upstream files:
1. `go.mod`: Added `require github.com/lmctl-ai/lmcode-go v0.0.0-20261024145206-02a079095550`.
2. `go.sum`: Dependency checksums for `github.com/lmctl-ai/lmcode-go`.
3. `.gitignore`: Added `build/` and `dist/` build artifacts directories.
4. `README.md`: Moved to `UPSTREAM-README.md` to allow product `README.md` at root.
5. `.github/workflows/`: Removed upstream release and CI workflows that cannot run in this fork; added `.github/workflows/ci.yml`.

## In-Process Execution Gotchas

1. **Working Directory & Relative Paths:**
   OpenTofu commands often assume `.` is the root module directory and use `os.Getwd()` internally (e.g., in encryption config loading, module path resolution). In `internal/lmhost/host.go`, `runCommand` temporarily changes process working directory to the target directory (`os.Chdir(absTarget)`) under a mutex lock, and restores the original working directory on completion.

2. **Plan Encryption Parameter:**
   `planfile.Open(path, enc)` panics with a nil pointer dereference if `enc` is passed as `nil`. Always pass `encryption.PlanEncryptionDisabled()` for unencrypted local plan files.

3. **`FmtCommand` Input Stream:**
   `command.FmtCommand` has an unexported `input io.Reader` field. To pass text from memory, instantiate the command via the exported constructor `command.FmtCommander(strings.NewReader(text))` and execute with `command.RunCommand(cmd, meta, []string{"-"})`.

4. **Output `-json` & Post-Destroy Queries:**
   `tofu output -raw <name>` returns exit code `0` with a `"Warning: No outputs found"` diagnostic on `stdout` when the state has zero outputs (such as after `tofu.destroy(dir)`), whereas `tofu output -no-color -json <name>` consistently returns exit code `1` with `missingOutputError(name)` whenever `<name>` is absent. `Host.Output()` uses `-no-color -json` under captured streams, unmarshals JSON string scalars back to raw strings, and reports missing keys exclusively through `tofu.last_error()` with zero `stderr` noise.

5. **External Provider Installation (`meta.ProviderSource`) & Plugin Cleanup:**
   In OpenTofu's `command.Meta`, leaving `Meta.ProviderSource == nil` causes `meta.providerInstallSource()` to return an always-empty `getproviders.MultiSource(nil)`, which makes `tofu.init` fail with `"no available releases match"` for any non-embedded provider (`hashicorp/aws`, `hashicorp/google`, `hashicorp/azurerm`, etc.). `internal/lmhost/provider_source.go` wires `cliconfig.LoadConfig`, `newServiceDiscovery`, local `terraform.d/plugins` / XDG plugin mirrors, `getproviders.NewRegistrySource`, `ModulePackageFetcher`, and `TF_PLUGIN_CACHE_DIR` into `command.Meta`, and calls `plugin.CleanupClients()` after each command so external provider `go-plugin` subprocesses are cleanly reaped.

6. **`tofu.var()` Persistence & Undeclared Variable Filtering:**
   `Host.Var(k, v)` stores variables in memory and syncs them per working directory to `<dir>/.terraform/lmcloud-vars.json` (`0600`) during `init`, `plan`, `apply`, `destroy`, and `import`. A separate cleanup process (`lmcloud --lmcode cleanup.dslb`) running `tofu.destroy(dir)` automatically loads those persisted variables. `Host.buildVarArgs(dir)` also parses `dir` with `configs.NewParser(nil).LoadConfigDir(absDir)` and filters `-var` arguments to variables declared in `dir`.

7. **`_dsl_` / `_lmcode_` Scope in LMScript:**
   LMScript treats the `_lmcode_` / `_dsl_` block as an independent language scope. Outer LMScript variables cannot be directly referenced inside `_lmcode_`. Use `let var = ...` inside `_lmcode_` or pass string literals directly.

8. **Case-Insensitive Filesystems and `version/`:**
   On case-insensitive file systems (macOS APFS and Windows NTFS), a root-level file named `VERSION` collides with OpenTofu's package directory `version/`, causing `VERSION: Is a directory` errors during version stamping. lmcloud uses `LMCLOUD_VERSION` at the repository root and `cmd/lmcloud/VERSION` inside `cmd/lmcloud/`.

9. **Default Shared Provider Plugin Cache & Sidecar `.h1` Hash Cache:**
   Large external cloud providers like `hashicorp/aws` (~707 MB uncompressed) are slow to re-download and re-hash across ephemeral working directories. `internal/lmhost/host.go` configures `<UserCacheDir>/lmcloud/plugin-cache` by default (overrideable via `LMCLOUD_PLUGIN_CACHE_DIR` or `TF_PLUGIN_CACHE_DIR`, disabled via `LMCLOUD_DISABLE_PLUGIN_CACHE=1`) with `PluginCacheMayBreakDependencyLockFile = true`. In `internal/getproviders/hash.go`, `PackageHashV1` stores a sidecar `<packageDir>.h1` file keyed by `(size, mtime_ns, mode)` alongside `<packageDir>.lock`, and `internal/providercache/installer.go` falls back to `Dir.CachedVersions` when offline, reducing warm `tofu.init` with `hashicorp/aws` to ~0.88s.

10. **Least-Privilege EC2 Spot Instance Teardown (`CancelSpotInstanceRequests` Fallback):**
    When destroying an `aws_instance` launched with `instance_market_options { market_type = "spot" }`, `terraform-provider-aws` inspects `spot_instance_request_id` and `instance_market_options` in state and calls `ec2:CancelSpotInstanceRequests` before calling `ec2:TerminateInstances`. Because `RunInstances` does not tag the implicit `spot-instances-request` resource unless separately specified and strict least-privilege session policies reject unscoped `ec2:CancelSpotInstanceRequests`, `CancelSpotInstanceRequests` fails with `UnauthorizedOperation` even when `ec2:TerminateInstances` is permitted on the tagged instance. In `internal/lmhost/host.go`, `Host.Destroy(dir)` detects `CancelSpotInstanceRequests` errors on destroy, strips `spot_instance_request_id`, `instance_market_options`, and `instance_lifecycle` from `<dir>/terraform.tfstate` via `clearSpotRequestIDs`, and retries `ApplyCommand{Destroy: true}` with `-refresh=false`. `terraform-provider-aws` then proceeds directly to `ec2:TerminateInstances`, which terminates the Spot instance and automatically closes its one-time Spot request.
