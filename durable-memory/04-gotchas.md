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

4. **Output `-raw` vs Complex Types:**
   `tofu output -raw` writes raw text without trailing whitespace for strings/numbers/booleans, but fails for maps/lists/objects. `Host.Output()` attempts `-raw` first, and if that fails, falls back to `-json` to return a machine-readable JSON representation.

5. **`_dsl_` Scope in LMScript:**
   LMScript treats the `_dsl_` block as an independent language scope. Outer LMScript variables cannot be directly referenced inside `_dsl_`. Use `let var = ...` inside `_dsl_` or pass string literals directly.

6. **Case-Insensitive Filesystems and `version/`:**
   On case-insensitive file systems (macOS APFS and Windows NTFS), a root-level file named `VERSION` collides with OpenTofu's package directory `version/`, causing `VERSION: Is a directory` errors during version stamping. lmcloud uses `LMCLOUD_VERSION` at the repository root and `cmd/lmcloud/VERSION` inside `cmd/lmcloud/`.
