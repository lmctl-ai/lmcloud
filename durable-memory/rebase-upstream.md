# Keeping Current with Upstream OpenTofu

This fork tracks upstream releases from `https://github.com/opentofu/opentofu`.

## Step-by-Step Rebase / Sync Procedure

1. **Configure Upstream Remote (if not present):**
   ```bash
   git remote add upstream https://github.com/opentofu/opentofu.git || true
   git fetch upstream --tags
   ```

2. **Check for New Stable Releases:**
   ```bash
   gh release list -R opentofu/opentofu -L 5
   ```

3. **Merge or Rebase against New Tag:**
   For a minor/patch update (e.g. `v1.13.3`):
   ```bash
   git checkout main
   git merge v1.13.3
   ```

4. **Verify Internal Package Compatibility:**
   Check if upstream changed signatures in:
   - `internal/command/` (`InitCommand`, `ValidateCommand`, `PlanCommand`, `ApplyCommand`, `OutputCommand`, `ShowCommand`, `FmtCommand`)
   - `internal/plans/planfile/` (`Open`, `ReadPlan`)
   - `internal/command/views/` (`NewView`)
   - `internal/terminal/` (`Streams`)

5. **Re-run Tests:**
   ```bash
   go test -v ./internal/lmhost
   CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ./bin/lmcloud ./cmd/lmcloud
   ./test.sh
   ```

6. **Update Documentation:**
   Update `version/VERSION` references in durable-memory if upstream bumped version numbers.
