# Spec 007: Manifest Lifecycle Management

## Why This Is Critical

The gate's single point of failure is the manifest. If it's stale, the gate
is blind to new actions. If nobody updates it, the gate degrades silently.
This spec makes the manifest self-maintaining.

## New Commands

### `pinpoint manifest refresh`

Updates an existing manifest in-place. Resolves current tag SHAs for all
actions already in the manifest, adds any new actions found in the specified
workflows, and writes the updated manifest.

```bash
# Refresh manifest against current tag SHAs
pinpoint manifest refresh --manifest .pinpoint-manifest.json --workflows .github/workflows/

# Refresh and also discover new actions from workflows
pinpoint manifest refresh --manifest .pinpoint-manifest.json --workflows .github/workflows/ --discover
```

**Logic:**
1. Load existing manifest from `--manifest` path (local file, not API)
2. If `--discover` flag set: scan `--workflows` dir, extract all action refs,
   add any new repos/tags not already in the manifest
3. Collect all unique repos from the manifest
4. Call GraphQL `FetchTagsBatch` to resolve current tag SHAs
5. For each action/tag in the manifest:
   - If current SHA matches existing SHA: no change
   - If current SHA differs: update SHA, update `recorded_at`, print diff
   - If tag no longer exists on remote: warn, keep old entry with note
6. Write updated manifest to the same file path
7. Exit 0 if no changes, exit 3 if changes detected (useful for CI)

**Output (to stderr):**
```
Refreshing manifest (.pinpoint-manifest.json)...
  actions/checkout@v4: unchanged (34e1148...)
  actions/setup-go@v5: UPDATED 40f1582... → 8bb5382... (tag advanced)
  docker/build-push-action@v5: unchanged (ca052bb...)
  + aquasecurity/trivy-action@0.36.0: NEW (discovered from ci.yml)

Manifest updated: 1 changed, 1 added, 3 unchanged.
```

**Exit codes:** 0=no changes, 1=error, 3=changes written

### `pinpoint manifest verify`

Checks if the manifest matches current live tag SHAs without modifying it.
Essentially a dry-run of refresh.

```bash
pinpoint manifest verify --manifest .pinpoint-manifest.json
```

**Exit codes:** 0=all match, 1=error, 3=drift detected

**Output on drift:**
```
Verifying manifest (.pinpoint-manifest.json)...
  ✓ actions/checkout@v4: matches (34e1148...)
  ✗ actions/setup-go@v5: DRIFTED
    manifest: 40f1582...  (recorded 2026-03-20)
    current:  8bb5382...  (resolved just now)

✗ Manifest drift detected: 1 of 4 tags have changed.
  Run: pinpoint manifest refresh --manifest .pinpoint-manifest.json
```

## Workflow Templates

### `.github/workflows/pinpoint-refresh.yml`

Template workflow that users copy into their repo. Runs on schedule, refreshes
the manifest, and opens a PR if anything changed.

```yaml
# .github/workflows/pinpoint-refresh.yml
name: Pinpoint Manifest Refresh
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday at 6am UTC
  workflow_dispatch:       # Manual trigger

permissions:
  contents: write
  pull-requests: write

jobs:
  refresh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4

      - name: Install pinpoint
        run: |
          curl -sSL "https://github.com/tehreet/pinpoint/releases/download/v0.3.0/pinpoint-linux-amd64" \
            -o /usr/local/bin/pinpoint
          chmod +x /usr/local/bin/pinpoint

      - name: Refresh manifest
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          pinpoint manifest refresh \
            --manifest .pinpoint-manifest.json \
            --workflows .github/workflows/ \
            --discover

      - name: Create PR if changed
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          if git diff --quiet .pinpoint-manifest.json; then
            echo "No changes detected."
            exit 0
          fi
          BRANCH="pinpoint/manifest-refresh-$(date +%Y%m%d)"
          git checkout -b "$BRANCH"
          git add .pinpoint-manifest.json
          git commit -m "chore: refresh pinpoint manifest

          Updated by pinpoint manifest refresh.
          Review tag changes before merging."
          git push origin "$BRANCH"
          gh pr create \
            --title "chore: refresh pinpoint manifest" \
            --body "Automated manifest refresh by pinpoint. Review the tag SHA changes below before merging." \
            --base main
```

This template should be output by a new command:

```bash
pinpoint manifest init
```

Which writes:
- `.pinpoint-manifest.json` (generated via audit or scan)
- `.github/workflows/pinpoint-refresh.yml` (the template above)
- `.github/workflows/pinpoint-gate.yml` (reusable gate workflow)

### `.github/workflows/pinpoint-gate.yml`

Reusable workflow for org-wide gate enforcement:

```yaml
# .github/workflows/pinpoint-gate.yml
name: Security Gate
on:
  workflow_call:
    inputs:
      manifest:
        type: string
        default: '.pinpoint-manifest.json'
      fail-on-missing:
        type: boolean
        default: false

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Pinpoint Gate
        uses: tehreet/pinpoint@SHA_HERE
        with:
          manifest: ${{ inputs.manifest }}
          fail-on-missing: ${{ inputs.fail-on-missing }}
```

## Implementation

### New file: `internal/manifest/manifest.go`

```go
package manifest

type RefreshResult struct {
    Unchanged int
    Updated   int
    Added     int
    Removed   int
    Changes   []Change
}

type Change struct {
    Action     string
    Tag        string
    Type       string // "updated", "added", "removed"
    OldSHA     string
    NewSHA     string
}

func Refresh(ctx context.Context, manifestPath string, workflowDir string, discover bool, token string) (*RefreshResult, error)
func Verify(ctx context.Context, manifestPath string, token string) (*RefreshResult, error)
```

### New file: `internal/manifest/manifest_test.go`

Tests:
- TestRefreshNoChanges — all SHAs match, exit 0
- TestRefreshWithDrift — one tag changed, manifest updated, exit 3
- TestRefreshWithDiscover — new action found in workflow, added to manifest
- TestVerifyClean — all match, exit 0
- TestVerifyDrift — mismatch detected, exit 3
- TestRefreshMissingManifest — file doesn't exist, error

### Changes to `cmd/pinpoint/main.go`

Add `manifest` subcommand with sub-subcommands:
```
pinpoint manifest refresh --manifest <path> --workflows <dir> [--discover]
pinpoint manifest verify --manifest <path>
pinpoint manifest init [--org <n>]
```

### New file: `internal/manifest/templates.go`

Embeds the workflow YAML templates as Go string constants.
`manifest init` writes them to disk.

## Files to Create/Modify

- CREATE: `internal/manifest/manifest.go`
- CREATE: `internal/manifest/manifest_test.go`
- CREATE: `internal/manifest/templates.go`
- MODIFY: `cmd/pinpoint/main.go` — add `manifest` subcommand routing

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
./pinpoint manifest --help
./pinpoint manifest refresh --help
./pinpoint manifest verify --help
./pinpoint manifest init --help
```
