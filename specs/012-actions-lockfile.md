# Spec 012: Actions Lockfile

## The Pitch

GitHub Actions has no lockfile. npm has package-lock.json. Go has go.sum.
Python has requirements.txt. But the system that executes arbitrary code
with access to all your secrets — GitHub Actions — resolves every
dependency at runtime with no integrity verification.

Pinpoint's manifest already IS a lockfile. This spec reframes it as one
through naming, a one-word command, and a default behavior change.

## Three Changes

### Change 1: `pinpoint lock` command

```bash
pinpoint lock
```

That's it. No flags required. It:
1. Scans `.github/workflows/` for all `uses:` directives
2. Resolves every tag to its current commit SHA via GraphQL
3. Writes `.github/actions-lock.json`

If the lockfile already exists, it updates it: new actions are added,
existing SHAs are refreshed, removed actions are pruned.

Under the hood, `pinpoint lock` is equivalent to:
```bash
pinpoint manifest refresh \
  --manifest .github/actions-lock.json \
  --workflows .github/workflows/ \
  --discover
```

Optional flags (passed through to manifest refresh):
- `--workflows <dir>` — override workflow directory (default: `.github/workflows/`)
- `--lockfile <path>` — override lockfile path (default: `.github/actions-lock.json`)

Exit codes:
- 0: lockfile is unchanged (all SHAs already match)
- 1: error
- 3: lockfile was updated (new SHAs written)

### Change 2: Default file path

Old default: `.pinpoint-manifest.json`
New default: `.github/actions-lock.json`

The `.github/` directory is where GitHub Actions configuration lives.
Putting the lockfile there is natural. The name `actions-lock.json`
communicates intent instantly to anyone who's used npm or Go.

**Backwards compatibility:** When resolving the lockfile path (in both
the gate and the lock command), check in this order:

1. If `--manifest` or `--lockfile` flag is set: use that path exactly
2. If `.github/actions-lock.json` exists: use it
3. If `.pinpoint-manifest.json` exists: use it (legacy fallback)
4. Neither exists: no lockfile found

This means existing users with `.pinpoint-manifest.json` don't break.
They just see a one-line notice:

```
ℹ Using legacy manifest path .pinpoint-manifest.json
  Migrate with: pinpoint lock
```

The `pinpoint lock` command always writes to `.github/actions-lock.json`.
If a legacy `.pinpoint-manifest.json` exists, it reads from it first
(to preserve existing entries), writes the new file, and suggests:

```
✓ Created .github/actions-lock.json (4 actions, 4 tags)
ℹ You can now remove .pinpoint-manifest.json
```

### Change 3: Gate enforces lockfile by default

Current behavior: if an action is in the workflow but NOT in the lockfile,
the gate warns and passes (exit 0). This is the `--fail-on-missing` flag.

New behavior:

- If `.github/actions-lock.json` exists → `--fail-on-missing` defaults to `true`
- If `.pinpoint-manifest.json` exists (legacy) → `--fail-on-missing` defaults to `false`
- If `--fail-on-missing` is explicitly passed → always honored

The logic: if you've committed a file called `actions-lock.json`, you
intend it to be enforced. If you're still on the legacy manifest name,
we don't change your existing behavior.

This is the critical UX shift. A lockfile that warns but doesn't fail
is not a lockfile. It's a suggestion.

## Lockfile Format

No changes to the JSON structure. Same format, new default name:

```json
{
  "version": 1,
  "generated_at": "2026-03-21T15:00:00Z",
  "generated_by": "pinpoint lock",
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "recorded_at": "2026-03-21T15:00:00Z"
      }
    },
    "actions/setup-go": {
      "v5": {
        "sha": "40f1582b2485089dde7abd97c1529aa768e1baff",
        "recorded_at": "2026-03-21T15:00:00Z"
      }
    }
  }
}
```

## Complete Workflow (What Users See)

### Setup (once)

```bash
# Install
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

# Generate lockfile
cd your-repo
pinpoint lock

# Commit
git add .github/actions-lock.json
git commit -m "Add actions lockfile"
git push
```

### Gate (every CI run)

```yaml
steps:
  - uses: tehreet/pinpoint@FULL_SHA
  - uses: actions/checkout@v4      # verified against lockfile
  - uses: actions/setup-go@v5      # verified against lockfile
```

If `actions/checkout@v4` has been repointed since the lockfile was
committed, the gate fails and the job aborts. Exactly like `go build`
failing when `go.sum` doesn't match.

### Update (when you change dependencies)

```bash
# After adding a new action to a workflow, or updating a version:
pinpoint lock
git add .github/actions-lock.json
git commit -m "Update actions lockfile"
```

Or automate it with the refresh workflow from spec 007:
- Weekly cron runs `pinpoint lock`
- If lockfile changed, opens a PR
- Team reviews SHA changes before merging

### Verify (check without modifying)

```bash
pinpoint lock --verify
```

Read-only mode. Exit 0 if lockfile matches live tags, exit 3 if drift.
Equivalent to `pinpoint manifest verify` but with the right defaults.

## Implementation

### Changes to `cmd/pinpoint/main.go`

Add `lock` as a top-level subcommand:

```go
case "lock":
    cmdLock()
```

```go
func cmdLock() {
    lockfile := getFlag("lockfile")
    if lockfile == "" {
        lockfile = resolveLockfilePath(".")
    }
    workflowDir := getFlag("workflows")
    if workflowDir == "" {
        workflowDir = ".github/workflows/"
    }
    verify := hasFlag("verify")

    if verify {
        // delegate to manifest verify logic
        // ...
        return
    }

    // delegate to manifest refresh with --discover
    // ...
}
```

Add `resolveLockfilePath` helper:

```go
// resolveLockfilePath checks for lockfile in priority order.
// Returns the path and whether it's the legacy format.
func resolveLockfilePath(dir string) (path string, legacy bool) {
    newPath := filepath.Join(dir, ".github", "actions-lock.json")
    if _, err := os.Stat(newPath); err == nil {
        return newPath, false
    }
    oldPath := filepath.Join(dir, ".pinpoint-manifest.json")
    if _, err := os.Stat(oldPath); err == nil {
        return oldPath, true
    }
    // Neither exists — default to new path (will be created)
    return newPath, false
}
```

Update `cmdGate` to use `resolveLockfilePath` when no `--manifest` flag:

```go
manifestPath := getFlag("manifest")
isLegacy := false
if manifestPath == "" {
    // For the gate running in CI, check both paths via the API
    // The gate fetches from the API, not local disk, so we check
    // both paths and use whichever exists.
    // Try new path first, fall back to legacy.
    manifestPath = ".github/actions-lock.json"
    // (The gate will try this path; if 404, try legacy path)
}
```

Actually, the gate fetches via API, not local disk. So the resolution
needs to happen at the API level in gate.go:

```go
// In RunGate, after determining manifestRef:
manifestContent, err := client.fetchFileContent(ctx, opts.Repo, opts.ManifestPath, manifestRef)
if err != nil && isNotFound(err) {
    // Try legacy path
    if opts.ManifestPath == ".github/actions-lock.json" {
        legacyPath := ".pinpoint-manifest.json"
        fmt.Fprintf(messageWriter, "  ℹ No lockfile at %s, trying legacy path %s\n",
            opts.ManifestPath, legacyPath)
        manifestContent, err = client.fetchFileContent(ctx, opts.Repo, legacyPath, manifestRef)
        if err == nil {
            opts.ManifestPath = legacyPath
            isLegacy = true
        }
    }
}
```

When the lockfile is `.github/actions-lock.json` (not legacy), the gate
defaults `FailOnMissing` to true unless explicitly overridden:

```go
// In cmdGate, after resolving the path:
if !hasFlag("fail-on-missing") && !isLegacy {
    opts.FailOnMissing = true  // lockfile enforces by default
}
```

### Changes to `internal/gate/gate.go`

Add fallback path resolution as described above.

### Changes to `action.yml`

```yaml
inputs:
  manifest:
    description: 'Path to lockfile (default: auto-detect .github/actions-lock.json or .pinpoint-manifest.json)'
    required: false
    default: '.github/actions-lock.json'
```

### Changes to `cmd/pinpoint/main.go` (cmdManifestInit)

Update `manifest init` to write `.github/actions-lock.json` instead of
`.pinpoint-manifest.json`.

### Changes to help text

Update usage strings:
```
pinpoint lock          Generate or update .github/actions-lock.json
pinpoint lock --verify Check lockfile against live tags without modifying
```

## Tests

### TestLock_ResolvePath_NewExists
`.github/actions-lock.json` exists → returns new path, legacy=false

### TestLock_ResolvePath_LegacyExists
Only `.pinpoint-manifest.json` exists → returns legacy path, legacy=true

### TestLock_ResolvePath_BothExist
Both exist → returns new path (takes priority)

### TestLock_ResolvePath_NeitherExists
Neither exists → returns new path (will be created)

### TestGate_LockfileEnforcesByDefault
Gate with `.github/actions-lock.json` and an action not in the lockfile.
No `--fail-on-missing` flag. Expected: exit 2 (enforced by default).

### TestGate_LegacyManifestWarnsOnly
Gate with `.pinpoint-manifest.json` and an action not in the manifest.
No `--fail-on-missing` flag. Expected: exit 0 with warning (legacy behavior).

### TestGate_FallbackToLegacy
Gate checks `.github/actions-lock.json` (404), falls back to
`.pinpoint-manifest.json` (found). Verification works.

### TestLock_CreatesNewLockfile
No lockfile exists. `pinpoint lock` scans workflows, creates
`.github/actions-lock.json`. File is valid JSON, contains discovered actions.

### TestLock_UpdatesExisting
Lockfile exists with 3 actions. Workflow now references 4 actions.
`pinpoint lock` adds the new action, updates SHAs. Exit 3 (changed).

### TestLock_Verify
Lockfile matches live tags. `pinpoint lock --verify` exits 0.
Tag drifts. `pinpoint lock --verify` exits 3.

## Files to Create/Modify

- MODIFY: `cmd/pinpoint/main.go` — add `lock` subcommand, add
  `resolveLockfilePath`, update `cmdGate` for auto-detect + default
  enforcement, update `cmdManifestInit` default path
- MODIFY: `internal/gate/gate.go` — add fallback path resolution
  in RunGate, add legacy path notice
- MODIFY: `action.yml` — update default manifest path
- MODIFY: `internal/manifest/templates.go` — update template paths
- CREATE: `internal/gate/lock_test.go` — 10 tests for path resolution,
  enforcement defaults, and fallback behavior
- UPDATE: `README.md` — replace manifest references with lockfile

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
./pinpoint lock --help
./pinpoint help  # verify lock appears in command list
```
