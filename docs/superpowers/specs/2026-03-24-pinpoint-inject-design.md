# Design: `pinpoint inject` Command

## Problem

Gate deployed as a separate reusable workflow job is vulnerable to TOCTOU: gate verifies action SHAs in job 1, but the runner downloads actions fresh for job 2. If a tag is repointed between those two moments (~1 second window), the runner pulls malicious code that gate already blessed.

## Solution

`pinpoint inject` inserts `pinpoint-action` as a step inside the same job as the actions it protects. GitHub Actions downloads all actions for a job at job start, before any steps execute — eliminating the TOCTOU window.

## Architecture

### Core Library: `internal/inject/inject.go`

Line-based YAML manipulation (no `yaml.v3` roundtrip, which destroys comments/formatting).

**Public API:**
- `InjectFile(path string, opts InjectOptions) (*InjectResult, error)` — process one file
- `InjectDir(dir string, opts InjectOptions) ([]*InjectResult, error)` — process all `.yml`/`.yaml` in a directory

**Types:**
- `InjectOptions{Mode, Version, DryRun}` — configuration
- `InjectResult{File, JobsFound, JobsInjected, JobsSkipped, Modified, Output}` — per-file outcome

**Algorithm:**
1. Read file as lines
2. Find each `jobs:` section
3. For each job, find the `steps:` key
4. Find the first `- uses:` or `- name:` line (first step)
5. Determine its indentation
6. Check first step identity:
   - Already `pinpoint-action` → skip (idempotent)
   - `harden-runner` → insert as step 2
   - Otherwise → insert as step 1
7. Insert pinpoint-action step block at correct indentation

**Edge cases:**
- Reusable workflow jobs (`uses:` at job level, no `steps:`) → skip
- Jobs with `if: false` → skip
- Matrix/container jobs → inject normally
- Already has pinpoint-action → skip (idempotent)

### CLI: `cmd/pinpoint/main.go`

New `inject` subcommand:
```
pinpoint inject [--workflows <dir>] [--file <path>] [--dry-run] [--mode warn|enforce]
                [--version <tag>] [--pr <org>] [--pr-title <title>]
```

- **Local mode** (default): `--file` or `--workflows` for file/directory manipulation
- **PR mode**: `--pr <org>` lists org repos via `gh`, clones, injects, creates branch, commits, opens PR

### Script: `scripts/deploy-inject-prs.sh`

Lightweight bash alternative for org-wide PR creation using `gh` CLI directly.

### Tests: `internal/inject/inject_test.go`

8 table-driven test cases:
1. Simple single-job workflow → inserted as step 1
2. Multi-job workflow → injected into each job
3. Already has pinpoint-action → skip (idempotent)
4. Has harden-runner as step 1 → insert as step 2
5. Reusable workflow job → skip
6. Job with `if: false` → skip
7. Preserves comments and formatting
8. Preserves existing step indentation

## Inserted YAML

```yaml
      - name: Pinpoint Gate
        uses: tehreet/pinpoint-action@v1
        with:
          mode: warn
```

(Or `mode: enforce` when `--mode enforce` is specified.)

## Success Criteria

1. `pinpoint inject --file` modifies a workflow file correctly
2. `pinpoint inject --workflows` processes a directory
3. Idempotent: running twice produces no diff
4. Comments and formatting preserved
5. Harden-runner ordering respected
6. All tests pass
7. Deploy script opens PRs across org repos
8. Gate runs on the inject PR itself (bootstrapping)
