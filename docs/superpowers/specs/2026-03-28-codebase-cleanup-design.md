# Codebase Cleanup & Refactoring Design

## Purpose

Prepare pinpoint for handoff to CoreWeave org by cleaning up dead code, splitting the oversized main.go, adding missing test coverage, removing hardcoded stats from docs, and updating STEELMAN.md with behavioral anomaly limitations.

## Scope

Five workstreams, all independent:

1. Cleanup & fixes (dead code, typo, copyright, duplicates, stale doc stats)
2. Split main.go into commands/ subpackage
3. Add tests for 4 untested packages
4. Add t.Parallel() and CI benchmarks
5. Update STEELMAN.md

---

## 1. Cleanup & Fixes

### Remove hardcoded stats from docs

Strip test counts, LOC counts, commit counts from CLAUDE.md, PROJECT-CONTEXT.md, and README.md. These are dynamic and go stale within days. Replace with either nothing or a note like "run `go test ./...`" where contextually useful. Keep signal documentation — those are features, not stats.

**Files:** CLAUDE.md, PROJECT-CONTEXT.md, README.md

### Remove dead config field

Delete `GitHubIssues bool` from `AlertConfig` in `internal/config/config.go`. The project uses Jira, not GitHub Issues. This field was never wired into the emitter.

### Fix error message typo

`cmd/pinpoint/main.go:1482` prints `repo` instead of `err` in a temp dir error message:
```go
// Current (wrong):
fmt.Fprintf(os.Stderr, "  Error creating temp dir: %v\n", repo)
// Fixed:
fmt.Fprintf(os.Stderr, "  Error creating temp dir: %v\n", err)
```

### Add copyright header

Add the standard CoreWeave copyright header to `scripts/parallel-audit.go`:
```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only
```

### Consolidate duplicate functions

Create `internal/util/strings.go` with:

- `ShortSHA(sha string) string` — currently duplicated in main.go:1292, sarif/sarif.go:322, verify/verify.go:650. All identical: truncate to 7 chars + "...".
- `LeadingSpaces(line string) string` — currently in audit/triggers.go:307 and inject/inject.go:31. Use the triggers.go version (handles both spaces and tabs).

Update all call sites to use `util.ShortSHA()` and `util.LeadingSpaces()`. Delete the local copies.

### Remove CLAUDE.md package reorg restriction

Already done — the line "Do not reorganize the package structure without explicit instruction" has been removed.

---

## 2. Split main.go

### Current state

`cmd/pinpoint/main.go` is 1592 lines containing all 11 subcommands, helpers, and usage strings.

### Target structure

```
cmd/pinpoint/
├── main.go                 (~150 lines)
│   package main
│   Dispatches os.Args[1] to commands.Cmd<Name>()
│   Contains printUsage() and main()
│
├── commands/
│   package commands
│   ├── scan.go             cmdScan, cmdWatch, runScan, fetchTagsREST
│   ├── gate.go             cmdGate
│   ├── lock.go             cmdLock (manifest lock/refresh/verify/init/tree)
│   ├── audit.go            cmdAudit
│   ├── discover.go         cmdDiscover
│   ├── verify.go           cmdVerify
│   ├── inject.go           cmdInject, cmdInjectPR
│   └── helpers.go          getFlag, hasFlag, truncate, computeMeanInterval
```

### Interface contract

Each command file exports a single entry point:
```go
func CmdScan(args []string)
func CmdWatch(args []string)
func CmdGate(args []string)
// etc.
```

`main.go` does:
```go
switch os.Args[1] {
case "scan":    commands.CmdScan(os.Args[2:])
case "watch":   commands.CmdWatch(os.Args[2:])
// ...
}
```

### What moves where

| Current location | Destination | Content |
|---|---|---|
| main.go:137-205 | commands/scan.go | cmdScan + cmdWatch |
| main.go:207-284 | commands/scan.go | watch loop, signal handling |
| main.go:286-308 | commands/discover.go | cmdDiscover |
| main.go:310-402 | commands/audit.go | cmdAudit |
| main.go:404-536 | commands/gate.go | cmdGate |
| main.go:538-615 | commands/verify.go | cmdVerify |
| main.go:617-917 | commands/scan.go | runScan (enrichment pipeline) |
| main.go:937-1121 | commands/lock.go | manifest subcommands |
| main.go:1123-1290 | commands/lock.go | cmdLock |
| main.go:1292-1320 | commands/helpers.go | shortSHA → util.ShortSHA, truncate, flags |
| main.go:1325-1592 | commands/inject.go | cmdInject + cmdInjectPR |

### Flag parsing

Keep the current manual flag parsing (`getFlag`, `hasFlag`) in `commands/helpers.go`. No framework.

---

## 3. Tests for Untested Packages

### internal/alert — alert_test.go

Test cases:
- `TestEmitStdout` — verify alert prints to writer with severity badge
- `TestEmitSlack` — mock HTTP server, verify POST body contains action/tag/signals
- `TestEmitWebhook` — mock HTTP server, verify JSON alert payload
- `TestFormatJSON` — verify JSON marshaling of Alert struct
- `TestEmitSlackError` — mock server returns 500, verify no panic (graceful failure)

Pattern: `httptest.NewServer` for Slack/webhook, capture stdout with `bytes.Buffer`.

### internal/config — config_test.go

Test cases:
- `TestLoadValidConfig` — valid YAML with actions, allow rules, alerts
- `TestLoadInvalidYAML` — malformed YAML returns error
- `TestAllowRuleRequiresReason` — allow rule without `reason` field fails validation
- `TestWildcardTags` — `tags: ["*"]` sets `AllTags: true`
- `TestDefaults` — Default() returns sensible defaults (medium severity, stdout, state path)
- `TestEmptyConfig` — empty file returns defaults, not error

Pattern: Table-driven, `LoadFromBytes()` with inline YAML strings.

### internal/discover — discover_test.go

Test cases:
- `TestFromWorkflowDir` — temp dir with workflow files, verify extracted refs
- `TestSHAPinnedSkipped` — SHA-pinned refs filtered out
- `TestGroupByRepo` — deduplication across multiple workflow files
- `TestNoWorkflows` — empty dir returns empty results
- `TestGenerateConfig` — verify YAML output format
- `TestMalformedYAML` — bad workflow file doesn't crash, returns partial results

Pattern: `t.TempDir()`, write workflow YAML files, call `FromWorkflowDir()`.

### internal/store — store_test.go

Test cases:
- `TestNewFileStore` — create, verify empty state
- `TestRecordTagNew` — first tag record returns changed=true
- `TestRecordTagUnchanged` — same SHA returns changed=false
- `TestRecordTagChanged` — different SHA returns changed=true, previousSHA correct
- `TestRecordDeletedTag` — deleted tag tracked in state
- `TestSaveAndLoad` — write to disk, read back, verify round-trip
- `TestConcurrentAccess` — multiple goroutines calling RecordTag simultaneously
- `TestAtomicWrite` — verify temp file + rename pattern

Pattern: `t.TempDir()`, `t.Parallel()` where safe.

---

## 4. t.Parallel() and CI Benchmarks

### t.Parallel()

Add `t.Parallel()` to all test functions that don't share mutable state. Skip for:
- Tests that share a mock server within a single `TestFoo` function (subtests with `t.Run` that share the server are fine — each top-level test gets its own)
- Tests that write to the same temp directory

In practice, nearly all top-level `Test*` functions can be parallel since they use `t.TempDir()` or create their own `httptest.NewServer`.

### CI Benchmarks

Add to `.github/workflows/ci.yml`:

```yaml
- name: Run benchmarks
  run: go test -bench=. -benchmem -run=^$ ./internal/manifest/ ./internal/integrity/ | tee benchmark-results.txt

- name: Upload benchmark results
  uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08 # v4
  with:
    name: benchmark-results
    path: benchmark-results.txt
    retention-days: 90
```

No regression enforcement — just capture baselines. The benchmark action ref should be SHA-pinned (practicing what we preach).

---

## 5. STEELMAN.md Update

Add a new section after the existing limitations:

### Behavioral Anomaly Signal Limitations (Spec 025)

**CONTRIBUTOR_ANOMALY can be bypassed by compromised maintainers.** If the attacker IS a known maintainer (like the tj-actions attack where a maintainer account was compromised), their commits won't trigger this signal because they're already in the known contributors set. This signal catches new/unknown accounts, not insider threats.

**DIFF_ANOMALY has false positives for action.yml changes.** The classifier treats all `action.yml` modifications as suspicious because determining whether only `description`/`inputs` changed (benign) vs `runs.using`/`runs.main` changed (suspicious) requires fetching and diffing file content — an additional API call. Actions that frequently update their `action.yml` metadata will generate noise.

**RELEASE_CADENCE_ANOMALY needs baseline data.** Requires ≥3 releases in the lockfile's `release_history` before the signal activates. New actions or actions added after upgrade have no cadence baseline. High-cadence projects (mean interval <7 days) are excluded entirely to avoid false positives on active projects.

**All behavioral signals are blind on first scan.** The `known_contributors` and `release_history` fields are populated during lockfile updates. The first `pinpoint lock` after upgrading to v0.7+ captures the initial baseline but cannot detect anomalies until the second tag movement. There is no retroactive population from git history.

**`diff_ignore` allow-list not yet implemented.** The spec describes `allow: { diff_ignore: ["dist/*"] }` for actions that legitimately bundle compiled output, but this config option hasn't been built yet. Actions that always change `dist/` will trigger DIFF_ANOMALY on every release.

---

## Out of Scope

- Module path migration (`tehreet/pinpoint` → `coreweave/pinpoint`) — separate task
- Refactoring main.go into a CLI framework — keeping manual flag parsing per CLAUDE.md conventions
- Adding fuzz testing — nice to have but not part of this cleanup
