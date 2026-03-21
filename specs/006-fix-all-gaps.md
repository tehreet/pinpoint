# Spec 006: Fix All Gaps from Test Plan (005)

## Overview

This spec fixes every gap identified in spec 005. Read specs/005-test-plan.md
first for full context. Changes are grouped by file.

---

## Fix 1: Manifest Poisoning via Fork PR (P0, Critical)

**Problem:** For `pull_request` events, `$GITHUB_SHA` is the merge commit
which includes the attacker's changes to `.pinpoint-manifest.json`. The gate
trusts the manifest at that SHA, so an attacker can pre-authorize malicious SHAs.

**Fix:** When `GITHUB_EVENT_NAME` is `pull_request` or `pull_request_target`,
fetch the manifest from the base branch (`$GITHUB_BASE_REF`) instead of
from `$GITHUB_SHA`. The workflow file is still fetched at `$GITHUB_SHA`
(we want to verify the actions the PR is actually using).

### Changes to `internal/gate/gate.go`

Add two fields to `GateOptions`:

```go
type GateOptions struct {
    // ... existing fields ...
    EventName string // "push", "pull_request", etc. From GITHUB_EVENT_NAME
    BaseRef   string // "main", "develop", etc. From GITHUB_BASE_REF
}
```

In `RunGate`, after fetching the workflow file (step 2), determine the
manifest ref:

```go
// Step 3: Determine manifest ref
// For pull_request events, fetch manifest from base branch to prevent
// manifest poisoning via fork PRs (see spec 005, section 1.10).
manifestRef := opts.SHA
if isPullRequestEvent(opts.EventName) {
    if opts.BaseRef == "" {
        fmt.Fprintf(messageWriter, "⚠ Pull request detected but GITHUB_BASE_REF not set. Falling back to GITHUB_SHA for manifest.\n")
    } else {
        manifestRef = opts.BaseRef
        fmt.Fprintf(messageWriter, "  ℹ Pull request detected. Fetching manifest from base branch %q (not PR merge commit).\n", opts.BaseRef)
    }
}

// Step 4: Fetch manifest (using manifestRef, not opts.SHA)
manifestContent, err := client.fetchFileContent(ctx, opts.Repo, opts.ManifestPath, manifestRef)
```

Add helper:

```go
func isPullRequestEvent(eventName string) bool {
    return eventName == "pull_request" ||
        eventName == "pull_request_target" ||
        eventName == "merge_group"
}
```

### Changes to `cmd/pinpoint/main.go` (cmdGate)

Read the new env vars:

```go
eventName := os.Getenv("GITHUB_EVENT_NAME")
baseRef := os.Getenv("GITHUB_BASE_REF")
```

Pass them in opts:

```go
opts := gate.GateOptions{
    // ... existing ...
    EventName: eventName,
    BaseRef:   baseRef,
}
```

### Test: `TestManifestPoisoningPrevention`

In `internal/gate/gate_test.go`, add a test:

1. Set up mock REST server that serves TWO different manifests:
   - At ref `abc123` (merge commit): manifest with EVIL SHA for actions/checkout@v4
   - At ref `main` (base branch): manifest with GOOD SHA for actions/checkout@v4
2. Set up mock GraphQL server returning the GOOD SHA as current
3. Run gate with EventName="pull_request", SHA="abc123", BaseRef="main"
4. Verify: gate fetches manifest at "main", SHA matches, exit 0

Then test the attack scenario:
1. Same setup but run gate WITHOUT the fix (EventName="push", SHA="abc123")
2. Verify: gate fetches manifest at "abc123" (the evil one), SHA matches evil, exit 0
   This proves the attack works without the fix.

---

## Fix 2: Descendant Commit Scoring (P1)

**Problem:** In `internal/risk/score.go`, MAJOR_TAG_ADVANCE subtracts 30 points.
Combined with a descendant commit that has a large size anomaly (SIZE_ANOMALY +60),
the final score is 60-30=30, which is only MEDIUM. It should be CRITICAL.

**Fix:** SIZE_ANOMALY should set a minimum floor. If SIZE_ANOMALY fires,
the score cannot go below 50 (CRITICAL threshold), regardless of deductions.

### Changes to `internal/risk/score.go`

After all signals are computed, add:

```go
// SIZE_ANOMALY floor: if the entry point changed dramatically,
// no deduction should reduce this below CRITICAL.
hasSizeAnomaly := false
for _, s := range signals {
    if strings.HasPrefix(s, "SIZE_ANOMALY") {
        hasSizeAnomaly = true
        break
    }
}
if hasSizeAnomaly && score < 50 {
    score = 50
    signals = append(signals, "SCORE_FLOOR: SIZE_ANOMALY enforces minimum CRITICAL severity")
}
```

### Test: `TestSizeAnomalyOverridesMajorTagAdvance`

In a new file `internal/risk/score_test.go`:

```go
func TestSizeAnomalyOverridesMajorTagAdvance(t *testing.T) {
    sev, signals := Score(ScoreContext{
        TagName:       "v4",           // major version tag
        IsDescendant:  true,           // descendant (triggers MAJOR_TAG_ADVANCE -30)
        EntryPointOld: 1000,           // old size
        EntryPointNew: 5000,           // +400% (triggers SIZE_ANOMALY +60)
        ReleaseExists: true,
    })
    if sev != SeverityCritical {
        t.Errorf("expected CRITICAL, got %s (signals: %v)", sev, signals)
    }
    // Verify both signals present
    hasSize := false
    hasMajor := false
    for _, s := range signals {
        if strings.HasPrefix(s, "SIZE_ANOMALY") { hasSize = true }
        if strings.HasPrefix(s, "MAJOR_TAG_ADVANCE") { hasMajor = true }
    }
    if !hasSize || !hasMajor {
        t.Errorf("expected both SIZE_ANOMALY and MAJOR_TAG_ADVANCE signals, got: %v", signals)
    }
}
```

Also add basic scoring tests:

```go
func TestScoreSemverRepoint(t *testing.T) {
    sev, _ := Score(ScoreContext{TagName: "v1.2.3", IsDescendant: false})
    if sev != SeverityCritical {
        t.Errorf("expected CRITICAL for semver repoint, got %s", sev)
    }
}

func TestScoreMassRepoint(t *testing.T) {
    sev, _ := Score(ScoreContext{TagName: "v1", BatchSize: 10})
    if sev != SeverityCritical {
        t.Errorf("expected CRITICAL for mass repoint, got %s", sev)
    }
}

func TestScoreLegitimateAdvance(t *testing.T) {
    sev, _ := Score(ScoreContext{
        TagName: "v4", IsDescendant: true, ReleaseExists: true,
    })
    if sev != SeverityLow {
        t.Errorf("expected LOW for legitimate major tag advance, got %s", sev)
    }
}
```

---

## Fix 3: Audit Flags Unprotected Workflows (P1)

**Problem:** No way to know which workflows in an org lack the gate step.

**Fix:** During audit phase 2 (parsing workflow content), also check if
each workflow contains a pinpoint gate reference. Track and report.

### Changes to `internal/audit/audit.go`

Add field to AuditResult:

```go
type AuditResult struct {
    // ... existing fields ...
    WorkflowsWithGate    int
    WorkflowsWithoutGate int
    UnprotectedWorkflows []string // "repo-name/.github/workflows/ci.yml"
}
```

During workflow parsing (where extractRefs is called), also check:

```go
func hasGateStep(content string) bool {
    // Check for pinpoint gate usage in any form:
    // - uses: tehreet/pinpoint@ or uses: coreweave/pinpoint@
    // - pinpoint gate
    // - /pinpoint gate
    lower := strings.ToLower(content)
    return strings.Contains(lower, "pinpoint gate") ||
        strings.Contains(lower, "pinpoint@")
}
```

In FormatReport, add a section after RECOMMENDATIONS:

```
UNPROTECTED WORKFLOWS (no pinpoint gate detected):
  47 of 200 workflows have no gate step.
  repo-a/.github/workflows/deploy.yml
  repo-b/.github/workflows/ci.yml
  ...
```

Only show first 20 unprotected workflows in the report (with "and N more...").

---

## Fix 4: Clear Error for Private Action Repos (P1)

**Problem:** When GraphQL can't resolve a private action repo, the error
is opaque: "Could not resolve to a Repository with the name 'some-org/private-action'."

**Fix:** In `internal/gate/gate.go`, after the GraphQL call, check for
"Could not resolve" errors and provide an actionable message.

### Changes to `internal/gate/gate.go`

After the `FetchTagsBatch` call in RunGate, process errors:

```go
fetchResults, err := graphqlClient.FetchTagsBatch(ctx, repos)
if err != nil {
    // Check if the error contains "Could not resolve to a Repository"
    if strings.Contains(err.Error(), "Could not resolve") {
        return nil, fmt.Errorf("resolve tags: %w\n\nOne or more action repositories could not be accessed.\nIf using private actions, ensure GITHUB_TOKEN has read access to those repos,\nor use a PAT with the 'repo' scope.", err)
    }
    return nil, fmt.Errorf("resolve tags: %w", err)
}
```

Note: GraphQL errors for individual repos are already logged to stderr
and the repo is skipped (not a fatal error). The above only fires if
the entire batch call fails. The per-repo handling is already correct —
repos that error out are skipped and the gate warns about them.

BUT: currently the gate doesn't distinguish between "repo doesn't exist"
and "repo is private and token lacks access". Both result in the repo
being missing from fetchResults. When the gate later tries to look up
the tag, it finds nothing and says "tag not found on remote" — which is
misleading for private repos.

Better fix: track which repos had GraphQL errors and include that in
the warning message:

```go
// After processing fetchResults, check which requested repos are missing
for _, repo := range repos {
    if _, ok := fetchResults[repo]; !ok {
        // This repo had a GraphQL error (likely 404 or access denied)
        for i, ar := range tagRefs {
            if ar.Owner+"/"+ar.Repo == repo {
                // Update the warning message for this ref
                result.Warnings = append(result.Warnings, Warning{
                    Action:  repo,
                    Ref:     ar.Ref,
                    Message: "repository not accessible (may be private or deleted)",
                })
                fmt.Fprintf(messageWriter, "  ⚠ %s@%s → repository not accessible. If private, ensure GITHUB_TOKEN has read access.\n", repo, ar.Ref)
                // Mark as handled so the comparison loop skips it
                tagRefs[i].Owner = "" // sentinel
            }
        }
    }
}
```

Then in the comparison loop, skip refs where Owner was cleared:

```go
for _, ar := range tagRefs {
    if ar.Owner == "" {
        continue // already handled as inaccessible
    }
    // ... existing comparison logic ...
}
```

---

## Fix 5: Warn on Old Manifest (P1)

**Problem:** Manifest could be months old and the gate silently trusts it.

**Fix:** After parsing the manifest, check `generated_at`. If older than
30 days, print a warning.

### Changes to `internal/gate/gate.go`

After `json.Unmarshal(manifestContent, &manifest)`:

```go
// Warn if manifest is stale
if manifest.GeneratedAt != "" {
    if genTime, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err == nil {
        age := time.Since(genTime)
        if age > 30*24*time.Hour {
            days := int(age.Hours() / 24)
            fmt.Fprintf(messageWriter, "  ⚠ Manifest is %d days old (generated %s). Consider regenerating:\n    pinpoint audit --org <name> --output manifest > .pinpoint-manifest.json\n", days, manifest.GeneratedAt)
        }
    }
}
```

---

## Fix 6: Handle Zero uses: Directives (P1)

**Problem:** If a workflow has only `run:` steps and no `uses:` directives,
the gate's behavior is unclear.

**Fix:** After extracting raw refs, if zero are found, print a clean message
and exit 0.

### Changes to `internal/gate/gate.go`

After `rawRefs := ExtractUsesDirectives(string(wfContent))`:

```go
if len(rawRefs) == 0 {
    fmt.Fprintf(messageWriter, "pinpoint gate: no action references found in workflow. Nothing to verify.\n")
    result.Duration = time.Since(start)
    return result, nil
}
```

### Test: `TestZeroUsesDirectives`

Workflow content:
```yaml
name: Script Only
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
      - run: go build ./...
```

Verify: gate returns 0 verified, 0 skipped, 0 violations. No error.

---

## Fix 7: Additional Test Cases (P2)

Add these tests to `internal/gate/gate_test.go`:

### TestSubPathActionRef
Input: `"aws-actions/configure-aws-credentials/subdir@v4"`
Expected: owner="aws-actions", repo="configure-aws-credentials", ref="v4"

### TestSHAWithInlineComment
Workflow content containing:
```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
```
Expected: Full 40-char SHA extracted, classified as SHA-pinned.

### TestQuotedUsesValues
Workflow content:
```yaml
- uses: 'actions/checkout@v4'
- uses: "actions/setup-go@v5"
```
Expected: Both extracted correctly, quotes stripped.

### TestDynamicExpressionUses
Workflow content:
```yaml
- uses: ${{ matrix.action }}
```
Expected: Not extracted (doesn't match regex). Gate should handle zero
matching refs gracefully (covered by Fix 6).

---

## Files to Modify

- `internal/gate/gate.go` — Fixes 1, 4, 5, 6
- `internal/gate/gate_test.go` — Tests for fixes 1, 6, 7
- `internal/risk/score.go` — Fix 2
- `internal/risk/score_test.go` — CREATE, tests for fix 2
- `internal/audit/audit.go` — Fix 3
- `cmd/pinpoint/main.go` — Fix 1 (pass EventName, BaseRef to gate)

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
```

All existing tests must continue to pass. New tests:
- TestManifestPoisoningPrevention
- TestSizeAnomalyOverridesMajorTagAdvance
- TestScoreSemverRepoint
- TestScoreMassRepoint
- TestScoreLegitimateAdvance
- TestZeroUsesDirectives
- TestSubPathActionRef
- TestSHAWithInlineComment
- TestQuotedUsesValues
- TestDynamicExpressionUses
