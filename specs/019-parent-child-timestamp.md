# Spec 019: Parent-Child Timestamp Consistency

## Problem

In the Trivy attack, the attacker cloned original commit timestamps (2021-2024) onto
fabricated commits whose parent was the March 2026 master HEAD (`57a97c7e`). This creates
a physical impossibility: a commit cannot predate its parent in any legitimate Git workflow.

Pinpoint's existing BACKDATED_COMMIT signal checks whether the commit date is >30 days old,
which works but has a higher false positive rate (e.g., long-running branches merged late).
Parent-child timestamp inversion is a much stronger signal — it proves the commit metadata
was fabricated.

## Design

### New signal: IMPOSSIBLE_TIMESTAMP

This is NOT a replacement for BACKDATED_COMMIT — it's a separate, higher-confidence signal
that fires independently. A commit can trigger BACKDATED_COMMIT (old date) without
IMPOSSIBLE_TIMESTAMP (if it has no parent, or parent is also old), or both.

```go
// Commit date precedes its parent commit's date (fabricated metadata)
if !ctx.ParentDate.IsZero() && ctx.CommitDate.Before(ctx.ParentDate) {
    score += 70
    signals = append(signals, formatSignal(
        "IMPOSSIBLE_TIMESTAMP: commit dated %s but parent dated %s (child predates parent)",
        ctx.CommitDate.Format("2006-01-02"),
        ctx.ParentDate.Format("2006-01-02"),
    ))
}
```

Score: +70. Rationale: this is near-proof of fabrication. Higher than SIZE_ANOMALY (+60)
because there is virtually no legitimate scenario where a commit predates its parent.
Lower than MASS_REPOINT (+100) and OFF_BRANCH (+80) because those are the primary
attack indicators — this is a confirming forensic signal.

### New fields in ScoreContext

```go
type ScoreContext struct {
    // ... existing fields ...
    ParentSHA     string    // SHA of the new commit's first parent
    ParentDate    time.Time // Date of the parent commit
}
```

### When to fetch parent data

This should NOT be an unconditional extra API call for every check. The parent commit
data is only needed when BACKDATED_COMMIT has already fired (commit date >30 days old).
This keeps the cost at zero for the common case and adds at most 1 API call per flagged
action in the rare attack case.

Implementation pattern:

```go
// In gate.go or scan logic, after initial scoring:
if time.Since(commitInfo.Date) > 30*24*time.Hour && commitInfo.ParentSHA != "" {
    // BACKDATED_COMMIT will fire — fetch parent to check for impossibility
    parentInfo, err := client.FetchCommitInfo(ctx, owner, repo, commitInfo.ParentSHA)
    if err == nil {
        scoreCtx.ParentDate = parentInfo.Date
        scoreCtx.ParentSHA = commitInfo.ParentSHA
    }
    // If fetch fails, just skip the check — BACKDATED_COMMIT still fires
}
```

### Getting parent SHA

The parent SHA is already available in the commit object that Pinpoint fetches. The
GitHub REST API commit response includes:

```json
{
  "sha": "abc123...",
  "parents": [
    { "sha": "def456..." }
  ],
  "commit": {
    "committer": { "date": "2022-06-15T..." }
  }
}
```

Pinpoint just needs to parse `parents[0].sha` from the existing response. This is a
zero-cost addition to the existing API call.

### Updated ScoreContext population

**internal/poller/github.go** — extend CommitInfo to include parent SHA:

```go
type CommitInfo struct {
    SHA         string
    Date        time.Time
    Author      string
    Email       string
    ParentSHA   string    // NEW — first parent SHA, empty if root commit
    GPGVerified bool      // from spec 017
    GPGSigner   string    // from spec 017
}
```

Parse from the existing API response:

```go
if len(commitResponse.Parents) > 0 {
    info.ParentSHA = commitResponse.Parents[0].SHA
}
```

### Combined scoring example: Trivy attack replay

For a single compromised trivy-action tag (e.g., `0.18.0` repointed to malicious commit):

| Signal | Score | Notes |
|---|---|---|
| MASS_REPOINT | +100 | 76 tags in same interval |
| OFF_BRANCH | +80 | New commit not descendant of original |
| IMPOSSIBLE_TIMESTAMP | +70 | Commit claims 2022, parent is March 2026 |
| SIZE_ANOMALY | +60 | entrypoint.sh doubled in size |
| SEMVER_REPOINT | +50 | Exact version tag moved |
| SIGNATURE_DROPPED | +45 | Was GPG-signed, now unsigned (spec 017) |
| BACKDATED_COMMIT | +40 | Commit date >30 days old |
| NO_RELEASE | +20 | No corresponding release |
| **TOTAL** | **+465** | **CRITICAL** (threshold: 50) |

This is significant overkill for detection, which is exactly the point — defense in
depth means no single evasion technique can drop the score below threshold.

## Tests

### Unit tests in risk/score_test.go

- TestImpossibleTimestamp — child dated 2022, parent dated 2026 → +70, signal present
- TestNormalTimestampOrder — child dated 2026-03-20, parent dated 2026-03-19 → no signal
- TestSameDate — child and parent same date → no signal
- TestNoParent — ParentDate is zero → no signal (root commits are fine)
- TestImpossibleWithBackdated — both IMPOSSIBLE_TIMESTAMP and BACKDATED_COMMIT fire
  independently, scores stack
- TestTrivyFullReplay — all 8 signals fire together, total score >400

### Integration tests

- TestGateDetectsImpossibleTimestamp — create a test scenario where a tag points to
  a commit with fabricated timestamps, verify IMPOSSIBLE_TIMESTAMP appears in gate output

## Edge cases

**Merge commits:** A merge commit has two parents. We only check the first parent
(the branch the merge was onto). This is correct because force-pushed tags point to
a single-parent commit chain, not merge commits.

**Root commits:** If `parents` is empty (initial commit), `ParentDate` stays zero and
the signal never fires. Correct — root commits have no parent to compare against.

**Squash merges:** GitHub squash merges create a new commit with the original PR commits
squashed. The new commit's date is the merge time, parent is the branch tip. Dates
are always in order. No false positive.

**Cherry-picks with original date preserved:** Some workflows preserve the original
author date on cherry-picks. The committer date would still be recent. We check
`committer.date` (not `author.date`) which is always set to the actual commit creation
time. No false positive.

## Implementation cost

This is the cheapest of the three new signals to implement:

1. Parse `parents[0].sha` from existing commit API response (zero new API calls)
2. Conditionally fetch parent commit (1 API call, only when BACKDATED_COMMIT fires)
3. Add ~15 lines to risk/score.go
4. Add ParentSHA/ParentDate to ScoreContext

Total: ~50 lines of new code across 3 files.

## Files to create/modify

- MODIFY: `internal/poller/github.go` — parse ParentSHA from commit response
- MODIFY: `internal/risk/score.go` — add IMPOSSIBLE_TIMESTAMP signal
- MODIFY: `internal/gate/gate.go` — conditionally fetch parent, populate ScoreContext
- MODIFY: `internal/risk/score_test.go` — add timestamp consistency test cases
