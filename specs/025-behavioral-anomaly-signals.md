# Spec 025: Behavioral Anomaly Signals for Legitimate-Looking Attacks

## Problem

Pinpoint's current risk scoring catches structurally abnormal attacks — mass
repoints, off-branch commits, backdated timestamps, size anomalies. These
cover opportunistic attacks like Trivy and tj-actions.

But the hardest attack to detect is the "legitimate-looking commit": an attacker
merges a PR with malicious code mixed into a real change, then advances the tag
forward. Every existing signal says "normal" — the commit is a descendant, on
the default branch, merged by a maintainer, with a corresponding release. Score:
-30 (auto-suppressed).

This spec adds three new behavioral signals that detect anomalies in *who*
contributed, *what* changed, and *when* the release happened — even when the
structural signals look clean.

## New Signals

### Signal 1: CONTRIBUTOR_ANOMALY (+35)

**What it detects:** A release that includes commits from authors who have never
previously contributed to the action repository.

**Why it matters:** The tj-actions attack used a compromised maintainer account,
so this isn't bulletproof. But many attacks use newly created accounts, social
engineering to get a first PR merged, or compromised accounts that have never
contributed to the specific repo being targeted. A first-time contributor whose
code ends up in a release tag is worth flagging.

**How it works:**

1. When `pinpoint lock` records a new SHA, also record the set of commit
   authors (login + email) between the old SHA and the new SHA using the
   Compare API (`GET /repos/{owner}/{repo}/compare/{old}...{new}`).

2. The Compare API returns a `commits` array. Extract `author.login` from each.

3. Store the cumulative set of known contributors per action in the lockfile
   (new field: `known_contributors`).

4. On the next tag movement, compare the commits in the new range against the
   known set. If any commit author is not in the known set → fire the signal.

**ScoreContext addition:**
```go
NewContributors  []string  // Logins not seen in previous releases
```

**Lockfile addition:**
```json
{
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "...",
        "known_contributors": ["actions-bot", "joshmgross", "cory-miller"],
        ...
      }
    }
  }
}
```

**API cost:** 1 REST call (Compare API) per tag movement during `scan`/`watch`.
Already called for ancestry checking — extend the existing call to also extract
author logins. Zero additional API calls.

**False positive mitigation:** Only fires when a new contributor's code is in a
*release*. New contributors to the repo in general (issues, docs PRs) don't
trigger it. The signal is informational (+35) — not enough alone to reach
CRITICAL, but stacks with other signals.

### Signal 2: DIFF_ANOMALY (+40)

**What it detects:** A release where the code diff touches files outside the
expected release pattern — specifically, changes to CI/workflow files,
post-install scripts, or new executable entry points in a release that also
touches normal source code.

**Why it matters:** Legitimate releases change source code and maybe docs. A
supply chain attack needs to inject code that *executes* — typically by modifying
the action's entry point, adding a new script that runs during setup, or
changing workflow files. If a release touches both `src/main.ts` and
`.github/workflows/release.yml`, that's more suspicious than either change alone.

**How it works:**

1. Use the Compare API response (already fetched for CONTRIBUTOR_ANOMALY).
   The `files` array contains every file changed between old and new SHA.

2. Categorize each changed file:
   - **Normal:** `*.ts`, `*.js`, `*.go`, `*.py`, `*.rs`, `README*`, `LICENSE`,
     `docs/*`, `*.md`, `package.json`, `go.mod`, `Cargo.toml`
   - **Suspicious:** `.github/workflows/*`, `Makefile`, `Dockerfile`,
     `entrypoint.sh`, `setup.py`, `postinstall*`, `preinstall*`,
     `action.yml` (if the change modifies `runs.using` or `runs.image`)
   - **High-risk:** `dist/*.js` when combined with `action.yml` changes
     (action.yml changes the entry point, dist/ contains the new code)

3. Fire the signal if the diff includes files in the Suspicious or High-risk
   category AND also includes Normal changes (i.e., the suspicious change is
   mixed into a legitimate-looking release).

4. If ONLY suspicious files changed (no cover of normal changes), fire
   DIFF_ANOMALY at +50 instead — a release that only touches CI files is more
   suspicious than one that also has real code changes.

**ScoreContext addition:**
```go
SuspiciousFiles  []string  // Files in the diff that match suspicious patterns
DiffOnly         bool      // True if ONLY suspicious files changed (no cover)
```

**API cost:** Zero additional. The Compare API already returns the file list
in the same response used for ancestry checking.

**False positive mitigation:**
- `action.yml` changes that only modify `description`, `inputs`, or `branding`
  are filtered out — only `runs.*` changes count as suspicious.
- The signal doesn't fire on the first lock (no previous SHA to compare against).
- Allow-list by file path pattern: `allow: { diff_ignore: ["dist/*"] }` for
  actions that legitimately bundle compiled output in releases.

### Signal 3: RELEASE_CADENCE_ANOMALY (+25)

**What it detects:** A release that deviates significantly from the action's
historical release pattern — e.g., an action that releases monthly suddenly
releases twice in one day, or an action that hasn't released in 6 months
suddenly pushes a release.

**Why it matters:** Compromised maintainer accounts often act quickly — push
a malicious release, wait for CI runs to execute it, then clean up. This
creates an anomalous burst of release activity. Similarly, a dormant action
that suddenly releases is suspicious because the maintainer may have lost
control of the account.

**How it works:**

1. Track release timestamps per action in the lockfile (new field:
   `release_history`).

2. When a new tag movement is detected, calculate:
   - **Mean interval** between previous releases
   - **Time since last release**
   - **Releases in last 24 hours**

3. Fire the signal if:
   - Time since last release is < 10% of the mean interval AND mean interval
     is > 7 days (burst release on a slow-release action)
   - OR releases in last 24 hours > 3 (rapid-fire releases)
   - OR time since last release > 3× the mean interval AND mean interval is
     < 90 days (dormant action suddenly releasing)

**ScoreContext addition:**
```go
MeanReleaseInterval  time.Duration  // Average time between releases
TimeSinceLastRelease time.Duration  // Time since previous release
ReleasesLast24h      int            // Number of releases in last 24 hours
```

**Lockfile addition:**
```json
{
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "...",
        "release_history": [
          "2026-01-15T10:00:00Z",
          "2026-02-12T14:30:00Z",
          "2026-03-10T09:15:00Z"
        ],
        ...
      }
    }
  }
}
```

**API cost:** Zero additional. Release dates come from the Release API, which
is already called for the `NO_RELEASE` signal. Just store the timestamps.

**False positive mitigation:**
- Only fires when mean interval > 7 days (high-cadence projects like nightly
  releases are excluded).
- The +25 score is deliberately low — this is a supporting signal, not a
  primary one. It contributes to the composite score but doesn't reach MEDIUM
  on its own.
- New actions with < 3 releases in history → signal is skipped (not enough
  data to establish a baseline).

## Composite Scoring Example

**Scenario: Legitimate-looking supply chain attack**

An attacker compromises a maintainer account for a popular action. They merge a
PR that adds a credential stealer to `dist/index.js`, mixed in with a legitimate
dependency update. They tag the commit and create a GitHub Release.

Current scoring:
- Is descendant: yes → MAJOR_TAG_ADVANCE (-30)
- Release exists: yes → no NO_RELEASE signal
- Size change: minimal → no SIZE_ANOMALY
- GPG signed: yes (web-flow) → no SIGNATURE_DROPPED
- **Total: -30 (LOW, auto-suppressed)**

With new signals:
- Is descendant: yes → MAJOR_TAG_ADVANCE (-30)
- New contributor in diff: the attacker's account → CONTRIBUTOR_ANOMALY (+35)
- Diff touches `dist/index.js` + `action.yml runs.main`: → DIFF_ANOMALY (+40)
- Released 2 hours after previous release (mean interval: 30 days) → RELEASE_CADENCE_ANOMALY (+25)
- **Total: +70 (CRITICAL)**

The gap goes from -30 (invisible) to +70 (immediate alert). That's a 100-point
swing from adding three behavioral signals.

## Implementation

### Files to modify

- `internal/risk/score.go` — Add three new scoring branches + ScoreContext fields
- `internal/risk/score_test.go` — Test cases for each new signal + composite scenarios
- `internal/poller/github.go` — Extend CompareCommits to return file list + author list
- `internal/manifest/manifest.go` — Add `KnownContributors` and `ReleaseHistory` fields
- `cmd/pinpoint/main.go` — Wire new enrichment data into ScoreContext

### Lockfile backward compatibility

New fields (`known_contributors`, `release_history`) are optional. Old lockfiles
without them work fine — the new signals simply don't fire (no data = no anomaly).
First `pinpoint lock` after upgrade populates the fields.

### API budget impact

Zero additional API calls. All data comes from responses we already fetch:
- Compare API → already called for ancestry check → add author extraction + file list
- Release API → already called for NO_RELEASE → add timestamp storage

### Test cases

1. **CONTRIBUTOR_ANOMALY:** Known contributors [A, B], new release has commit from C → +35
2. **CONTRIBUTOR_ANOMALY:** Known contributors [A, B], new release only from A → no signal
3. **CONTRIBUTOR_ANOMALY:** First lock (no known contributors) → no signal
4. **DIFF_ANOMALY:** Diff touches `dist/index.js` + `src/main.ts` → +40
5. **DIFF_ANOMALY:** Diff only touches `src/main.ts` → no signal
6. **DIFF_ANOMALY:** Diff only touches `.github/workflows/ci.yml` → +50 (suspicious-only)
7. **DIFF_ANOMALY:** Diff touches `action.yml` description only → no signal
8. **DIFF_ANOMALY:** Diff touches `action.yml` runs.main → +40
9. **RELEASE_CADENCE_ANOMALY:** Mean 30 days, released 2 hours ago → +25
10. **RELEASE_CADENCE_ANOMALY:** Mean 30 days, released 20 days ago → no signal
11. **RELEASE_CADENCE_ANOMALY:** Mean 2 days (high cadence) → no signal (excluded)
12. **RELEASE_CADENCE_ANOMALY:** < 3 releases in history → no signal
13. **RELEASE_CADENCE_ANOMALY:** Dormant 6 months, mean 30 days → +25
14. **Composite:** All three fire together on a descendant commit → CRITICAL (+70)
15. **Composite:** Legitimate release (known author, normal diff, normal cadence) → LOW (-30)

## Milestones

1. **M1:** ScoreContext + score.go changes + tests → half day
2. **M2:** CompareCommits extended (author list + file list) → half day
3. **M3:** Lockfile fields (known_contributors, release_history) → half day
4. **M4:** Wire into scan/watch enrichment pipeline → half day
5. **M5:** Integration test with real action tag movement → half day
