# Behavioral Anomaly Signals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three new risk scoring signals (CONTRIBUTOR_ANOMALY, DIFF_ANOMALY, RELEASE_CADENCE_ANOMALY) that detect behavioral anomalies in who contributed, what changed, and when a release happened — catching legitimate-looking supply chain attacks that evade all existing structural signals.

**Architecture:** Extend `CompareCommits` to return author logins and changed filenames from the already-fetched Compare API response. Add `KnownContributors` and `ReleaseHistory` fields to `ManifestEntry` for cross-release tracking. Add three new scoring branches to `Score()` using new `ScoreContext` fields populated during the enrichment phase in `runScan`.

**Tech Stack:** Go 1.24, standard library only (no new deps)

**Spec:** `specs/025-behavioral-anomaly-signals.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/risk/score.go` | Modify | Add 3 new scoring branches + ScoreContext fields |
| `internal/risk/score_test.go` | Modify | 15 new test cases |
| `internal/poller/github.go` | Modify | Extend `CompareCommits` to return `CompareResult` with authors + files |
| `internal/poller/github_test.go` | Create | Tests for extended `CompareCommits` |
| `internal/manifest/manifest.go` | Modify | Add `KnownContributors` and `ReleaseHistory` to `ManifestEntry` |
| `cmd/pinpoint/main.go` | Modify | Wire new enrichment data into ScoreContext during `runScan` |

---

### Task 1: Extend CompareCommits return type

**Files:**
- Modify: `internal/poller/github.go:203-238`
- Create: `internal/poller/github_test.go`

- [ ] **Step 1: Write the failing test for CompareCommits returning authors and files**

Create `internal/poller/github_test.go`:

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package poller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareCommitsReturnsAuthorsAndFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "ahead",
			"ahead_by":      3,
			"behind_by":     0,
			"total_commits": 3,
			"commits": []map[string]interface{}{
				{"author": map[string]interface{}{"login": "alice"}},
				{"author": map[string]interface{}{"login": "bob"}},
				{"author": map[string]interface{}{"login": "alice"}}, // duplicate
			},
			"files": []map[string]interface{}{
				{"filename": "src/main.ts"},
				{"filename": "dist/index.js"},
				{"filename": ".github/workflows/ci.yml"},
			},
		})
	}))
	defer srv.Close()

	client := NewGitHubClient("")
	client.SetBaseURL(srv.URL)

	result, err := client.CompareCommits(context.Background(), "owner", "repo", "oldsha", "newsha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsDescendant {
		t.Error("expected IsDescendant=true")
	}
	if result.AheadBy != 3 {
		t.Errorf("expected AheadBy=3, got %d", result.AheadBy)
	}

	// Authors should be deduplicated
	if len(result.AuthorLogins) != 2 {
		t.Errorf("expected 2 unique authors, got %d: %v", len(result.AuthorLogins), result.AuthorLogins)
	}
	if len(result.Files) != 3 {
		t.Errorf("expected 3 files, got %d: %v", len(result.Files), result.Files)
	}
}

func TestCompareCommitsNilAuthor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "ahead",
			"ahead_by":      1,
			"behind_by":     0,
			"total_commits": 1,
			"commits": []map[string]interface{}{
				{"author": nil}, // deleted GitHub account
			},
			"files": []map[string]interface{}{},
		})
	}))
	defer srv.Close()

	client := NewGitHubClient("")
	client.SetBaseURL(srv.URL)

	result, err := client.CompareCommits(context.Background(), "owner", "repo", "old", "new")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.AuthorLogins) != 0 {
		t.Errorf("expected 0 authors for nil author, got %d", len(result.AuthorLogins))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/poller/ -run TestCompareCommits -v`
Expected: FAIL — `CompareCommits` returns `(bool, int, int, error)`, not `*CompareResult`

- [ ] **Step 3: Change CompareCommits signature and implement**

In `internal/poller/github.go`, replace the `CompareCommits` method (lines 203-238):

```go
// CompareResult holds the result of comparing two commits.
type CompareResult struct {
	IsDescendant bool
	AheadBy      int
	BehindBy     int
	AuthorLogins []string // Deduplicated commit author logins
	Files        []string // Changed file paths
}

// CompareCommits checks if newSHA is a descendant of oldSHA on the default branch.
// Also extracts commit author logins and changed file paths from the response.
func (c *GitHubClient) CompareCommits(ctx context.Context, owner, repo, oldSHA, newSHA string) (*CompareResult, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/compare/%s...%s", c.baseURL, owner, repo, oldSHA, newSHA)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("compare returned %d", resp.StatusCode)
	}

	var raw struct {
		Status       string `json:"status"`
		AheadBy      int    `json:"ahead_by"`
		BehindBy     int    `json:"behind_by"`
		TotalCommits int    `json:"total_commits"`
		Commits      []struct {
			Author *struct {
				Login string `json:"login"`
			} `json:"author"`
		} `json:"commits"`
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	result := &CompareResult{
		IsDescendant: raw.Status == "ahead",
		AheadBy:      raw.AheadBy,
		BehindBy:     raw.BehindBy,
	}

	// Deduplicate author logins
	seen := make(map[string]bool)
	for _, c := range raw.Commits {
		if c.Author != nil && c.Author.Login != "" && !seen[c.Author.Login] {
			seen[c.Author.Login] = true
			result.AuthorLogins = append(result.AuthorLogins, c.Author.Login)
		}
	}

	// Extract file paths
	for _, f := range raw.Files {
		result.Files = append(result.Files, f.Filename)
	}

	return result, nil
}
```

- [ ] **Step 4: Update all callers of CompareCommits**

The signature changed from `(bool, int, int, error)` to `(*CompareResult, error)`. Update `cmd/pinpoint/main.go` (around line 706):

Old:
```go
isDesc, ahead, behind, err := restClient.CompareCommits(ctx, owner, repo, previousSHA, tag.CommitSHA)
if err == nil {
    scoreCtx.IsDescendant = isDesc
    scoreCtx.AheadBy = ahead
    scoreCtx.BehindBy = behind
}
```

New:
```go
compareResult, err := restClient.CompareCommits(ctx, owner, repo, previousSHA, tag.CommitSHA)
if err == nil {
    scoreCtx.IsDescendant = compareResult.IsDescendant
    scoreCtx.AheadBy = compareResult.AheadBy
    scoreCtx.BehindBy = compareResult.BehindBy
}
```

Search for any other callers with: `grep -rn "CompareCommits" --include="*.go"`

- [ ] **Step 5: Run tests to verify everything compiles and passes**

Run: `go build ./... && go test ./internal/poller/ -run TestCompareCommits -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/poller/github.go internal/poller/github_test.go cmd/pinpoint/main.go
git commit -m "refactor: extend CompareCommits to return author logins and file list

Spec 025 preparation: the Compare API response already contains commit
authors and changed files. Extract them into CompareResult so behavioral
anomaly signals can use this data without additional API calls."
```

---

### Task 2: Add lockfile fields to ManifestEntry

**Files:**
- Modify: `internal/manifest/manifest.go:29-39`

- [ ] **Step 1: Add KnownContributors and ReleaseHistory fields**

In `internal/manifest/manifest.go`, add two fields to `ManifestEntry`:

```go
type ManifestEntry struct {
	SHA               string          `json:"sha"`
	Integrity         string          `json:"integrity,omitempty"`
	DiskIntegrity     string          `json:"disk_integrity,omitempty"`
	GPGSigned         *bool           `json:"gpg_signed,omitempty"`
	GPGSigner         string          `json:"gpg_signer,omitempty"`
	RecordedAt        string          `json:"recorded_at,omitempty"`
	Type              string          `json:"type,omitempty"`
	Docker            *DockerInfo     `json:"docker,omitempty"`
	Dependencies      []TransitiveDep `json:"dependencies,omitempty"`
	KnownContributors []string        `json:"known_contributors,omitempty"`
	ReleaseHistory    []string        `json:"release_history,omitempty"` // RFC3339 timestamps
}
```

- [ ] **Step 2: Verify build and all existing tests pass**

Run: `go build ./... && go test ./...`
Expected: PASS — new fields are `omitempty`, so existing lockfiles are unaffected.

- [ ] **Step 3: Commit**

```bash
git add internal/manifest/manifest.go
git commit -m "feat: add KnownContributors and ReleaseHistory to ManifestEntry

New optional lockfile fields for spec 025 behavioral anomaly signals.
Old lockfiles without these fields work fine — signals simply don't fire."
```

---

### Task 3: Add ScoreContext fields and CONTRIBUTOR_ANOMALY signal

**Files:**
- Modify: `internal/risk/score.go:36-55` (ScoreContext) and `score.go:65-166` (Score function)
- Modify: `internal/risk/score_test.go`

- [ ] **Step 1: Write failing tests for CONTRIBUTOR_ANOMALY**

Append to `internal/risk/score_test.go`:

```go
// === Spec 025: Behavioral Anomaly Signal tests ===

func TestContributorAnomaly_NewContributor(t *testing.T) {
	// Known contributors [A, B], new release has commit from C → +35
	sev, signals := Score(ScoreContext{
		TagName:          "v4",
		IsDescendant:     true,
		ReleaseExists:    true,
		CommitDate:       time.Now(),
		NewContributors:  []string{"attacker-account"},
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "CONTRIBUTOR_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CONTRIBUTOR_ANOMALY signal, got: %v", signals)
	}
	// Score: -30 (MAJOR_TAG_ADVANCE) + 35 (CONTRIBUTOR_ANOMALY) = 5 → LOW
	if sev != SeverityLow {
		t.Errorf("expected LOW (score=5), got %s", sev)
	}
}

func TestContributorAnomaly_AllKnown(t *testing.T) {
	// Known contributors [A, B], new release only from A → no signal
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		NewContributors: []string{}, // empty = all known
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "CONTRIBUTOR_ANOMALY") {
			t.Errorf("CONTRIBUTOR_ANOMALY should not fire when all authors known, got: %v", signals)
		}
	}
}

func TestContributorAnomaly_FirstLock(t *testing.T) {
	// First lock (nil NewContributors) → no signal
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		NewContributors: nil,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "CONTRIBUTOR_ANOMALY") {
			t.Errorf("CONTRIBUTOR_ANOMALY should not fire on first lock, got: %v", signals)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/risk/ -run TestContributorAnomaly -v`
Expected: FAIL — `NewContributors` field doesn't exist

- [ ] **Step 3: Add ScoreContext fields and CONTRIBUTOR_ANOMALY scoring branch**

In `internal/risk/score.go`, add to `ScoreContext`:

```go
// Behavioral anomaly fields (spec 025)
NewContributors      []string      // Logins not seen in previous releases (nil = first lock)
SuspiciousFiles      []string      // Files in the diff matching suspicious patterns
DiffOnly             bool          // True if ONLY suspicious files changed
MeanReleaseInterval  time.Duration // Average time between releases
TimeSinceLastRelease time.Duration // Time since previous release
ReleasesLast24h      int           // Number of releases in last 24 hours
ReleaseHistoryLen    int           // Number of entries in release history
```

In the `Score` function, add after the `SIGNATURE_DROPPED` block (before `// === MEDIUM SIGNALS ===`):

```go
// === BEHAVIORAL ANOMALY SIGNALS (spec 025) ===

// New contributor in release diff
if ctx.NewContributors != nil && len(ctx.NewContributors) > 0 {
    score += 35
    signals = append(signals, "CONTRIBUTOR_ANOMALY: release includes commits from new contributor(s): "+strings.Join(ctx.NewContributors, ", "))
}
```

Note: Uses simple string concatenation to stay consistent with the existing convention in `score.go` of not importing `fmt`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/risk/ -run TestContributorAnomaly -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/risk/score.go internal/risk/score_test.go
git commit -m "feat: add CONTRIBUTOR_ANOMALY signal (+35)

Fires when a release includes commits from authors not seen in previous
releases. Detects compromised/new accounts injecting code into actions."
```

---

### Task 4: Add DIFF_ANOMALY signal

**Files:**
- Modify: `internal/risk/score.go`
- Modify: `internal/risk/score_test.go`

- [ ] **Step 1: Write failing tests for DIFF_ANOMALY**

Append to `internal/risk/score_test.go`:

```go
func TestDiffAnomaly_SuspiciousMixedWithNormal(t *testing.T) {
	// Diff touches dist/index.js + src/main.ts → +40
	sev, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: []string{"dist/index.js"},
		DiffOnly:        false,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DIFF_ANOMALY signal, got: %v", signals)
	}
	// -30 + 40 = 10 → LOW
	if sev != SeverityLow {
		t.Errorf("expected LOW, got %s", sev)
	}
}

func TestDiffAnomaly_NormalOnly(t *testing.T) {
	// Diff only touches src/main.ts → no signal
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: []string{},
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			t.Errorf("DIFF_ANOMALY should not fire for normal-only diff, got: %v", signals)
		}
	}
}

func TestDiffAnomaly_SuspiciousOnly(t *testing.T) {
	// Diff only touches .github/workflows/ci.yml → +50 (suspicious-only)
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: []string{".github/workflows/ci.yml"},
		DiffOnly:        true,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			found = true
			if !strings.Contains(s, "suspicious files only") {
				t.Errorf("expected 'suspicious files only' in signal, got: %s", s)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected DIFF_ANOMALY signal, got: %v", signals)
	}
}

func TestDiffAnomaly_NilSuspicious(t *testing.T) {
	// nil SuspiciousFiles (no compare data) → no signal
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: nil,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			t.Errorf("DIFF_ANOMALY should not fire with nil SuspiciousFiles, got: %v", signals)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/risk/ -run TestDiffAnomaly -v`
Expected: FAIL — `SuspiciousFiles` field doesn't exist yet (added in Task 3 step 3, but scoring branch doesn't exist)

- [ ] **Step 3: Add DIFF_ANOMALY scoring branch**

In `internal/risk/score.go`, add after the CONTRIBUTOR_ANOMALY block:

```go
// Suspicious files in release diff
if ctx.SuspiciousFiles != nil && len(ctx.SuspiciousFiles) > 0 {
    if ctx.DiffOnly {
        score += 50
        signals = append(signals, "DIFF_ANOMALY: release changes suspicious files only (no normal code changes): "+strings.Join(ctx.SuspiciousFiles, ", "))
    } else {
        score += 40
        signals = append(signals, "DIFF_ANOMALY: release mixes suspicious files with normal changes: "+strings.Join(ctx.SuspiciousFiles, ", "))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/risk/ -run TestDiffAnomaly -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/risk/score.go internal/risk/score_test.go
git commit -m "feat: add DIFF_ANOMALY signal (+40/+50)

Fires when a release diff touches suspicious files (CI, entrypoints,
dist/) mixed with or instead of normal source changes."
```

---

### Task 5: Add RELEASE_CADENCE_ANOMALY signal

**Files:**
- Modify: `internal/risk/score.go`
- Modify: `internal/risk/score_test.go`

- [ ] **Step 1: Write failing tests for RELEASE_CADENCE_ANOMALY**

Append to `internal/risk/score_test.go`:

```go
func TestReleaseCadence_BurstRelease(t *testing.T) {
	// Mean 30 days, released 2 hours ago → +25
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 2 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RELEASE_CADENCE_ANOMALY signal, got: %v", signals)
	}
}

func TestReleaseCadence_NormalTiming(t *testing.T) {
	// Mean 30 days, released 20 days ago → no signal
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 20 * 24 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			t.Errorf("RELEASE_CADENCE_ANOMALY should not fire for normal timing, got: %v", signals)
		}
	}
}

func TestReleaseCadence_HighCadenceExcluded(t *testing.T) {
	// Mean 2 days (high cadence) → no signal even with burst
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  2 * 24 * time.Hour,
		TimeSinceLastRelease: 1 * time.Hour,
		ReleaseHistoryLen:    10,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			t.Errorf("RELEASE_CADENCE_ANOMALY should not fire for high-cadence projects, got: %v", signals)
		}
	}
}

func TestReleaseCadence_TooFewReleases(t *testing.T) {
	// < 3 releases in history → no signal
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 1 * time.Hour,
		ReleaseHistoryLen:    2,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			t.Errorf("RELEASE_CADENCE_ANOMALY should not fire with < 3 releases, got: %v", signals)
		}
	}
}

func TestReleaseCadence_DormantAction(t *testing.T) {
	// Dormant 6 months, mean 30 days → +25
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 180 * 24 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RELEASE_CADENCE_ANOMALY for dormant action, got: %v", signals)
	}
}

func TestReleaseCadence_RapidFire(t *testing.T) {
	// 4 releases in last 24h → +25
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 1 * time.Hour,
		ReleasesLast24h:      4,
		ReleaseHistoryLen:    10,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RELEASE_CADENCE_ANOMALY for rapid-fire releases, got: %v", signals)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/risk/ -run TestReleaseCadence -v`
Expected: FAIL — scoring branch doesn't exist

- [ ] **Step 3: Add RELEASE_CADENCE_ANOMALY scoring branch**

In `internal/risk/score.go`, add after the DIFF_ANOMALY block:

```go
// Release cadence anomaly
if ctx.ReleaseHistoryLen >= 3 && ctx.MeanReleaseInterval > 7*24*time.Hour {
    fired := false
    reason := ""

    // Burst: released in < 10% of mean interval
    if ctx.TimeSinceLastRelease > 0 && ctx.TimeSinceLastRelease < ctx.MeanReleaseInterval/10 {
        fired = true
        reason = "burst release (time since last release far below average)"
    }

    // Rapid-fire: > 3 releases in 24h
    if ctx.ReleasesLast24h > 3 {
        fired = true
        reason = "rapid-fire releases in last 24 hours"
    }

    // Dormant: > 3× mean interval and mean < 90 days
    if ctx.MeanReleaseInterval < 90*24*time.Hour &&
        ctx.TimeSinceLastRelease > 3*ctx.MeanReleaseInterval {
        fired = true
        reason = "dormant action suddenly releasing (time since last release exceeds 3× average)"
    }

    if fired {
        score += 25
        signals = append(signals, "RELEASE_CADENCE_ANOMALY: "+reason)
    }
}
```

Note: This block avoids `fmt.Sprintf` to stay consistent with the existing `score.go` convention of not importing `fmt`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/risk/ -run TestReleaseCadence -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/risk/score.go internal/risk/score_test.go
git commit -m "feat: add RELEASE_CADENCE_ANOMALY signal (+25)

Fires on burst releases, rapid-fire releases (>3 in 24h), or dormant
actions suddenly releasing. Excluded for high-cadence (<7d) projects."
```

---

### Task 6: Add composite scoring tests

**Files:**
- Modify: `internal/risk/score_test.go`

- [ ] **Step 1: Write composite scenario tests**

Append to `internal/risk/score_test.go`:

```go
func TestComposite_AllBehavioralSignals_Critical(t *testing.T) {
	// Legitimate-looking attack: descendant, release exists, but all 3 behavioral signals fire
	// Score: -30 (MAJOR_TAG_ADVANCE) + 35 (CONTRIBUTOR) + 40 (DIFF) + 25 (CADENCE) = +70 → CRITICAL
	sev, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		NewContributors:      []string{"attacker"},
		SuspiciousFiles:      []string{"dist/index.js", "action.yml"},
		DiffOnly:             false,
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 2 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for composite behavioral anomaly, got %s (signals: %v)", sev, signals)
	}
	expected := []string{"MAJOR_TAG_ADVANCE", "CONTRIBUTOR_ANOMALY", "DIFF_ANOMALY", "RELEASE_CADENCE_ANOMALY"}
	for _, prefix := range expected {
		found := false
		for _, s := range signals {
			if strings.HasPrefix(s, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing signal %s in %v", prefix, signals)
		}
	}
}

func TestComposite_LegitimateRelease_Low(t *testing.T) {
	// Legitimate release: known author, normal diff, normal cadence → LOW (-30)
	sev, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		NewContributors:      []string{},   // all known
		SuspiciousFiles:      []string{},   // normal files only
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 25 * 24 * time.Hour,
		ReleaseHistoryLen:    10,
	})
	if sev != SeverityLow {
		t.Errorf("expected LOW for legitimate release, got %s (signals: %v)", sev, signals)
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/risk/ -v`
Expected: ALL PASS (these are validation tests, the signals are already implemented)

- [ ] **Step 3: Commit**

```bash
git add internal/risk/score_test.go
git commit -m "test: add composite scoring tests for behavioral anomaly signals

Validates the 100-point swing scenario from spec 025: legitimate-looking
attack goes from -30 (invisible) to +70 (CRITICAL)."
```

---

### Task 7: Add suspicious file classification helper

**Files:**
- Modify: `internal/risk/score.go`
- Modify: `internal/risk/score_test.go`

This helper classifies files from the Compare API response into suspicious vs normal. It's called from `main.go` during enrichment to populate `SuspiciousFiles` and `DiffOnly`.

- [ ] **Step 1: Write failing tests for ClassifyDiffFiles**

Append to `internal/risk/score_test.go`:

```go
func TestClassifyDiffFiles_MixedSuspicious(t *testing.T) {
	files := []string{"src/main.ts", "dist/index.js", ".github/workflows/ci.yml"}
	suspicious, diffOnly := ClassifyDiffFiles(files)
	if len(suspicious) != 2 {
		t.Errorf("expected 2 suspicious files, got %d: %v", len(suspicious), suspicious)
	}
	if diffOnly {
		t.Error("expected diffOnly=false when normal files present")
	}
}

func TestClassifyDiffFiles_NormalOnly(t *testing.T) {
	files := []string{"src/main.ts", "README.md", "package.json"}
	suspicious, _ := ClassifyDiffFiles(files)
	if len(suspicious) != 0 {
		t.Errorf("expected 0 suspicious files, got %d: %v", len(suspicious), suspicious)
	}
}

func TestClassifyDiffFiles_SuspiciousOnly(t *testing.T) {
	files := []string{".github/workflows/ci.yml", "Makefile"}
	suspicious, diffOnly := ClassifyDiffFiles(files)
	if len(suspicious) != 2 {
		t.Errorf("expected 2 suspicious files, got %d: %v", len(suspicious), suspicious)
	}
	if !diffOnly {
		t.Error("expected diffOnly=true when only suspicious files")
	}
}

func TestClassifyDiffFiles_EntrypointSh(t *testing.T) {
	files := []string{"entrypoint.sh", "src/main.go"}
	suspicious, diffOnly := ClassifyDiffFiles(files)
	if len(suspicious) != 1 || suspicious[0] != "entrypoint.sh" {
		t.Errorf("expected [entrypoint.sh], got: %v", suspicious)
	}
	if diffOnly {
		t.Error("expected diffOnly=false")
	}
}

func TestClassifyDiffFiles_Dockerfile(t *testing.T) {
	files := []string{"Dockerfile", "src/index.ts"}
	suspicious, _ := ClassifyDiffFiles(files)
	if len(suspicious) != 1 {
		t.Errorf("expected 1 suspicious file, got %d: %v", len(suspicious), suspicious)
	}
}

func TestClassifyDiffFiles_ActionYml(t *testing.T) {
	files := []string{"action.yml", "src/index.ts"}
	suspicious, _ := ClassifyDiffFiles(files)
	// action.yml is classified as suspicious at the file level.
	// The spec notes that action.yml changes to description/inputs/branding
	// (not runs.*) should be filtered out, but this requires fetching the
	// actual diff content from the API — deferred to a follow-up.
	if len(suspicious) != 1 || suspicious[0] != "action.yml" {
		t.Errorf("expected [action.yml], got: %v", suspicious)
	}
}

func TestClassifyDiffFiles_DocsOnly(t *testing.T) {
	files := []string{"docs/guide.md", "README.md", "LICENSE"}
	suspicious, _ := ClassifyDiffFiles(files)
	if len(suspicious) != 0 {
		t.Errorf("expected 0 suspicious for docs-only, got: %v", suspicious)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/risk/ -run TestClassifyDiffFiles -v`
Expected: FAIL — `ClassifyDiffFiles` doesn't exist

- [ ] **Step 3: Implement ClassifyDiffFiles**

Add to `internal/risk/score.go`:

```go
// ClassifyDiffFiles separates changed files into suspicious and normal categories.
// Returns the list of suspicious files and whether ALL changed files are suspicious
// (diffOnly=true means no normal files to provide cover).
func ClassifyDiffFiles(files []string) (suspicious []string, diffOnly bool) {
	normalCount := 0
	for _, f := range files {
		if isSuspiciousFile(f) {
			suspicious = append(suspicious, f)
		} else {
			normalCount++
		}
	}
	diffOnly = len(suspicious) > 0 && normalCount == 0
	return suspicious, diffOnly
}

func isSuspiciousFile(path string) bool {
	// Exact matches
	switch path {
	case "Makefile", "Dockerfile", "entrypoint.sh", "action.yml", "action.yaml",
		"setup.py", "setup.cfg":
		return true
	}

	// Prefix matches
	if strings.HasPrefix(path, ".github/workflows/") {
		return true
	}
	if strings.HasPrefix(path, "dist/") {
		return true
	}

	// Basename matches
	base := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		base = path[idx+1:]
	}
	if strings.HasPrefix(base, "postinstall") || strings.HasPrefix(base, "preinstall") {
		return true
	}

	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/risk/ -run TestClassifyDiffFiles -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/risk/score.go internal/risk/score_test.go
git commit -m "feat: add ClassifyDiffFiles for DIFF_ANOMALY enrichment

Categorizes changed files as suspicious (CI, entrypoints, dist/, install
scripts) or normal (source, docs, config). Used during scan enrichment."
```

---

### Task 8: Wire enrichment and lockfile updates into runScan

**Files:**
- Modify: `cmd/pinpoint/main.go` (runScan function, around lines 690-810)

This task loads the lockfile once at scan start, uses it for behavioral enrichment during scoring, updates it with new baseline data after each tag movement, and saves once at the end.

- [ ] **Step 1: Add lockfile loading at the top of runScan**

In `cmd/pinpoint/main.go`, at the top of `runScan` (after the `scoreContexts` declaration), add:

```go
// Load lockfile for behavioral baseline data (spec 025)
lockfilePath, _ := manifest.ResolveLockfilePath(".")
behavioralManifest, behavioralLoadErr := manifest.LoadManifest(lockfilePath)
lockfileExists := behavioralLoadErr == nil
behavioralUpdated := false
```

- [ ] **Step 2: Update the CompareCommits call and add behavioral enrichment**

The `compareResult` variable must be declared BEFORE the `if err == nil` block so it's accessible later for lockfile updates. Replace the existing CompareCommits enrichment block:

```go
// Enrichment: check commit ancestry
var compareResult *poller.CompareResult
var compareErr error
compareResult, compareErr = restClient.CompareCommits(ctx, owner, repo, previousSHA, tag.CommitSHA)
if compareErr == nil {
    scoreCtx.IsDescendant = compareResult.IsDescendant
    scoreCtx.AheadBy = compareResult.AheadBy
    scoreCtx.BehindBy = compareResult.BehindBy

    // Behavioral enrichment: diff anomaly (spec 025)
    scoreCtx.SuspiciousFiles, scoreCtx.DiffOnly = risk.ClassifyDiffFiles(compareResult.Files)

    // Behavioral enrichment from lockfile (spec 025)
    if lockfileExists {
        if tags, ok := behavioralManifest.Actions[actionCfg.Repo]; ok {
            if entry, ok := tags[tag.Name]; ok {
                // Contributor anomaly
                if len(entry.KnownContributors) > 0 {
                    known := make(map[string]bool)
                    for _, c := range entry.KnownContributors {
                        known[c] = true
                    }
                    for _, login := range compareResult.AuthorLogins {
                        if !known[login] {
                            scoreCtx.NewContributors = append(scoreCtx.NewContributors, login)
                        }
                    }
                    if scoreCtx.NewContributors == nil {
                        scoreCtx.NewContributors = []string{} // empty = all known
                    }
                }

                // Release cadence anomaly
                if len(entry.ReleaseHistory) >= 3 {
                    scoreCtx.ReleaseHistoryLen = len(entry.ReleaseHistory)
                    scoreCtx.MeanReleaseInterval = computeMeanInterval(entry.ReleaseHistory)
                    if last, parseErr := time.Parse(time.RFC3339, entry.ReleaseHistory[len(entry.ReleaseHistory)-1]); parseErr == nil {
                        scoreCtx.TimeSinceLastRelease = time.Since(last)
                    }
                    cutoff := time.Now().Add(-24 * time.Hour)
                    for _, ts := range entry.ReleaseHistory {
                        if parsed, parseErr := time.Parse(time.RFC3339, ts); parseErr == nil && parsed.After(cutoff) {
                            scoreCtx.ReleasesLast24h++
                        }
                    }
                }
            }
        }
    }
}
```

Note: `var compareResult *poller.CompareResult` is declared outside the `if` block so it's accessible for lockfile updates later. Uses `compareErr` as the error variable name to avoid conflicting with any prior `err` declarations in the scope. The inner loop variable is `parsed` (not `t`) to avoid shadowing the outer `tag` loop variable.

- [ ] **Step 3: Add lockfile update after alert creation**

After the alert is appended to `allAlerts`, add:

```go
// Update behavioral baselines in lockfile (spec 025)
if lockfileExists {
    if tags, ok := behavioralManifest.Actions[actionCfg.Repo]; ok {
        if entry, ok := tags[tag.Name]; ok {
            // Merge new contributors into known set
            if compareResult != nil && len(compareResult.AuthorLogins) > 0 {
                known := make(map[string]bool)
                for _, c := range entry.KnownContributors {
                    known[c] = true
                }
                for _, login := range compareResult.AuthorLogins {
                    if !known[login] {
                        entry.KnownContributors = append(entry.KnownContributors, login)
                    }
                }
            }

            // Append release timestamp
            now := time.Now().UTC().Format(time.RFC3339)
            entry.ReleaseHistory = append(entry.ReleaseHistory, now)
            tags[tag.Name] = entry
            behavioralUpdated = true
        }
    }
}
```

- [ ] **Step 4: Add lockfile save at the end of runScan**

At the end of `runScan`, before the final `return`, add:

```go
// Save behavioral baseline updates (spec 025)
if behavioralUpdated && lockfileExists {
    _ = manifest.SaveManifest(lockfilePath, behavioralManifest)
}
```

- [ ] **Step 5: Add the computeMeanInterval helper**

Add to `cmd/pinpoint/main.go` (near the other helper functions like `truncate`):

```go
// computeMeanInterval calculates the average time between release timestamps.
func computeMeanInterval(history []string) time.Duration {
	if len(history) < 2 {
		return 0
	}
	var times []time.Time
	for _, ts := range history {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			times = append(times, t)
		}
	}
	if len(times) < 2 {
		return 0
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	total := times[len(times)-1].Sub(times[0])
	return total / time.Duration(len(times)-1)
}
```

Ensure `sort` is imported in the import block.

- [ ] **Step 6: Verify build**

Run: `go build ./cmd/pinpoint/`
Expected: BUILD SUCCESS

- [ ] **Step 7: Run all tests**

Run: `go vet ./... && go test ./...`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add cmd/pinpoint/main.go
git commit -m "feat: wire behavioral anomaly enrichment and lockfile persistence

Loads lockfile once per scan for behavioral baselines. Populates
NewContributors, SuspiciousFiles, DiffOnly, and cadence fields during
enrichment. Updates known_contributors and release_history after tag
movements. Saves once at end of scan."
```

---

### Task 9: Update existing tests for new signal count

**Files:**
- Modify: `internal/risk/score_test.go`

Existing tests that assert exact signal counts or expected severity may need updating if the new ScoreContext fields (when zero-valued) inadvertently trigger signals.

- [ ] **Step 1: Verify all existing tests still pass with new signals**

Run: `go test ./internal/risk/ -v`

Check output carefully. The new signals should NOT fire when their fields are zero/nil:
- `NewContributors nil` → no CONTRIBUTOR_ANOMALY (guarded by `!= nil && len > 0`)
- `SuspiciousFiles nil` → no DIFF_ANOMALY (guarded by `!= nil && len > 0`)
- `ReleaseHistoryLen 0` → no RELEASE_CADENCE_ANOMALY (guarded by `>= 3`)

Expected: ALL PASS with no changes needed.

- [ ] **Step 2: If any test fails, update the assertion**

For example, if `TestScore_AllSignalsCritical` asserts `len(signals) < 7`, update to account for new signals if new fields are populated. (They shouldn't be — fields default to zero values.)

- [ ] **Step 3: Run full test suite**

Run: `go vet ./... && go test ./...`
Expected: ALL PASS (264+ tests)

- [ ] **Step 4: Commit if any test updates were needed**

```bash
git add internal/risk/score_test.go
git commit -m "test: update existing tests for behavioral anomaly signal compatibility"
```

---

### Task 10: Final validation

**Files:** None (read-only)

- [ ] **Step 1: Run go vet**

Run: `go vet ./...`
Expected: No issues

- [ ] **Step 2: Run full test suite**

Run: `go test ./... -count=1`
Expected: ALL PASS

- [ ] **Step 3: Build binary and check version**

Run: `go build -o pinpoint ./cmd/pinpoint/ && ./pinpoint version`
Expected: Builds successfully

- [ ] **Step 4: Verify signal count**

Count the total number of risk signals now: MASS_REPOINT, OFF_BRANCH, IMPOSSIBLE_TIMESTAMP, SIZE_ANOMALY, SEMVER_REPOINT, BACKDATED_COMMIT, SIGNATURE_DROPPED, NO_RELEASE, SELF_HOSTED, MAJOR_TAG_ADVANCE, CONTRIBUTOR_ANOMALY, DIFF_ANOMALY, RELEASE_CADENCE_ANOMALY = **13 signals** (was 10).

---

## Deferred Items

These items from the spec are explicitly deferred to follow-up work:

1. **`action.yml` description-only filtering** (spec test case 7): The spec says `action.yml` changes that only modify `description`, `inputs`, or `branding` should be filtered out. This requires fetching the actual diff content from the Compare API (the `patch` field per file), which adds complexity. Currently `action.yml` is always classified as suspicious. A follow-up can add content-aware filtering.

2. **`diff_ignore` allow-list** (spec: "Allow-list by file path pattern"): The spec mentions `allow: { diff_ignore: ["dist/*"] }` for actions that legitimately bundle compiled output. This requires a config schema change (`config.go`) and integration with `ClassifyDiffFiles`. Deferred to avoid scope creep in this PR.
