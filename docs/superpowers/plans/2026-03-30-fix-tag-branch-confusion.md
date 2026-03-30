# Fix Tag/Branch Ref Confusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the systemic bug where branch names that look like semver versions (e.g., "v1", "v1.2.3") are misclassified as tags across the entire codebase.

**Architecture:** Replace the hardcoded branch name list in the gate with a heuristic that queries the GitHub API to disambiguate refs. For offline/non-API contexts (audit, discover, risk scoring), improve the regex heuristics to catch common branch patterns. Add an `IsBranch` field to `ScoreContext` so tag-specific signals can guard against branch refs.

**Tech Stack:** Go 1.24, standard library only (no new dependencies).

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/gate/gate.go` | Modify | Replace `knownBranches` map with `looksLikeBranch()` heuristic + optional API disambiguation |
| `internal/gate/gate_test.go` | Modify | Add tests for branch-like version refs |
| `internal/audit/audit.go` | Modify | Fix `classifyRef()` regex and `tagRe` pattern |
| `internal/audit/audit_test.go` | Modify | Add tests for version-like branch classification |
| `internal/risk/score.go` | Modify | Add `IsBranch` guard to SEMVER_REPOINT and MAJOR_TAG_ADVANCE |
| `internal/risk/score_test.go` | Modify | Add tests for branch refs not triggering tag signals |
| `internal/suppress/suppress.go` | Modify | Add `IsBranch` guard to `major_tag_advance` condition |
| `internal/suppress/suppress_test.go` | Modify | Add tests for branch refs not being suppressed |
| `internal/discover/discover.go` | Modify | Add `IsBranch` field to `ActionRef` using same heuristic |
| `internal/discover/discover_test.go` | Modify | Add tests for branch classification |
| `internal/manifest/transitive.go` | Modify | Add branch fallback to `resolveRefToSHA()` |
| `internal/manifest/transitive_test.go` | Modify | Add test for branch ref resolution fallback |

---

### Task 1: Fix Gate — Replace Hardcoded Branch List with Heuristic

The gate is the most critical path. The hardcoded 8-name list misses any branch with a version-like name.

**Files:**
- Modify: `internal/gate/gate.go:72-76` (knownBranches), `internal/gate/gate.go:262` (classification)
- Test: `internal/gate/gate_test.go`

- [ ] **Step 1: Write failing tests for branch-like version refs**

Add to `internal/gate/gate_test.go`:

```go
func TestGate_VersionBranch_DetectedAsBranch(t *testing.T) {
	// A ref like "v1" that exists as a branch but NOT as a tag should be
	// detected as branch-pinned, not treated as a tag.
	//
	// We simulate this by having GraphQL return NO tags for the repo.
	// If the gate treats "v1" as a tag, it will say "tag not found on remote".
	// If it correctly detects it as a branch, it will say "branch-pinned".
	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return empty tag list for the repo
		fmt.Fprintf(w, `{"data":{"actions_checkout":{"refs":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}`)
	}))
	defer graphqlServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "actions-lock.json") {
			manifest := `{"version":2,"actions":{}}`
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, base64Encode(manifest))
			return
		}
		if strings.Contains(path, ".github/workflows") && !strings.Contains(path, "contents") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `["ci.yml"]`)
			return
		}
		if strings.Contains(path, "ci.yml") {
			wf := "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v1\n"
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, base64Encode(wf))
			return
		}
		http.NotFound(w, r)
	}))
	defer apiServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "myorg/myrepo",
		SHA:          "abc1234567890abc1234567890abc1234567890ab",
		ManifestPath: ".github/actions-lock.json",
		Token:        "test-token",
		APIURL:       apiServer.URL,
		GraphQLURL:   graphqlServer.URL,
		AllWorkflows: true,
		FailOnUnpinned: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect as branch-pinned, not "tag not found"
	foundBranchWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w.Message, "branch-pinned") {
			foundBranchWarning = true
		}
	}
	if !foundBranchWarning {
		t.Errorf("expected branch-pinned warning for v1 ref not found as tag, got warnings: %+v", result.Warnings)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -run TestGate_VersionBranch_DetectedAsBranch -v`
Expected: FAIL — "v1" is treated as a tag, not a branch

- [ ] **Step 3: Replace knownBranches with looksLikeBranch() heuristic**

In `internal/gate/gate.go`, replace lines 72-76:

```go
// knownBranches is a set of common branch names used to detect branch-pinned refs.
var knownBranches = map[string]bool{
	"main": true, "master": true, "develop": true, "dev": true,
	"trunk": true, "release": true, "staging": true, "production": true,
}
```

With:

```go
// knownBranches is a set of common branch names that are definitely branches.
var knownBranches = map[string]bool{
	"main": true, "master": true, "develop": true, "dev": true,
	"trunk": true, "release": true, "staging": true, "production": true,
}

// looksLikeBranch returns true if the ref is likely a branch, not a tag.
// A ref is classified as a branch if:
//   - It's in the known branches list, OR
//   - It contains a "/" (e.g., "release/v1.0", "feature/foo"), OR
//   - It does NOT look like a version tag (not matching v?\d patterns)
//
// Refs that look like version tags (v1, v1.2.3, 1.0) are NOT classified
// as branches here — they are resolved via the GitHub API. If the API shows
// no matching tag, they are reclassified as branches at that point.
func looksLikeBranch(ref string) bool {
	if knownBranches[ref] {
		return true
	}
	// Refs with slashes are branches (release/v1.0, feature/foo)
	if strings.Contains(ref, "/") {
		return true
	}
	return false
}
```

Then update the classification at line 262 from:

```go
		isBranch := knownBranches[ref]
		tagRefs = append(tagRefs, actionRef{
			Owner: owner, Repo: repo, Ref: ref, Raw: raw,
			IsSHA: false, IsBranch: isBranch,
		})
```

To:

```go
		isBranch := looksLikeBranch(ref)
		tagRefs = append(tagRefs, actionRef{
			Owner: owner, Repo: repo, Ref: ref, Raw: raw,
			IsSHA: false, IsBranch: isBranch,
		})
```

And add a post-GraphQL reclassification step. After the GraphQL tag resolution (around line 290, after `tagMap` is populated), add:

```go
	// Reclassify version-like refs that aren't found as tags.
	// If GraphQL returns no matching tag for a ref like "v1", it's a branch.
	for i, ar := range tagRefs {
		if ar.IsBranch || ar.IsSHA {
			continue
		}
		key := ar.Owner + "/" + ar.Repo
		repoTags := tagMap[key]
		if repoTags != nil && repoTags[ar.Ref] == "" {
			// Ref looks like a version but doesn't exist as a tag — it's a branch
			tagRefs[i].IsBranch = true
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -run TestGate_VersionBranch_DetectedAsBranch -v`
Expected: PASS

- [ ] **Step 5: Run all gate tests**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -v`
Expected: All existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add internal/gate/gate.go internal/gate/gate_test.go
git commit -m "fix(gate): detect version-like branch refs via API disambiguation

Replace hardcoded 8-name knownBranches with looksLikeBranch() heuristic
plus post-GraphQL reclassification. Refs like 'v1' that don't exist as
tags are now correctly identified as branch-pinned."
```

---

### Task 2: Fix Audit — Improve classifyRef() Heuristic

The audit's `tagRe = ^v?\d` is too broad. It matches "v1-beta", "v2-rc1" etc.

**Files:**
- Modify: `internal/audit/audit.go:68` (tagRe regex), `internal/audit/audit.go:308-317` (classifyRef)
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/audit/audit_test.go`:

```go
func TestClassifyRef_BranchLikeVersions(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		// Pure versions → tag (correct)
		{"v1", "tag"},
		{"v4", "tag"},
		{"v1.2.3", "tag"},
		{"1.0.0", "tag"},
		{"v2.0", "tag"},
		// Version-like branches → branch (the bug fix)
		{"v1-beta", "branch"},
		{"v2-rc1", "branch"},
		{"v3.0-rc1", "branch"},
		{"v1-fix", "branch"},
		{"v2.0-experimental", "branch"},
		// Slash branches → branch
		{"release/v1.0", "branch"},
		{"feature/v2", "branch"},
		// Standard branches → branch (unchanged)
		{"main", "branch"},
		{"master", "branch"},
		{"develop", "branch"},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got := classifyRef(tt.ref)
			if got != tt.want {
				t.Errorf("classifyRef(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/joshf/pinpoint && go test ./internal/audit/ -run TestClassifyRef_BranchLikeVersions -v`
Expected: FAIL — "v1-beta", "v2-rc1", etc. classified as "tag"

- [ ] **Step 3: Fix the tagRe regex and classifyRef**

In `internal/audit/audit.go`, replace line 68:

```go
	tagRe  = regexp.MustCompile(`^v?\d`)
```

With:

```go
	// tagRe matches version tags: v1, v1.2, v1.2.3, 1.0.0
	// Must be ONLY digits, dots, and optional v prefix — no hyphens, no letters after.
	tagRe = regexp.MustCompile(`^v?\d+(\.\d+)*$`)
```

And update `classifyRef` to also handle slash-branches:

```go
func classifyRef(ref string) string {
	if shaRe.MatchString(ref) {
		return "sha"
	}
	// Refs with slashes are always branches (release/v1.0, feature/foo)
	if strings.Contains(ref, "/") {
		return "branch"
	}
	if tagRe.MatchString(ref) {
		return "tag"
	}
	return "branch"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/joshf/pinpoint && go test ./internal/audit/ -run TestClassifyRef_BranchLikeVersions -v`
Expected: PASS

- [ ] **Step 5: Run all audit tests**

Run: `cd /home/joshf/pinpoint && go test ./internal/audit/ -v`
Expected: All existing tests pass. The existing `TestClassifyRef` test case `{"1.0", "tag"}` should still pass since `1.0` matches `^v?\d+(\.\d+)*$`.

- [ ] **Step 6: Commit**

```bash
git add internal/audit/audit.go internal/audit/audit_test.go
git commit -m "fix(audit): tighten tagRe regex to reject version-like branch names

classifyRef now requires refs to be purely numeric (with dots and optional
v prefix) to classify as tags. Refs like 'v1-beta' and 'v2-rc1' are now
correctly classified as branches, triggering the +40 branch-pinned penalty."
```

---

### Task 3: Fix Risk Scoring — Guard Tag Signals with IsBranch

SEMVER_REPOINT (+50) and MAJOR_TAG_ADVANCE (-30) fire based on regex alone with no check if the ref is actually a tag.

**Files:**
- Modify: `internal/risk/score.go:36-60` (ScoreContext), `internal/risk/score.go:109`, `internal/risk/score.go:186`
- Test: `internal/risk/score_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/risk/score_test.go`:

```go
func TestScore_BranchRefSkipsTagSignals(t *testing.T) {
	// A branch named "v1.2.3" should NOT trigger SEMVER_REPOINT
	sev, signals := Score(ScoreContext{
		TagName:    "v1.2.3",
		IsBranch:   true,
		CommitDate: time.Now(),
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SEMVER_REPOINT") {
			t.Errorf("SEMVER_REPOINT should not fire for branch ref, got: %s", s)
		}
	}
	_ = sev
}

func TestScore_BranchRefSkipsMajorTagAdvance(t *testing.T) {
	// A branch named "v2" should NOT get the -30 MAJOR_TAG_ADVANCE deduction
	_, signals := Score(ScoreContext{
		TagName:      "v2",
		IsBranch:     true,
		IsDescendant: true,
		CommitDate:   time.Now(),
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "MAJOR_TAG_ADVANCE") {
			t.Errorf("MAJOR_TAG_ADVANCE should not fire for branch ref, got: %s", s)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/joshf/pinpoint && go test ./internal/risk/ -run TestScore_BranchRef -v`
Expected: FAIL — both signals fire because there's no IsBranch field yet

- [ ] **Step 3: Add IsBranch field and guard the signals**

In `internal/risk/score.go`, add `IsBranch` to `ScoreContext` (after line 37):

```go
type ScoreContext struct {
	TagName         string
	IsBranch        bool   // True if the ref is a branch, not a tag
	IsDescendant    bool   // Is the new commit a descendant of the old?
```

Then guard SEMVER_REPOINT at line 108-112. Change:

```go
	// Exact semver tag was repointed (these should never move)
	if semverExactRe.MatchString(ctx.TagName) {
		score += 50
		signals = append(signals, "SEMVER_REPOINT: exact version tag should never be moved")
	}
```

To:

```go
	// Exact semver tag was repointed (these should never move)
	// Skip for branch refs — branches named like versions are mutable by design.
	if !ctx.IsBranch && semverExactRe.MatchString(ctx.TagName) {
		score += 50
		signals = append(signals, "SEMVER_REPOINT: exact version tag should never be moved")
	}
```

And guard MAJOR_TAG_ADVANCE at line 185-189. Change:

```go
	// Major version tag moved forward to descendant (expected behavior)
	if majorVersionRe.MatchString(ctx.TagName) && ctx.IsDescendant {
		score -= 30
		signals = append(signals, "MAJOR_TAG_ADVANCE: major version tag moved forward (routine)")
	}
```

To:

```go
	// Major version tag moved forward to descendant (expected behavior)
	// Skip for branch refs — branches don't get this deduction.
	if !ctx.IsBranch && majorVersionRe.MatchString(ctx.TagName) && ctx.IsDescendant {
		score -= 30
		signals = append(signals, "MAJOR_TAG_ADVANCE: major version tag moved forward (routine)")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/joshf/pinpoint && go test ./internal/risk/ -run TestScore_BranchRef -v`
Expected: PASS

- [ ] **Step 5: Run all risk tests**

Run: `cd /home/joshf/pinpoint && go test ./internal/risk/ -v`
Expected: All existing tests pass (they don't set IsBranch, so it defaults to false)

- [ ] **Step 6: Commit**

```bash
git add internal/risk/score.go internal/risk/score_test.go
git commit -m "fix(risk): skip tag-specific signals when ref is a branch

Add IsBranch field to ScoreContext. SEMVER_REPOINT and MAJOR_TAG_ADVANCE
now check !ctx.IsBranch before firing. Prevents false +50 on branch
'v1.2.3' and incorrect -30 deduction on branch 'v2'."
```

---

### Task 4: Fix Suppress — Guard major_tag_advance Condition

The suppress module's `major_tag_advance` condition matches branch "v1"/"v2" and could suppress real alerts.

**Files:**
- Modify: `internal/suppress/suppress.go:86-87`
- Test: `internal/suppress/suppress_test.go`

- [ ] **Step 1: Write failing test**

Add to `internal/suppress/suppress_test.go`:

```go
func TestSuppress_BranchRefNotSuppressedByMajorTagAdvance(t *testing.T) {
	// A branch named "v2" should NOT be suppressed by major_tag_advance,
	// even if it matches the regex and is a descendant.
	alerts := []risk.Alert{
		{
			Severity:    risk.SeverityMedium,
			Type:        "TAG_REPOINTED",
			Action:      "actions/checkout",
			Tag:         "v2",
			PreviousSHA: "aaa",
			CurrentSHA:  "bbb",
		},
	}
	rules := []config.AllowRule{
		{
			Repo:      "actions/*",
			Condition: "major_tag_advance",
			Reason:    "test",
		},
	}
	contexts := map[string]risk.ScoreContext{
		"actions/checkout@v2": {
			TagName:      "v2",
			IsBranch:     true,
			IsDescendant: true,
		},
	}

	result := Filter(alerts, rules, contexts)
	if len(result.Allowed) != 1 {
		t.Errorf("expected branch ref alert to pass through, got %d allowed, %d suppressed",
			len(result.Allowed), len(result.Suppressed))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/joshf/pinpoint && go test ./internal/suppress/ -run TestSuppress_BranchRefNotSuppressedByMajorTagAdvance -v`
Expected: FAIL — the alert is suppressed because IsBranch isn't checked

- [ ] **Step 3: Add IsBranch guard**

In `internal/suppress/suppress.go`, change line 86-87 from:

```go
	case "major_tag_advance":
		return majorVersionRe.MatchString(a.Tag) && ctx.IsDescendant
```

To:

```go
	case "major_tag_advance":
		return !ctx.IsBranch && majorVersionRe.MatchString(a.Tag) && ctx.IsDescendant
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/joshf/pinpoint && go test ./internal/suppress/ -run TestSuppress_BranchRefNotSuppressedByMajorTagAdvance -v`
Expected: PASS

- [ ] **Step 5: Run all suppress tests**

Run: `cd /home/joshf/pinpoint && go test ./internal/suppress/ -v`
Expected: All existing tests pass (they don't set IsBranch)

- [ ] **Step 6: Commit**

```bash
git add internal/suppress/suppress.go internal/suppress/suppress_test.go
git commit -m "fix(suppress): don't suppress branch refs via major_tag_advance

The major_tag_advance condition now checks !ctx.IsBranch before matching.
A branch named 'v2' will no longer be incorrectly suppressed."
```

---

### Task 5: Fix Discover — Add IsBranch Field to ActionRef

The discover module has no tag/branch distinction. Add a heuristic consistent with the audit fix.

**Files:**
- Modify: `internal/discover/discover.go:17-24` (ActionRef struct), `internal/discover/discover.go:95-101`
- Test: `internal/discover/discover_test.go`

- [ ] **Step 1: Write failing test**

Add to `internal/discover/discover_test.go`:

```go
func TestDiscover_BranchClassification(t *testing.T) {
	// Create a temp workflow file with various ref types
	dir := t.TempDir()
	wf := `name: test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@main
      - uses: some/action@v1-beta
      - uses: other/action@release/v2
      - uses: pinned/action@abc1234567890abc1234567890abc1234567890ab
`
	os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(wf), 0644)

	refs, err := FromWorkflowDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]bool{
		"actions/checkout@v4":    false, // tag
		"actions/setup-go@main": true,  // branch
		"some/action@v1-beta":   true,  // branch (hyphenated version)
		"other/action@release/v2": true, // branch (slash)
	}

	for _, ref := range refs {
		if ref.IsPinned {
			continue // skip SHA-pinned
		}
		key := ref.Full() + "@" + ref.Ref
		expectedBranch, ok := want[key]
		if !ok {
			continue
		}
		if ref.IsBranch != expectedBranch {
			t.Errorf("%s: IsBranch = %v, want %v", key, ref.IsBranch, expectedBranch)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/joshf/pinpoint && go test ./internal/discover/ -run TestDiscover_BranchClassification -v`
Expected: FAIL — ActionRef has no IsBranch field

- [ ] **Step 3: Add IsBranch to ActionRef and classification logic**

In `internal/discover/discover.go`, update the ActionRef struct (lines 17-24):

```go
type ActionRef struct {
	Owner    string
	Repo     string
	Ref      string // Tag, branch, or SHA
	IsPinned bool   // True if ref looks like a full SHA
	IsBranch bool   // True if ref looks like a branch name
	Source   string // Workflow file where it was found
	Raw      string // The full uses: string
}
```

Add the classification regex and helper (after line 35):

```go
	// tagLikeRe matches refs that look like version tags: v1, v1.2, v1.2.3, 1.0
	tagLikeRe = regexp.MustCompile(`^v?\d+(\.\d+)*$`)
)

// looksLikeBranch returns true if a non-SHA ref appears to be a branch.
func looksLikeBranch(ref string) bool {
	// Known branch names
	switch ref {
	case "main", "master", "develop", "dev", "trunk", "release", "staging", "production":
		return true
	}
	// Slash-separated refs are branches (release/v1.0, feature/foo)
	if strings.Contains(ref, "/") {
		return true
	}
	// If it doesn't look like a version tag, it's a branch
	if !tagLikeRe.MatchString(ref) {
		return true
	}
	return false
}
```

Remove the trailing `)` from the existing `var` block (so the new regex is inside it), and update the ref construction at line 95-101:

```go
		ref := ActionRef{
			Owner:    matches[1],
			Repo:     matches[2],
			Ref:      matches[3],
			IsPinned: shaRe.MatchString(matches[3]),
			IsBranch: !shaRe.MatchString(matches[3]) && looksLikeBranch(matches[3]),
			Source:   filepath.Base(path),
			Raw:      matches[0],
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/joshf/pinpoint && go test ./internal/discover/ -run TestDiscover_BranchClassification -v`
Expected: PASS

- [ ] **Step 5: Run all discover tests**

Run: `cd /home/joshf/pinpoint && go test ./internal/discover/ -v`
Expected: All existing tests pass

- [ ] **Step 6: Commit**

```bash
git add internal/discover/discover.go internal/discover/discover_test.go
git commit -m "fix(discover): add IsBranch field to ActionRef

Refs like 'v1-beta', 'release/v2', and 'main' are now classified as
branches. Pure version patterns (v1, v1.2.3) remain classified as tags."
```

---

### Task 6: Fix Manifest — Add Branch Fallback to resolveRefToSHA

The transitive dependency resolver only queries `/git/ref/tags/`. If a composite action references a branch, resolution silently fails.

**Files:**
- Modify: `internal/manifest/transitive.go:228-262` (resolveRefToSHA)
- Test: `internal/manifest/transitive_test.go`

- [ ] **Step 1: Write failing test**

Add to `internal/manifest/transitive_test.go`:

```go
func TestResolveRefToSHA_FallsBackToBranch(t *testing.T) {
	// When a ref doesn't exist as a tag, resolveRefToSHA should try
	// the heads (branch) endpoint as fallback.
	commitSHA := "abc1234567890abc1234567890abc1234567890ab"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "/git/ref/tags/v1") {
			// Tag doesn't exist
			http.NotFound(w, r)
			return
		}
		if strings.Contains(path, "/git/ref/heads/v1") {
			// Branch exists
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ref":"refs/heads/v1","object":{"type":"commit","sha":"%s"}}`, commitSHA)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sha, err := resolveRefToSHA(context.Background(), server.Client(), server.URL, "", "actions", "checkout", "v1")
	if err != nil {
		t.Fatalf("resolveRefToSHA failed: %v", err)
	}
	if sha != commitSHA {
		t.Errorf("got SHA %q, want %q", sha, commitSHA)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/joshf/pinpoint && go test ./internal/manifest/ -run TestResolveRefToSHA_FallsBackToBranch -v`
Expected: FAIL — no branch fallback exists

- [ ] **Step 3: Add branch fallback**

In `internal/manifest/transitive.go`, replace `resolveRefToSHA` (lines 228-262):

```go
// resolveRefToSHA resolves a tag or branch ref to a commit SHA using the GitHub REST API.
// Tries tags first, then falls back to branches.
func resolveRefToSHA(ctx context.Context, client *http.Client, baseURL, token, owner, repo, ref string) (string, error) {
	// Try tags first (most common for action refs)
	sha, err := resolveGitRef(ctx, client, baseURL, token, owner, repo, "tags/"+ref)
	if err == nil {
		return sha, nil
	}

	// Fall back to branches
	sha, branchErr := resolveGitRef(ctx, client, baseURL, token, owner, repo, "heads/"+ref)
	if branchErr == nil {
		return sha, nil
	}

	// Return the original tag error (more likely what the user intended)
	return "", fmt.Errorf("ref %q not found as tag or branch: %w", ref, err)
}

// resolveGitRef resolves a fully-qualified git ref (e.g., "tags/v1" or "heads/main") to a commit SHA.
func resolveGitRef(ctx context.Context, client *http.Client, baseURL, token, owner, repo, qualifiedRef string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/ref/%s", baseURL, owner, repo, qualifiedRef)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d resolving ref %s", resp.StatusCode, qualifiedRef)
	}

	var gr gitRefResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", err
	}

	// If it's an annotated tag, dereference to get the commit SHA
	if gr.Object.Type == "tag" {
		return dereferenceAnnotatedTag(ctx, client, baseURL, token, owner, repo, gr.Object.SHA)
	}

	return gr.Object.SHA, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/joshf/pinpoint && go test ./internal/manifest/ -run TestResolveRefToSHA_FallsBackToBranch -v`
Expected: PASS

- [ ] **Step 5: Run all manifest tests**

Run: `cd /home/joshf/pinpoint && go test ./internal/manifest/ -v`
Expected: All existing tests pass

- [ ] **Step 6: Commit**

```bash
git add internal/manifest/transitive.go internal/manifest/transitive_test.go
git commit -m "fix(manifest): add branch fallback to ref resolution

resolveRefToSHA now tries /git/ref/heads/ when /git/ref/tags/ returns
404. This fixes silent failures when composite actions reference branches
instead of tags."
```

---

### Task 7: Integration — Wire IsBranch Through Scan Command

The scan command builds `ScoreContext` but doesn't set `IsBranch`. Since the poller only fetches `refs/tags/`, branch refs won't appear in scan results today. But for consistency and future-proofing, the field should be plumbed through.

**Files:**
- Modify: `cmd/pinpoint/commands/scan.go:264-268`

- [ ] **Step 1: Verify the scan command compiles with new ScoreContext field**

Run: `cd /home/joshf/pinpoint && go build ./cmd/pinpoint/`
Expected: PASS — `IsBranch` defaults to `false` (zero value), which is correct since the poller only fetches tags

- [ ] **Step 2: Run full test suite**

Run: `cd /home/joshf/pinpoint && go test ./...`
Expected: All tests pass

- [ ] **Step 3: Run go vet**

Run: `cd /home/joshf/pinpoint && go vet ./...`
Expected: Clean

- [ ] **Step 4: Commit (if any changes needed)**

Only commit if build/vet revealed issues. Otherwise skip — no changes needed since the zero value is correct.

---

### Task 8: Final Verification

- [ ] **Step 1: Build binary**

Run: `cd /home/joshf/pinpoint && go build ./cmd/pinpoint/`
Expected: Clean build

- [ ] **Step 2: Run full test suite**

Run: `cd /home/joshf/pinpoint && go test ./... -count=1`
Expected: All tests pass

- [ ] **Step 3: Run go vet**

Run: `cd /home/joshf/pinpoint && go vet ./...`
Expected: Clean

- [ ] **Step 4: Verify binary works**

Run: `cd /home/joshf/pinpoint && ./pinpoint version`
Expected: Version output

- [ ] **Step 5: Final commit if needed, otherwise done**
