# Scenario Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub App auth, a repo pool, and 7 scenario-based integration tests on top of the existing test harness.

**Architecture:** auth.go provides token minting (GITHUB_TOKEN fallback → App JWT). pool.go pre-creates fixture repos and hands them out via channel. scenario.go defines the Scenario interface + runner. 7 scenario files implement specific attack patterns. All files use `//go:build integration`.

**Tech Stack:** Go stdlib only (crypto/rsa, encoding/pem for JWT). No new dependencies.

---

### Task 1: auth.go — GitHub App token minting

**Files:**
- Create: `tests/harness/auth.go`

- [ ] **Step 1: Create auth.go with MintAppToken and mintTokenFromKey**

`MintAppToken(t)` checks GITHUB_TOKEN first, then falls back to PINPOINT_APP_ID + PINPOINT_APP_KEY_PATH. `mintTokenFromKey` does stdlib-only JWT creation: read PEM key → build JWT header+claims → sign with RS256 → GET /app/installations → POST /app/installations/{id}/access_tokens.

- [ ] **Step 2: Verify compilation**

Run: `go build -tags integration ./tests/harness/`

- [ ] **Step 3: Update harness.go NewTestHelper to use MintAppToken**

Change `NewTestHelper` to call `MintAppToken(t)` instead of raw `os.Getenv("GITHUB_TOKEN")`.

- [ ] **Step 4: Add deleteAllTags and repoName helpers to harness.go**

`deleteAllTags(t, repo)` lists all tag refs via GET /repos/{org}/{repo}/git/refs/tags and deletes each one. `repoName(fullRepo)` extracts repo name from "org/repo".

- [ ] **Step 5: Verify all existing tests still compile**

Run: `go vet -tags integration ./tests/harness/`

### Task 2: pool.go — Fixture repo pool

**Files:**
- Create: `tests/harness/pool.go`

- [ ] **Step 1: Create pool.go with RepoPool struct**

RepoPool has `repos []poolRepo`, `available chan int`, helper *TestHelper. `NewRepoPool` creates N repos named `fixture-00` through `fixture-{N-1}`, records initSHA and initTree for each. `Acquire` blocks on channel, registers t.Cleanup for release. `Release` deletes all tags + force-pushes main to initSHA. `Destroy` deletes all fixture repos. Pool size from PINPOINT_POOL_SIZE env var, default 10.

- [ ] **Step 2: Verify compilation**

Run: `go build -tags integration ./tests/harness/`

### Task 3: scenario.go — Interface + runner

**Files:**
- Create: `tests/harness/scenario.go`

- [ ] **Step 1: Create scenario.go**

Define `Scenario` interface (Name, Setup, Attack, Verify), `ScenarioState` struct, `RunScenarios` function. RunScenarios iterates scenarios, runs each as `t.Run(s.Name(), ...)` with `t.Parallel()`, acquires repo from pool, calls Setup → baseline scan → Attack → Verify.

- [ ] **Step 2: Verify compilation**

Run: `go build -tags integration ./tests/harness/`

### Task 4: Scenario implementations

**Files:**
- Create: `tests/harness/scenario_trivy.go`
- Create: `tests/harness/scenario_chain.go`
- Create: `tests/harness/scenario_gpg.go`
- Create: `tests/harness/scenario_timestamp.go`
- Create: `tests/harness/scenario_triggers.go`
- Create: `tests/harness/scenario_legit.go`
- Create: `tests/harness/scenario_ondisk.go`

- [ ] **Step 1: Implement TrivyMassRepoint** — 76-tag mass repoint with backdated commits, size change. IMPOSSIBLE_TIMESTAMP and SIGNATURE_DROPPED assertions commented out with TODO.

- [ ] **Step 2: Implement TjActionsChain** — 3-repo cross-repo cascade. Acquires 3 repos from pool. Tests audit for pull_request_target + scan for tag repointing.

- [ ] **Step 3: Implement GPGSignatureDrop** — Single tag, lockfile with gpg_signed:true, repoint to unsigned. Uses gate. Assertions commented with TODO until spec 017 is implemented.

- [ ] **Step 4: Implement ImpossibleTimestamp** — Single tag, 2022-dated commit with 2026 parent. Assertions commented with TODO until spec 019 is implemented.

- [ ] **Step 5: Implement PullRequestTargetAudit** — Workflow with pull_request_target + checkout of PR head. Runs audit, checks report/JSON/SARIF.

- [ ] **Step 6: Implement LegitMajorAdvance** — Descendant advance, assert NOT critical.

- [ ] **Step 7: Implement OnDiskTOCTOU** — Lock, swap files on disk, gate --on-disk.

- [ ] **Step 8: Verify all scenarios compile**

Run: `go build -tags integration ./tests/harness/`

### Task 5: scenarios_test.go — Test entrypoint

**Files:**
- Create: `tests/harness/scenarios_test.go`

- [ ] **Step 1: Create scenarios_test.go**

Note: harness_test.go already has a package-level test file, so scenarios_test.go must NOT have its own TestMain (only one TestMain per package). Instead, wrap pool creation in a sync.Once or use a test that creates its own pool.

Actually — the existing tests don't have a TestMain. So we CAN add one, but it must not break existing tests that use NewTestHelper directly. The TestMain should only create the pool if auth is available, then run all tests. Existing tests that call NewTestHelper will still work because MintAppToken falls back to GITHUB_TOKEN.

- [ ] **Step 2: Verify full compilation**

Run: `go vet -tags integration ./tests/harness/ && go build -tags integration ./tests/harness/`

- [ ] **Step 3: Verify non-integration build is clean**

Run: `go build ./... && go vet ./... && go test ./... -count=1`
