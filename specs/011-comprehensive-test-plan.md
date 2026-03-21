# Spec 011: Comprehensive Automated Test Plan

## Overview

This spec defines an automated test suite that validates pinpoint against
every known attack pattern, every edge case, and every feature. It includes
replay scenarios modeled on the 4 major real-world GitHub Actions supply chain
attacks.

The tests are split into two categories:
- **Unit tests** (no network, mock servers) — run in CI on every push
- **Integration tests** (live GitHub API) — run on demand in pinpoint-testing org

---

## Part 1: Real-World Attack Replays

Each scenario recreates the exact mechanics of a documented supply chain
attack. The test harness creates real repos in the pinpoint-testing org,
executes the attack operations, and verifies pinpoint detects them.

### Attack 1: tj-actions/changed-files (CVE-2025-30066, March 2025)

**What happened:**
- Attacker compromised a PAT belonging to @tj-actions-bot
- Pushed malicious commit (0e58ed8) disguised as renovate[bot]
- Retroactively updated ALL version tags (v1 through v45.0.7) to point
  to the malicious commit — every tag, every version
- Malicious code: Base64-encoded Node.js that downloaded Python script
  from a GitHub Gist to dump Runner.Worker process memory
- Secrets dumped to workflow logs (not exfiltrated to external server)
- 23,000+ repositories affected
- Active window: March 14-15, 2025 (~22 hours)

**Unique characteristics:**
- ALL tags repointed (not just a few)
- Single malicious commit for all tags
- Commit impersonated a legitimate bot (renovate[bot])
- No external exfiltration — secrets in logs only
- Attack chain: spotbugs → reviewdog/action-setup → tj-actions/changed-files

**Test: TestReplay_TJActions**

Setup:
1. Create repo `pinpoint-testing/replay-tj-actions`
2. Create 20 tags (v1 through v20) pointing to legitimate commits
3. Run baseline scan → all tags recorded
4. Create one malicious commit with backdated author date and
   author name "renovate[bot]"
5. Force-push ALL 20 tags to the single malicious commit

Verify (scan):
- All 20 tags detected as repointed
- MASS_REPOINT signal fires (20 > threshold of 5)
- SEMVER_REPOINT fires for exact versions (v1.2.3 etc.)
- OFF_BRANCH fires (malicious commit not descendant of any original)
- BACKDATED_COMMIT fires (author date is backdated)
- Severity: CRITICAL
- Exit code: 2

Verify (gate):
- Manifest contains original SHAs
- Gate detects all 20 tags mismatch
- Exit code: 2
- Output contains "TAG HAS BEEN REPOINTED"

### Attack 2: reviewdog/action-setup (CVE-2025-30154, March 2025)

**What happened:**
- Part of a chained attack: attacker first compromised spotbugs/sonar-findbugs
  via a pull_request_target exploit to steal a PAT
- Used stolen PAT to compromise reviewdog/action-setup
- reviewdog was a transitive dependency of tj-actions/eslint-changed-files
  which was used by tj-actions/changed-files
- Only the v1 tag was repointed (major version tag)
- The new commit was a DESCENDANT of the old one (attacker merged a PR
  first, then moved the tag forward)

**Unique characteristics:**
- Single major version tag (v1) repointed
- Descendant commit (legitimate-looking advance)
- Transitive dependency chain (the real target was downstream)
- Attack started November 2024, not discovered until March 2025

**Test: TestReplay_Reviewdog**

Setup:
1. Create repo `pinpoint-testing/replay-reviewdog`
2. Create tag v1 pointing to a legitimate commit on main
3. Run baseline scan
4. Create a new commit ON main (so it's a descendant of v1's commit)
5. Make the new commit modify action.yml significantly (+300% size)
6. Force-push v1 to the new descendant commit

Verify (scan):
- v1 tag detected as repointed
- MAJOR_TAG_ADVANCE fires (v1 is a major version tag, commit is descendant)
- SIZE_ANOMALY fires (action.yml tripled in size)
- SIZE_ANOMALY floor prevents MAJOR_TAG_ADVANCE from reducing below CRITICAL
- Severity: CRITICAL (not LOW, despite being a descendant)
- This validates our fix from spec 006

Verify (gate):
- Manifest has original v1 SHA
- Gate detects mismatch
- Exit code: 2

### Attack 3: aquasecurity/trivy-action (March 19, 2026)

**What happened:**
- TeamPCP used credentials retained from an earlier compromise (Feb 28
  hackerbot-claw pull_request_target exploit)
- Force-pushed 75 of 76 version tags to malicious commits
- Each malicious commit was a FORGED commit:
  - Author/committer dates cloned from original commits (backdated)
  - Author name spoofed real maintainer (DmitriyLewen)
  - Single-file change: only entrypoint.sh modified
  - Parent commit was current master HEAD (impossible timestamp relationship)
- Malicious entrypoint.sh: 204 lines, three-stage credential stealer
  - Stage 1: Dump Runner.Worker process memory on GitHub-hosted runners
  - Stage 2: Python filesystem sweep on self-hosted runners (50+ paths)
  - Stage 3: AES-256 encrypt + exfiltrate to typosquatted C2 domain
  - Fallback: create public repo tpcp-docs, upload as release asset
- After stealing, runs legitimate Trivy normally (output looks correct)
- 10,000+ workflow files affected
- Exposure window: ~12 hours (March 19 17:43 UTC - March 20 ~05:40 UTC)
- Only v0.35.0 was NOT compromised

**Unique characteristics:**
- Near-total tag compromise (75/76, all but latest)
- Forged commit metadata (backdated, spoofed author)
- Entry point size change: 2,855 → 17,592 bytes (+516%)
- Legitimate functionality preserved (scanner still works)
- No GitHub Release created for the malicious commits
- Commits were NOT GPG-signed (originals were)

**Test: TestReplay_Trivy**

Setup:
1. Create repo `pinpoint-testing/replay-trivy`
2. Create 76 tags (0.0.1 through 0.35.0) with legitimate commits
3. Create initial entrypoint.sh at ~100 bytes
4. Run baseline scan → all 76 tags recorded
5. Create malicious commit:
   - Author: "DmitriyLewen" (spoofed)
   - Date: backdated to 2024-07-09 (clone of legit commit)
   - Modify only entrypoint.sh (increase to ~600 bytes, simulating +516%)
6. Force-push 75 tags (all except 0.35.0) to the malicious commit
7. Do NOT create a GitHub Release for any of the repointed tags

Verify (scan):
- 75 tags detected as repointed
- MASS_REPOINT fires (75 >> threshold of 5)
- SEMVER_REPOINT fires for all exact semver tags
- OFF_BRANCH fires (orphan commit, not descendant)
- SIZE_ANOMALY fires (entry point +516%)
- BACKDATED_COMMIT fires (date >30 days old)
- NO_RELEASE fires (no release object)
- Severity: CRITICAL on every single alert
- Every signal fires simultaneously (this is the Trivy signature)
- Exit code: 2

Verify (gate):
- Manifest contains original SHAs for all 76 tags
- Gate detects 75 mismatches, 0.35.0 matches
- Exit code: 2
- Output lists each violated tag

### Attack 4: spotbugs/sonar-findbugs → Chained PAT Theft (Nov 2024 - March 2025)

**What happened:**
- Attacker submitted malicious PR to spotbugs/sonar-findbugs
- Exploited pull_request_target workflow (runs fork code with base secrets)
- Stole a PAT that was embedded in a workflow file
- Used stolen PAT to access reviewdog org → compromised action-setup
- reviewdog/action-setup was a transitive dep of tj-actions
- Chain: spotbugs PAT → reviewdog compromise → tj-actions compromise
- The initial exploit was NOT a tag repoint — it was a PWN request

**Unique characteristics:**
- Multi-hop attack chain (3 orgs, 4+ months)
- Initial vector was workflow misconfiguration, not tag manipulation
- Tag repointing was the FINAL stage of the chain
- Demonstrates: pinpoint catches the final stage but NOT the initial exploit

**Test: TestReplay_ChainedAttack**

This tests a simplified version: one repo's tag repoint enables
access to a second repo. Pinpoint should catch both independently.

Setup:
1. Create repos:
   - `pinpoint-testing/replay-chain-upstream` (the "reviewdog")
   - `pinpoint-testing/replay-chain-downstream` (the "tj-actions")
2. Create v1 tag on upstream, v1 tag on downstream
3. Run baseline scan on both
4. Repoint upstream v1 to malicious commit
5. Repoint downstream v1 to different malicious commit (simulating
   the attacker using upstream access to compromise downstream)

Verify (scan):
- Both repos detected independently
- Each generates its own alert with its own signals
- MASS_REPOINT does NOT fire (only 1 tag per repo)
- Both are CRITICAL (SEMVER_REPOINT + OFF_BRANCH)

Verify (gate with both in manifest):
- Both mismatches detected in a single gate run
- Exit code: 2

---

## Part 2: Edge Case Unit Tests

These run without network access using mock HTTP servers.
Add to existing test files.

### Gate Edge Cases (`internal/gate/gate_test.go`)

```
TestGate_WorkflowWithOnlyRunSteps
  Workflow has no uses: directives. Gate exits 0 with clean message.

TestGate_MixedPinnedAndUnpinned
  3 SHA-pinned, 2 tag-pinned, 1 branch-pinned. Gate verifies the 2 tags,
  skips 3 SHAs, warns on 1 branch. All tag SHAs match. Exit 0.

TestGate_AllBranchPinned_StrictMode
  3 branch-pinned actions with --fail-on-unpinned. Exit 2.

TestGate_ManifestOlderThan30Days
  Manifest generated_at is 60 days ago. Gate prints stale warning but
  still verifies tags. If tags match, exit 0 with warning.

TestGate_ManifestInvalidJSON
  Manifest file contains invalid JSON. Gate exits 1 with parse error
  and actionable message about regenerating.

TestGate_LargeWorkflow_50Actions
  Synthetic workflow with 50 unique action repos. Verifies GraphQL
  batching (1 query for 50 repos). All match manifest. Exit 0.

TestGate_PREvent_ManifestFromBaseRef
  EventName="pull_request", BaseRef="main". Two manifest versions served:
  one at merge commit SHA (poisoned), one at "main" (clean). Verify
  gate fetches from "main" and passes.

TestGate_PREvent_PoisonedManifest
  Same setup but verify that WITHOUT the PR fix (EventName="push"),
  the poisoned manifest is used and the gate incorrectly passes.

TestGate_ReusableWorkflow_Nested
  uses: org/repo/.github/workflows/build.yml@v1 alongside regular actions.
  Both verified against manifest. Exit 0.

TestGate_GraphQLPartialFailure
  3 repos in query, 1 returns error (private/deleted). The other 2 verify
  correctly. Warning emitted for the failed repo. Exit 0 (not violation).

TestGate_TagDeletedOnRemote
  Tag in manifest exists but tag no longer on remote. Warning: "tag not
  found on remote". Not a violation by default.

TestGate_EmptyManifestActions
  Manifest exists but has empty actions map. All refs show as "not in
  manifest". With --fail-on-missing: exit 2.
```

### Risk Scoring Edge Cases (`internal/risk/score_test.go`)

```
TestScore_AllSignalsCritical
  ScoreContext that triggers every signal simultaneously:
  BatchSize=10, IsDescendant=false, EntryPointOld=100, EntryPointNew=5000,
  TagName="v1.2.3", CommitDate=6months ago, ReleaseExists=false,
  SelfHosted=true. Verify CRITICAL and all 7 signals present.

TestScore_MajorTagDescendantWithSizeAnomaly
  v4, descendant=true, size changed 5x. MAJOR_TAG_ADVANCE fires (-30)
  but SIZE_ANOMALY fires (+60) and floor enforces minimum CRITICAL.
  Already covered but verify the floor message is in signals.

TestScore_MajorTagDescendantNoAnomaly
  v4, descendant=true, size unchanged, release exists. Should be LOW.
  This is the legitimate upgrade path. Verify no false positive.

TestScore_SingleTagNonDescendant
  v1.5.0, not descendant, small size change, release exists.
  SEMVER_REPOINT (+50) + OFF_BRANCH (+80) = CRITICAL.

TestScore_BackdatedWithRelease
  Backdated commit (+40) but release exists (-20 not applied, NO_RELEASE
  doesn't fire). Verify score is correct.

TestScore_ZeroBatchSize
  BatchSize=0 (single tag). MASS_REPOINT should NOT fire.

TestScore_ExactlyFiveBatchSize
  BatchSize=5. MASS_REPOINT threshold is >5. Should NOT fire at exactly 5.

TestScore_SixBatchSize
  BatchSize=6. MASS_REPOINT fires.
```

### Manifest Lifecycle Edge Cases (`internal/manifest/manifest_test.go`)

```
TestRefresh_TagDeletedOnRemote
  Manifest has tag v3 but remote repo no longer has it. Refresh warns
  but keeps the entry (don't delete data the user might want).

TestRefresh_NewRepoDiscovered
  --discover finds a new repo not in manifest. After refresh, the new
  repo and all its referenced tags are in the manifest.

TestRefresh_ConcurrentSHAChange
  Tag SHA changes between verify and refresh calls. Refresh captures
  the latest SHA. Verify shows drift.

TestVerify_ExitCodeThree
  Verify detects drift. Exit code is 3 (not 0 or 1 or 2).

TestInit_CreatesFiles
  pinpoint manifest init creates .pinpoint-manifest.json and workflow
  templates. Verify files exist and are valid YAML/JSON.

TestRefresh_EmptyManifest
  Manifest exists but has no actions. With --discover, actions are found
  and added. Without --discover, nothing happens (0 changes).
```

### Suppress Edge Cases (`internal/suppress/suppress_test.go`)

```
TestSuppress_MultipleRulesMatch
  Alert matches 2 rules. Suppressed once (not double-counted).

TestSuppress_RuleOrderDoesntMatter
  Same rules in different order produce same result.

TestSuppress_NoRules
  Empty allow list. All alerts pass through.

TestSuppress_AllSuppressed
  Every alert matches a rule. Result.Allowed is empty.

TestSuppress_CriticalNotSuppressed
  CRITICAL alert with MASS_REPOINT. Even if repo glob matches an
  allow rule with condition "major_tag_advance", the condition doesn't
  match so the alert passes through.
```

### SARIF Edge Cases (`internal/sarif/sarif_test.go`)

```
TestSARIF_ScanWithZeroAlerts
  Valid SARIF with empty results array (not null).

TestSARIF_AuditWithAllClean
  Audit where everything is SHA-pinned. SARIF has zero results.

TestSARIF_RuleIDsUnique
  All rule IDs in the driver are unique strings.

TestSARIF_VersionFromBuild
  version field in driver matches the passed-in version string.
```

### Audit Edge Cases (`internal/audit/audit_test.go`)

```
TestAudit_RepoWithNoWorkflows
  Org has repos without .github/workflows. Counted as "repos without
  workflows", not an error.

TestAudit_ArchivedReposSkipped
  Archived repos in the org are skipped and counted correctly.

TestAudit_ForkedReposSkipped
  Forked repos are skipped.

TestAudit_UnprotectedWorkflowDetection
  Workflow file content does NOT contain "pinpoint". Counted in
  WorkflowsWithoutGate.

TestAudit_ProtectedWorkflowDetection
  Workflow file content contains "uses: tehreet/pinpoint@abc123".
  Counted in WorkflowsWithGate.
```

---

## Part 3: Integration Test Harness Additions

Add to `tests/harness/harness_test.go`. These run against the live
GitHub API with `//go:build integration`.

### TestReplay_TJActions
### TestReplay_Reviewdog
### TestReplay_Trivy
### TestReplay_ChainedAttack

(As described in Part 1. These create real repos, execute real attacks,
run pinpoint scan and gate against the live API.)

### TestGate_LiveVerification

Test the gate against a real repo with a real manifest:
1. Create repo with workflow containing tag-pinned actions
2. Generate manifest with `pinpoint audit --output manifest`
3. Run gate — should pass
4. Tamper one tag (force-push)
5. Run gate — should detect violation

### TestAudit_LiveOrg

Run `pinpoint audit --org pinpoint-testing` against the live org.
Verify:
- Repo count matches actual org
- Workflow files discovered
- Actions extracted
- Report format is valid

### TestManifest_LiveRefresh

1. Generate manifest from a test repo
2. Advance a tag legitimately
3. Run `pinpoint manifest verify` — should detect drift (exit 3)
4. Run `pinpoint manifest refresh` — should update SHA (exit 3)
5. Run `pinpoint manifest verify` again — should pass (exit 0)

---

## Part 4: Test Matrix

| Category | Test Count | Location |
|---|---|---|
| Attack replays (integration) | 4 | tests/harness/harness_test.go |
| Gate unit tests | 12 | internal/gate/gate_test.go |
| Risk scoring unit tests | 8 | internal/risk/score_test.go |
| Manifest unit tests | 6 | internal/manifest/manifest_test.go |
| Suppress unit tests | 5 | internal/suppress/suppress_test.go |
| SARIF unit tests | 4 | internal/sarif/sarif_test.go |
| Audit unit tests | 5 | internal/audit/audit_test.go |
| Live integration tests | 3 | tests/harness/harness_test.go |
| **Total new tests** | **47** | |
| **Existing tests** | **89** | |
| **Total after implementation** | **136+** | |

## Implementation Notes

The unit tests (Part 2) should be implemented first — they don't need
network access and will run in CI.

The integration tests (Part 1 + Part 3) require `GITHUB_TOKEN` and access
to the `pinpoint-testing` org. They should be in a separate file with
the `//go:build integration` build tag.

The attack replay tests will be slow (creating repos, pushing tags, waiting
for API consistency). Budget 2-5 minutes per replay. Total integration
suite: ~15-20 minutes.

## Files to Create/Modify

- MODIFY: `internal/gate/gate_test.go` — 12 new unit tests
- MODIFY: `internal/risk/score_test.go` — 8 new unit tests
- MODIFY: `internal/manifest/manifest_test.go` — 6 new unit tests
- MODIFY: `internal/suppress/suppress_test.go` — 5 new unit tests
- MODIFY: `internal/sarif/sarif_test.go` — 4 new unit tests
- MODIFY: `internal/audit/audit_test.go` — 5 new unit tests
- CREATE: `tests/harness/replay_test.go` — 4 attack replays + 3 live tests
- MODIFY: `tests/harness/harness.go` — add helpers for bulk tag creation,
  entry point file creation, force-push simulation

## Build Verification

```bash
# Unit tests (fast, no network)
go test ./internal/... -v

# Integration tests (slow, needs token)
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ -tags integration -v -timeout 30m
```
