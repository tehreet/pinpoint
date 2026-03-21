# Spec 005: Comprehensive Test Plan & Attack Path Analysis

## Purpose

Every attack path, detection gap, gate bypass, and edge case we can
identify. Each item is **COVERED**, **GAP** (needs work), or **WONTFIX**.

---

## Part 1: Attack Paths

### 1.1 Tag Repointing (Basic)
Force-push a tag to a malicious commit.
**Status: COVERED** — scan detects via state diff, gate detects via manifest.
Tests: TestScenario_SingleRepoint, TestTagRepointed.

### 1.2 Tag Delete + Recreate
Delete tag, recreate pointing to malicious commit. Avoids force-push logs.
**Status: COVERED** — store records DeletedTag. Test: TestScenario_DeleteRecreate.

### 1.3 Annotated Tag Repointing
Swap annotated tag object so it dereferences to a different commit.
**Status: COVERED** — GraphQL `... on Tag { target { oid } }` dereferences.
Test: TestScenario_AnnotatedRepoint.

### 1.4 Mass Repointing
Repoint 75 tags at once (Trivy signature).
**Status: COVERED** — MASS_REPOINT signal fires at >5 tags. Score +100.
Test: TestScenario_MassRepoint.

### 1.5 Descendant Commit Attack
Create branch from legit tag, add malware, repoint tag to descendant.
OFF_BRANCH doesn't fire because it IS a descendant.
**Status: GAP (partial)**
- Exact semver (v1.2.3): SEMVER_REPOINT fires. Covered.
- Major version (v1): MAJOR_TAG_ADVANCE *subtracts* 30 points. Dangerous.
  A v1 tag moved to a descendant with a fat payload would score LOW.
- SIZE_ANOMALY is implemented but requires enrichment to fetch entry point
  sizes. Need to verify enrichment actually runs for major version advances.

**Test needed:** Repoint v1 to descendant with action.yml tripled in size.
Verify SIZE_ANOMALY fires despite MAJOR_TAG_ADVANCE deduction.

### 1.6 Slow Drip Attack
One tag per day, staying under MASS_REPOINT threshold of 5.
**Status: GAP (by design)**
- Individual per-tag signals still fire (SEMVER_REPOINT, SIZE_ANOMALY etc.)
- Gate is the real defense — SHA won't match manifest regardless of pace.

**Test needed:** 3 individual repoints over 3 scan cycles. Verify each
triggers its own alert independently.

### 1.7 Transitive Dependency Attack
Composite action references OTHER actions in its action.yml. Attacker
compromises the transitive dep. Top-level tag doesn't change.
**Status: GAP (fundamental limitation)**
- Gate only parses the calling workflow, not action.yml of dependencies.
- No recursive verification.

**Future feature:** `pinpoint audit` fetches each action's action.yml,
discovers transitive deps, adds to monitoring config. Document in STEELMAN.md.

### 1.8 Dynamic Action Reference
`uses: ${{ env.ACTION_REF }}` — resolved at runtime, invisible to static analysis.
**Status: GAP (fundamental limitation)**
- Regex can't evaluate GitHub Actions expressions.

**Test needed:** Workflow with `uses: ${{ matrix.action }}` — gate shouldn't
crash. Should warn about unparseable refs.

### 1.9 Docker Image Reference
`uses: docker://malicious-image:latest` — no tag/SHA verification possible.
**Status: WONTFIX** — out of scope. ParseActionRef skips `docker://`.
Test: COVERED (TestParseActionRef).

### 1.10 Manifest Poisoning via Fork PR ⚠️ CRITICAL
Attacker opens PR from fork. PR modifies `.pinpoint-manifest.json` to
include the malicious SHA. Gate fetches manifest at `$GITHUB_SHA` which
is the merge commit — includes attacker's manifest changes.
**Status: CRITICAL GAP**

**Fix required:**
- For `pull_request` events: fetch manifest from base branch (`$GITHUB_BASE_REF`),
  NOT from the PR merge commit
- For `push` events: `$GITHUB_SHA` is correct
- Detect via `$GITHUB_EVENT_NAME` environment variable

**Test needed:** Gate with event_name=pull_request fetches manifest from
base ref, not from merge commit SHA.

### 1.11 TOCTOU: Runner Download vs Gate Verification
Runner downloads actions (lifecycle step 3), gate verifies (step 4).
If tag repointed between download and verification, gate says clean but
runner has malicious code.
**Status: GAP (inherent, tiny window)**
- Window is seconds. Attacker needs precise timing.
- Continuous monitoring (watch) catches on next cycle.

**Future:** Hash action code on disk at `_work/_actions/` against manifest.
Verifies what's actually going to execute.

---

## Part 2: Gate Bypass Paths

### 2.1 Workflow Without Gate
Some workflows lack the gate step. Attacker targets ungated workflow.
**Status: GAP (operational)**

**Fix needed:** `pinpoint audit` should flag workflows missing a gate step.
Add to audit report: "UNPROTECTED WORKFLOWS: 47 of 200 workflows have no gate"

### 2.2 `continue-on-error: true` on Gate Step
Gate fails but job continues.
**Status: WONTFIX** — user error. Document as misconfiguration.

### 2.3 Conditional Gate (`if:` skipping)
Gate has `if: github.event_name == 'push'`, attacker triggers via PR.
**Status: WONTFIX** — user error. Document: never condition the gate.

### 2.4 Compromised Gate Binary
Attacker compromises pinpoint release AND updates the .sha256 file.
Both match because both are on the same GitHub Release.
**Status: GAP (partial)**
- SHA256 check exists but both files are co-located
- Self-verifying bootstrap mitigates (hardcoded hash)

**Fix needed:**
- Publish hashes in a separate location (README, docs site)
- Future: SLSA provenance / Sigstore signing

### 2.5 Repointed Gate Action Tag
`tehreet/pinpoint@v0.3.0` itself repointed to malicious commit.
**Status: COVERED** — docs mandate SHA-pinning the gate.
Self-verifying bootstrap available for maximum security.

---

## Part 3: Parsing Edge Cases

### 3.1 Commented-Out uses:
`# - uses: actions/checkout@v4`
**Status: COVERED** — regex requires non-comment line.
Test: TestExtractRefsSkipsComments.

### 3.2 Quoted uses: Values
`uses: 'actions/checkout@v4'` and `uses: "actions/checkout@v4"`
**Status: COVERED** — regex has `['"]?` for optional quotes.
**Test needed:** Explicit test with both quote styles.

### 3.3 YAML Anchors and Aliases
```yaml
checkout: &checkout
  uses: actions/checkout@v4
steps:
  - *checkout
```
**Status: WONTFIX** — extremely rare. Anchor definition gets caught.

### 3.4 Multi-line YAML Values
```yaml
uses: >-
  actions/checkout@v4
```
**Status: WONTFIX** — never seen in the wild. Document as unsupported.

### 3.5 Action with Sub-Path
`uses: aws-actions/configure-aws-credentials/subdir@v4`
**Status: Need to verify.** ParseActionRef splits on `/`, takes first 2 for
owner/repo. Should work but needs explicit test.

**Test needed:** Sub-path action ref parsed correctly.

### 3.6 Inline Comment After uses:
`uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4`
**Status: COVERED** — regex stops at `#`. But verify the SHA is captured
correctly (not truncated).

**Test needed:** SHA-pinned ref with inline comment. Verify full 40-char SHA extracted.

---

## Part 4: Operational Edge Cases

### 4.1 Rate Limiting
GraphQL: 5,000 points/hour (PAT), 10,000/hr (Enterprise Cloud).
Gate: 1 point per CI run. Watch at 5min intervals: 12/hr. Audit: ~40 points.
**Status: COVERED** — well within limits.

**Test needed:** Gate handles GraphQL 403 rate limit response gracefully.
Currently: GraphQL client retries 3x with backoff. Need to verify error
message is actionable ("rate limited, try again later" not "unknown error").

### 4.2 Token Permissions
GITHUB_TOKEN needs `contents: read` to fetch workflow and manifest.
GITHUB_TOKEN needs read access to upstream action repos for GraphQL.
Default GITHUB_TOKEN has read access to public repos but NOT private actions.
**Status: GAP (documentation)**

**Fix needed:** Document required permissions clearly. Gate should print
a specific error when it gets 403 on an action repo: "Cannot access
{owner}/{repo}. If this is a private action, ensure GITHUB_TOKEN has
read access, or use a PAT."

### 4.3 Stale Manifest
Manifest was generated 6 months ago. New tags have been added to actions
that aren't in the manifest. Gate says "not in manifest" (warning) but
doesn't fail by default.
**Status: COVERED (by design)** — default is warn, not fail.
`--fail-on-missing` enforces strict mode.

**Enhancement needed:** Gate should warn if manifest is older than a
configurable age: "⚠ Manifest is 180 days old. Regenerate with:
pinpoint audit --org <n> --output manifest"

### 4.4 Empty Workflow (No uses: directives)
Workflow only has `run:` steps, no `uses:`.
**Status: Need to verify.** Gate should pass cleanly with "0 refs found".

**Test needed:** Workflow with only `run:` steps. Gate exits 0.

### 4.5 Massive Workflow (1000+ lines)
Enterprise workflow with 50+ action references across many jobs.
**Status: Need to verify.** Regex extraction should handle any size.
GraphQL batching handles 50 repos per query.

**Test needed:** Synthetic workflow with 60 unique action refs.
Verify batching works (2 GraphQL calls).

### 4.6 Network Failure Mid-Gate
API call fails after workflow fetch succeeds but before GraphQL resolves.
**Status: COVERED (partial)** — GraphQL client has 3x retry with backoff.
But if all retries fail, gate returns exit 1 (error), not exit 2 (violation).
Job fails but for the wrong reason.

**Enhancement needed:** On network failure, print clear message:
"⚠ Could not verify action integrity due to API error. This is NOT
a detected attack, but verification was incomplete. Re-run the job
or check GitHub API status."

### 4.7 GHES / GHE.com Compatibility
Gate uses GITHUB_API_URL and GITHUB_GRAPHQL_URL.
**Status: COVERED (in theory)** — code reads these env vars.
**Not tested against actual GHES instance.**

### 4.8 Concurrent Gate Executions
1000 CI jobs hitting the gate simultaneously across an org.
**Status: COVERED** — each gate is independent, stateless. No shared
state to corrupt. GraphQL rate limit is the only constraint (see 4.1).

### 4.9 Large State File
Watching 500 repos, 50,000 tags for months. JSON state file grows.
**Status: COVERED** — scale test showed 2.1MB for 7,736 tags.
50,000 tags ≈ 14MB. JSON parse/write is fast.

**Enhancement needed:** State file compaction — prune tags that haven't
changed in N days. Or move to SQLite (already on roadmap).

---

## Part 5: Feature Gaps (Not Security, Just Missing)

### 5.1 No README
The repo has a README.md but it's likely auto-generated placeholder.
**Status: GAP** — need a real README with install, quickstart, examples.

### 5.2 No go install Support
`go install github.com/tehreet/pinpoint/cmd/pinpoint@latest` — does this work?
The module path needs to be correct in go.mod.
**Status: Need to verify.**

### 5.3 No Homebrew / Package Manager
No easy install for non-Go users.
**Status: Future** — can add a Homebrew formula after public release.

### 5.4 No GitHub Actions Marketplace Listing
action.yml exists but repo is private. When public, needs marketplace listing.
**Status: Future** — flip public, add marketplace metadata.

### 5.5 No Slack/Webhook Alert Integration Test
Alert module supports stdout, slack, webhook. Only stdout tested.
**Status: GAP** — need at least a mock webhook test.

### 5.6 pinpoint audit --output manifest Doesn't Resolve Tags
The audit command discovers actions and checks immutable releases, but
the `--output manifest` mode needs to resolve current tag SHAs to populate
the manifest. Need to verify this actually calls the GraphQL poller.
**Status: Need to verify.** If it doesn't resolve, the manifest will be
empty and the gate will have nothing to compare against.

---

## Part 6: Priority-Ordered Action Items

### P0 — Must Fix Before Public Release

1. **Manifest poisoning via fork PR (1.10)**
   Gate must fetch manifest from base branch for PR events.
   ~50 lines of code in gate.go.

2. **Verify audit --output manifest resolves tags (5.6)**
   If broken, the entire gate workflow is useless.

3. **Verify go install works (5.2)**
   Users need to actually install this thing.

### P1 — Should Fix Soon

4. **Descendant commit + major version tag scoring (1.5)**
   SIZE_ANOMALY should still fire even with MAJOR_TAG_ADVANCE deduction.
   Add test case.

5. **Audit: flag unprotected workflows (2.1)**
   "47 of 200 workflows have no gate step" in audit report.

6. **Gate: clear error for private action repos (4.2)**
   Actionable error message when token lacks access.

7. **Gate: warn on old manifest (4.3)**
   "Manifest is 180 days old, regenerate."

8. **Gate: handle zero uses: directives gracefully (4.4)**
   Exit 0 with "no action references found" message.

### P2 — Nice to Have

9. Sub-path action ref test (3.5)
10. SHA with inline comment test (3.6)
11. Quoted uses: values test (3.2)
12. Massive workflow batching test (4.5)
13. Network failure messaging (4.6)
14. Mock webhook alert test (5.5)
15. Slow drip multi-cycle test (1.6)
