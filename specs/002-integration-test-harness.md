# Spec 002: Integration Test Harness

## Summary

A fully automated test harness that creates GitHub repos, pushes tags,
repoints tags, and verifies that pinpoint detects every attack scenario.
LLM-orchestrated adversarial testing at scale.

## Prerequisites

- A GitHub org dedicated to testing (e.g., `pinpoint-testing`)
- Create manually at: https://github.com/account/organizations/new
- Free plan is fine: unlimited public repos, 100K repo limit

## Architecture

```
tests/
  harness/
    harness.go          — Test orchestrator (creates repos, pushes tags, etc.)
    scenarios.go        — Attack scenario definitions
    harness_test.go     — Go integration tests (build tag: integration)
  scenarios/
    01-single-repoint.yml
    02-mass-repoint.yml
    03-tag-delete-recreate.yml
    04-gradual-rotation.yml
    05-annotated-tag-repoint.yml
    06-entry-point-size-change.yml
    07-legitimate-major-version-advance.yml
    08-mixed-benign-and-malicious.yml
```

## Test Org Setup Script

```bash
#!/usr/bin/env bash
# Run once to create the test fixture repos
ORG="pinpoint-testing"

# Create 10 repos that simulate real GitHub Actions
for i in $(seq -w 1 10); do
    gh repo create "$ORG/test-action-$i" --public --description "Pinpoint test fixture $i" \
        --add-readme
done

# Create repos with different tag patterns
for repo in "$ORG/test-action-"{01..10}; do
    cd $(mktemp -d)
    gh repo clone "$repo" . 2>/dev/null

    # Create lightweight tags
    for v in v1.0.0 v1.1.0 v1.2.0; do
        git tag "$v"
    done

    # Create annotated tags
    for v in v1 v2; do
        git tag -a "$v" -m "Major version $v"
    done

    git push --tags
done
```

## Scenario Definitions

### Scenario 1: Single Tag Repoint (Trivy-like, single tag)
```yaml
name: single-repoint
setup:
  repo: test-action-01
  tags: {v1.0.0: commit-A}
attack:
  action: force-push v1.0.0 to commit-B (new commit with modified entrypoint)
expected:
  alert: TAG_REPOINTED
  severity: CRITICAL
  signals: [SEMVER_REPOINT, OFF_BRANCH]
```

### Scenario 2: Mass Repoint (Trivy-like, 75 tags at once)
```yaml
name: mass-repoint
setup:
  repo: test-action-02
  tags: {v1.0.0 through v1.74.0: various commits on main}
attack:
  action: force-push ALL 75 tags to single malicious commit
expected:
  alert: TAG_REPOINTED (×75)
  severity: CRITICAL
  signals: [MASS_REPOINT, OFF_BRANCH, SEMVER_REPOINT]
```

### Scenario 3: Tag Delete + Recreate
```yaml
name: delete-recreate
setup:
  repo: test-action-03
  tags: {v1.0.0: commit-A}
attack:
  action: delete v1.0.0, recreate v1.0.0 pointing to commit-B
expected:
  alert: TAG_DELETED then new tag recorded
  # On next poll: tag exists again with different SHA
  severity: MEDIUM (TAG_DELETED) then detection depends on timing
```

### Scenario 4: Gradual Rotation (1 tag per poll cycle)
```yaml
name: gradual-rotation
setup:
  repo: test-action-04
  tags: {v1.0.0 through v1.9.0: legitimate commits}
attack:
  action: repoint one tag per poll cycle, 10 cycles
expected:
  alerts: 10 individual TAG_REPOINTED
  severity: varies (each is a single repoint)
  # This tests whether cumulative tracking detects the pattern
```

### Scenario 5: Annotated Tag Repoint
```yaml
name: annotated-repoint
setup:
  repo: test-action-05
  tags: {v1 (annotated): commit-A}
attack:
  action: delete v1, create new annotated tag v1 pointing to commit-B
expected:
  alert: TAG_REPOINTED
  signals: should show both tag_sha and commit_sha changed
```

### Scenario 6: Entry Point Size Change
```yaml
name: size-change
setup:
  repo: test-action-06
  files: {entrypoint.sh: 100 bytes}
  tags: {v1.0.0: commit with small entrypoint}
attack:
  action: new commit with entrypoint.sh at 5000 bytes, repoint v1.0.0
expected:
  alert: TAG_REPOINTED
  signals: [SIZE_ANOMALY, SEMVER_REPOINT]
```

### Scenario 7: Legitimate Major Version Advance (false positive test)
```yaml
name: legitimate-advance
setup:
  repo: test-action-07
  tags: {v1 (annotated): commit-A}
attack:
  action: new commit on main (descendant of A), move v1 forward
expected:
  alert: TAG_REPOINTED
  severity: LOW
  signals: [MAJOR_TAG_ADVANCE]
  # This SHOULD NOT trigger a high-severity alert
```

### Scenario 8: Mixed Benign and Malicious
```yaml
name: mixed-signals
setup:
  repo: test-action-08
  tags: {v1: commit-A, v1.0.0: commit-A, v1.1.0: commit-B}
attack:
  action: advance v1 legitimately, repoint v1.1.0 maliciously
expected:
  - {tag: v1, severity: LOW, signals: [MAJOR_TAG_ADVANCE]}
  - {tag: v1.1.0, severity: CRITICAL, signals: [SEMVER_REPOINT, OFF_BRANCH]}
```

## Harness Implementation

The harness is a Go program that uses the GitHub API to:

1. **Setup phase:**
   - Create repos (or verify they exist)
   - Push initial commits with specific file content
   - Create tags (lightweight and annotated)
   - Run `pinpoint scan` to establish baseline state

2. **Attack phase:**
   - Execute the attack (force-push tags, delete/recreate, etc.)
   - Wait one poll cycle

3. **Verify phase:**
   - Run `pinpoint scan` again
   - Parse stdout/JSON output
   - Assert expected alerts, severities, and signals
   - Assert NO unexpected alerts (false positive check)

4. **Cleanup phase:**
   - Reset tags to original state (or delete repos)

### GitHub API Operations Needed

```go
// Create a new commit with specific file content
POST /repos/{owner}/{repo}/git/blobs      — create blob
POST /repos/{owner}/{repo}/git/trees      — create tree
POST /repos/{owner}/{repo}/git/commits    — create commit
PATCH /repos/{owner}/{repo}/git/refs/heads/main — update branch

// Create/update/delete tags
POST /repos/{owner}/{repo}/git/refs       — create tag ref
PATCH /repos/{owner}/{repo}/git/refs/tags/{tag} — update (repoint)
DELETE /repos/{owner}/{repo}/git/refs/tags/{tag} — delete tag

// Create annotated tag
POST /repos/{owner}/{repo}/git/tags       — create tag object
POST /repos/{owner}/{repo}/git/refs       — create ref pointing to tag object
```

### Rate Limit Budget for Testing

Repo creation: 80/min content limit applies.
Tag operations: ~5 API calls per tag (create blob, tree, commit, ref, tag).
For 10 repos × 10 tags: ~500 API calls. Well within limits.

A full test suite run: ~15 minutes including setup, attack, verify, cleanup.

## Running Tests

```bash
# One-time setup (creates repos in the test org)
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ -tags integration \
    -run TestSetup -v -org pinpoint-testing

# Run all scenarios
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ -tags integration \
    -run TestScenarios -v -org pinpoint-testing -timeout 30m

# Run a specific scenario
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ -tags integration \
    -run TestScenarios/mass-repoint -v -org pinpoint-testing

# Cleanup (reset all repos to clean state)
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ -tags integration \
    -run TestCleanup -v -org pinpoint-testing
```

## Future: LLM-Orchestrated Adversarial Testing

The dream scenario you described: an LLM that plays the attacker.

Give Claude Code (or another agent) write access to the test org and a prompt:

"You are an adversary. Your goal is to repoint tags in the pinpoint-testing
org WITHOUT triggering a CRITICAL alert from pinpoint. You may create commits,
move tags, delete and recreate tags, backdate commits, spoof author info, or
use any combination. Pinpoint is watching with a 2-minute poll interval.
You have 30 minutes. Go."

Meanwhile, pinpoint is running in watch mode. At the end, we compare:
- What the attacker did (logged by the attacker agent)
- What pinpoint detected
- Any gaps = new test cases = stronger risk scoring

This is a red-team exercise automated end-to-end. It's how you find the
evasion techniques that humans haven't thought of yet.

Not for v0.2 — but absolutely for v0.5 and the conference talk.
