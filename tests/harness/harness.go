// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type TestHelper struct {
	token   string
	org     string
	client  *http.Client
	baseURL string
}

func NewTestHelper(t *testing.T) *TestHelper {
	t.Helper()
	token := MintAppToken(t)
	return &TestHelper{
		token:   token,
		org:     "pinpoint-testing",
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: "https://api.github.com",
	}
}

// CreateRepo creates a public repo with a README in the test org.
// If the repo already exists, it is deleted first to ensure clean state.
// Returns the SHA of the initial commit on main.
func (h *TestHelper) CreateRepo(t *testing.T, name string) string {
	t.Helper()

	// Delete if exists (ignore 404)
	h.apiDelete(t, fmt.Sprintf("/repos/%s/%s", h.org, name))
	time.Sleep(1 * time.Second)

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

// UpdateBranch moves a branch ref to a new commit SHA.
func (h *TestHelper) UpdateBranch(t *testing.T, repo, branch, sha string) {
	t.Helper()
	h.apiPatch(t, fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", h.org, repo, branch),
		map[string]interface{}{
			"sha":   sha,
			"force": true,
		})
}

// CreateLightweightTag creates a tag ref pointing directly to a commit.
func (h *TestHelper) CreateLightweightTag(t *testing.T, repo, tag, commitSHA string) {
	t.Helper()
	h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/refs", h.org, repo),
		map[string]interface{}{
			"ref": "refs/tags/" + tag,
			"sha": commitSHA,
		})
}

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

// DeleteTag removes a tag entirely.
func (h *TestHelper) DeleteTag(t *testing.T, repo, tag string) {
	t.Helper()
	h.apiDelete(t, fmt.Sprintf("/repos/%s/%s/git/refs/tags/%s", h.org, repo, tag))
}

// DeleteRepo removes a test repo. Requires delete_repo scope.
func (h *TestHelper) DeleteRepo(t *testing.T, name string) {
	t.Helper()
	h.apiDelete(t, fmt.Sprintf("/repos/%s/%s", h.org, name))
}

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

// RunPinpointScan builds and executes pinpoint scan, returning output and exit code.
// NOTE: We build the binary first because "go run" swallows exit codes —
// any non-zero exit becomes 1, losing the distinction between 1 (error) and 2 (alert).
func RunPinpointScan(t *testing.T, configPath, statePath string) (string, int) {
	t.Helper()
	projectRoot := findProjectRoot(t)
	token := os.Getenv("GITHUB_TOKEN")

	// Build binary to a temp location
	binPath := filepath.Join(t.TempDir(), "pinpoint")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/pinpoint/")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build pinpoint: %v\n%s", err, string(out))
	}

	// Run the built binary directly
	cmd := exec.Command(binPath, "scan",
		"--config", configPath,
		"--state", statePath,
		"--json")
	cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+token)
	cmd.Dir = projectRoot
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

// CreateBulkTags creates N lightweight tags on a chain of commits.
// Returns a map of tag name → commit SHA and the final commit SHA.
func (h *TestHelper) CreateBulkTags(t *testing.T, repo string, tags []string, baseSHA, baseTree string) (map[string]string, string) {
	t.Helper()
	tagSHAs := make(map[string]string)
	prevSHA := baseSHA
	for _, tag := range tags {
		commit := h.CreateCommit(t, repo, "Release "+tag, baseTree, []string{prevSHA})
		h.CreateLightweightTag(t, repo, tag, commit)
		tagSHAs[tag] = commit
		prevSHA = commit
	}
	return tagSHAs, prevSHA
}

// CreateCommitWithAuthor creates a commit with custom author name, email, and date.
func (h *TestHelper) CreateCommitWithAuthor(t *testing.T, repo, message, treeSHA string, parents []string, authorName, authorEmail, authorDate string) string {
	t.Helper()
	author := map[string]string{
		"name":  authorName,
		"email": authorEmail,
		"date":  authorDate,
	}
	resp := h.apiPost(t, fmt.Sprintf("/repos/%s/%s/git/commits", h.org, repo),
		map[string]interface{}{
			"message":   message,
			"tree":      treeSHA,
			"parents":   parents,
			"author":    author,
			"committer": author,
		})
	return resp["sha"].(string)
}

// CreateFileContent creates a file via the Contents API (convenience for simple files).
func (h *TestHelper) CreateFileContent(t *testing.T, repo, path, content, branch string) string {
	t.Helper()
	resp := h.apiPut(t, fmt.Sprintf("/repos/%s/%s/contents/%s", h.org, repo, path),
		map[string]interface{}{
			"message": "Create " + path,
			"content": encodeBase64(content),
			"branch":  branch,
		})
	commit := resp["commit"].(map[string]interface{})
	return commit["sha"].(string)
}

// GetCommitTree returns the tree SHA for a given commit.
func (h *TestHelper) GetCommitTree(t *testing.T, repo, commitSHA string) string {
	t.Helper()
	resp := h.apiGet(t, fmt.Sprintf("/repos/%s/%s/git/commits/%s", h.org, repo, commitSHA))
	tree := resp["tree"].(map[string]interface{})
	return tree["sha"].(string)
}

func (h *TestHelper) apiPut(t *testing.T, path string, body interface{}) map[string]interface{} {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", h.baseURL+path, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("API PUT %s: %v", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("API PUT %s returned %d: %s", path, resp.StatusCode, string(respBody))
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	return result
}

func (h *TestHelper) apiGet(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	req, _ := http.NewRequest("GET", h.baseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("API GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("API GET %s returned %d: %s", path, resp.StatusCode, string(respBody))
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	return result
}

func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// RunPinpointGate builds and executes pinpoint gate, returning output and exit code.
func RunPinpointGate(t *testing.T, manifestPath, repo, sha, workflowRef string) (string, int) {
	t.Helper()
	projectRoot := findProjectRoot(t)
	token := os.Getenv("GITHUB_TOKEN")

	binPath := filepath.Join(t.TempDir(), "pinpoint")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/pinpoint/")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build pinpoint: %v\n%s", err, string(out))
	}

	cmd := exec.Command(binPath, "gate",
		"--manifest", manifestPath,
		"--repo", repo,
		"--sha", sha,
		"--workflow-ref", workflowRef)
	cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+token)
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("Failed to run pinpoint gate: %v", err)
		}
	}
	return string(out), exitCode
}

// RunPinpointAudit builds and executes pinpoint audit, returning output and exit code.
func RunPinpointAudit(t *testing.T, org, outputFormat string) (string, int) {
	t.Helper()
	projectRoot := findProjectRoot(t)
	token := os.Getenv("GITHUB_TOKEN")

	binPath := filepath.Join(t.TempDir(), "pinpoint")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/pinpoint/")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build pinpoint: %v\n%s", err, string(out))
	}

	cmd := exec.Command(binPath, "audit",
		"--org", org,
		"--output", outputFormat,
		"--skip-upstream")
	cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+token)
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("Failed to run pinpoint audit: %v", err)
		}
	}
	return string(out), exitCode
}

// RunPinpointManifestVerify executes pinpoint manifest verify, returning output and exit code.
func RunPinpointManifestVerify(t *testing.T, manifestPath string) (string, int) {
	t.Helper()
	return runPinpointManifestCmd(t, "verify", manifestPath, "")
}

// RunPinpointManifestRefresh executes pinpoint manifest refresh, returning output and exit code.
func RunPinpointManifestRefresh(t *testing.T, manifestPath, workflowDir string) (string, int) {
	t.Helper()
	return runPinpointManifestCmd(t, "refresh", manifestPath, workflowDir)
}

func runPinpointManifestCmd(t *testing.T, subcmd, manifestPath, workflowDir string) (string, int) {
	t.Helper()
	projectRoot := findProjectRoot(t)
	token := os.Getenv("GITHUB_TOKEN")

	binPath := filepath.Join(t.TempDir(), "pinpoint")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/pinpoint/")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build pinpoint: %v\n%s", err, string(out))
	}

	args := []string{"manifest", subcmd, "--manifest", manifestPath}
	if workflowDir != "" {
		args = append(args, "--workflows", workflowDir)
	}
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+token)
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("Failed to run pinpoint manifest %s: %v", subcmd, err)
		}
	}
	return string(out), exitCode
}

// WriteManifestJSON writes a manifest file to the given path.
func WriteManifestJSON(t *testing.T, path string, actions map[string]map[string]string) {
	t.Helper()
	type entry struct {
		SHA        string `json:"sha"`
		RecordedAt string `json:"recorded_at"`
	}
	manifest := struct {
		Version     int                           `json:"version"`
		GeneratedAt string                        `json:"generated_at"`
		Actions     map[string]map[string]entry   `json:"actions"`
	}{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Actions:     make(map[string]map[string]entry),
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for repo, tags := range actions {
		manifest.Actions[repo] = make(map[string]entry)
		for tag, sha := range tags {
			manifest.Actions[repo][tag] = entry{SHA: sha, RecordedAt: now}
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}
}

// CommitGateFiles commits a workflow file and manifest to the repo so the gate can fetch them.
// The workflow references the given action repo+tags, and the manifest maps tags to SHAs.
// Returns the new HEAD SHA after the commit.
func (h *TestHelper) CommitGateFiles(t *testing.T, repo string, actionRepo string, tagSHAs map[string]string) string {
	t.Helper()

	// Build workflow content referencing each tag
	wfContent := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
	for tag := range tagSHAs {
		wfContent += fmt.Sprintf("      - uses: %s@%s\n", actionRepo, tag)
	}

	// Build manifest JSON
	type entry struct {
		SHA string `json:"sha"`
	}
	manifest := struct {
		Version int                         `json:"version"`
		Actions map[string]map[string]entry `json:"actions"`
	}{
		Version: 1,
		Actions: map[string]map[string]entry{actionRepo: {}},
	}
	for tag, sha := range tagSHAs {
		manifest.Actions[actionRepo][tag] = entry{SHA: sha}
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")

	// Get current HEAD
	headSHA := h.getRef(t, repo, "heads/main")
	baseTree := h.GetCommitTree(t, repo, headSHA)

	// Create blobs
	wfBlob := h.CreateBlob(t, repo, wfContent)
	mfBlob := h.CreateBlob(t, repo, string(manifestData))

	// Create tree with both files
	tree := h.CreateTree(t, repo, baseTree, map[string]string{
		".github/workflows/ci.yml":  wfBlob,
		".pinpoint-manifest.json":   mfBlob,
	})

	// Create commit and update branch
	commitSHA := h.CreateCommit(t, repo, "Add gate files", tree, []string{headSHA})
	h.UpdateBranch(t, repo, "main", commitSHA)
	return commitSHA
}

// WriteMultiRepoConfig writes a pinpoint config for multiple repos with all tags.
func WriteMultiRepoConfig(t *testing.T, repos map[string][]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	var content string
	content = "actions:\n"
	for repo, tags := range repos {
		content += fmt.Sprintf("  - repo: %s\n    tags:\n", repo)
		for _, tag := range tags {
			content += fmt.Sprintf("      - %q\n", tag)
		}
	}
	content += "alerts:\n  min_severity: low\n  stdout: true\nstore:\n  path: " + dir + "/state.json\n"
	os.WriteFile(path, []byte(content), 0644)
	return path
}

// writeConfig writes a minimal pinpoint config for a single repo with the given tags.
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

// assertContains checks that output contains the expected substring.
func assertContains(t *testing.T, output, substr string) {
	t.Helper()
	if !strings.Contains(output, substr) {
		t.Errorf("Expected output to contain %q, got:\n%s", substr, output)
	}
}

// deleteAllTags lists all tag refs on a repo and deletes each one.
func (h *TestHelper) deleteAllTags(t *testing.T, repo string) {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/repos/%s/%s/git/refs/tags",
		h.baseURL, h.org, repo), nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("Failed to list tags for %s: %v", repo, err)
	}
	defer resp.Body.Close()

	// 404 means no tags exist — that's fine
	if resp.StatusCode == 404 {
		return
	}

	var refs []struct {
		Ref string `json:"ref"`
	}
	json.NewDecoder(resp.Body).Decode(&refs)

	for _, ref := range refs {
		// ref.Ref is "refs/tags/v1.0.0" — extract tag name
		tag := strings.TrimPrefix(ref.Ref, "refs/tags/")
		h.DeleteTag(t, repo, tag)
	}
}

// repoName extracts the repo name from a "org/repo" string.
func repoName(fullRepo string) string {
	parts := strings.SplitN(fullRepo, "/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return fullRepo
}
