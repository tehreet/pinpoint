// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

// RunPinpointScan executes pinpoint scan and returns stdout+stderr and exit code.
func RunPinpointScan(t *testing.T, configPath, statePath string) (string, int) {
	t.Helper()
	token := os.Getenv("GITHUB_TOKEN")
	cmd := exec.Command("go", "run", "./cmd/pinpoint/", "scan",
		"--config", configPath,
		"--state", statePath,
		"--json")
	cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+token)
	cmd.Dir = findProjectRoot(t)
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
