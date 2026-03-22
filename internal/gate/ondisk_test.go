// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package gate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tehreet/pinpoint/internal/integrity"
)

// setupOnDiskAction creates a mock actions directory at actionsDir/owner/repo/ref/
// with the given files. Returns the actionsDir and the tree hash.
func setupOnDiskAction(t *testing.T, owner, repo, ref string, files map[string]string) (actionsDir string, treeHash string) {
	t.Helper()
	dir := t.TempDir()
	actionsDir = filepath.Join(dir, "_actions")

	actionPath := filepath.Join(actionsDir, owner, repo, ref)
	if err := os.MkdirAll(actionPath, 0755); err != nil {
		t.Fatal(err)
	}

	for name, content := range files {
		path := filepath.Join(actionPath, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	hash, err := integrity.ComputeTreeHash(actionPath)
	if err != nil {
		t.Fatalf("computing tree hash: %v", err)
	}

	return actionsDir, hash
}

func b64JSON(v any) string {
	data, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(data)
}

func b64Str(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// onDiskGateTest runs a gate with the given options and returns the result.
func onDiskGateTest(t *testing.T, workflowYAML string, manifestData Manifest, opts GateOptions) *GateResult {
	t.Helper()

	// Suppress gate messages during tests
	var buf bytes.Buffer
	old := messageWriter
	messageWriter = &buf
	defer func() { messageWriter = old }()

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/contents/") {
			var content string
			if strings.Contains(r.URL.Path, "ci.yml") {
				content = b64Str(workflowYAML)
			} else if strings.Contains(r.URL.Path, "actions-lock.json") {
				content = b64JSON(manifestData)
			} else {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			resp := map[string]string{"content": content, "encoding": "base64"}
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{
			"rateLimit": map[string]any{"cost": 1, "remaining": 4999},
			"actions_checkout": map[string]any{
				"refs": map[string]any{
					"totalCount": 1,
					"pageInfo":   map[string]any{"endCursor": "", "hasNextPage": false},
					"nodes": []map[string]any{
						{
							"name": "v4",
							"target": map[string]any{
								"__typename": "Commit",
								"oid":        "abc123abc123abc123abc123abc123abc123abc1",
							},
						},
					},
				},
			},
		}
		resp := map[string]any{"data": data}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer graphqlServer.Close()

	opts.APIURL = restServer.URL
	opts.GraphQLURL = graphqlServer.URL
	if opts.Repo == "" {
		opts.Repo = "test/repo"
	}
	if opts.SHA == "" {
		opts.SHA = "abc123abc123abc123abc123abc123abc123abc1"
	}
	if opts.WorkflowRef == "" {
		opts.WorkflowRef = opts.Repo + "/.github/workflows/ci.yml@refs/heads/main"
	}
	if opts.ManifestPath == "" {
		opts.ManifestPath = ".github/actions-lock.json"
	}

	result, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate error: %v", err)
	}
	return result
}

func TestGateOnDisk_Match(t *testing.T) {
	actionSHA := "abc123abc123abc123abc123abc123abc123abc1"
	files := map[string]string{
		"action.yml":    "name: checkout\nruns:\n  using: node20\n  main: index.js\n",
		"dist/index.js": "console.log('checkout');",
	}
	actionsDir, treeHash := setupOnDiskAction(t, "actions", "checkout", "v4", files)

	manifest := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {
					SHA:           actionSHA,
					DiskIntegrity: treeHash,
				},
			},
		},
	}

	workflow := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

	result := onDiskGateTest(t, workflow, manifest, GateOptions{
		OnDisk:     true,
		ActionsDir: actionsDir,
	})

	for _, v := range result.Violations {
		t.Errorf("unexpected violation: %s@%s expected=%s actual=%s", v.Action, v.Tag, v.ExpectedSHA, v.ActualSHA)
	}
}

func TestGateOnDisk_Mismatch(t *testing.T) {
	actionSHA := "abc123abc123abc123abc123abc123abc123abc1"
	files := map[string]string{
		"action.yml":    "name: checkout\nruns:\n  using: node20\n  main: index.js\n",
		"dist/index.js": "console.log('checkout');",
	}
	actionsDir, treeHash := setupOnDiskAction(t, "actions", "checkout", "v4", files)

	// Tamper with a file after computing the hash
	tamperedPath := filepath.Join(actionsDir, "actions", "checkout", "v4", "dist", "index.js")
	if err := os.WriteFile(tamperedPath, []byte("malicious code!"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {
					SHA:           actionSHA,
					DiskIntegrity: treeHash, // original hash, but file is now tampered
				},
			},
		},
	}

	workflow := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

	result := onDiskGateTest(t, workflow, manifest, GateOptions{
		OnDisk:     true,
		ActionsDir: actionsDir,
	})

	foundMismatch := false
	for _, v := range result.Violations {
		if v.Action == "actions/checkout" && v.ExpectedSHA == treeHash {
			foundMismatch = true
		}
	}
	if !foundMismatch {
		t.Error("expected ON-DISK INTEGRITY MISMATCH violation")
	}
}

func TestGateOnDisk_MissingAction(t *testing.T) {
	actionSHA := "abc123abc123abc123abc123abc123abc123abc1"
	// Create an empty actions dir — no checkout present
	dir := t.TempDir()
	actionsDir := filepath.Join(dir, "_actions")
	if err := os.MkdirAll(actionsDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifest := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {
					SHA:           actionSHA,
					DiskIntegrity: "sha256-fakehash",
				},
			},
		},
	}

	workflow := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

	result := onDiskGateTest(t, workflow, manifest, GateOptions{
		OnDisk:     true,
		ActionsDir: actionsDir,
	})

	// Should be a warning, NOT a violation
	if len(result.Violations) > 0 {
		t.Errorf("expected no violations for missing action on disk, got %d", len(result.Violations))
	}

	foundWarning := false
	for _, w := range result.Warnings {
		if w.Action == "actions/checkout" && strings.Contains(w.Message, "not found on disk") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expected warning about action not found on disk")
	}
}

func TestGateOnDisk_MissingDiskIntegrity(t *testing.T) {
	actionSHA := "abc123abc123abc123abc123abc123abc123abc1"
	// Create action on disk but lockfile has no disk_integrity
	files := map[string]string{"action.yml": "name: test\n"}
	actionsDir, _ := setupOnDiskAction(t, "actions", "checkout", "v4", files)

	manifest := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {
					SHA: actionSHA,
					// No DiskIntegrity field
				},
			},
		},
	}

	workflow := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

	result := onDiskGateTest(t, workflow, manifest, GateOptions{
		OnDisk:     true,
		ActionsDir: actionsDir,
	})

	if len(result.Violations) > 0 {
		t.Errorf("expected no violations for missing disk_integrity, got %d", len(result.Violations))
	}

	foundWarning := false
	for _, w := range result.Warnings {
		if w.Action == "actions/checkout" && strings.Contains(w.Message, "disk_integrity not recorded") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expected warning about disk_integrity not recorded")
	}
}

func TestGateOnDisk_NoRunnerWorkspace(t *testing.T) {
	// Ensure RUNNER_WORKSPACE is unset
	old := os.Getenv("RUNNER_WORKSPACE")
	os.Unsetenv("RUNNER_WORKSPACE")
	defer func() {
		if old != "" {
			os.Setenv("RUNNER_WORKSPACE", old)
		}
	}()

	actionSHA := "abc123abc123abc123abc123abc123abc123abc1"
	manifest := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {
					SHA:           actionSHA,
					DiskIntegrity: "sha256-fakehash",
				},
			},
		},
	}

	workflow := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

	// Suppress gate messages
	var buf bytes.Buffer
	oldWriter := messageWriter
	messageWriter = &buf
	defer func() { messageWriter = oldWriter }()

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/contents/") {
			var content string
			if strings.Contains(r.URL.Path, "ci.yml") {
				content = b64Str(workflow)
			} else if strings.Contains(r.URL.Path, "actions-lock.json") {
				content = b64JSON(manifest)
			} else {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			resp := map[string]string{"content": content, "encoding": "base64"}
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{
			"rateLimit": map[string]any{"cost": 1, "remaining": 4999},
			"actions_checkout": map[string]any{
				"refs": map[string]any{
					"totalCount": 1,
					"pageInfo":   map[string]any{"endCursor": "", "hasNextPage": false},
					"nodes": []map[string]any{{
						"name":   "v4",
						"target": map[string]any{"__typename": "Commit", "oid": actionSHA},
					}},
				},
			},
		}
		resp := map[string]any{"data": data}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer graphqlServer.Close()

	opts := GateOptions{
		Repo:         "test/repo",
		SHA:          actionSHA,
		WorkflowRef:  "test/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".github/actions-lock.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
		OnDisk:       true,
		// ActionsDir deliberately empty, RUNNER_WORKSPACE unset
	}

	_, err := RunGate(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error about RUNNER_WORKSPACE not set")
	}
	if !strings.Contains(err.Error(), "RUNNER_WORKSPACE") {
		t.Errorf("expected RUNNER_WORKSPACE error, got: %v", err)
	}
}

func TestGateOnDisk_CustomActionsDir(t *testing.T) {
	actionSHA := "abc123abc123abc123abc123abc123abc123abc1"
	files := map[string]string{
		"action.yml": "name: checkout\nruns:\n  using: node20\n  main: index.js\n",
	}
	actionsDir, treeHash := setupOnDiskAction(t, "actions", "checkout", "v4", files)

	manifest := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {
					SHA:           actionSHA,
					DiskIntegrity: treeHash,
				},
			},
		},
	}

	workflow := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

	result := onDiskGateTest(t, workflow, manifest, GateOptions{
		OnDisk:     true,
		ActionsDir: actionsDir, // Custom path, not derived from RUNNER_WORKSPACE
	})

	// Should pass with custom dir
	for _, v := range result.Violations {
		t.Errorf("unexpected violation: %s@%s", v.Action, v.Tag)
	}
}
