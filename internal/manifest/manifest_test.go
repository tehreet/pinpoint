// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tehreet/pinpoint/internal/poller"
)

// graphqlHandler returns an http.HandlerFunc that serves GraphQL responses
// with the given tag mappings per repo alias.
func graphqlHandler(repoTags map[string]map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Build response data with rateLimit and repo aliases
		data := map[string]any{
			"rateLimit": map[string]any{
				"cost":      1,
				"remaining": 4999,
			},
		}

		for alias, tags := range repoTags {
			var nodes []map[string]any
			for name, sha := range tags {
				nodes = append(nodes, map[string]any{
					"name": name,
					"target": map[string]any{
						"__typename": "Commit",
						"oid":        sha,
					},
				})
			}
			data[alias] = map[string]any{
				"refs": map[string]any{
					"totalCount": len(nodes),
					"pageInfo": map[string]any{
						"endCursor":   "",
						"hasNextPage": false,
					},
					"nodes": nodes,
				},
			}
		}

		resp := map[string]any{"data": data}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func writeManifest(t *testing.T, dir string, m *Manifest) string {
	t.Helper()
	path := filepath.Join(dir, ".pinpoint-manifest.json")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRefreshNoChanges(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "34e1148e"},
			},
			"actions/setup-go": {
				"v5": {SHA: "40f1582e"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "34e1148e"},
		"actions_setup_go": {"v5": "40f1582e"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Refresh(context.Background(), manifestPath, "", false, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Unchanged != 2 {
		t.Errorf("expected 2 unchanged, got %d", result.Unchanged)
	}
	if result.Updated != 0 {
		t.Errorf("expected 0 updated, got %d", result.Updated)
	}
	if result.Added != 0 {
		t.Errorf("expected 0 added, got %d", result.Added)
	}
	if len(result.Changes) != 0 {
		t.Errorf("expected no changes, got %d", len(result.Changes))
	}
}

func TestRefreshWithDrift(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "34e1148e"},
			},
			"actions/setup-go": {
				"v5": {SHA: "40f1582e"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	// setup-go v5 has drifted
	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "34e1148e"},
		"actions_setup_go": {"v5": "8bb5382e"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Refresh(context.Background(), manifestPath, "", false, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}

	c := result.Changes[0]
	if c.Action != "actions/setup-go" || c.Tag != "v5" {
		t.Errorf("expected actions/setup-go@v5, got %s@%s", c.Action, c.Tag)
	}
	if c.OldSHA != "40f1582e" || c.NewSHA != "8bb5382e" {
		t.Errorf("expected SHA change 40f1582e→8bb5382e, got %s→%s", c.OldSHA, c.NewSHA)
	}
	if c.Type != "updated" {
		t.Errorf("expected type 'updated', got %q", c.Type)
	}

	// Verify the manifest file was updated
	updated, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("failed to reload manifest: %v", err)
	}
	if updated.Actions["actions/setup-go"]["v5"].SHA != "8bb5382e" {
		t.Errorf("manifest not updated on disk")
	}
}

func TestRefreshWithDiscover(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "34e1148e"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	// Create a workflow dir with a new action reference
	workflowDir := filepath.Join(dir, "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
`
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout":           {"v4": "34e1148e"},
		"docker_build_push_action": {"v5": "ca052bb1"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Refresh(context.Background(), manifestPath, workflowDir, true, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
	if result.Added != 1 {
		t.Errorf("expected 1 added, got %d", result.Added)
	}

	// Verify the new action was added to the manifest on disk
	updated, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("failed to reload manifest: %v", err)
	}
	entry, ok := updated.Actions["docker/build-push-action"]["v5"]
	if !ok {
		t.Fatal("docker/build-push-action@v5 not found in manifest")
	}
	if entry.SHA != "ca052bb1" {
		t.Errorf("expected SHA ca052bb1, got %s", entry.SHA)
	}
}

func TestVerifyClean(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "34e1148e"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "34e1148e"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Verify(context.Background(), manifestPath, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
	if result.Updated != 0 {
		t.Errorf("expected 0 updated, got %d", result.Updated)
	}
	if len(result.Changes) != 0 {
		t.Errorf("expected no changes, got %d", len(result.Changes))
	}
}

func TestVerifyDrift(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "34e1148e"},
			},
			"actions/setup-go": {
				"v5": {SHA: "40f1582e"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "34e1148e"},
		"actions_setup_go": {"v5": "DRIFTED1"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Verify(context.Background(), manifestPath, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
	if result.Updated != 1 {
		t.Errorf("expected 1 drifted, got %d", result.Updated)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}

	c := result.Changes[0]
	if c.OldSHA != "40f1582e" || c.NewSHA != "DRIFTED1" {
		t.Errorf("unexpected SHA change: %s→%s", c.OldSHA, c.NewSHA)
	}

	// Verify the manifest was NOT modified (verify is read-only)
	reloaded, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("failed to reload manifest: %v", err)
	}
	if reloaded.Actions["actions/setup-go"]["v5"].SHA != "40f1582e" {
		t.Error("verify should not modify the manifest")
	}
}

func TestRefreshMissingManifest(t *testing.T) {
	client := poller.NewGraphQLClient("")

	_, err := Refresh(context.Background(), "/nonexistent/.pinpoint-manifest.json", "", false, client)
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}

	fmt.Println("Error message:", err.Error())
	// Verify actionable guidance is in the error
	if got := err.Error(); got == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRefresh_TagDeletedOnRemote(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v3": {SHA: "old123"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	// GraphQL returns only v4 for actions/checkout — v3 is gone
	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "new456"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Refresh(context.Background(), manifestPath, "", false, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Missing != 1 {
		t.Errorf("expected 1 missing, got %d", result.Missing)
	}

	// Should have a missing_tag change
	found := false
	for _, c := range result.Changes {
		if c.Type == "missing_tag" && c.Action == "actions/checkout" && c.Tag == "v3" {
			found = true
			if c.OldSHA != "old123" {
				t.Errorf("expected OldSHA old123, got %s", c.OldSHA)
			}
		}
	}
	if !found {
		t.Error("expected a missing_tag change for actions/checkout@v3")
	}

	// Entry should still be in the manifest on disk (don't delete data)
	reloaded, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("failed to reload manifest: %v", err)
	}
	if _, ok := reloaded.Actions["actions/checkout"]["v3"]; !ok {
		t.Error("v3 entry should still be in the manifest on disk")
	}
}

func TestRefresh_NewRepoDiscovered(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "34e1148e"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	// Create a workflow dir with ci.yml using both actions/checkout@v4 and docker/build-push-action@v5
	workflowDir := filepath.Join(dir, "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
`
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout":         {"v4": "34e1148e"},
		"docker_build_push_action": {"v5": "ca052bb1"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Refresh(context.Background(), manifestPath, workflowDir, true, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Added < 1 {
		t.Errorf("expected Added >= 1, got %d", result.Added)
	}

	// Verify docker/build-push-action@v5 is in the manifest on disk
	reloaded, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("failed to reload manifest: %v", err)
	}
	entry, ok := reloaded.Actions["docker/build-push-action"]["v5"]
	if !ok {
		t.Fatal("docker/build-push-action@v5 not found in manifest after discover")
	}
	if entry.SHA != "ca052bb1" {
		t.Errorf("expected SHA ca052bb1, got %s", entry.SHA)
	}
}

func TestRefresh_ConcurrentSHAChange(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "old_sha"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	// GraphQL always returns "new_sha" for v4
	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "new_sha"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	// First: Verify detects drift
	verifyResult, err := Verify(context.Background(), manifestPath, client)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if verifyResult.Updated != 1 {
		t.Errorf("first verify: expected 1 updated (drift), got %d", verifyResult.Updated)
	}

	// Second: Refresh updates the manifest
	refreshResult, err := Refresh(context.Background(), manifestPath, "", false, client)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshResult.Updated != 1 {
		t.Errorf("refresh: expected 1 updated, got %d", refreshResult.Updated)
	}

	// Third: Verify again — no drift now
	verifyResult2, err := Verify(context.Background(), manifestPath, client)
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if verifyResult2.Unchanged != 1 {
		t.Errorf("second verify: expected 1 unchanged, got %d", verifyResult2.Unchanged)
	}
	if verifyResult2.Updated != 0 {
		t.Errorf("second verify: expected 0 updated, got %d", verifyResult2.Updated)
	}
}

func TestVerify_ExitCodeThree(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "original"},
			},
		},
	}
	manifestPath := writeManifest(t, dir, m)

	// Return a different SHA to cause drift
	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "drifted1"},
	}))
	defer ts.Close()

	client := poller.NewGraphQLClient("")
	client.SetEndpoint(ts.URL)

	result, err := Verify(context.Background(), manifestPath, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// In the CLI, exit code 3 is signaled when Updated+Missing > 0
	if result.Updated+result.Missing <= 0 {
		t.Errorf("expected Updated+Missing > 0 (exit code 3 condition), got Updated=%d Missing=%d",
			result.Updated, result.Missing)
	}
}

func TestInit_CreatesFiles(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, ".pinpoint-manifest.json")

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{
			"actions/checkout": {
				"v4": {SHA: "abc123"},
			},
		},
	}

	if err := SaveManifest(manifestPath, m); err != nil {
		t.Fatalf("SaveManifest: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("manifest file was not created")
	}

	// Verify it's valid JSON by loading it back
	loaded, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	if loaded.Version != 1 {
		t.Errorf("expected version 1, got %d", loaded.Version)
	}
	entry, ok := loaded.Actions["actions/checkout"]["v4"]
	if !ok {
		t.Fatal("missing actions/checkout@v4")
	}
	if entry.SHA != "abc123" {
		t.Errorf("expected SHA abc123, got %s", entry.SHA)
	}
}

func TestManifestEntryDockerSerialization(t *testing.T) {
	entry := ManifestEntry{
		SHA:       "abc123def456",
		Integrity: "sha256-AAAA",
		Type:      "docker",
		Docker: &DockerInfo{
			Image:  "ghcr.io/aquasecurity/trivy",
			Tag:    "0.58.1",
			Digest: "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00",
			Source: "action.yml",
		},
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ManifestEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Docker == nil {
		t.Fatal("Docker field is nil after round-trip")
	}
	if got.Docker.Image != "ghcr.io/aquasecurity/trivy" {
		t.Errorf("Image = %q, want %q", got.Docker.Image, "ghcr.io/aquasecurity/trivy")
	}
	if got.Docker.Digest != "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00" {
		t.Errorf("Digest = %q", got.Docker.Digest)
	}

	// Verify omitempty: entry without Docker should not have "docker" key
	noDocker := ManifestEntry{SHA: "abc", Type: "node20"}
	data2, _ := json.Marshal(noDocker)
	if strings.Contains(string(data2), `"docker"`) {
		t.Error("docker key present when DockerInfo is nil")
	}
}

func TestManifestEntryDockerfileBaseImages(t *testing.T) {
	entry := ManifestEntry{
		SHA:  "abc123",
		Type: "docker",
		Docker: &DockerInfo{
			Image: "Dockerfile",
			BaseImages: []DockerBaseImage{
				{Image: "alpine", Tag: "3.19", Digest: "sha256:aaa"},
				{Image: "golang", Tag: "1.24", Digest: "sha256:bbb"},
			},
			Source: "Dockerfile",
		},
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ManifestEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Docker.BaseImages) != 2 {
		t.Fatalf("BaseImages len = %d, want 2", len(got.Docker.BaseImages))
	}
	if got.Docker.BaseImages[0].Image != "alpine" {
		t.Errorf("BaseImages[0].Image = %q", got.Docker.BaseImages[0].Image)
	}
}

func TestRefresh_EmptyManifest(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Version: 1,
		Actions: map[string]map[string]ManifestEntry{},
	}
	manifestPath := writeManifest(t, dir, m)

	client := poller.NewGraphQLClient("")
	// No server needed — empty manifest means no repos to query

	// Without discover: 0 changes
	result, err := Refresh(context.Background(), manifestPath, "", false, client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Unchanged+result.Updated+result.Added+result.Missing != 0 {
		t.Errorf("expected 0 total changes, got unchanged=%d updated=%d added=%d missing=%d",
			result.Unchanged, result.Updated, result.Added, result.Missing)
	}

	// With discover and a workflow dir
	workflowDir := filepath.Join(dir, "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(graphqlHandler(map[string]map[string]string{
		"actions_checkout": {"v4": "resolved1"},
	}))
	defer ts.Close()

	client2 := poller.NewGraphQLClient("")
	client2.SetEndpoint(ts.URL)

	result2, err := Refresh(context.Background(), manifestPath, workflowDir, true, client2)
	if err != nil {
		t.Fatalf("unexpected error with discover: %v", err)
	}
	if result2.Added < 1 {
		t.Errorf("expected at least 1 added with discover, got %d", result2.Added)
	}
}
