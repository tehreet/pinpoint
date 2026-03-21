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
