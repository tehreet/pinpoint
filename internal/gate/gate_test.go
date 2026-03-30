// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package gate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	manifestpkg "github.com/tehreet/pinpoint/internal/manifest"
)

// silenceOutput redirects gate messages to a buffer during tests.
func silenceOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	old := messageWriter
	messageWriter = buf
	t.Cleanup(func() { messageWriter = old })
	return buf
}

// buildContentResponse builds a GitHub contents API response with base64 content.
func buildContentResponse(content string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	resp, _ := json.Marshal(contentResponse{
		Content:  encoded,
		Encoding: "base64",
	})
	return string(resp)
}

// buildGraphQLResponse builds a GraphQL response for tag resolution.
func buildGraphQLResponse(repos map[string]map[string]string) string {
	data := map[string]any{
		"rateLimit": map[string]any{"cost": 1, "remaining": 4999},
	}
	for repo, tags := range repos {
		alias := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return r
			}
			return '_'
		}, repo)
		if len(alias) > 0 && alias[0] >= '0' && alias[0] <= '9' {
			alias = "_" + alias
		}

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
				"pageInfo":   map[string]any{"endCursor": "", "hasNextPage": false},
				"nodes":      nodes,
			},
		}
	}

	resp, _ := json.Marshal(map[string]any{"data": data})
	return string(resp)
}

const testWorkflow = `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - uses: docker/build-push-action@v5
      - run: go build ./...
`

const testManifest = `{
  "version": 1,
  "generated_at": "2026-03-21T08:00:00Z",
  "actions": {
    "actions/checkout": {
      "v4": {"sha": "abc1234567890abc1234567890abc1234567890a", "recorded_at": "2026-03-21T08:00:00Z"}
    },
    "actions/setup-go": {
      "v5": {"sha": "def4567890abc1234567890abc1234567890abcd", "recorded_at": "2026-03-21T08:00:00Z"}
    },
    "docker/build-push-action": {
      "v5": {"sha": "789abc1234567890abc1234567890abc12345678", "recorded_at": "2026-03-21T08:00:00Z"}
    }
  }
}`

func TestParseWorkflowPath(t *testing.T) {
	tests := []struct {
		name        string
		workflowRef string
		repo        string
		want        string
		wantErr     bool
	}{
		{
			name:        "standard branch ref",
			workflowRef: "coreweave/ml-platform/.github/workflows/ci.yml@refs/heads/main",
			repo:        "coreweave/ml-platform",
			want:        ".github/workflows/ci.yml",
		},
		{
			name:        "tag ref",
			workflowRef: "tehreet/pinpoint/.github/workflows/ci.yml@refs/tags/v1.0.0",
			repo:        "tehreet/pinpoint",
			want:        ".github/workflows/ci.yml",
		},
		{
			name:        "empty ref",
			workflowRef: "",
			repo:        "owner/repo",
			wantErr:     true,
		},
		{
			name:        "repo mismatch",
			workflowRef: "other/repo/.github/workflows/ci.yml@refs/heads/main",
			repo:        "owner/repo",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWorkflowPath(tt.workflowRef, tt.repo)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractUsesDirectives(t *testing.T) {
	workflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 'actions/setup-go@v5'
      - uses: "docker/build-push-action@v5"
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.18
      - run: echo hello
      - uses: org/repo/.github/workflows/build.yml@v1
      - uses: actions/upload-artifact@a824008efbb0f27efdc2560e1a50bde6cebcf823
`
	refs := ExtractUsesDirectives(workflow)
	want := []string{
		"actions/checkout@v4",
		"actions/setup-go@v5",
		"docker/build-push-action@v5",
		"./.github/actions/local",
		"docker://alpine:3.18",
		"org/repo/.github/workflows/build.yml@v1",
		"actions/upload-artifact@a824008efbb0f27efdc2560e1a50bde6cebcf823",
	}
	if len(refs) != len(want) {
		t.Fatalf("got %d refs, want %d:\n  got:  %v\n  want: %v", len(refs), len(want), refs, want)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Errorf("ref[%d] = %q, want %q", i, refs[i], want[i])
		}
	}
}

func TestParseActionRef(t *testing.T) {
	tests := []struct {
		raw        string
		wantOwner  string
		wantRepo   string
		wantRef    string
		wantWF     bool
		wantErr    bool
	}{
		{"actions/checkout@v4", "actions", "checkout", "v4", false, false},
		{"docker/build-push-action@v5", "docker", "build-push-action", "v5", false, false},
		{"actions/upload-artifact@a824008efbb0f27efdc2560e1a50bde6cebcf823", "actions", "upload-artifact", "a824008efbb0f27efdc2560e1a50bde6cebcf823", false, false},
		{"org/repo/.github/workflows/build.yml@v1", "org", "repo", "v1", true, false},
		{"org/repo/subpath@v2", "org", "repo", "v2", false, false},
		{"./.github/actions/local@v1", "", "", "", false, true},
		{"docker://alpine:3.18", "", "", "", false, true},
		{"noslash", "", "", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			owner, repo, ref, isWF, err := ParseActionRef(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if owner != tt.wantOwner || repo != tt.wantRepo || ref != tt.wantRef || isWF != tt.wantWF {
				t.Errorf("got (%q, %q, %q, %v), want (%q, %q, %q, %v)",
					owner, repo, ref, isWF, tt.wantOwner, tt.wantRepo, tt.wantRef, tt.wantWF)
			}
		})
	}
}

func TestCleanVerification(t *testing.T) {
	buf := silenceOutput(t)

	// Mock REST server for workflow + manifest
	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(testWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(testManifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	// Mock GraphQL server
	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout":          {"v4": "abc1234567890abc1234567890abc1234567890a"},
			"actions/setup-go":          {"v5": "def4567890abc1234567890abc1234567890abcd"},
			"docker/build-push-action":  {"v5": "789abc1234567890abc1234567890abc12345678"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verified != 3 {
		t.Errorf("verified = %d, want 3", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}

	output := buf.String()
	if !strings.Contains(output, "matches manifest") {
		t.Errorf("output should contain 'matches manifest', got:\n%s", output)
	}
}

func TestTagRepointed(t *testing.T) {
	buf := silenceOutput(t)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(testWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(testManifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a DIFFERENT sha for docker/build-push-action — simulating repointing
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout":         {"v4": "abc1234567890abc1234567890abc1234567890a"},
			"actions/setup-go":         {"v5": "def4567890abc1234567890abc1234567890abcd"},
			"docker/build-push-action": {"v5": "bad9999999999999999999999999999999999999"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(result.Violations))
	}
	v := result.Violations[0]
	if v.Action != "docker/build-push-action" {
		t.Errorf("violation action = %q, want docker/build-push-action", v.Action)
	}
	if v.ExpectedSHA != "789abc1234567890abc1234567890abc12345678" {
		t.Errorf("expected SHA wrong")
	}
	if v.ActualSHA != "bad9999999999999999999999999999999999999" {
		t.Errorf("actual SHA wrong")
	}

	output := buf.String()
	if !strings.Contains(output, "TAG HAS BEEN REPOINTED") {
		t.Errorf("output should contain repoint warning, got:\n%s", output)
	}
}

func TestMissingManifest(t *testing.T) {
	silenceOutput(t)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(testWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	// Default: warn and exit 0
	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   "http://unused",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("default mode: violations = %d, want 0", len(result.Violations))
	}

	// With --fail-on-missing: violation
	result, err = RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            "http://unused",
		FailOnMissing:         true,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Errorf("fail-on-missing mode: violations = %d, want 1", len(result.Violations))
	}
}

func TestActionNotInManifest(t *testing.T) {
	silenceOutput(t)

	// Manifest only has actions/checkout, workflow has more
	sparseManifest := `{
		"version": 1,
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "abc1234567890abc1234567890abc1234567890a"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(testWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(sparseManifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout":         {"v4": "abc1234567890abc1234567890abc1234567890a"},
			"actions/setup-go":         {"v5": "def4567890abc1234567890abc1234567890abcd"},
			"docker/build-push-action": {"v5": "789abc1234567890abc1234567890abc12345678"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	// Default: warn, no violations
	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("default: violations = %d, want 0", len(result.Violations))
	}
	if len(result.Warnings) != 2 {
		t.Errorf("default: warnings = %d, want 2", len(result.Warnings))
	}

	// With --fail-on-missing: violations for missing actions
	result, err = RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            graphqlServer.URL,
		FailOnMissing:         true,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 2 {
		t.Errorf("fail-on-missing: violations = %d, want 2", len(result.Violations))
	}
}

func TestSHAPinnedActions(t *testing.T) {
	silenceOutput(t)

	shaWorkflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a824008efbb0f27efdc2560e1a50bde6cebcf823
      - uses: actions/setup-go@b824008efbb0f27efdc2560e1a50bde6cebcf823
`
	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(shaWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(`{"version":1,"actions":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	// No GraphQL server needed — SHA-pinned actions skip tag resolution
	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   "http://should-not-be-called",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Skipped != 2 {
		t.Errorf("skipped = %d, want 2", result.Skipped)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
}

func TestBranchPinnedActions(t *testing.T) {
	silenceOutput(t)

	branchWorkflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - uses: actions/setup-go@v5
`
	manifest := `{
		"version": 1,
		"actions": {
			"actions/setup-go": {
				"v5": {"sha": "def4567890abc1234567890abc1234567890abcd"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(branchWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v4": "abc123"},
			"actions/setup-go": {"v5": "def4567890abc1234567890abc1234567890abcd"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	// Default: warn only
	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("default: violations = %d, want 0", len(result.Violations))
	}
	if len(result.Warnings) != 1 {
		t.Errorf("default: warnings = %d, want 1", len(result.Warnings))
	}

	// With --fail-on-unpinned
	result, err = RunGate(context.Background(), GateOptions{
		Repo:           "owner/repo",
		SHA:            "abc123",
		WorkflowRef:    "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:   ".pinpoint-manifest.json",
		APIURL:         restServer.URL,
		GraphQLURL:     graphqlServer.URL,
		FailOnUnpinned: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Errorf("fail-on-unpinned: violations = %d, want 1", len(result.Violations))
	}
}

func TestReusableWorkflowRef(t *testing.T) {
	silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: org/repo/.github/workflows/build.yml@v1
`
	manifest := `{
		"version": 1,
		"actions": {
			"org/repo": {
				"v1": {"sha": "aaa1234567890abc1234567890abc1234567890a"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"org/repo": {"v1": "aaa1234567890abc1234567890abc1234567890a"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 1 {
		t.Errorf("verified = %d, want 1", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
}

func TestEndToEndWithMockServers(t *testing.T) {
	buf := silenceOutput(t)

	// Workflow with mixed action types including one that will be repointed
	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - uses: aquasecurity/trivy-action@0.35.0
      - uses: actions/upload-artifact@a824008efbb0f27efdc2560e1a50bde6cebcf823
      - uses: ./.github/actions/local
      - uses: some-org/some-action@main
`
	manifest := `{
		"version": 1,
		"generated_at": "2026-03-20T08:00:00Z",
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "abc1234567890abc1234567890abc1234567890a", "recorded_at": "2026-03-20T08:00:00Z"}
			},
			"actions/setup-go": {
				"v5": {"sha": "def4567890abc1234567890abc1234567890abcd", "recorded_at": "2026-03-20T08:00:00Z"}
			},
			"aquasecurity/trivy-action": {
				"0.35.0": {"sha": "fed3210987654321fedcba0987654321fedcba09", "recorded_at": "2026-03-20T08:00:00Z"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trivy tag has been repointed!
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout":          {"v4": "abc1234567890abc1234567890abc1234567890a"},
			"actions/setup-go":          {"v5": "def4567890abc1234567890abc1234567890abcd"},
			"aquasecurity/trivy-action": {"0.35.0": "bad9999999999999999999999999999999999999"},
			"some-org/some-action":     {"main": "doesntmatter"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect: 2 verified (checkout, setup-go), 1 violation (trivy), 1 skipped (SHA-pinned upload-artifact), 1 warning (branch-pinned some-action)
	if result.Verified != 2 {
		t.Errorf("verified = %d, want 2", result.Verified)
	}
	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", result.Skipped)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(result.Violations))
	}
	if result.Violations[0].Action != "aquasecurity/trivy-action" {
		t.Errorf("violation action = %q, want aquasecurity/trivy-action", result.Violations[0].Action)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("warnings = %d, want 1", len(result.Warnings))
	}

	output := buf.String()
	if !strings.Contains(output, "TAG HAS BEEN REPOINTED") {
		t.Errorf("output should contain repoint warning, got:\n%s", output)
	}
	if !strings.Contains(output, "SHA-pinned") {
		t.Errorf("output should mention SHA-pinned, got:\n%s", output)
	}
}

// Test: Manifest Poisoning Prevention (Fix 1)
func TestManifestPoisoningPrevention(t *testing.T) {
	silenceOutput(t)

	goodSHA := "abc1234567890abc1234567890abc1234567890a"
	evilSHA := "evil234567890abc1234567890abc1234567890a"

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	goodManifest := fmt.Sprintf(`{"version":1,"actions":{"actions/checkout":{"v4":{"sha":"%s"}}}}`, goodSHA)
	evilManifest := fmt.Sprintf(`{"version":1,"actions":{"actions/checkout":{"v4":{"sha":"%s"}}}}`, evilSHA)

	// REST server that serves different manifests depending on ref query param
	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ref := r.URL.Query().Get("ref")
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			if ref == "main" {
				fmt.Fprint(w, buildContentResponse(goodManifest))
			} else {
				// merge commit SHA gets the evil manifest
				fmt.Fprint(w, buildContentResponse(evilManifest))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v4": goodSHA},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	// With PR event: should fetch manifest from base branch ("main"), SHA matches -> pass
	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "mergecommitsha",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
		EventName:    "pull_request",
		BaseRef:      "main",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("PR event with base branch manifest: expected 0 violations, got %d", len(result.Violations))
	}
	if result.Verified != 1 {
		t.Errorf("PR event: verified = %d, want 1", result.Verified)
	}

	// Without PR event (push): fetches manifest at merge commit SHA (evil), evil SHA matches evil -> pass
	// This proves the attack works without the fix.
	silenceOutput(t)
	result2, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "mergecommitsha",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
		EventName:    "push",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The evil manifest expects evilSHA, but actual is goodSHA -> violation
	if len(result2.Violations) != 1 {
		t.Errorf("push event with evil manifest: expected 1 violation (sha mismatch), got %d", len(result2.Violations))
	}
}

// Test: Zero uses: directives (Fix 6)
func TestZeroUsesDirectives(t *testing.T) {
	buf := silenceOutput(t)

	wf := `name: Script Only
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
      - run: go build ./...
`
	manifest := `{"version":1,"actions":{}}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   "http://should-not-be-called",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 0 {
		t.Errorf("verified = %d, want 0", result.Verified)
	}
	if result.Skipped != 0 {
		t.Errorf("skipped = %d, want 0", result.Skipped)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
	output := buf.String()
	if !strings.Contains(output, "no action references found") {
		t.Errorf("expected 'no action references found' message, got:\n%s", output)
	}
}

// Test: Sub-path action ref (Fix 7)
func TestSubPathActionRef(t *testing.T) {
	owner, repo, ref, isWF, err := ParseActionRef("aws-actions/configure-aws-credentials/subdir@v4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "aws-actions" || repo != "configure-aws-credentials" || ref != "v4" || isWF {
		t.Errorf("got (%q, %q, %q, %v), want (aws-actions, configure-aws-credentials, v4, false)",
			owner, repo, ref, isWF)
	}
}

// Test: SHA with inline comment (Fix 7)
func TestSHAWithInlineComment(t *testing.T) {
	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
`
	refs := ExtractUsesDirectives(wf)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d: %v", len(refs), refs)
	}
	expected := "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
	if refs[0] != expected {
		t.Errorf("got %q, want %q", refs[0], expected)
	}
	// Verify it's classified as SHA-pinned
	_, _, ref, _, err := ParseActionRef(refs[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !shaRegexp.MatchString(ref) {
		t.Errorf("expected SHA-pinned ref, got %q", ref)
	}
}

// Test: Quoted uses values (Fix 7)
func TestQuotedUsesValues(t *testing.T) {
	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: 'actions/checkout@v4'
      - uses: "actions/setup-go@v5"
`
	refs := ExtractUsesDirectives(wf)
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %v", len(refs), refs)
	}
	if refs[0] != "actions/checkout@v4" {
		t.Errorf("ref[0] = %q, want %q", refs[0], "actions/checkout@v4")
	}
	if refs[1] != "actions/setup-go@v5" {
		t.Errorf("ref[1] = %q, want %q", refs[1], "actions/setup-go@v5")
	}
}

// Test: Dynamic expression uses (Fix 7)
func TestDynamicExpressionUses(t *testing.T) {
	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ${{ matrix.action }}
`
	refs := ExtractUsesDirectives(wf)
	// The ${{ ... }} expression should not match the regex
	for _, ref := range refs {
		if strings.Contains(ref, "matrix") {
			t.Errorf("dynamic expression should not be extracted, got %q", ref)
		}
	}
}

// Test: Workflow with only run: steps, no uses: directives.
func TestGate_WorkflowWithOnlyRunSteps(t *testing.T) {
	buf := silenceOutput(t)

	wf := `name: Script Only
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello world"
      - run: go test ./...
      - run: make build
`
	manifest := `{"version":1,"actions":{}}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   "http://should-not-be-called",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 0 {
		t.Errorf("verified = %d, want 0", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
	output := buf.String()
	if !strings.Contains(output, "no action references found") {
		t.Errorf("expected 'no action references found' in output, got:\n%s", output)
	}
}

// Test: Mixed pinned and unpinned actions.
func TestGate_MixedPinnedAndUnpinned(t *testing.T) {
	silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a824008efbb0f27efdc2560e1a50bde6cebcf823
      - uses: actions/setup-go@b824008efbb0f27efdc2560e1a50bde6cebcf823
      - uses: actions/upload-artifact@c824008efbb0f27efdc2560e1a50bde6cebcf823
      - uses: docker/build-push-action@v5
      - uses: docker/login-action@v3
      - uses: some-org/deploy@main
`
	manifest := fmt.Sprintf(`{
		"version": 1,
		"generated_at": "2026-03-21T08:00:00Z",
		"actions": {
			"docker/build-push-action": {
				"v5": {"sha": "%s"}
			},
			"docker/login-action": {
				"v3": {"sha": "%s"}
			}
		}
	}`, "aaa1234567890abc1234567890abc1234567890a", "bbb1234567890abc1234567890abc1234567890b")

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"docker/build-push-action": {"v5": "aaa1234567890abc1234567890abc1234567890a"},
			"docker/login-action":      {"v3": "bbb1234567890abc1234567890abc1234567890b"},
			"some-org/deploy":          {"main": "doesntmatter"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 2 {
		t.Errorf("verified = %d, want 2", result.Verified)
	}
	if result.Skipped != 3 {
		t.Errorf("skipped = %d, want 3", result.Skipped)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("warnings = %d, want 1 (branch-pinned)", len(result.Warnings))
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
}

// Test: All branch-pinned actions with strict mode.
func TestGate_AllBranchPinned_StrictMode(t *testing.T) {
	silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - uses: actions/setup-go@develop
      - uses: docker/build-push-action@master
`
	manifest := `{"version":1,"actions":{}}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout":         {"main": "aaa"},
			"actions/setup-go":         {"develop": "bbb"},
			"docker/build-push-action": {"master": "ccc"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:           "owner/repo",
		SHA:            "abc123",
		WorkflowRef:    "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:   ".pinpoint-manifest.json",
		APIURL:         restServer.URL,
		GraphQLURL:     graphqlServer.URL,
		FailOnUnpinned: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 3 {
		t.Errorf("violations = %d, want 3", len(result.Violations))
	}
}

// Test: Manifest older than 30 days triggers staleness warning.
func TestGate_ManifestOlderThan30Days(t *testing.T) {
	buf := silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	manifest := `{
		"version": 1,
		"generated_at": "2025-01-01T00:00:00Z",
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "abc1234567890abc1234567890abc1234567890a"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v4": "abc1234567890abc1234567890abc1234567890a"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 1 {
		t.Errorf("verified = %d, want 1", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
	output := buf.String()
	if !strings.Contains(output, "days old") {
		t.Errorf("expected 'days old' warning in output, got:\n%s", output)
	}
}

// Test: Invalid JSON in manifest returns parse error.
func TestGate_ManifestInvalidJSON(t *testing.T) {
	silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse("this is { not valid json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	_, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   "http://unused",
	})
	if err == nil {
		t.Fatal("expected error for invalid JSON manifest, got nil")
	}
	if !strings.Contains(err.Error(), "parse manifest") {
		t.Errorf("error should contain 'parse manifest', got: %v", err)
	}
	if !strings.Contains(err.Error(), "Regenerate") {
		t.Errorf("error should contain 'Regenerate', got: %v", err)
	}
}

// Test: Large workflow with 50 actions all matching.
func TestGate_LargeWorkflow_50Actions(t *testing.T) {
	silenceOutput(t)

	// Build workflow with 50 uses directives
	var wfBuilder strings.Builder
	wfBuilder.WriteString("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&wfBuilder, "      - uses: org%d/action%d@v1\n", i, i)
	}
	wf := wfBuilder.String()

	// Build manifest with all 50 actions
	actions := make(map[string]map[string]manifestpkg.ManifestEntry)
	graphqlRepos := make(map[string]map[string]string)
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("org%d/action%d", i, i)
		sha := fmt.Sprintf("%040x", i+1)
		actions[key] = map[string]manifestpkg.ManifestEntry{
			"v1": {SHA: sha},
		}
		graphqlRepos[key] = map[string]string{"v1": sha}
	}
	manifestObj := manifestpkg.Manifest{Version: 1, Actions: actions}
	manifestBytes, _ := json.Marshal(manifestObj)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(string(manifestBytes)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(graphqlRepos)
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 50 {
		t.Errorf("verified = %d, want 50", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
}

// Test: PR event fetches manifest from base ref.
func TestGate_PREvent_ManifestFromBaseRef(t *testing.T) {
	silenceOutput(t)

	goodSHA := "abc1234567890abc1234567890abc1234567890a"
	evilSHA := "evil234567890abc1234567890abc1234567890a"

	wf := `name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	goodManifest := fmt.Sprintf(`{"version":1,"actions":{"actions/checkout":{"v4":{"sha":"%s"}}}}`, goodSHA)
	evilManifest := fmt.Sprintf(`{"version":1,"actions":{"actions/checkout":{"v4":{"sha":"%s"}}}}`, evilSHA)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ref := r.URL.Query().Get("ref")
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			if ref == "main" {
				fmt.Fprint(w, buildContentResponse(goodManifest))
			} else {
				fmt.Fprint(w, buildContentResponse(evilManifest))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v4": goodSHA},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "mergecommitsha",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
		EventName:    "pull_request",
		BaseRef:      "main",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("PR event: violations = %d, want 0", len(result.Violations))
	}
	if result.Verified != 1 {
		t.Errorf("PR event: verified = %d, want 1", result.Verified)
	}
}

// Test: Push event uses poisoned manifest (no base ref protection).
func TestGate_PREvent_PoisonedManifest(t *testing.T) {
	silenceOutput(t)

	goodSHA := "abc1234567890abc1234567890abc1234567890a"
	evilSHA := "evil234567890abc1234567890abc1234567890a"

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	evilManifest := fmt.Sprintf(`{"version":1,"actions":{"actions/checkout":{"v4":{"sha":"%s"}}}}`, evilSHA)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			// Always serve evil manifest (no base ref override)
			fmt.Fprint(w, buildContentResponse(evilManifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v4": goodSHA},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
		EventName:    "push",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("push event: violations = %d, want 1", len(result.Violations))
	}
	v := result.Violations[0]
	if v.ExpectedSHA != evilSHA {
		t.Errorf("expected SHA = %q, want %q", v.ExpectedSHA, evilSHA)
	}
	if v.ActualSHA != goodSHA {
		t.Errorf("actual SHA = %q, want %q", v.ActualSHA, goodSHA)
	}
}

// Test: Reusable workflow ref is verified alongside regular actions.
func TestGate_ReusableWorkflow_Nested(t *testing.T) {
	silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: myorg/shared/.github/workflows/build.yml@v2
`
	manifest := `{
		"version": 1,
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "abc1234567890abc1234567890abc1234567890a"}
			},
			"myorg/shared": {
				"v2": {"sha": "def4567890abc1234567890abc1234567890abcd"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v4": "abc1234567890abc1234567890abc1234567890a"},
			"myorg/shared":    {"v2": "def4567890abc1234567890abc1234567890abcd"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 2 {
		t.Errorf("verified = %d, want 2", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
}

// Test: GraphQL partial failure — one repo inaccessible.
func TestGate_GraphQLPartialFailure(t *testing.T) {
	silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: private/deleted-repo@v1
      - uses: docker/build-push-action@v5
`
	manifest := `{
		"version": 1,
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "abc1234567890abc1234567890abc1234567890a"}
			},
			"private/deleted-repo": {
				"v1": {"sha": "fff1234567890abc1234567890abc1234567890f"}
			},
			"docker/build-push-action": {
				"v5": {"sha": "789abc1234567890abc1234567890abc12345678"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	// GraphQL returns data for checkout and docker, but not private/deleted-repo
	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build response with only 2 repos, omitting private/deleted-repo
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout":         {"v4": "abc1234567890abc1234567890abc1234567890a"},
			"docker/build-push-action": {"v5": "789abc1234567890abc1234567890abc12345678"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verified != 2 {
		t.Errorf("verified = %d, want 2", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
	// Should have a warning about the inaccessible repo
	foundWarning := false
	for _, w := range result.Warnings {
		if w.Action == "private/deleted-repo" {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Errorf("expected warning for inaccessible repo private/deleted-repo, warnings: %+v", result.Warnings)
	}
}

// Test: Tag deleted on remote — present in manifest but absent from GraphQL tags.
func TestGate_TagDeletedOnRemote(t *testing.T) {
	buf := silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	manifest := `{
		"version": 1,
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "abc1234567890abc1234567890abc1234567890a"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	// GraphQL returns the repo but only with v3, not v4
	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v3": "old1234567890abc1234567890abc1234567890o"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
	output := buf.String()
	// v4 is a version-like ref that doesn't exist as a tag on the remote,
	// so looksLikeBranch returns false, then post-GraphQL reclassification
	// marks it as a branch since the tag is missing.
	if !strings.Contains(output, "branch-pinned") {
		t.Errorf("expected 'branch-pinned' warning (reclassified from missing tag), got:\n%s", output)
	}
}

// Test: Empty manifest actions — warnings without fail-on-missing, violations with it.
func TestGate_EmptyManifestActions(t *testing.T) {
	silenceOutput(t)

	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
`
	manifest := `{"version":1,"actions":{}}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(wf))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := buildGraphQLResponse(map[string]map[string]string{
			"actions/checkout": {"v4": "abc1234567890abc1234567890abc1234567890a"},
			"actions/setup-go": {"v5": "def4567890abc1234567890abc1234567890abcd"},
		})
		fmt.Fprint(w, resp)
	}))
	defer graphqlServer.Close()

	// Without --fail-on-missing: warnings only
	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".pinpoint-manifest.json",
		APIURL:       restServer.URL,
		GraphQLURL:   graphqlServer.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Warnings) != 2 {
		t.Errorf("without fail-on-missing: warnings = %d, want 2", len(result.Warnings))
	}
	if len(result.Violations) != 0 {
		t.Errorf("without fail-on-missing: violations = %d, want 0", len(result.Violations))
	}

	// With --fail-on-missing: violations
	silenceOutput(t)
	result, err = RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            graphqlServer.URL,
		FailOnMissing:         true,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Violations) != 2 {
		t.Errorf("with fail-on-missing: violations = %d, want 2", len(result.Violations))
	}
}

func TestListDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/contents/.github/workflows" && r.URL.Query().Get("ref") == "abc123" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
				{"name": "ci.yml", "type": "file", "path": ".github/workflows/ci.yml"},
				{"name": "deploy.yaml", "type": "file", "path": ".github/workflows/deploy.yaml"},
				{"name": "README.md", "type": "file", "path": ".github/workflows/README.md"}
			]`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	client := &httpClient{
		token:   "test-token",
		baseURL: srv.URL,
		http:    &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()
	files, err := client.listDirectory(ctx, "owner/repo", ".github/workflows", "abc123")
	if err != nil {
		t.Fatalf("listDirectory failed: %v", err)
	}

	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(files))
	}
	expected := []string{"ci.yml", "deploy.yaml", "README.md"}
	for i, name := range expected {
		if files[i] != name {
			t.Errorf("file[%d]: expected %q, got %q", i, name, files[i])
		}
	}

	// Test 404 handling
	_, err = client.listDirectory(ctx, "owner/repo", "nonexistent/path", "abc123")
	if err == nil {
		t.Fatal("expected notFoundError for missing path, got nil")
	}
	if !isNotFound(err) {
		t.Fatalf("expected notFoundError, got %T: %v", err, err)
	}
}

func TestAllWorkflowsMode(t *testing.T) {
	buf := silenceOutput(t)

	// Two workflow files with different actions
	ciYml := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
`
	deployYml := `name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
`

	manifest := `{
		"version": 1,
		"generated_at": "` + time.Now().Format(time.RFC3339) + `",
		"actions": {
			"actions/checkout": {"v4": {"sha": "` + strings.Repeat("a", 40) + `"}},
			"actions/setup-go": {"v5": {"sha": "` + strings.Repeat("b", 40) + `"}},
			"aws-actions/configure-aws-credentials": {"v4": {"sha": "` + strings.Repeat("c", 40) + `"}}
		}
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows" && r.URL.Query().Get("ref") != "":
			fmt.Fprint(w, `[
				{"name": "ci.yml", "type": "file", "path": ".github/workflows/ci.yml"},
				{"name": "deploy.yml", "type": "file", "path": ".github/workflows/deploy.yml"}
			]`)
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows/ci.yml":
			content := base64.StdEncoding.EncodeToString([]byte(ciYml))
			fmt.Fprintf(w, `{"content": %q, "encoding": "base64"}`, content)
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows/deploy.yml":
			content := base64.StdEncoding.EncodeToString([]byte(deployYml))
			fmt.Fprintf(w, `{"content": %q, "encoding": "base64"}`, content)
		case r.URL.Path == "/repos/owner/repo/contents/.github/actions-lock.json":
			content := base64.StdEncoding.EncodeToString([]byte(manifest))
			fmt.Fprintf(w, `{"content": %q, "encoding": "base64"}`, content)
		case r.URL.Path == "/graphql":
			fmt.Fprint(w, buildGraphQLResponse(map[string]map[string]string{
				"actions/checkout":                       {"v4": strings.Repeat("a", 40)},
				"actions/setup-go":                       {"v5": strings.Repeat("b", 40)},
				"aws-actions/configure-aws-credentials":  {"v4": strings.Repeat("c", 40)},
			}))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	opts := GateOptions{
		Repo:         "owner/repo",
		SHA:          strings.Repeat("d", 40),
		AllWorkflows: true,
		ManifestPath: ".github/actions-lock.json",
		// WorkflowRef intentionally omitted
		Token:      "test-token",
		APIURL:     srv.URL,
		GraphQLURL: srv.URL + "/graphql",
	}

	result, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}

	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d: %+v", len(result.Violations), result.Violations)
	}

	// actions/checkout appears in both files but should be deduplicated.
	// Expect 3 unique refs verified: checkout@v4, setup-go@v5, configure-aws-credentials@v4
	if result.Verified != 3 {
		t.Errorf("expected 3 verified (deduplicated), got %d", result.Verified)
	}

	output := buf.String()
	if !strings.Contains(output, "all-workflows") {
		t.Errorf("expected output to mention all-workflows mode, got: %s", output)
	}
}

// --- Spec 023: Verify SHA-pinned references against lockfile ---

func TestSHAPinnedVerifiedAgainstManifest(t *testing.T) {
	buf := silenceOutput(t)

	correctSHA := "a824008efbb0f27efdc2560e1a50bde6cebcf823"
	shaWorkflow := fmt.Sprintf(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@%s
`, correctSHA)

	manifest := fmt.Sprintf(`{
		"version": 1,
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "%s"}
			}
		}
	}`, correctSHA)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(shaWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            "http://should-not-be-called",
		FailOnMissing:         true,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verified != 1 {
		t.Errorf("verified = %d, want 1", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}
	if result.Skipped != 0 {
		t.Errorf("skipped = %d, want 0 (SHA should be verified, not skipped)", result.Skipped)
	}

	output := buf.String()
	if !strings.Contains(output, "SHA matches manifest") {
		t.Errorf("output should contain 'SHA matches manifest', got:\n%s", output)
	}
}

func TestSHAPinnedNotInManifest(t *testing.T) {
	buf := silenceOutput(t)

	wrongSHA := "b4ffde65f46336ab88eb53be808477a3936bae11"
	shaWorkflow := fmt.Sprintf(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@%s
`, wrongSHA)

	manifest := `{
		"version": 1,
		"actions": {
			"actions/checkout": {
				"v4": {"sha": "a824008efbb0f27efdc2560e1a50bde6cebcf823"}
			}
		}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(shaWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            "http://should-not-be-called",
		FailOnMissing:         true,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(result.Violations))
	}
	if result.Violations[0].Action != "actions/checkout" {
		t.Errorf("violation action = %q, want actions/checkout", result.Violations[0].Action)
	}

	output := buf.String()
	if !strings.Contains(output, "SHA not in manifest") {
		t.Errorf("output should contain 'SHA not in manifest', got:\n%s", output)
	}
}

func TestSHAPinnedActionNotInManifest(t *testing.T) {
	buf := silenceOutput(t)

	shaWorkflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: unknown/action@a824008efbb0f27efdc2560e1a50bde6cebcf823
`
	manifest := `{
		"version": 1,
		"actions": {}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(shaWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            "http://should-not-be-called",
		FailOnMissing:         true,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(result.Violations))
	}

	output := buf.String()
	if !strings.Contains(output, "not in manifest") {
		t.Errorf("output should contain 'not in manifest', got:\n%s", output)
	}
}

func TestSHAPinnedLegacyModeSkips(t *testing.T) {
	buf := silenceOutput(t)

	shaWorkflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a824008efbb0f27efdc2560e1a50bde6cebcf823
`
	manifest := `{
		"version": 1,
		"actions": {}
	}`

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(shaWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	// Legacy mode: FailOnMissing=false — SHA-pinned should be skipped as before
	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            "http://should-not-be-called",
		FailOnMissing:         false,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", result.Skipped)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}

	output := buf.String()
	if !strings.Contains(output, "SHA-pinned (inherently safe)") {
		t.Errorf("output should contain legacy skip message, got:\n%s", output)
	}
}

func TestSHAPinnedReusableWorkflowVerified(t *testing.T) {
	buf := silenceOutput(t)

	correctSHA := "a824008efbb0f27efdc2560e1a50bde6cebcf823"
	shaWorkflow := fmt.Sprintf(`name: CI
on: push
jobs:
  build:
    uses: org/shared/.github/workflows/build.yml@%s
`, correctSHA)

	manifest := fmt.Sprintf(`{
		"version": 1,
		"actions": {
			"org/shared": {
				"v1": {"sha": "%s"}
			}
		}
	}`, correctSHA)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(shaWorkflow))
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(manifest))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restServer.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".pinpoint-manifest.json",
		APIURL:                restServer.URL,
		GraphQLURL:            "http://should-not-be-called",
		FailOnMissing:         true,
		FailOnMissingExplicit: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verified != 1 {
		t.Errorf("verified = %d, want 1", result.Verified)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d, want 0", len(result.Violations))
	}

	output := buf.String()
	if !strings.Contains(output, "SHA matches manifest") {
		t.Errorf("output should contain 'SHA matches manifest', got:\n%s", output)
	}
}

func TestLooksLikeBranch(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"main", true},
		{"master", true},
		{"develop", true},
		{"release/v1.0", true},
		{"feature/foo", true},
		{"v1", false},       // ambiguous — needs API check
		{"v1.2.3", false},   // ambiguous — needs API check
		{"v4", false},       // ambiguous — needs API check
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got := looksLikeBranch(tt.ref)
			if got != tt.want {
				t.Errorf("looksLikeBranch(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}
