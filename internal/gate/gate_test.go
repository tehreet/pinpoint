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
		Repo:          "owner/repo",
		SHA:           "abc123",
		WorkflowRef:   "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:  ".pinpoint-manifest.json",
		APIURL:        restServer.URL,
		GraphQLURL:    "http://unused",
		FailOnMissing: true,
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
		Repo:          "owner/repo",
		SHA:           "abc123",
		WorkflowRef:   "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:  ".pinpoint-manifest.json",
		APIURL:        restServer.URL,
		GraphQLURL:    graphqlServer.URL,
		FailOnMissing: true,
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
