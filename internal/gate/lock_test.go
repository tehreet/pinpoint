// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package gate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testLockfile is the same as testManifest but for lockfile tests.
const testLockfile = `{
  "version": 1,
  "generated_at": "2026-03-21T08:00:00Z",
  "generated_by": "pinpoint lock",
  "actions": {
    "actions/checkout": {
      "v4": {"sha": "abc1234567890abc1234567890abc1234567890a", "recorded_at": "2026-03-21T08:00:00Z"}
    },
    "actions/setup-go": {
      "v5": {"sha": "def4567890abc1234567890abc1234567890abcd", "recorded_at": "2026-03-21T08:00:00Z"}
    }
  }
}`

func TestGate_LockfileEnforcesByDefault(t *testing.T) {
	buf := silenceOutput(t)

	// Workflow references docker/build-push-action which is NOT in the lockfile
	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(testWorkflow))
		case strings.Contains(r.URL.Path, "actions-lock.json"):
			fmt.Fprint(w, buildContentResponse(testLockfile))
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

	// FailOnMissing NOT explicitly set, but using new lockfile path → enforced by default
	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".github/actions-lock.json",
		APIURL:                restServer.URL,
		GraphQLURL:            graphqlServer.URL,
		FailOnMissing:         false,
		FailOnMissingExplicit: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// docker/build-push-action@v5 is not in the lockfile → should be a violation
	if len(result.Violations) == 0 {
		t.Errorf("expected violations for actions not in lockfile, got 0\noutput: %s", buf.String())
	}
	// Verify that the missing action is the violation
	foundMissing := false
	for _, v := range result.Violations {
		if v.Action == "docker/build-push-action" {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Errorf("expected violation for docker/build-push-action, got: %+v", result.Violations)
	}
}

func TestGate_LegacyManifestWarnsOnly(t *testing.T) {
	buf := silenceOutput(t)

	// Sparse manifest that only has checkout — setup-go and docker/build-push-action missing
	legacyManifest := `{
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
		case strings.Contains(r.URL.Path, "actions-lock.json"):
			// 404 for new lockfile path
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(legacyManifest))
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

	// Using default lockfile path (will 404 and fall back to legacy)
	// FailOnMissing NOT explicitly set
	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".github/actions-lock.json",
		APIURL:                restServer.URL,
		GraphQLURL:            graphqlServer.URL,
		FailOnMissing:         false,
		FailOnMissingExplicit: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Legacy path: FailOnMissing defaults to false → warnings, not violations
	if len(result.Violations) != 0 {
		t.Errorf("legacy mode: violations = %d, want 0 (should warn only)\noutput: %s", len(result.Violations), buf.String())
	}
	// Should have warnings for the 2 missing actions
	if len(result.Warnings) < 2 {
		t.Errorf("legacy mode: warnings = %d, want >= 2", len(result.Warnings))
	}
	// Should print legacy path notice
	if !strings.Contains(buf.String(), "legacy manifest path") {
		t.Errorf("expected legacy path notice in output, got: %s", buf.String())
	}
}

func TestGate_FallbackToLegacy(t *testing.T) {
	buf := silenceOutput(t)

	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "workflows/ci.yml"):
			fmt.Fprint(w, buildContentResponse(testWorkflow))
		case strings.Contains(r.URL.Path, "actions-lock.json"):
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "pinpoint-manifest.json"):
			fmt.Fprint(w, buildContentResponse(testManifest))
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

	result, err := RunGate(context.Background(), GateOptions{
		Repo:                  "owner/repo",
		SHA:                   "abc123",
		WorkflowRef:           "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath:          ".github/actions-lock.json",
		APIURL:                restServer.URL,
		GraphQLURL:            graphqlServer.URL,
		FailOnMissing:         false,
		FailOnMissingExplicit: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All three actions are in testManifest and SHAs match → no violations
	if len(result.Violations) != 0 {
		t.Errorf("fallback: violations = %d, want 0", len(result.Violations))
	}
	if result.Verified != 3 {
		t.Errorf("fallback: verified = %d, want 3", result.Verified)
	}
	// Should contain legacy fallback notice
	if !strings.Contains(buf.String(), "legacy manifest path") {
		t.Errorf("expected legacy path notice, got: %s", buf.String())
	}
}

func TestGate_ExplicitFailOnMissingOverrides(t *testing.T) {
	silenceOutput(t)

	// Sparse legacy manifest — only has checkout
	legacyManifest := `{
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
			fmt.Fprint(w, buildContentResponse(legacyManifest))
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

	// Using legacy path directly, but with FailOnMissing explicitly set to true
	result, err := RunGate(context.Background(), GateOptions{
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
	// Explicit --fail-on-missing should override legacy default → violations
	if len(result.Violations) != 2 {
		t.Errorf("explicit fail-on-missing: violations = %d, want 2", len(result.Violations))
	}
}
