// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockGraphQLHandler builds an httptest handler that responds with repo data.
func mockGraphQLHandler(repoData map[string]repoVerifyPayload) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the query to extract aliases
		var req graphqlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}

		data := make(map[string]json.RawMessage)
		for alias, payload := range repoData {
			raw, _ := json.Marshal(payload)
			data[alias] = raw
		}

		resp := graphqlResponse{Data: data}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// mockAdvisoryHandler returns an httptest handler that responds with advisories.
func mockAdvisoryHandler(advisories []advisory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/advisories") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(advisories)
			return
		}
		http.NotFound(w, r)
	}
}

// helper to create bool pointer
func boolPtr(b bool) *bool { return &b }

// makeRelease builds a releaseNode with common defaults.
func makeRelease(tagName, sha string, signed bool, authoredDate, parentDate string) releaseNode {
	r := releaseNode{
		TagName:   tagName,
		CreatedAt: "2025-11-20T10:00:00Z",
	}
	r.TagCommit.OID = sha
	if signed {
		r.TagCommit.Signature = &struct {
			IsValid bool `json:"isValid"`
			Signer  *struct {
				Login string `json:"login"`
			} `json:"signer"`
		}{
			IsValid: true,
			Signer: &struct {
				Login string `json:"login"`
			}{Login: "web-flow"},
		}
	}
	r.TagCommit.AuthoredDate = authoredDate
	r.TagCommit.CommittedDate = authoredDate
	if parentDate != "" {
		r.TagCommit.Parents.Nodes = []struct {
			OID           string `json:"oid"`
			CommittedDate string `json:"committedDate"`
		}{
			{OID: "parentabc1234567890123456789012345678901", CommittedDate: parentDate},
		}
	}
	return r
}

// makeRef builds a refNode for a lightweight tag.
func makeRef(name, sha string) refNode {
	return refNode{
		Name: name,
		Target: struct {
			TypeName string `json:"__typename"`
			OID      string `json:"oid"`
			Target   *struct {
				OID string `json:"oid"`
			} `json:"target,omitempty"`
		}{
			TypeName: "Commit",
			OID:      sha,
		},
	}
}

func TestVerify_AllClean(t *testing.T) {
	sha1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sha2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sha3 := "cccccccccccccccccccccccccccccccccccccccc"

	graphqlData := map[string]repoVerifyPayload{
		"actions_checkout": {
			Releases: releasesPayload{Nodes: []releaseNode{
				makeRelease("v4.2.2", sha1, true, "2025-11-20T10:00:00Z", "2025-11-19T10:00:00Z"),
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v4.2.2", sha1),
			}},
		},
		"actions_setup_go": {
			Releases: releasesPayload{Nodes: []releaseNode{
				makeRelease("v5.0.0", sha2, true, "2025-10-15T10:00:00Z", "2025-10-14T10:00:00Z"),
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v5.0.0", sha2),
			}},
		},
		"docker_build_push_action": {
			Releases: releasesPayload{Nodes: []releaseNode{
				makeRelease("v6.0.0", sha3, true, "2025-09-01T10:00:00Z", "2025-08-31T10:00:00Z"),
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v6.0.0", sha3),
			}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	actions := []ActionInput{
		{Repo: "actions/checkout", Tag: "v4.2.2"},
		{Repo: "actions/setup-go", Tag: "v5.0.0"},
		{Repo: "docker/build-push-action", Tag: "v6.0.0"},
	}

	result, err := Verify(context.Background(), actions, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.Clean != 3 {
		t.Errorf("expected 3 clean, got %d", result.Clean)
	}
	if result.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", result.Failed)
	}
	for _, av := range result.Actions {
		if av.Status != StatusClean {
			t.Errorf("%s: expected clean, got %s", av.Repo, av.Status)
		}
		if av.ReleaseSHAMatch == nil || !*av.ReleaseSHAMatch {
			t.Errorf("%s: expected release SHA match", av.Repo)
		}
	}
}

func TestVerify_ReleaseMismatch(t *testing.T) {
	releaseSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	currentSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	graphqlData := map[string]repoVerifyPayload{
		"evil_action": {
			Releases: releasesPayload{Nodes: []releaseNode{
				makeRelease("v1.0.0", releaseSHA, true, "2025-11-20T10:00:00Z", "2025-11-19T10:00:00Z"),
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v1.0.0", currentSHA),
			}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "evil/action", Tag: "v1.0.0"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", result.Failed)
	}
	av := result.Actions[0]
	if av.Status != StatusFailed {
		t.Errorf("expected failed, got %s", av.Status)
	}
	if av.ReleaseSHAMatch == nil || *av.ReleaseSHAMatch {
		t.Error("expected release SHA mismatch")
	}
	assertHasNote(t, av.Notes, "RELEASE_MISMATCH")
}

func TestVerify_GPGDiscontinuity(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Current release is unsigned, but another release is signed
	unsignedRelease := makeRelease("v2.0.0", sha, false, "2025-11-20T10:00:00Z", "2025-11-19T10:00:00Z")
	signedRelease := makeRelease("v1.0.0", "cccccccccccccccccccccccccccccccccccccccc", true, "2025-10-01T10:00:00Z", "2025-09-30T10:00:00Z")

	graphqlData := map[string]repoVerifyPayload{
		"some_org_action": {
			Releases: releasesPayload{Nodes: []releaseNode{
				unsignedRelease,
				signedRelease,
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v2.0.0", sha),
			}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "some-org/action", Tag: "v2.0.0"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusFailed {
		t.Errorf("expected failed, got %s", av.Status)
	}
	if !av.GPGDiscontinuity {
		t.Error("expected GPG discontinuity to be flagged")
	}
	assertHasNote(t, av.Notes, "GPG_DISCONTINUITY")
}

func TestVerify_ImpossibleChronology(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Authored date is July 2024, but parent committed March 2026 — backdated
	release := makeRelease("v0.20.0", sha, true,
		"2024-07-09T10:00:00Z", // authored
		"2026-03-19T10:00:00Z", // parent committed
	)

	graphqlData := map[string]repoVerifyPayload{
		"aquasecurity_trivy_action": {
			Releases: releasesPayload{Nodes: []releaseNode{release}},
			Refs:     refsPayload{Nodes: []refNode{makeRef("v0.20.0", sha)}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "aquasecurity/trivy-action", Tag: "v0.20.0"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusFailed {
		t.Errorf("expected failed, got %s", av.Status)
	}
	if av.ChronologyValid == nil || *av.ChronologyValid {
		t.Error("expected chronology to be invalid")
	}
	assertHasNote(t, av.Notes, "IMPOSSIBLE_CHRONOLOGY")
}

func TestVerify_NoReleases(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	graphqlData := map[string]repoVerifyPayload{
		"some_org_custom_action": {
			Releases: releasesPayload{Nodes: nil},
			Refs:     refsPayload{Nodes: []refNode{makeRef("v2", sha)}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "some-org/custom-action", Tag: "v2"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusLimited {
		t.Errorf("expected limited, got %s", av.Status)
	}
	if result.Limited != 1 {
		t.Errorf("expected 1 limited, got %d", result.Limited)
	}
}

func TestVerify_MajorTagResolution(t *testing.T) {
	// v4 and v4.2.2 point to the same SHA
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	graphqlData := map[string]repoVerifyPayload{
		"actions_checkout": {
			Releases: releasesPayload{Nodes: []releaseNode{
				// No release for "v4", but v4.2.2 release has the same SHA
				makeRelease("v4.2.2", sha, true, "2025-11-20T10:00:00Z", "2025-11-19T10:00:00Z"),
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v4", sha),
				makeRef("v4.2.2", sha),
			}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "actions/checkout", Tag: "v4"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusClean {
		t.Errorf("expected clean, got %s (notes: %v)", av.Status, av.Notes)
	}
	if av.ReleaseSHAMatch == nil || !*av.ReleaseSHAMatch {
		t.Error("expected release SHA match via smart resolution")
	}
	if av.ReleaseTag != "v4.2.2" {
		t.Errorf("expected release tag v4.2.2, got %s", av.ReleaseTag)
	}
}

func TestVerify_KnownBadSHA(t *testing.T) {
	// SHA starting with known-bad prefix "0e58ed8"
	sha := "0e58ed8671d6b60e0d8e05b5d65bcbc18b67e161"

	graphqlData := map[string]repoVerifyPayload{
		"tj_actions_changed_files": {
			Releases: releasesPayload{Nodes: []releaseNode{
				makeRelease("v35", sha, false, "2025-03-14T10:00:00Z", "2025-03-13T10:00:00Z"),
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v35", sha),
			}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "tj-actions/changed-files", Tag: "v35"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusFailed {
		t.Errorf("expected failed, got %s", av.Status)
	}
	assertHasNote(t, av.Notes, "KNOWN_BAD_SHA")
}

func TestVerify_AdvisoryMatch(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	graphqlData := map[string]repoVerifyPayload{
		"tj_actions_changed_files": {
			Releases: releasesPayload{Nodes: []releaseNode{
				makeRelease("v40.0.0", sha, true, "2025-11-20T10:00:00Z", "2025-11-19T10:00:00Z"),
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v40.0.0", sha),
			}},
		},
	}

	advisories := []advisory{
		{
			GHSAID: "GHSA-test-1234",
			CVEID:  "CVE-2025-30066",
			Vulnerabilities: []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			}{
				{Package: struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				}{Ecosystem: "actions", Name: "tj-actions/changed-files"}},
			},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(advisories))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "tj-actions/changed-files", Tag: "v40.0.0"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusFailed {
		t.Errorf("expected failed, got %s", av.Status)
	}
	if len(av.Advisories) == 0 {
		t.Error("expected advisories to be populated")
	}
	assertHasNote(t, av.Notes, "ADVISORY")
}

func TestVerify_ChronologyTolerance(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Authored date is 24 hours before parent committed date — within 48h tolerance
	parentTime := time.Date(2025, 11, 20, 10, 0, 0, 0, time.UTC)
	authorTime := parentTime.Add(-24 * time.Hour)

	release := makeRelease("v1.0.0", sha, true,
		authorTime.Format(time.RFC3339),
		parentTime.Format(time.RFC3339),
	)

	graphqlData := map[string]repoVerifyPayload{
		"some_org_action": {
			Releases: releasesPayload{Nodes: []releaseNode{release}},
			Refs:     refsPayload{Nodes: []refNode{makeRef("v1.0.0", sha)}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "some-org/action", Tag: "v1.0.0"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusClean {
		t.Errorf("expected clean (within tolerance), got %s (notes: %v)", av.Status, av.Notes)
	}
	if av.ChronologyValid == nil || !*av.ChronologyValid {
		t.Error("expected chronology to be valid (within 48h tolerance)")
	}
}

func TestVerify_CombinedSignals(t *testing.T) {
	releaseSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	currentSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// Release mismatch + unsigned (with prior signed) + impossible chronology
	unsignedRelease := releaseNode{
		TagName:   "v3.0.0",
		CreatedAt: "2025-11-20T10:00:00Z",
	}
	unsignedRelease.TagCommit.OID = releaseSHA
	unsignedRelease.TagCommit.AuthoredDate = "2024-01-01T10:00:00Z"
	unsignedRelease.TagCommit.CommittedDate = "2024-01-01T10:00:00Z"
	unsignedRelease.TagCommit.Parents.Nodes = []struct {
		OID           string `json:"oid"`
		CommittedDate string `json:"committedDate"`
	}{
		{OID: "parent123", CommittedDate: "2026-03-01T10:00:00Z"},
	}

	signedPrior := makeRelease("v2.0.0", "cccccccccccccccccccccccccccccccccccccccc", true,
		"2025-06-01T10:00:00Z", "2025-05-31T10:00:00Z")

	graphqlData := map[string]repoVerifyPayload{
		"evil_org_bad_action": {
			Releases: releasesPayload{Nodes: []releaseNode{
				unsignedRelease,
				signedPrior,
			}},
			Refs: refsPayload{Nodes: []refNode{
				makeRef("v3.0.0", currentSHA), // Different from release SHA
			}},
		},
	}

	graphqlServer := httptest.NewServer(mockGraphQLHandler(graphqlData))
	defer graphqlServer.Close()

	restServer := httptest.NewServer(mockAdvisoryHandler(nil))
	defer restServer.Close()

	result, err := Verify(context.Background(), []ActionInput{
		{Repo: "evil-org/bad-action", Tag: "v3.0.0"},
	}, VerifyOptions{
		GraphQLEndpoint: graphqlServer.URL,
		RESTEndpoint:    restServer.URL,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	av := result.Actions[0]
	if av.Status != StatusFailed {
		t.Errorf("expected failed, got %s", av.Status)
	}

	// All three signals should fire
	assertHasNote(t, av.Notes, "RELEASE_MISMATCH")
	assertHasNote(t, av.Notes, "GPG_DISCONTINUITY")
	assertHasNote(t, av.Notes, "IMPOSSIBLE_CHRONOLOGY")
	assertHasNote(t, av.Notes, "MULTIPLE INTEGRITY SIGNALS FAILED")

	// Count failed signals
	failCount := 0
	for _, n := range av.Notes {
		if strings.HasPrefix(n, "RELEASE_MISMATCH") || strings.HasPrefix(n, "GPG_DISCONTINUITY") || strings.HasPrefix(n, "IMPOSSIBLE_CHRONOLOGY") {
			failCount++
		}
	}
	if failCount != 3 {
		t.Errorf("expected 3 failed signals, got %d (notes: %v)", failCount, av.Notes)
	}
}

func assertHasNote(t *testing.T, notes []string, prefix string) {
	t.Helper()
	for _, n := range notes {
		if strings.HasPrefix(n, prefix) || strings.Contains(n, prefix) {
			return
		}
	}
	t.Errorf("expected note with prefix %q, got notes: %v", prefix, notes)
}

// Verify FormatText doesn't panic and produces expected output.
func TestVerify_FormatText(t *testing.T) {
	result := &VerifyResult{
		Clean:   1,
		Limited: 1,
		Failed:  0,
		Actions: []ActionVerification{
			{Repo: "actions/checkout", Tag: "v4", Status: StatusClean, CurrentSHA: "abc1234"},
			{Repo: "some/action", Tag: "v1", Status: StatusLimited, Notes: []string{"no release found"}},
		},
	}
	text := FormatText(result)
	if !strings.Contains(text, "actions/checkout@v4") {
		t.Error("expected actions/checkout in output")
	}
	if !strings.Contains(text, "1 clean") {
		t.Error(fmt.Sprintf("expected '1 clean' in output, got: %s", text))
	}
}
