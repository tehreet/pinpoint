// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tehreet/pinpoint/internal/poller"
)

func TestClassifyRef(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"v4", "tag"},
		{"v1.2.3", "tag"},
		{"40f1582b2485089dde7abd97c1529aa768e1baff", "sha"},
		{"main", "branch"},
		{"master", "branch"},
		{"develop", "branch"},
		{"1.0", "tag"},
	}

	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			got := classifyRef(tc.ref)
			if got != tc.want {
				t.Errorf("classifyRef(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

func TestExtractRefs(t *testing.T) {
	content := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5
      - uses: docker/build-push-action@v5
      - uses: ./.github/actions/local-action
      - uses: some-org/some-action@main
`

	refs := extractRefs(content)

	if len(refs) != 4 {
		t.Fatalf("expected 4 refs, got %d", len(refs))
	}

	// actions/checkout@v4 → tag
	if refs[0].Owner != "actions" || refs[0].Repo != "checkout" || refs[0].Ref != "v4" || refs[0].Type != "tag" {
		t.Errorf("ref[0] = %+v, want actions/checkout@v4 tag", refs[0])
	}

	// actions/setup-go@SHA → sha
	if refs[1].Type != "sha" {
		t.Errorf("ref[1].Type = %q, want sha", refs[1].Type)
	}

	// docker/build-push-action@v5 → tag
	if refs[2].Type != "tag" {
		t.Errorf("ref[2].Type = %q, want tag", refs[2].Type)
	}

	// some-org/some-action@main → branch
	if refs[3].Type != "branch" {
		t.Errorf("ref[3].Type = %q, want branch", refs[3].Type)
	}
}

func TestExtractRefsSkipsLocalActions(t *testing.T) {
	content := `steps:
  - uses: ./.github/actions/local-action
  - uses: actions/checkout@v4
`
	refs := extractRefs(content)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref (local action skipped), got %d", len(refs))
	}
	if refs[0].Repo != "checkout" {
		t.Errorf("expected checkout, got %s", refs[0].Repo)
	}
}

func TestExtractRefsSkipsComments(t *testing.T) {
	content := `steps:
  # - uses: actions/checkout@v3
  - uses: actions/checkout@v4
`
	refs := extractRefs(content)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Ref != "v4" {
		t.Errorf("expected v4, got %s", refs[0].Ref)
	}
}

func TestScoreAction(t *testing.T) {
	falseVal := false
	trueVal := true

	tests := []struct {
		name string
		action ActionSummary
		want   string
	}{
		{
			name: "low risk - sha pinned, immutable",
			action: ActionSummary{
				Repo:             "actions/checkout",
				UsedInRepos:      5,
				ImmutableRelease: &trueVal,
				Refs:             []RefSummary{{Ref: "abc123", Type: "sha", Count: 10}},
			},
			want: "low",
		},
		{
			name: "high risk - known compromised",
			action: ActionSummary{
				Repo:        "tj-actions/changed-files",
				UsedInRepos: 5,
				Refs:        []RefSummary{{Ref: "v1", Type: "tag", Count: 10}},
			},
			want: "high",
		},
		{
			name: "critical - branch pinned + known compromised",
			action: ActionSummary{
				Repo:        "tj-actions/changed-files",
				UsedInRepos: 5,
				Refs:        []RefSummary{{Ref: "main", Type: "branch", Count: 10}},
			},
			want: "critical",
		},
		{
			name: "medium - no immutable, low usage",
			action: ActionSummary{
				Repo:             "some/action",
				UsedInRepos:      5,
				ImmutableRelease: &falseVal,
				Refs:             []RefSummary{{Ref: "v1", Type: "tag", Count: 10}},
			},
			want: "medium",
		},
		{
			name: "critical - high usage, unpinned, no immutable",
			action: ActionSummary{
				Repo:             "popular/action",
				UsedInRepos:      50,
				ImmutableRelease: &falseVal,
				Refs:             []RefSummary{{Ref: "v1", Type: "tag", Count: 100}},
			},
			want: "critical",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scoreAction(tc.action)
			if got != tc.want {
				t.Errorf("scoreAction(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestFormatReport(t *testing.T) {
	falseVal := false
	trueVal := true

	result := &AuditResult{
		Org:                "test-org",
		ScannedAt:          time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC),
		TotalRepos:         100,
		ActiveRepos:        80,
		ArchivedSkipped:    15,
		ForkedSkipped:      5,
		ReposWithWorkflows: 60,
		TotalWorkflowFiles: 150,
		TotalRefs:          500,
		SHAPinned:          50,
		TagPinned:          400,
		BranchPinned:       50,
		UniqueActions: []ActionSummary{
			{
				Repo:             "actions/checkout",
				UsedInRepos:      60,
				ImmutableRelease: &falseVal,
				Refs: []RefSummary{
					{Ref: "v4", Type: "tag", Count: 55},
					{Ref: "abc123", Type: "sha", Count: 5},
				},
				Risk: "medium",
			},
			{
				Repo:             "tj-actions/changed-files",
				UsedInRepos:      20,
				ImmutableRelease: &falseVal,
				Refs:             []RefSummary{{Ref: "v1", Type: "tag", Count: 20}},
				Risk:             "critical",
				Notes:            []string{"Compromised March 2025 (CVE-2025-30066)"},
			},
			{
				Repo:             "some/action",
				UsedInRepos:      15,
				ImmutableRelease: &trueVal,
				Refs:             []RefSummary{{Ref: "main", Type: "branch", Count: 15}},
				Risk:             "critical",
			},
		},
		OrgPolicy: &poller.OrgPolicy{
			SHAPinningRequired: false,
			AllowedActions:     "selected",
		},
	}

	report := FormatReport(result)

	// Check that all required sections are present
	checks := []string{
		"PINPOINT AUDIT: test-org",
		"Repos scanned:",
		"Repos with workflows:",
		"PINNING STATUS",
		"SHA-pinned:",
		"Tag-pinned:",
		"Branch-pinned:",
		"UNIQUE UPSTREAM ACTIONS:",
		"TOP 20 MOST USED ACTIONS",
		"actions/checkout",
		"HIGH RISK ACTIONS",
		"tj-actions/changed-files",
		"BRANCH-PINNED ACTIONS",
		"some/action@main",
		"RECOMMENDATIONS",
		"SHA pinning enforced: No",
	}

	for _, check := range checks {
		if !strings.Contains(report, check) {
			t.Errorf("report missing expected content: %q", check)
		}
	}
}

func TestFormatConfig(t *testing.T) {
	falseVal := false

	result := &AuditResult{
		Org:       "test-org",
		ScannedAt: time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC),
		UniqueActions: []ActionSummary{
			{
				Repo:             "actions/checkout",
				UsedInRepos:      60,
				ImmutableRelease: &falseVal,
				Refs:             []RefSummary{{Ref: "v4", Type: "tag", Count: 55}},
				Risk:             "low",
			},
			{
				Repo:        "tj-actions/changed-files",
				UsedInRepos: 20,
				Refs:        []RefSummary{{Ref: "v1", Type: "tag", Count: 20}},
				Risk:        "critical",
				Notes:       []string{"Compromised March 2025"},
			},
		},
	}

	config := FormatConfig(result)

	if !strings.Contains(config, "# Generated by: pinpoint audit --org test-org") {
		t.Error("config missing header")
	}
	if !strings.Contains(config, "actions:") {
		t.Error("config missing actions key")
	}
	if !strings.Contains(config, "repo: tj-actions/changed-files") {
		t.Error("config missing high-risk action")
	}
	if !strings.Contains(config, "repo: actions/checkout") {
		t.Error("config missing standard action")
	}
	if !strings.Contains(config, "HIGH RISK") {
		t.Error("config missing HIGH RISK section")
	}
	if !strings.Contains(config, "WARNING: Compromised March 2025") {
		t.Error("config missing warning note")
	}
}

func TestFormatJSON(t *testing.T) {
	result := &AuditResult{
		Org:                "test-org",
		ScannedAt:          time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC),
		TotalRepos:         100,
		ReposWithWorkflows: 60,
		ArchivedSkipped:    15,
		ForkedSkipped:      5,
		TotalRefs:          500,
		SHAPinned:          50,
		TagPinned:          400,
		BranchPinned:       50,
		UniqueActions: []ActionSummary{
			{
				Repo:        "actions/checkout",
				UsedInRepos: 60,
				Refs:        []RefSummary{{Ref: "v4", Type: "tag", Count: 55}},
				Risk:        "medium",
			},
		},
		OrgPolicy: &poller.OrgPolicy{SHAPinningRequired: false},
	}

	jsonStr, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed["org"] != "test-org" {
		t.Errorf("org = %v, want test-org", parsed["org"])
	}

	repos := parsed["repos"].(map[string]interface{})
	if repos["total"].(float64) != 100 {
		t.Errorf("repos.total = %v, want 100", repos["total"])
	}

	refs := parsed["references"].(map[string]interface{})
	if refs["sha_pinned"].(float64) != 50 {
		t.Errorf("references.sha_pinned = %v, want 50", refs["sha_pinned"])
	}

	actions := parsed["unique_actions"].([]interface{})
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
}

func TestRunAuditEndToEnd(t *testing.T) {
	// Mock GraphQL server for org repos
	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"rateLimit": map[string]interface{}{
					"cost":      1,
					"remaining": 4999,
				},
				"organization": map[string]interface{}{
					"repositories": map[string]interface{}{
						"totalCount": 3,
						"pageInfo": map[string]interface{}{
							"hasNextPage": false,
							"endCursor":   "abc",
						},
						"nodes": []map[string]interface{}{
							{
								"name":       "active-repo",
								"isArchived": false,
								"isFork":     false,
								"defaultBranchRef": map[string]interface{}{
									"name": "main",
								},
								"workflows": map[string]interface{}{
									"entries": []map[string]interface{}{
										{
											"name": "ci.yml",
											"object": map[string]interface{}{
												"byteSize": 100,
												"text":     "steps:\n  - uses: actions/checkout@v4\n  - uses: some-org/some-action@main\n",
											},
										},
									},
								},
							},
							{
								"name":             "archived-repo",
								"isArchived":       true,
								"isFork":           false,
								"defaultBranchRef": nil,
								"workflows":        nil,
							},
							{
								"name":       "forked-repo",
								"isArchived": false,
								"isFork":     true,
								"defaultBranchRef": map[string]interface{}{
									"name": "main",
								},
								"workflows": nil,
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer graphqlServer.Close()

	// Mock REST server for immutable release + org policy
	restServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/releases"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"immutable": false},
			})
		case strings.Contains(r.URL.Path, "/actions/permissions"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sha_pinning_required": true,
				"allowed_actions":      "selected",
			})
		default:
			w.WriteHeader(404)
		}
	}))
	defer restServer.Close()

	graphqlClient := poller.NewGraphQLClient("")
	graphqlClient.SetEndpoint(graphqlServer.URL)
	restClient := poller.NewGitHubClient("")
	restClient.SetBaseURL(restServer.URL)

	result, err := RunAudit(context.Background(), Options{
		Org:    "test-org",
		Output: "report",
	}, graphqlClient, restClient)
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}

	if result.TotalRepos != 3 {
		t.Errorf("TotalRepos = %d, want 3", result.TotalRepos)
	}
	if result.ArchivedSkipped != 1 {
		t.Errorf("ArchivedSkipped = %d, want 1", result.ArchivedSkipped)
	}
	if result.ForkedSkipped != 1 {
		t.Errorf("ForkedSkipped = %d, want 1", result.ForkedSkipped)
	}
	if result.ReposWithWorkflows != 1 {
		t.Errorf("ReposWithWorkflows = %d, want 1", result.ReposWithWorkflows)
	}
	if result.TotalRefs != 2 {
		t.Errorf("TotalRefs = %d, want 2", result.TotalRefs)
	}
	if result.TagPinned != 1 {
		t.Errorf("TagPinned = %d, want 1", result.TagPinned)
	}
	if result.BranchPinned != 1 {
		t.Errorf("BranchPinned = %d, want 1", result.BranchPinned)
	}
	if len(result.UniqueActions) != 2 {
		t.Errorf("UniqueActions = %d, want 2", len(result.UniqueActions))
	}
	if result.OrgPolicy == nil {
		t.Fatal("OrgPolicy is nil, expected non-nil")
	}
	if !result.OrgPolicy.SHAPinningRequired {
		t.Error("SHAPinningRequired = false, want true")
	}

	// Verify report output works
	report := FormatReport(result)
	if !strings.Contains(report, "PINPOINT AUDIT: test-org") {
		t.Error("report missing header")
	}

	// Verify JSON output works
	jsonStr, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Verify config output works
	config := FormatConfig(result)
	if !strings.Contains(config, "actions:") {
		t.Error("config output missing actions key")
	}
}

func TestFmtInt(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{2047, "2,047"},
		{12847, "12,847"},
	}
	for _, tc := range tests {
		got := fmtInt(tc.n)
		if got != tc.want {
			t.Errorf("fmtInt(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestFormatManifest(t *testing.T) {
	trueVal := true

	result := &AuditResult{
		Org:       "test-org",
		ScannedAt: time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC),
		UniqueActions: []ActionSummary{
			{
				Repo:             "actions/checkout",
				UsedInRepos:      10,
				ImmutableRelease: &trueVal,
				Refs:             []RefSummary{{Ref: "v4", Type: "tag", Count: 10}},
			},
		},
	}

	tagResults := map[string]*poller.FetchResult{
		"actions/checkout": {
			Tags: []poller.ResolvedTag{
				{Name: "v4", CommitSHA: "abc123def456"},
				{Name: "v3", CommitSHA: "old789"},
			},
		},
	}

	manifestStr, err := FormatManifest(result, tagResults)
	if err != nil {
		t.Fatalf("FormatManifest: %v", err)
	}

	var manifest struct {
		Version int                                      `json:"version"`
		Actions map[string]map[string]struct{ SHA string } `json:"actions"`
	}
	if err := json.Unmarshal([]byte(manifestStr), &manifest); err != nil {
		t.Fatalf("invalid manifest JSON: %v", err)
	}

	if manifest.Version != 1 {
		t.Errorf("version = %d, want 1", manifest.Version)
	}

	checkout, ok := manifest.Actions["actions/checkout"]
	if !ok {
		t.Fatal("manifest missing actions/checkout")
	}
	v4, ok := checkout["v4"]
	if !ok {
		t.Fatal("manifest missing v4 tag")
	}
	if v4.SHA != "abc123def456" {
		t.Errorf("v4 SHA = %q, want abc123def456", v4.SHA)
	}
	// v3 should NOT be in manifest (not used in org workflows)
	if _, ok := checkout["v3"]; ok {
		t.Error("manifest should not include v3 (not used in org)")
	}
}

// Ensure fmtInt handles larger numbers
func TestFmtIntLarge(t *testing.T) {
	_ = fmt.Sprintf("test") // avoid unused import
	got := fmtInt(999999)
	// This is a simple implementation; just verify it doesn't panic
	if got == "" {
		t.Error("fmtInt returned empty string")
	}
}
