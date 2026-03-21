// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package sarif

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/tehreet/pinpoint/internal/audit"
	"github.com/tehreet/pinpoint/internal/risk"
)

func TestFormatScanSARIF(t *testing.T) {
	alerts := []risk.Alert{
		{
			Severity:    risk.SeverityCritical,
			Type:        "TAG_REPOINTED",
			Action:      "aquasecurity/trivy-action",
			Tag:         "0.35.0",
			PreviousSHA: "abc123abc123abc123abc123abc123abc123abc1",
			CurrentSHA:  "def456def456def456def456def456def456def4",
			DetectedAt:  time.Now(),
			Signals:     []string{"MASS_REPOINT", "SEMVER_REPOINT"},
		},
		{
			Severity:    risk.SeverityMedium,
			Type:        "TAG_REPOINTED",
			Action:      "actions/setup-go",
			Tag:         "v5",
			PreviousSHA: "aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
			CurrentSHA:  "bbb222bbb222bbb222bbb222bbb222bbb222bbb2",
			DetectedAt:  time.Now(),
			Signals:     []string{"MAJOR_TAG_ADVANCE"},
		},
	}

	output, err := FormatScanSARIF(alerts, "0.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var log Log
	if err := json.Unmarshal([]byte(output), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(log.Runs[0].Results))
	}

	// Check first result
	r := log.Runs[0].Results[0]
	if r.RuleID != "pinpoint/tag-repointed" {
		t.Errorf("expected rule pinpoint/tag-repointed, got %s", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("expected level error for CRITICAL, got %s", r.Level)
	}
	if r.Properties == nil || r.Properties.Severity != "CRITICAL" {
		t.Error("expected CRITICAL severity in properties")
	}
	if len(r.Properties.Signals) != 2 {
		t.Errorf("expected 2 signals, got %d", len(r.Properties.Signals))
	}

	// Check second result
	r2 := log.Runs[0].Results[1]
	if r2.Level != "warning" {
		t.Errorf("expected level warning for MEDIUM, got %s", r2.Level)
	}

	// Check driver version
	if log.Runs[0].Tool.Driver.Version != "0.3.0" {
		t.Errorf("expected driver version 0.3.0, got %s", log.Runs[0].Tool.Driver.Version)
	}
}

func TestFormatAuditSARIF(t *testing.T) {
	boolFalse := false
	result := &audit.AuditResult{
		Org: "testorg",
		UniqueActions: []audit.ActionSummary{
			{
				Repo:             "actions/checkout",
				UsedInRepos:      50,
				ImmutableRelease: &boolFalse,
				Risk:             "medium",
				Refs: []audit.RefSummary{
					{Ref: "v4", Type: "tag", Count: 45},
					{Ref: "main", Type: "branch", Count: 5},
				},
			},
		},
		UnprotectedWorkflows: []string{"my-repo/.github/workflows/ci.yml"},
	}

	output, err := FormatAuditSARIF(result, "0.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var log Log
	if err := json.Unmarshal([]byte(output), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	results := log.Runs[0].Results
	// Expect: 1 tag-unpinned + 1 branch-pinned + 1 no-immutable-release + 1 no-gate = 4
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// Verify rule IDs present
	ruleIDs := make(map[string]int)
	for _, r := range results {
		ruleIDs[r.RuleID]++
	}

	if ruleIDs["pinpoint/tag-unpinned"] != 1 {
		t.Error("expected 1 tag-unpinned result")
	}
	if ruleIDs["pinpoint/branch-pinned"] != 1 {
		t.Error("expected 1 branch-pinned result")
	}
	if ruleIDs["pinpoint/no-immutable-release"] != 1 {
		t.Error("expected 1 no-immutable-release result")
	}
	if ruleIDs["pinpoint/no-gate"] != 1 {
		t.Error("expected 1 no-gate result")
	}

	// Check no-gate has a location
	for _, r := range results {
		if r.RuleID == "pinpoint/no-gate" {
			if len(r.Locations) == 0 {
				t.Error("no-gate result should have a location")
			} else if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != ".github/workflows/ci.yml" {
				t.Errorf("unexpected URI: %s", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
			}
		}
	}
}

func TestSARIFSchema(t *testing.T) {
	alerts := []risk.Alert{
		{
			Severity:    risk.SeverityLow,
			Type:        "TAG_REPOINTED",
			Action:      "actions/checkout",
			Tag:         "v4",
			PreviousSHA: "aaa",
			CurrentSHA:  "bbb",
			DetectedAt:  time.Now(),
			Signals:     []string{"MAJOR_TAG_ADVANCE"},
		},
	}

	output, err := FormatScanSARIF(alerts, "0.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var log Log
	if err := json.Unmarshal([]byte(output), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Required SARIF 2.1.0 fields
	if log.Schema != sarifSchema {
		t.Errorf("expected schema %s, got %s", sarifSchema, log.Schema)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "pinpoint" {
		t.Errorf("expected driver name pinpoint, got %s", log.Runs[0].Tool.Driver.Name)
	}
	if log.Runs[0].Tool.Driver.InformationURI != informationURI {
		t.Errorf("expected informationUri %s, got %s", informationURI, log.Runs[0].Tool.Driver.InformationURI)
	}

	// Verify all 5 rules are present
	if len(log.Runs[0].Tool.Driver.Rules) != 5 {
		t.Errorf("expected 5 rules, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}

	expectedRules := map[string]bool{
		"pinpoint/tag-repointed":       false,
		"pinpoint/tag-unpinned":        false,
		"pinpoint/branch-pinned":       false,
		"pinpoint/no-immutable-release": false,
		"pinpoint/no-gate":             false,
	}
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if _, ok := expectedRules[rule.ID]; !ok {
			t.Errorf("unexpected rule ID: %s", rule.ID)
		}
		expectedRules[rule.ID] = true
		if rule.ShortDescription.Text == "" {
			t.Errorf("rule %s missing shortDescription", rule.ID)
		}
		if rule.FullDescription.Text == "" {
			t.Errorf("rule %s missing fullDescription", rule.ID)
		}
		if rule.DefaultConfiguration.Level == "" {
			t.Errorf("rule %s missing defaultConfiguration.level", rule.ID)
		}
		if rule.HelpURI == "" {
			t.Errorf("rule %s missing helpUri", rule.ID)
		}
	}
	for id, found := range expectedRules {
		if !found {
			t.Errorf("missing rule: %s", id)
		}
	}
}

func TestEmptyResults(t *testing.T) {
	output, err := FormatScanSARIF(nil, "0.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var log Log
	if err := json.Unmarshal([]byte(output), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	// Results should be an empty array, not null
	if log.Runs[0].Results == nil {
		t.Error("results should be empty array, not null")
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(log.Runs[0].Results))
	}

	// Should still have all 5 rules
	if len(log.Runs[0].Tool.Driver.Rules) != 5 {
		t.Errorf("expected 5 rules even with no results, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}

	// Verify version is passed through
	if log.Runs[0].Tool.Driver.Version != "0.3.0" {
		t.Errorf("expected version 0.3.0, got %s", log.Runs[0].Tool.Driver.Version)
	}
}
