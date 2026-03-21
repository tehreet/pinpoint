// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package suppress

import (
	"testing"
	"time"

	"github.com/tehreet/pinpoint/internal/config"
	"github.com/tehreet/pinpoint/internal/risk"
)

func makeAlert(action, tag string, severity risk.Severity) risk.Alert {
	return risk.Alert{
		Severity:    severity,
		Type:        "TAG_REPOINTED",
		Action:      action,
		Tag:         tag,
		PreviousSHA: "aaa111",
		CurrentSHA:  "bbb222",
		DetectedAt:  time.Now(),
		Signals:     []string{"test"},
	}
}

func TestSuppressMajorTagAdvance(t *testing.T) {
	alerts := []risk.Alert{
		makeAlert("actions/checkout", "v4", risk.SeverityLow),
	}
	rules := []config.AllowRule{
		{
			Repo:      "actions/*",
			Tags:      []string{"v*"},
			Condition: "major_tag_advance",
			Reason:    "GitHub-maintained actions routinely advance major tags",
		},
	}
	contexts := map[string]risk.ScoreContext{
		"actions/checkout@v4": {IsDescendant: true},
	}

	result := Filter(alerts, rules, contexts)

	if len(result.Allowed) != 0 {
		t.Errorf("expected 0 allowed, got %d", len(result.Allowed))
	}
	if len(result.Suppressed) != 1 {
		t.Fatalf("expected 1 suppressed, got %d", len(result.Suppressed))
	}
	if result.Suppressed[0].Reason != "GitHub-maintained actions routinely advance major tags" {
		t.Errorf("unexpected reason: %s", result.Suppressed[0].Reason)
	}
}

func TestNoSuppressForSemver(t *testing.T) {
	alerts := []risk.Alert{
		makeAlert("actions/checkout", "v1.2.3", risk.SeverityCritical),
	}
	rules := []config.AllowRule{
		{
			Repo:      "actions/*",
			Tags:      []string{"v*"},
			Condition: "major_tag_advance",
			Reason:    "GitHub-maintained actions routinely advance major tags",
		},
	}
	contexts := map[string]risk.ScoreContext{
		"actions/checkout@v1.2.3": {IsDescendant: true},
	}

	result := Filter(alerts, rules, contexts)

	// v1.2.3 is NOT a major version tag, so the condition should fail
	if len(result.Allowed) != 1 {
		t.Errorf("expected 1 allowed (semver should NOT be suppressed), got %d", len(result.Allowed))
	}
	if len(result.Suppressed) != 0 {
		t.Errorf("expected 0 suppressed, got %d", len(result.Suppressed))
	}
}

func TestSuppressByActor(t *testing.T) {
	alerts := []risk.Alert{
		makeAlert("myorg/my-action", "v2", risk.SeverityLow),
	}
	rules := []config.AllowRule{
		{
			Actor:     "github-actions[bot]",
			Condition: "descendant",
			Reason:    "Release automation advances tags to descendants",
		},
	}
	contexts := map[string]risk.ScoreContext{
		"myorg/my-action@v2": {
			CommitAuthor: "github-actions[bot]",
			IsDescendant: true,
		},
	}

	result := Filter(alerts, rules, contexts)

	if len(result.Allowed) != 0 {
		t.Errorf("expected 0 allowed, got %d", len(result.Allowed))
	}
	if len(result.Suppressed) != 1 {
		t.Errorf("expected 1 suppressed, got %d", len(result.Suppressed))
	}
}

func TestSuppressEntireRepo(t *testing.T) {
	alerts := []risk.Alert{
		makeAlert("coreweave/internal-action", "v1", risk.SeverityCritical),
		makeAlert("coreweave/internal-action", "v2.0.0", risk.SeverityMedium),
	}
	rules := []config.AllowRule{
		{
			Repo:     "coreweave/internal-action",
			Suppress: true,
			Reason:   "Internal action, we control the tags",
		},
	}
	contexts := map[string]risk.ScoreContext{}

	result := Filter(alerts, rules, contexts)

	if len(result.Allowed) != 0 {
		t.Errorf("expected 0 allowed, got %d", len(result.Allowed))
	}
	if len(result.Suppressed) != 2 {
		t.Errorf("expected 2 suppressed, got %d", len(result.Suppressed))
	}
}

func TestGlobMatching(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"actions/*", "actions/checkout", true},
		{"actions/*", "docker/build-push-action", false},
		{"*/checkout", "actions/checkout", true}, // * matches "actions", then /checkout matches
		{"docker/build-push-action", "docker/build-push-action", true},
		{"docker/build-push-action", "docker/setup-buildx-action", false},
	}

	for _, tt := range tests {
		got := globMatch(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestReasonRequired(t *testing.T) {
	yaml := `
actions:
  - repo: actions/checkout
    tags: ["v4"]
allow:
  - repo: actions/*
    condition: any
`
	cfg, err := config.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatalf("expected error for missing reason, got config with %d allow rules", len(cfg.AllowRules))
	}
}

func TestSuppressedAlertsCounted(t *testing.T) {
	alerts := []risk.Alert{
		makeAlert("actions/checkout", "v4", risk.SeverityLow),
		makeAlert("actions/setup-go", "v5", risk.SeverityLow),
		makeAlert("docker/build-push-action", "v5", risk.SeverityMedium),
	}
	rules := []config.AllowRule{
		{
			Repo:      "actions/*",
			Condition: "any",
			Reason:    "All GitHub actions are trusted",
		},
	}
	contexts := map[string]risk.ScoreContext{}

	result := Filter(alerts, rules, contexts)

	if len(result.Suppressed) != 2 {
		t.Errorf("expected 2 suppressed (actions/*), got %d", len(result.Suppressed))
	}
	if len(result.Allowed) != 1 {
		t.Errorf("expected 1 allowed (docker/*), got %d", len(result.Allowed))
	}
	if result.Allowed[0].Action != "docker/build-push-action" {
		t.Errorf("expected docker/build-push-action to pass through, got %s", result.Allowed[0].Action)
	}
}
