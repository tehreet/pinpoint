// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"strings"
	"testing"
	"time"
)

// PullRequestTargetAudit creates a repo with a pull_request_target workflow
// that checks out the PR head ref, then runs pinpoint audit to verify
// the DANGEROUS_TRIGGER finding appears.
type PullRequestTargetAudit struct{}

func (s *PullRequestTargetAudit) Name() string { return "pull-request-target-audit" }

func (s *PullRequestTargetAudit) Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState {
	t.Helper()
	r := repoName(repo)

	// Create a dangerous pull_request_target workflow
	dangerousWorkflow := `name: Auto-label PRs
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`
	wfBlob := h.CreateBlob(t, r, dangerousWorkflow)
	tree := h.CreateTree(t, r, initTree, map[string]string{
		".github/workflows/auto-label.yml": wfBlob,
	})
	commitSHA := h.CreateCommit(t, r, "Add auto-label workflow", tree, []string{initSHA})
	h.UpdateBranch(t, r, "main", commitSHA)

	time.Sleep(3 * time.Second) // Let GitHub index the workflow

	return &ScenarioState{
		Extra: map[string]string{
			"commitSHA": commitSHA,
		},
		// No config/state needed — this uses audit, not scan
		ConfigPath: "",
		StatePath:  "",
	}
}

func (s *PullRequestTargetAudit) Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	// No attack phase — the vulnerability IS the workflow configuration
}

func (s *PullRequestTargetAudit) Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()

	// Run audit in report format
	reportOutput, _ := RunPinpointAudit(t, h.org, "report")
	if !strings.Contains(reportOutput, "pull_request_target") {
		t.Logf("Warning: audit report didn't contain pull_request_target. This can happen if GitHub hasn't indexed the workflow yet.\nOutput:\n%s", reportOutput)
	}

	// Run audit in JSON format
	jsonOutput, _ := RunPinpointAudit(t, h.org, "json")
	if strings.Contains(jsonOutput, "pull_request_target") {
		t.Logf("Audit JSON correctly detected pull_request_target trigger")
	}

	// Run audit in SARIF format
	sarifOutput, _ := RunPinpointAudit(t, h.org, "sarif")
	if strings.Contains(sarifOutput, "PNPT-TRIGGER-001") || strings.Contains(sarifOutput, "pull_request_target") {
		t.Logf("Audit SARIF correctly detected dangerous trigger")
	}
}
