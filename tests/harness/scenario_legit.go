// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"strings"
	"testing"
)

// LegitMajorAdvance verifies that a descendant major version advance
// (v1 moved forward to a child commit) does NOT trigger false positives.
// Score should be LOW, not CRITICAL.
type LegitMajorAdvance struct{}

func (s *LegitMajorAdvance) Name() string { return "legit-major-advance" }

func (s *LegitMajorAdvance) Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState {
	t.Helper()
	r := repoName(repo)

	// Create initial action
	blob := h.CreateBlob(t, r, "#!/bin/bash\necho v1\n")
	tree := h.CreateTree(t, r, initTree, map[string]string{"entrypoint.sh": blob})
	commit1 := h.CreateCommit(t, r, "v1 initial", tree, []string{initSHA})
	h.UpdateBranch(t, r, "main", commit1)
	h.CreateAnnotatedTag(t, r, "v1", commit1, "Major v1")

	cfg := writeConfig(t, repo, []string{"v1"})
	return &ScenarioState{
		TagSHAs:    map[string]string{"v1": commit1},
		ConfigPath: cfg,
		StatePath:  t.TempDir() + "/state.json",
	}
}

func (s *LegitMajorAdvance) Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()
	r := repoName(repo)

	// Legitimate: new commit on main (descendant), advance v1
	commit1 := state.TagSHAs["v1"]
	blob2 := h.CreateBlob(t, r, "#!/bin/bash\necho v1-patched\n")
	tree1 := h.GetCommitTree(t, r, commit1)
	tree2 := h.CreateTree(t, r, tree1, map[string]string{"entrypoint.sh": blob2})
	commit2 := h.CreateCommit(t, r, "v1 patch", tree2, []string{commit1})
	h.UpdateBranch(t, r, "main", commit2)

	// Move v1 forward (delete + recreate since it's annotated)
	h.DeleteTag(t, r, "v1")
	h.CreateAnnotatedTag(t, r, "v1", commit2, "Major v1 updated")
}

func (s *LegitMajorAdvance) Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()
	output, _ := RunPinpointScan(t, state.ConfigPath, state.StatePath)
	// The key assertion: severity should be LOW, not CRITICAL
	if strings.Contains(output, "CRITICAL") {
		t.Fatalf("Legitimate major version advance should not be CRITICAL. Output:\n%s", output)
	}
}
