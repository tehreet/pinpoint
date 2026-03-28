// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writeWorkflow writes a workflow YAML file into dir with the given filename and content.
func writeWorkflow(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644); err != nil {
		t.Fatalf("writing workflow %s: %v", filename, err)
	}
}

func TestFromWorkflowDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		files     map[string]string // filename → content
		wantRefs  []string          // expected Raw strings (subset check)
		wantCount int               // exact count (-1 = don't check)
		wantErr   bool
	}{
		{
			name: "parse checkout and setup-go",
			files: map[string]string{
				"ci.yml": `
on: [push]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
`,
			},
			wantRefs:  []string{"uses: actions/checkout@v4", "uses: actions/setup-go@v5"},
			wantCount: 2,
		},
		{
			name:      "empty directory returns no refs",
			files:     map[string]string{},
			wantCount: 0,
		},
		{
			name: "SHA-pinned refs detected as pinned",
			files: map[string]string{
				"ci.yml": `
steps:
  - uses: actions/checkout@f4f7b36c09d09323a7408f5a6d0c0d1d2d3d4d5d
`,
			},
			wantCount: 1,
		},
		{
			name: "multiple workflow files in same directory",
			files: map[string]string{
				"ci.yml": `
steps:
  - uses: actions/checkout@v4
`,
				"deploy.yml": `
steps:
  - uses: docker/build-push-action@v5
`,
			},
			wantRefs:  []string{"uses: actions/checkout@v4", "uses: docker/build-push-action@v5"},
			wantCount: 2,
		},
		{
			name: "duplicate uses in same file deduped",
			files: map[string]string{
				"ci.yml": `
steps:
  - uses: actions/checkout@v4
  - uses: actions/checkout@v4
`,
			},
			wantCount: 1,
		},
		{
			name: "duplicate across files deduped",
			files: map[string]string{
				"a.yml": `steps:
  - uses: actions/checkout@v4`,
				"b.yml": `steps:
  - uses: actions/checkout@v4`,
			},
			wantCount: 1,
		},
		{
			name: "yaml and yml extensions both discovered",
			files: map[string]string{
				"ci.yml":  `steps:\n  - uses: actions/checkout@v4`,
				"cd.yaml": `steps:\n  - uses: docker/build-push-action@v5`,
			},
			wantCount: 2,
		},
		{
			name: "commented lines are skipped",
			files: map[string]string{
				"ci.yml": `
steps:
  # - uses: actions/checkout@v4
  - uses: actions/setup-go@v5
`,
			},
			wantRefs:  []string{"uses: actions/setup-go@v5"},
			wantCount: 1,
		},
		{
			name: "sub-path actions parsed",
			files: map[string]string{
				"ci.yml": `steps:
  - uses: github/codeql-action/analyze@v3`,
			},
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			for filename, content := range tc.files {
				writeWorkflow(t, dir, filename, content)
			}

			refs, err := FromWorkflowDir(dir)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantCount >= 0 && len(refs) != tc.wantCount {
				t.Errorf("want %d refs, got %d: %v", tc.wantCount, len(refs), rawRefs(refs))
			}

			for _, want := range tc.wantRefs {
				if !containsRaw(refs, want) {
					t.Errorf("want ref %q in results, got: %v", want, rawRefs(refs))
				}
			}
		})
	}
}

func TestActionRefFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
steps:
  - uses: actions/checkout@v4
  - uses: actions/checkout@f4f7b36c09d09323a7408f5a6d0c0d1d2d3d4d5d
`)

	refs, err := FromWorkflowDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("want 2 refs, got %d", len(refs))
	}

	// Sort refs by Ref so the test is deterministic.
	sort.Slice(refs, func(i, j int) bool { return refs[i].Ref < refs[j].Ref })

	// SHA-pinned ref
	pinned := refs[0]
	if pinned.Owner != "actions" {
		t.Errorf("pinned owner: want actions, got %s", pinned.Owner)
	}
	if pinned.Repo != "checkout" {
		t.Errorf("pinned repo: want checkout, got %s", pinned.Repo)
	}
	if !pinned.IsPinned {
		t.Error("want IsPinned=true for 40-char SHA ref")
	}
	if pinned.Source != "ci.yml" {
		t.Errorf("pinned source: want ci.yml, got %s", pinned.Source)
	}

	// Tag ref
	tag := refs[1]
	if tag.Ref != "v4" {
		t.Errorf("tag ref: want v4, got %s", tag.Ref)
	}
	if tag.IsPinned {
		t.Error("want IsPinned=false for tag ref")
	}
	if tag.Full() != "actions/checkout" {
		t.Errorf("Full(): want actions/checkout, got %s", tag.Full())
	}
}

func TestGroupByRepo(t *testing.T) {
	t.Parallel()

	refs := []ActionRef{
		{Owner: "actions", Repo: "checkout", Ref: "v4", IsPinned: false},
		{Owner: "actions", Repo: "checkout", Ref: "v3", IsPinned: false},
		{Owner: "docker", Repo: "build-push-action", Ref: "v5", IsPinned: false},
		// SHA-pinned refs should be excluded from tags list
		{Owner: "actions", Repo: "setup-go", Ref: "f4f7b36c09d09323a7408f5a6d0c0d1d2d3d4d5d", IsPinned: true},
	}

	grouped := GroupByRepo(refs)

	checkoutTags := grouped["actions/checkout"]
	sort.Strings(checkoutTags)
	if len(checkoutTags) != 2 {
		t.Errorf("want 2 tags for actions/checkout, got %d: %v", len(checkoutTags), checkoutTags)
	}

	dockerTags := grouped["docker/build-push-action"]
	if len(dockerTags) != 1 || dockerTags[0] != "v5" {
		t.Errorf("want [v5] for docker/build-push-action, got %v", dockerTags)
	}

	// SHA-pinned action should still appear in grouped but with empty tags.
	setupGoTags, ok := grouped["actions/setup-go"]
	if !ok {
		t.Error("want actions/setup-go present in grouped result")
	}
	if len(setupGoTags) != 0 {
		t.Errorf("want empty tags for SHA-pinned action, got %v", setupGoTags)
	}
}

func TestSummary(t *testing.T) {
	t.Parallel()

	refs := []ActionRef{
		{Owner: "actions", Repo: "checkout", Ref: "v4", IsPinned: false},
		{Owner: "actions", Repo: "setup-go", Ref: "f4f7b36c09d09323a7408f5a6d0c0d1d2d3d4d5d", IsPinned: true},
	}

	s := Summary(refs)
	if s == "" {
		t.Fatal("Summary returned empty string")
	}

	for _, want := range []string{"action", "SHA-pinned", "Tag-based"} {
		if !containsStr(s, want) {
			t.Errorf("Summary missing %q\nfull output: %s", want, s)
		}
	}
}

// rawRefs returns the Raw field of each ActionRef for error messages.
func rawRefs(refs []ActionRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Raw
	}
	return out
}

// containsRaw checks whether any ref has a Raw field equal to want.
func containsRaw(refs []ActionRef, want string) bool {
	for _, r := range refs {
		if r.Raw == want {
			return true
		}
	}
	return false
}

// containsStr reports whether s contains substr.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}())
}
