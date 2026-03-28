// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestNewFileStoreStartsEmpty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: unexpected error: %v", err)
	}
	if fs == nil {
		t.Fatal("NewFileStore returned nil")
	}
	if fs.TagCount() != 0 {
		t.Errorf("want 0 tags, got %d", fs.TagCount())
	}
}

func TestRecordTagNewTag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	changed, prev := fs.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")
	if changed {
		t.Error("want changed=false for new tag, got true")
	}
	if prev != "" {
		t.Errorf("want empty previousSHA for new tag, got %q", prev)
	}
	if fs.TagCount() != 1 {
		t.Errorf("want 1 tag, got %d", fs.TagCount())
	}
}

func TestRecordTagSameSHA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	fs.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")

	// Record same SHA again — no change.
	changed, prev := fs.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")
	if changed {
		t.Error("want changed=false for same SHA, got true")
	}
	if prev != "" {
		t.Errorf("want empty previousSHA for same SHA, got %q", prev)
	}
}

func TestRecordTagDifferentSHA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	fs.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")

	// Record different SHA — tag has been repointed.
	changed, prev := fs.RecordTag("actions/checkout", "v4", "sha2222", "tagsha2")
	if !changed {
		t.Error("want changed=true for different SHA, got false")
	}
	if prev != "sha1111" {
		t.Errorf("want previousSHA=sha1111, got %q", prev)
	}

	// Verify history was recorded.
	state := fs.GetActionState("actions/checkout")
	tag := state.Tags["v4"]
	if len(tag.History) != 1 {
		t.Fatalf("want 1 history entry, got %d", len(tag.History))
	}
	if tag.History[0].PreviousSHA != "sha1111" {
		t.Errorf("history PreviousSHA: want sha1111, got %s", tag.History[0].PreviousSHA)
	}
	if tag.History[0].NewSHA != "sha2222" {
		t.Errorf("history NewSHA: want sha2222, got %s", tag.History[0].NewSHA)
	}
}

func TestRecordDeletedTag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// Set up a tag, then delete it.
	fs.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")
	if fs.TagCount() != 1 {
		t.Fatalf("want 1 tag before delete, got %d", fs.TagCount())
	}

	fs.RecordDeletedTag("actions/checkout", "v4")

	if fs.TagCount() != 0 {
		t.Errorf("want 0 tags after delete, got %d", fs.TagCount())
	}

	// Verify deleted tag was recorded in the action state.
	state := fs.GetActionState("actions/checkout")
	if len(state.DeletedTags) != 1 {
		t.Fatalf("want 1 deleted tag, got %d", len(state.DeletedTags))
	}
	dt := state.DeletedTags[0]
	if dt.Name != "v4" {
		t.Errorf("deleted tag name: want v4, got %s", dt.Name)
	}
	if dt.LastSHA != "sha1111" {
		t.Errorf("deleted tag LastSHA: want sha1111, got %s", dt.LastSHA)
	}
}

func TestRecordDeletedTagUnknownRepo(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// Should not panic when repo doesn't exist.
	fs.RecordDeletedTag("unknown/repo", "v4")
}

func TestSaveAndReloadRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	fs.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")
	fs.RecordTag("actions/setup-go", "v5", "sha2222", "tagsha2")

	if err := fs.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from disk.
	fs2, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore (reload): %v", err)
	}

	if fs2.TagCount() != 2 {
		t.Errorf("after reload: want 2 tags, got %d", fs2.TagCount())
	}

	state := fs2.GetActionState("actions/checkout")
	tag, ok := state.Tags["v4"]
	if !ok {
		t.Fatal("after reload: missing actions/checkout@v4")
	}
	if tag.CommitSHA != "sha1111" {
		t.Errorf("after reload: CommitSHA want sha1111, got %s", tag.CommitSHA)
	}
}

func TestSaveRoundTripWithHistory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	fs.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")
	fs.RecordTag("actions/checkout", "v4", "sha2222", "tagsha2") // repoint

	if err := fs.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	fs2, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore (reload): %v", err)
	}

	state := fs2.GetActionState("actions/checkout")
	tag := state.Tags["v4"]
	if len(tag.History) != 1 {
		t.Errorf("after reload: want 1 history entry, got %d", len(tag.History))
	}
}

func TestConcurrentRecordTag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			repo := fmt.Sprintf("owner/repo-%d", i)
			fs.RecordTag(repo, "v1", "sha-initial", "tagsha")
			// Also do a repoint to exercise the change path.
			fs.RecordTag(repo, "v1", "sha-updated", "tagsha-new")
		}()
	}

	wg.Wait()

	if fs.TagCount() != goroutines {
		t.Errorf("after concurrent writes: want %d tags, got %d", goroutines, fs.TagCount())
	}
}

func TestGetActionStateCreatesIfMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	state := fs.GetActionState("new/repo")
	if state == nil {
		t.Fatal("GetActionState returned nil for new repo")
	}
	if state.Tags == nil {
		t.Error("GetActionState returned ActionState with nil Tags map")
	}
}

func TestSetRepoETag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fs, err := NewFileStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	fs.SetRepoETag("actions/checkout", `"abc123"`)

	state := fs.GetActionState("actions/checkout")
	if state.RepoETag != `"abc123"` {
		t.Errorf("RepoETag: want %q, got %q", `"abc123"`, state.RepoETag)
	}
}

func TestNewFileStoreLoadsExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Create and save a store.
	fs1, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore (create): %v", err)
	}
	fs1.RecordTag("actions/checkout", "v4", "sha1111", "tagsha1")
	if err := fs1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load it again — version and actions should be preserved.
	fs2, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore (load): %v", err)
	}
	if fs2.TagCount() != 1 {
		t.Errorf("want 1 tag after load, got %d", fs2.TagCount())
	}
}
