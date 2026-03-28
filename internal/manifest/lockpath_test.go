// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLockfilePath_NewExists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "actions-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	path, legacy := ResolveLockfilePath(dir)
	if legacy {
		t.Error("expected legacy=false, got true")
	}
	want := filepath.Join(dir, ".github", "actions-lock.json")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestResolveLockfilePath_LegacyExists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".pinpoint-manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	path, legacy := ResolveLockfilePath(dir)
	if !legacy {
		t.Error("expected legacy=true, got false")
	}
	want := filepath.Join(dir, ".pinpoint-manifest.json")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestResolveLockfilePath_BothExist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "actions-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".pinpoint-manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	path, legacy := ResolveLockfilePath(dir)
	if legacy {
		t.Error("expected legacy=false when both exist, got true")
	}
	want := filepath.Join(dir, ".github", "actions-lock.json")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestResolveLockfilePath_NeitherExists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	path, legacy := ResolveLockfilePath(dir)
	if legacy {
		t.Error("expected legacy=false when neither exists, got true")
	}
	want := filepath.Join(dir, ".github", "actions-lock.json")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}
