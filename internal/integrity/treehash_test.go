// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package integrity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestComputeTreeHash_Deterministic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "hello")
	writeFile(t, dir, "b.txt", "world")
	writeFile(t, dir, "subdir/c.txt", "nested")

	hash1, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}

	hash2, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hashes differ: %q vs %q", hash1, hash2)
	}

	if !strings.HasPrefix(hash1, "sha256-") {
		t.Errorf("expected SRI format, got %q", hash1)
	}
}

func TestComputeTreeHash_ContentSensitive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "hello")
	writeFile(t, dir, "b.txt", "world")

	hash1, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}

	// Change one byte
	writeFile(t, dir, "a.txt", "hellO")

	hash2, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}

	if hash1 == hash2 {
		t.Error("changing content should change hash")
	}
}

func TestComputeTreeHash_OrderIndependent(t *testing.T) {
	// Create dir1 with files written in order a, b, c
	dir1 := t.TempDir()
	writeFile(t, dir1, "a.txt", "aaa")
	writeFile(t, dir1, "b.txt", "bbb")
	writeFile(t, dir1, "c.txt", "ccc")

	// Create dir2 with same files written in order c, a, b
	dir2 := t.TempDir()
	writeFile(t, dir2, "c.txt", "ccc")
	writeFile(t, dir2, "a.txt", "aaa")
	writeFile(t, dir2, "b.txt", "bbb")

	hash1, err := ComputeTreeHash(dir1)
	if err != nil {
		t.Fatalf("dir1 hash: %v", err)
	}

	hash2, err := ComputeTreeHash(dir2)
	if err != nil {
		t.Fatalf("dir2 hash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("order-independent hashes differ: %q vs %q", hash1, hash2)
	}
}

func TestComputeTreeHash_SkipsGitDir(t *testing.T) {
	// Dir without .git
	dir1 := t.TempDir()
	writeFile(t, dir1, "a.txt", "hello")

	hash1, err := ComputeTreeHash(dir1)
	if err != nil {
		t.Fatalf("without .git: %v", err)
	}

	// Dir with .git containing files
	dir2 := t.TempDir()
	writeFile(t, dir2, "a.txt", "hello")
	writeFile(t, dir2, ".git/HEAD", "ref: refs/heads/main")
	writeFile(t, dir2, ".git/objects/pack/data", "binary data")

	hash2, err := ComputeTreeHash(dir2)
	if err != nil {
		t.Fatalf("with .git: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf(".git dir should be excluded: %q vs %q", hash1, hash2)
	}
}

func TestComputeTreeHash_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "hello")

	hash1, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("without symlink: %v", err)
	}

	// Create a symlink
	if err := os.Symlink(filepath.Join(dir, "a.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	hash2, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("with symlink: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("symlink should be excluded: %q vs %q", hash1, hash2)
	}
}

func TestComputeTreeHash_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	hash, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("empty dir: %v", err)
	}

	if !strings.HasPrefix(hash, "sha256-") {
		t.Errorf("expected SRI format for empty dir, got %q", hash)
	}

	// Should be deterministic
	hash2, err := ComputeTreeHash(t.TempDir())
	if err != nil {
		t.Fatalf("second empty dir: %v", err)
	}
	if hash != hash2 {
		t.Errorf("empty dir hashes should match: %q vs %q", hash, hash2)
	}
}

func TestComputeTreeHash_NestedDirectories(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "level1.txt", "l1")
	writeFile(t, dir, "a/level2.txt", "l2")
	writeFile(t, dir, "a/b/level3.txt", "l3")

	hash, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("nested dirs: %v", err)
	}

	if !strings.HasPrefix(hash, "sha256-") {
		t.Errorf("expected SRI format, got %q", hash)
	}

	// Verify different content at nested level changes hash
	writeFile(t, dir, "a/b/level3.txt", "l3-modified")
	hash2, err := ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("modified nested: %v", err)
	}
	if hash == hash2 {
		t.Error("nested file change should change hash")
	}
}
