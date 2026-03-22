// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package integrity

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// createFakeActionDir creates a temp directory with the specified number
// of random files distributed across subdirectories.
func createFakeActionDir(b *testing.B, numFiles int, avgSizeKB int) string {
	b.Helper()
	dir, err := os.MkdirTemp("", "bench-treehash-*")
	if err != nil {
		b.Fatal(err)
	}

	numSubdirs := numFiles / 20
	if numSubdirs < 1 {
		numSubdirs = 1
	}

	for i := 0; i < numFiles; i++ {
		subdir := fmt.Sprintf("dir%d", i%numSubdirs)
		dirPath := filepath.Join(dir, subdir)
		os.MkdirAll(dirPath, 0755)

		content := make([]byte, avgSizeKB*1024)
		rand.Read(content)

		filePath := filepath.Join(dirPath, fmt.Sprintf("file%d.js", i))
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			b.Fatal(err)
		}
	}

	return dir
}

func BenchmarkComputeTreeHash_20Files(b *testing.B) {
	dir := createFakeActionDir(b, 20, 2) // 20 files, ~2KB each = ~40KB
	defer os.RemoveAll(dir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ComputeTreeHash(dir)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeTreeHash_200Files(b *testing.B) {
	dir := createFakeActionDir(b, 200, 4) // 200 files, ~4KB each = ~800KB
	defer os.RemoveAll(dir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ComputeTreeHash(dir)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeTreeHash_500Files(b *testing.B) {
	dir := createFakeActionDir(b, 500, 10) // 500 files, ~10KB each = ~5MB
	defer os.RemoveAll(dir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ComputeTreeHash(dir)
		if err != nil {
			b.Fatal(err)
		}
	}
}
