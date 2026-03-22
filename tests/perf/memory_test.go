//go:build integration

// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package perf

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tehreet/pinpoint/internal/integrity"
	"github.com/tehreet/pinpoint/internal/manifest"
)

func TestMemory_LargeTarballStreaming(t *testing.T) {
	// Serve 50MB of random data on-the-fly (don't allocate 50MB in test)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, io.LimitReader(rand.Reader, 50*1024*1024))
	}))
	defer ts.Close()

	// Force GC and measure baseline
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	_, err := manifest.DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
	if err != nil {
		t.Fatalf("DownloadAndHash error: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	growthMB := float64(growth) / (1024 * 1024)

	t.Logf("Heap growth for 50MB tarball: %.2f MB", growthMB)

	if growth > 10*1024*1024 {
		t.Errorf("Heap grew by %.2f MB — tarball should be streamed, not buffered (limit: 10MB)", growthMB)
	}
}

func TestMemory_50ConcurrentSmallDownloads(t *testing.T) {
	// 500KB per request
	payload := make([]byte, 500*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()

	// 50 unique actions
	var actions []manifest.ActionRef
	for i := 0; i < 50; i++ {
		actions = append(actions, manifest.ActionRef{
			Owner: "owner",
			Repo:  "repo",
			SHA:   fmt.Sprintf("%040d", i),
		})
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	results := manifest.DownloadAndHashBatch(context.Background(), ts.Client(), ts.URL, "", actions)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if len(results) != 50 {
		t.Errorf("expected 50 results, got %d", len(results))
	}

	peakMB := float64(after.HeapAlloc) / (1024 * 1024)
	t.Logf("Peak heap after 50 concurrent downloads: %.2f MB", peakMB)

	if after.HeapAlloc > 200*1024*1024 {
		t.Errorf("Peak heap %.2f MB exceeds 200MB limit (semaphore should limit concurrency)", peakMB)
	}
}

func TestMemory_TreeHashLargeDirectory(t *testing.T) {
	// Create 1000 files, ~10KB each = 10MB total
	dir := t.TempDir()
	for i := 0; i < 1000; i++ {
		subdir := filepath.Join(dir, fmt.Sprintf("dir%d", i%10))
		os.MkdirAll(subdir, 0755)

		content := make([]byte, 10*1024)
		rand.Read(content)

		path := filepath.Join(subdir, fmt.Sprintf("file%d.js", i))
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatal(err)
		}
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	hash, err := integrity.ComputeTreeHash(dir)
	if err != nil {
		t.Fatalf("ComputeTreeHash error: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if !strings.HasPrefix(hash, "sha256-") {
		t.Errorf("invalid hash format: %q", hash)
	}

	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	growthMB := float64(growth) / (1024 * 1024)

	t.Logf("Heap growth for 1000-file tree hash: %.2f MB", growthMB)

	if growth > 10*1024*1024 {
		t.Errorf("Heap grew by %.2f MB — files should be streamed through hasher (limit: 10MB)", growthMB)
	}
}
