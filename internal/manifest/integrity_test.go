// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDownloadAndHash_Success(t *testing.T) {
	t.Parallel()
	content := []byte("test tarball content for hashing")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer ts.Close()

	hash, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(hash, "sha256-") {
		t.Errorf("expected SRI format, got %q", hash)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestDownloadAndHash_Deterministic(t *testing.T) {
	t.Parallel()
	content := []byte("deterministic content check")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer ts.Close()

	hash1, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	hash2, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hashes differ: %q vs %q", hash1, hash2)
	}
}

func TestDownloadAndHash_DifferentContent(t *testing.T) {
	t.Parallel()
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content A"))
	}))
	defer ts1.Close()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content B"))
	}))
	defer ts2.Close()

	hash1, err := DownloadAndHash(context.Background(), ts1.Client(), ts1.URL, "", "test", "repo", "sha1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	hash2, err := DownloadAndHash(context.Background(), ts2.Client(), ts2.URL, "", "test", "repo", "sha2")
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if hash1 == hash2 {
		t.Error("different content should produce different hashes")
	}
}

func TestDownloadAndHash_HTTPError(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	_, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestDownloadAndHash_SRIFormat(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some content"))
	}))
	defer ts.Close()

	hash, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(hash, "sha256-") {
		t.Fatalf("expected sha256- prefix, got %q", hash)
	}

	b64Part := strings.TrimPrefix(hash, "sha256-")
	decoded, err := base64.StdEncoding.DecodeString(b64Part)
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}
	if len(decoded) != 32 { // SHA-256 is 32 bytes
		t.Errorf("expected 32-byte hash, got %d bytes", len(decoded))
	}
}

func TestDownloadAndHashBatch_Concurrent(t *testing.T) {
	t.Parallel()
	var requestCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Write([]byte("tarball:" + r.URL.Path))
	}))
	defer ts.Close()

	var actions []ActionRef
	for i := 0; i < 20; i++ {
		actions = append(actions, ActionRef{
			Owner: "owner",
			Repo:  "repo",
			SHA:   strings.Repeat("a", 39) + string(rune('a'+i%26)),
		})
	}

	results := DownloadAndHashBatch(context.Background(), ts.Client(), ts.URL, "", actions)

	if len(results) != 20 {
		t.Errorf("expected 20 results, got %d", len(results))
	}

	for key, hr := range results {
		if hr.Err != nil {
			t.Errorf("error for %s: %v", key, hr.Err)
		}
		if !strings.HasPrefix(hr.Integrity, "sha256-") {
			t.Errorf("invalid hash for %s: %q", key, hr.Integrity)
		}
	}
}

func TestDownloadAndHashBatch_Deduplication(t *testing.T) {
	t.Parallel()
	var requestCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Write([]byte("tarball content"))
	}))
	defer ts.Close()

	// 10 actions but only 5 unique owner/repo/SHA combos
	var actions []ActionRef
	for i := 0; i < 10; i++ {
		actions = append(actions, ActionRef{
			Owner: "owner",
			Repo:  "repo",
			SHA:   strings.Repeat("a", 39) + string(rune('a'+i%5)),
		})
	}

	results := DownloadAndHashBatch(context.Background(), ts.Client(), ts.URL, "", actions)

	if len(results) != 5 {
		t.Errorf("expected 5 unique results, got %d", len(results))
	}

	got := requestCount.Load()
	if got != 5 {
		t.Errorf("expected 5 HTTP requests (deduplication), got %d", got)
	}
}
