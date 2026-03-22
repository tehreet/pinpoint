// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func BenchmarkDownloadAndHash_Single(b *testing.B) {
	// 500KB random payload
	payload := make([]byte, 500*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()

	b.SetBytes(500 * 1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDownloadAndHash_Parallel10(b *testing.B) {
	payload := make([]byte, 500*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()

	b.SetBytes(500 * 1024)
	b.SetParallelism(10)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDownloadAndHashBatch_20Actions(b *testing.B) {
	payload := make([]byte, 500*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		b.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()

	// 20 actions, 5 duplicates (15 unique)
	var actions []ActionRef
	for i := 0; i < 20; i++ {
		sha := strings.Repeat("a", 39) + string(rune('a'+i%15))
		actions = append(actions, ActionRef{Owner: "owner", Repo: "repo", SHA: sha})
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		results := DownloadAndHashBatch(context.Background(), ts.Client(), ts.URL, "", actions)
		if len(results) != 15 {
			b.Fatalf("expected 15 unique results, got %d", len(results))
		}
	}
}

func BenchmarkDownloadAndHash_LargePayload(b *testing.B) {
	// 10MB payload - serve from random reader to avoid allocating 10MB
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, io.LimitReader(rand.Reader, 10*1024*1024))
	}))
	defer ts.Close()

	b.SetBytes(10 * 1024 * 1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := DownloadAndHash(context.Background(), ts.Client(), ts.URL, "", "test", "repo", "abc123")
		if err != nil {
			b.Fatal(err)
		}
	}
}
