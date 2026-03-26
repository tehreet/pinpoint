// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package poller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareCommitsReturnsAuthorsAndFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "ahead",
			"ahead_by":      3,
			"behind_by":     0,
			"total_commits": 3,
			"commits": []map[string]interface{}{
				{"author": map[string]interface{}{"login": "alice"}},
				{"author": map[string]interface{}{"login": "bob"}},
				{"author": map[string]interface{}{"login": "alice"}},
			},
			"files": []map[string]interface{}{
				{"filename": "src/main.ts"},
				{"filename": "dist/index.js"},
				{"filename": ".github/workflows/ci.yml"},
			},
		})
	}))
	defer srv.Close()

	client := NewGitHubClient("")
	client.SetBaseURL(srv.URL)

	result, err := client.CompareCommits(context.Background(), "owner", "repo", "oldsha", "newsha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsDescendant {
		t.Error("expected IsDescendant=true")
	}
	if result.AheadBy != 3 {
		t.Errorf("expected AheadBy=3, got %d", result.AheadBy)
	}
	if len(result.AuthorLogins) != 2 {
		t.Errorf("expected 2 unique authors, got %d: %v", len(result.AuthorLogins), result.AuthorLogins)
	}
	if len(result.Files) != 3 {
		t.Errorf("expected 3 files, got %d: %v", len(result.Files), result.Files)
	}
}

func TestCompareCommitsNilAuthor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "ahead",
			"ahead_by":      1,
			"behind_by":     0,
			"total_commits": 1,
			"commits": []map[string]interface{}{
				{"author": nil},
			},
			"files": []map[string]interface{}{},
		})
	}))
	defer srv.Close()

	client := NewGitHubClient("")
	client.SetBaseURL(srv.URL)

	result, err := client.CompareCommits(context.Background(), "owner", "repo", "old", "new")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.AuthorLogins) != 0 {
		t.Errorf("expected 0 authors for nil author, got %d", len(result.AuthorLogins))
	}
}
