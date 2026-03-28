// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseActionType_Composite(t *testing.T) {
	t.Parallel()
	yml := []byte(`name: Test
runs:
  using: composite
  steps:
    - run: echo hello
`)
	got := ParseActionType(yml)
	if got != "composite" {
		t.Errorf("expected composite, got %q", got)
	}
}

func TestParseActionType_Node24(t *testing.T) {
	t.Parallel()
	yml := []byte(`name: Test
runs:
  using: 'node24'
  main: index.js
`)
	got := ParseActionType(yml)
	if got != "node24" {
		t.Errorf("expected node24, got %q", got)
	}
}

func TestParseActionType_Docker(t *testing.T) {
	t.Parallel()
	yml := []byte(`name: Test
runs:
  using: docker
  image: Dockerfile
`)
	got := ParseActionType(yml)
	if got != "docker" {
		t.Errorf("expected docker, got %q", got)
	}
}

func TestParseActionType_Unknown(t *testing.T) {
	t.Parallel()
	got := ParseActionType([]byte("not valid yaml: [[["))
	if got != "unknown" {
		t.Errorf("expected unknown, got %q", got)
	}
}

func TestExtractUsesFromComposite_MultipleUses(t *testing.T) {
	t.Parallel()
	yml := []byte(`name: Test
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
    - uses: docker/build-push-action@v5
`)
	refs := ExtractUsesFromComposite(yml)
	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %d: %v", len(refs), refs)
	}
	expected := []string{"actions/checkout@v4", "actions/setup-go@v5", "docker/build-push-action@v5"}
	for i, want := range expected {
		if refs[i] != want {
			t.Errorf("ref[%d]: expected %q, got %q", i, want, refs[i])
		}
	}
}

func TestExtractUsesFromComposite_SkipsLocal(t *testing.T) {
	t.Parallel()
	yml := []byte(`name: Test
runs:
  using: composite
  steps:
    - uses: ./local-action
    - uses: actions/checkout@v4
`)
	refs := ExtractUsesFromComposite(yml)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref (local skipped), got %d: %v", len(refs), refs)
	}
	if refs[0] != "actions/checkout@v4" {
		t.Errorf("expected actions/checkout@v4, got %q", refs[0])
	}
}

func TestExtractUsesFromComposite_SkipsEmpty(t *testing.T) {
	t.Parallel()
	yml := []byte(`name: Test
runs:
  using: composite
  steps:
    - run: echo hello
    - uses: actions/checkout@v4
`)
	refs := ExtractUsesFromComposite(yml)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref (empty skipped), got %d: %v", len(refs), refs)
	}
}

// b64Content encodes content as a GitHub Contents API response.
func b64Content(content string) string {
	resp := contentAPIResponse{
		Content:  base64.StdEncoding.EncodeToString([]byte(content)),
		Encoding: "base64",
	}
	data, _ := json.Marshal(resp)
	return string(data)
}

func TestResolveTransitiveDeps_NodeAction(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/contents/action.yml") {
			fmt.Fprint(w, b64Content(`name: Test
runs:
  using: node24
  main: index.js
`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	deps, actionType, _, err := ResolveTransitiveDeps(context.Background(), ts.Client(), ts.URL, "", "", "actions/checkout", "abc123", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if actionType != "node24" {
		t.Errorf("expected node24, got %q", actionType)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestResolveTransitiveDeps_CompositeWithDeps(t *testing.T) {
	t.Parallel()
	depSHA := "ea165f8d65b6e75b540449e92b4886f43607fa02"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Main action's action.yml — composite with one dep
		if strings.Contains(path, "actions/upload-pages-artifact/contents/action.yml") {
			fmt.Fprint(w, b64Content(fmt.Sprintf(`name: Upload Pages
runs:
  using: composite
  steps:
    - uses: actions/upload-artifact@%s
`, depSHA)))
			return
		}

		// Dependency's action.yml — node24
		if strings.Contains(path, "actions/upload-artifact/contents/action.yml") {
			fmt.Fprint(w, b64Content(`name: Upload Artifact
runs:
  using: node24
  main: index.js
`))
			return
		}

		// Tarball download for the dep
		if strings.Contains(path, "/tarball/") {
			w.Write([]byte("fake tarball content"))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	deps, actionType, _, err := ResolveTransitiveDeps(context.Background(), ts.Client(), ts.URL, "", "", "actions/upload-pages-artifact", "7b1f4a76", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if actionType != "composite" {
		t.Errorf("expected composite, got %q", actionType)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Action != "actions/upload-artifact" {
		t.Errorf("expected actions/upload-artifact, got %q", deps[0].Action)
	}
	if deps[0].Ref != depSHA {
		t.Errorf("expected ref %s, got %q", depSHA, deps[0].Ref)
	}
	if deps[0].Integrity == "" {
		t.Error("expected non-empty integrity for dep")
	}
	if deps[0].Type != "node24" {
		t.Errorf("expected dep type node24, got %q", deps[0].Type)
	}
}

func TestResolveTransitiveDeps_DepthLimit(t *testing.T) {
	t.Parallel()
	// Every action.yml is composite that references itself
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/contents/action.yml") {
			fmt.Fprint(w, b64Content(`name: Recursive
runs:
  using: composite
  steps:
    - uses: actions/recursive@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`))
			return
		}
		if strings.Contains(r.URL.Path, "/tarball/") {
			w.Write([]byte("tarball"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// Start at depth 5 — should immediately error
	_, _, _, err := ResolveTransitiveDeps(context.Background(), ts.Client(), ts.URL, "", "", "actions/recursive", "abc123", 6)
	if err == nil {
		t.Fatal("expected depth limit error")
	}
	if !strings.Contains(err.Error(), "depth exceeded") {
		t.Errorf("expected depth exceeded error, got: %v", err)
	}
}

func TestResolveTransitiveDeps_LocalRefSkipped(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/contents/action.yml") {
			fmt.Fprint(w, b64Content(`name: Composite
runs:
  using: composite
  steps:
    - uses: ./foo
    - uses: ./bar
`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	deps, actionType, _, err := ResolveTransitiveDeps(context.Background(), ts.Client(), ts.URL, "", "", "owner/repo", "abc123", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if actionType != "composite" {
		t.Errorf("expected composite, got %q", actionType)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps (locals skipped), got %d", len(deps))
	}
}
