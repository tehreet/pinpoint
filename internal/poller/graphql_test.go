// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRepoToAlias(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aquasecurity/trivy-action", "aquasecurity_trivy_action"},
		{"actions/checkout", "actions_checkout"},
		{"docker/build-push-action", "docker_build_push_action"},
		{"123org/repo", "_123org_repo"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := repoToAlias(tt.input)
			if got != tt.want {
				t.Errorf("repoToAlias(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildAliasMap_Collision(t *testing.T) {
	repos := []string{"foo/bar-baz", "foo/bar_baz"}
	aliasMap := buildAliasMap(repos)

	if len(aliasMap) != 2 {
		t.Fatalf("expected 2 aliases, got %d", len(aliasMap))
	}

	// Both repos should be present as values
	seen := make(map[string]bool)
	for _, repo := range aliasMap {
		seen[repo] = true
	}
	for _, repo := range repos {
		if !seen[repo] {
			t.Errorf("repo %q missing from alias map", repo)
		}
	}
}

func TestBuildBatchQuery(t *testing.T) {
	aliasMap := map[string]string{
		"actions_checkout":          "actions/checkout",
		"docker_build_push_action": "docker/build-push-action",
	}
	query := buildBatchQuery(aliasMap)

	mustContain := []string{
		"rateLimit { cost remaining }",
		`actions_checkout: repository(owner: "actions", name: "checkout")`,
		`docker_build_push_action: repository(owner: "docker", name: "build-push-action")`,
		`refs(refPrefix: "refs/tags/", first: 100)`,
		"__typename",
		"... on Tag { target { __typename oid } }",
	}
	for _, s := range mustContain {
		if !strings.Contains(query, s) {
			t.Errorf("query missing %q\nquery:\n%s", s, query)
		}
	}
}

func TestParseRefNodes_Lightweight(t *testing.T) {
	payload := refsPayload{}
	payload.Refs.Nodes = []struct {
		Name   string `json:"name"`
		Target struct {
			TypeName string `json:"__typename"`
			OID      string `json:"oid"`
			Target   *struct {
				TypeName string `json:"__typename"`
				OID      string `json:"oid"`
			} `json:"target,omitempty"`
		} `json:"target"`
	}{
		{
			Name: "0.35.0",
			Target: struct {
				TypeName string `json:"__typename"`
				OID      string `json:"oid"`
				Target   *struct {
					TypeName string `json:"__typename"`
					OID      string `json:"oid"`
				} `json:"target,omitempty"`
			}{
				TypeName: "Commit",
				OID:      "abc123",
			},
		},
	}

	tags := parseRefNodes(payload)
	if len(tags) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(tags))
	}
	tag := tags[0]
	if tag.Name != "0.35.0" {
		t.Errorf("Name = %q, want %q", tag.Name, "0.35.0")
	}
	if tag.CommitSHA != "abc123" {
		t.Errorf("CommitSHA = %q, want %q", tag.CommitSHA, "abc123")
	}
	if tag.TagSHA != "abc123" {
		t.Errorf("TagSHA = %q, want %q", tag.TagSHA, "abc123")
	}
	if tag.IsAnnotated {
		t.Errorf("IsAnnotated = true, want false")
	}
}

func TestParseRefNodes_Annotated(t *testing.T) {
	payload := refsPayload{}
	innerTarget := &struct {
		TypeName string `json:"__typename"`
		OID      string `json:"oid"`
	}{TypeName: "Commit", OID: "commit222"}

	payload.Refs.Nodes = []struct {
		Name   string `json:"name"`
		Target struct {
			TypeName string `json:"__typename"`
			OID      string `json:"oid"`
			Target   *struct {
				TypeName string `json:"__typename"`
				OID      string `json:"oid"`
			} `json:"target,omitempty"`
		} `json:"target"`
	}{
		{
			Name: "v1",
			Target: struct {
				TypeName string `json:"__typename"`
				OID      string `json:"oid"`
				Target   *struct {
					TypeName string `json:"__typename"`
					OID      string `json:"oid"`
				} `json:"target,omitempty"`
			}{
				TypeName: "Tag",
				OID:      "tag111",
				Target:   innerTarget,
			},
		},
	}

	tags := parseRefNodes(payload)
	if len(tags) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(tags))
	}
	tag := tags[0]
	if tag.Name != "v1" {
		t.Errorf("Name = %q, want %q", tag.Name, "v1")
	}
	if tag.CommitSHA != "commit222" {
		t.Errorf("CommitSHA = %q, want %q", tag.CommitSHA, "commit222")
	}
	if tag.TagSHA != "tag111" {
		t.Errorf("TagSHA = %q, want %q", tag.TagSHA, "tag111")
	}
	if !tag.IsAnnotated {
		t.Errorf("IsAnnotated = false, want true")
	}
}

// mockGraphQLResponse builds a JSON response for the given alias->tags mapping.
func mockGraphQLResponse(aliasToTags map[string][]ResolvedTag, cost, remaining int) []byte {
	data := make(map[string]interface{})
	data["rateLimit"] = map[string]int{"cost": cost, "remaining": remaining}

	for alias, tags := range aliasToTags {
		nodes := make([]map[string]interface{}, 0, len(tags))
		for _, tag := range tags {
			node := map[string]interface{}{
				"name": tag.Name,
			}
			if tag.IsAnnotated {
				node["target"] = map[string]interface{}{
					"__typename": "Tag",
					"oid":        tag.TagSHA,
					"target": map[string]interface{}{
						"__typename": "Commit",
						"oid":        tag.CommitSHA,
					},
				}
			} else {
				node["target"] = map[string]interface{}{
					"__typename": "Commit",
					"oid":        tag.CommitSHA,
				}
			}
			nodes = append(nodes, node)
		}
		data[alias] = map[string]interface{}{
			"refs": map[string]interface{}{
				"totalCount": len(tags),
				"pageInfo": map[string]interface{}{
					"endCursor":   "",
					"hasNextPage": false,
				},
				"nodes": nodes,
			},
		}
	}

	resp := map[string]interface{}{"data": data}
	b, _ := json.Marshal(resp)
	return b
}

func TestFetchTagsBatch_SingleBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockGraphQLResponse(map[string][]ResolvedTag{
			"actions_checkout": {
				{Name: "v3", CommitSHA: "aaa111", TagSHA: "aaa111", IsAnnotated: false},
				{Name: "v4", CommitSHA: "bbb222", TagSHA: "tag444", IsAnnotated: true},
			},
			"docker_build_push_action": {
				{Name: "v5", CommitSHA: "ccc333", TagSHA: "ccc333", IsAnnotated: false},
			},
		}, 1, 4999)
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}))
	defer server.Close()

	client := &GraphQLClient{
		httpClient: server.Client(),
		token:      "test-token",
		endpoint:   server.URL,
	}

	results, err := client.FetchTagsBatch(context.Background(), []string{
		"actions/checkout",
		"docker/build-push-action",
	})
	if err != nil {
		t.Fatalf("FetchTagsBatch error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 repos in results, got %d", len(results))
	}

	checkout := results["actions/checkout"]
	if checkout == nil {
		t.Fatal("missing results for actions/checkout")
	}
	if len(checkout.Tags) != 2 {
		t.Errorf("actions/checkout: expected 2 tags, got %d", len(checkout.Tags))
	}

	docker := results["docker/build-push-action"]
	if docker == nil {
		t.Fatal("missing results for docker/build-push-action")
	}
	if len(docker.Tags) != 1 {
		t.Errorf("docker/build-push-action: expected 1 tag, got %d", len(docker.Tags))
	}
}

func TestFetchTagsBatch_BatchSplitting(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		// Return empty but valid response for any batch
		resp := mockGraphQLResponse(map[string][]ResolvedTag{}, 1, 4999)

		// Parse the request to find which repos were queried, add empty results for them
		var req graphqlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			data := make(map[string]interface{})
			data["rateLimit"] = map[string]int{"cost": 1, "remaining": 4999}
			// Add empty refs for any alias found in the query
			for i := 0; i < 120; i++ {
				alias := fmt.Sprintf("org_repo%d", i)
				if strings.Contains(req.Query, alias+":") {
					data[alias] = map[string]interface{}{
						"refs": map[string]interface{}{
							"totalCount": 0,
							"pageInfo":   map[string]interface{}{"endCursor": "", "hasNextPage": false},
							"nodes":      []interface{}{},
						},
					}
				}
			}
			resp, _ = json.Marshal(map[string]interface{}{"data": data})
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}))
	defer server.Close()

	client := &GraphQLClient{
		httpClient: server.Client(),
		token:      "test-token",
		endpoint:   server.URL,
	}

	repos := make([]string, 120)
	for i := range repos {
		repos[i] = fmt.Sprintf("org/repo%d", i)
	}

	_, err := client.FetchTagsBatch(context.Background(), repos)
	if err != nil {
		t.Fatalf("FetchTagsBatch error: %v", err)
	}

	got := callCount.Load()
	if got != 3 {
		t.Errorf("expected 3 GraphQL calls (50+50+20), got %d", got)
	}
}

func TestFetchTagsBatch_PartialFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return data for repo1 but error for repo2
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"rateLimit": map[string]int{"cost": 1, "remaining": 4999},
				"good_repo": map[string]interface{}{
					"refs": map[string]interface{}{
						"totalCount": 1,
						"pageInfo":   map[string]interface{}{"endCursor": "", "hasNextPage": false},
						"nodes": []map[string]interface{}{
							{
								"name": "v1",
								"target": map[string]interface{}{
									"__typename": "Commit",
									"oid":        "sha111",
								},
							},
						},
					},
				},
				// bad_repo is missing from data (simulating a repo that errored)
			},
			"errors": []map[string]string{
				{"message": "Could not resolve to a Repository with the name 'bad/repo'."},
			},
		}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	defer server.Close()

	client := &GraphQLClient{
		httpClient: server.Client(),
		token:      "test-token",
		endpoint:   server.URL,
	}

	results, err := client.FetchTagsBatch(context.Background(), []string{
		"good/repo",
		"bad/repo",
	})
	if err != nil {
		t.Fatalf("FetchTagsBatch should not return error on partial failure: %v", err)
	}

	if results["good/repo"] == nil {
		t.Error("expected results for good/repo")
	}
	if len(results["good/repo"].Tags) != 1 {
		t.Errorf("expected 1 tag for good/repo, got %d", len(results["good/repo"].Tags))
	}

	// bad/repo should not be in results (no data returned)
	if results["bad/repo"] != nil {
		t.Error("expected no results for bad/repo")
	}
}

func TestFetchTagsBatch_Pagination(t *testing.T) {
	callNum := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callNum++
		w.Header().Set("Content-Type", "application/json")

		var req graphqlRequest
		json.NewDecoder(r.Body).Decode(&req)

		if callNum == 1 {
			// First call: batch query, repo has hasNextPage=true
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"rateLimit": map[string]int{"cost": 1, "remaining": 4999},
					"big_repo": map[string]interface{}{
						"refs": map[string]interface{}{
							"totalCount": 150,
							"pageInfo": map[string]interface{}{
								"endCursor":   "cursor123",
								"hasNextPage": true,
							},
							"nodes": []map[string]interface{}{
								{
									"name":   "v1",
									"target": map[string]interface{}{"__typename": "Commit", "oid": "sha1"},
								},
							},
						},
					},
				},
			}
			b, _ := json.Marshal(resp)
			w.Write(b)
		} else {
			// Pagination follow-up: return remaining tags
			if !strings.Contains(req.Query, `after: "cursor123"`) {
				t.Errorf("pagination query missing cursor, got:\n%s", req.Query)
			}
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"rateLimit": map[string]int{"cost": 1, "remaining": 4998},
					"repository": map[string]interface{}{
						"refs": map[string]interface{}{
							"totalCount": 150,
							"pageInfo": map[string]interface{}{
								"endCursor":   "",
								"hasNextPage": false,
							},
							"nodes": []map[string]interface{}{
								{
									"name":   "v2",
									"target": map[string]interface{}{"__typename": "Commit", "oid": "sha2"},
								},
							},
						},
					},
				},
			}
			b, _ := json.Marshal(resp)
			w.Write(b)
		}
	}))
	defer server.Close()

	client := &GraphQLClient{
		httpClient: server.Client(),
		token:      "test-token",
		endpoint:   server.URL,
	}

	results, err := client.FetchTagsBatch(context.Background(), []string{"big/repo"})
	if err != nil {
		t.Fatalf("FetchTagsBatch error: %v", err)
	}

	bigRepo := results["big/repo"]
	if bigRepo == nil {
		t.Fatal("missing results for big/repo")
	}
	if len(bigRepo.Tags) != 2 {
		t.Errorf("expected 2 tags (page1 + page2), got %d", len(bigRepo.Tags))
	}
	if callNum != 2 {
		t.Errorf("expected 2 GraphQL calls (batch + pagination), got %d", callNum)
	}
}

func TestFetchTagsBatch_GraphQLError_Retries(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
			return
		}
		// Third attempt succeeds
		resp := mockGraphQLResponse(map[string][]ResolvedTag{
			"actions_checkout": {
				{Name: "v1", CommitSHA: "sha1", TagSHA: "sha1", IsAnnotated: false},
			},
		}, 1, 4999)
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}))
	defer server.Close()

	client := &GraphQLClient{
		httpClient: server.Client(),
		token:      "test-token",
		endpoint:   server.URL,
	}

	results, err := client.FetchTagsBatch(context.Background(), []string{"actions/checkout"})
	if err != nil {
		t.Fatalf("FetchTagsBatch should succeed after retries: %v", err)
	}

	if results["actions/checkout"] == nil {
		t.Error("expected results for actions/checkout")
	}
	if callCount.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", callCount.Load())
	}
}

func TestFetchTagsBatch_AllRetriesFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := &GraphQLClient{
		httpClient: server.Client(),
		token:      "test-token",
		endpoint:   server.URL,
	}

	_, err := client.FetchTagsBatch(context.Background(), []string{"actions/checkout"})
	if err == nil {
		t.Fatal("expected error when all retries fail")
	}
}
