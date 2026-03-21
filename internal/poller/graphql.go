// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package poller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxBatchSize = 50
const maxPaginationPages = 3 // 300 tags max per repo

// GraphQLClient handles batched tag fetching via the GitHub GraphQL API.
type GraphQLClient struct {
	httpClient *http.Client
	token      string
	endpoint   string
}

// NewGraphQLClient creates a client for the GitHub GraphQL API.
func NewGraphQLClient(token string) *GraphQLClient {
	return &GraphQLClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		token:      token,
		endpoint:   "https://api.github.com/graphql",
	}
}

// SetEndpoint overrides the GraphQL endpoint (for testing).
func (c *GraphQLClient) SetEndpoint(endpoint string) {
	c.endpoint = endpoint
}

type graphqlRequest struct {
	Query string `json:"query"`
}

type graphqlResponse struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type refsPayload struct {
	Refs struct {
		TotalCount int `json:"totalCount"`
		PageInfo   struct {
			EndCursor   string `json:"endCursor"`
			HasNextPage bool   `json:"hasNextPage"`
		} `json:"pageInfo"`
		Nodes []struct {
			Name   string `json:"name"`
			Target struct {
				TypeName string `json:"__typename"`
				OID      string `json:"oid"`
				Target   *struct {
					TypeName string `json:"__typename"`
					OID      string `json:"oid"`
				} `json:"target,omitempty"`
			} `json:"target"`
		} `json:"nodes"`
	} `json:"refs"`
}

type rateLimitPayload struct {
	Cost      int `json:"cost"`
	Remaining int `json:"remaining"`
}

// repoToAlias converts "owner/repo" to a valid GraphQL alias.
func repoToAlias(ownerRepo string) string {
	alias := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, ownerRepo)
	if len(alias) > 0 && alias[0] >= '0' && alias[0] <= '9' {
		alias = "_" + alias
	}
	return alias
}

// buildAliasMap generates unique aliases for a set of repos, handling collisions.
func buildAliasMap(repos []string) map[string]string {
	aliasToRepo := make(map[string]string)
	for _, repo := range repos {
		alias := repoToAlias(repo)
		if _, exists := aliasToRepo[alias]; exists {
			for i := 2; ; i++ {
				candidate := fmt.Sprintf("%s_%d", alias, i)
				if _, exists := aliasToRepo[candidate]; !exists {
					alias = candidate
					break
				}
			}
		}
		aliasToRepo[alias] = repo
	}
	return aliasToRepo
}

// buildBatchQuery constructs a GraphQL query for multiple repos.
func buildBatchQuery(aliasToRepo map[string]string) string {
	var b strings.Builder
	b.WriteString("{\n  rateLimit { cost remaining }\n")
	for alias, repo := range aliasToRepo {
		parts := strings.SplitN(repo, "/", 2)
		owner, name := parts[0], parts[1]
		fmt.Fprintf(&b, `  %s: repository(owner: %q, name: %q) {
    refs(refPrefix: "refs/tags/", first: 100) {
      totalCount
      pageInfo { endCursor hasNextPage }
      nodes {
        name
        target {
          __typename
          oid
          ... on Tag { target { __typename oid } }
        }
      }
    }
  }
`, alias, owner, name)
	}
	b.WriteString("}")
	return b.String()
}

func buildPaginationQuery(owner, name, cursor string) string {
	return fmt.Sprintf(`{
  rateLimit { cost remaining }
  repository(owner: %q, name: %q) {
    refs(refPrefix: "refs/tags/", first: 100, after: %q) {
      totalCount
      pageInfo { endCursor hasNextPage }
      nodes {
        name
        target {
          __typename
          oid
          ... on Tag { target { __typename oid } }
        }
      }
    }
  }
}`, owner, name, cursor)
}

// FetchTagsBatch resolves all tags for up to N repos using batched GraphQL calls.
// repos is a slice of "owner/repo" strings.
func (c *GraphQLClient) FetchTagsBatch(ctx context.Context, repos []string) (map[string]*FetchResult, error) {
	results := make(map[string]*FetchResult)

	// Split into batches of maxBatchSize
	for i := 0; i < len(repos); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(repos) {
			end = len(repos)
		}
		batch := repos[i:end]

		batchResults, err := c.fetchBatch(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("batch %d: %w", i/maxBatchSize, err)
		}

		for k, v := range batchResults {
			results[k] = v
		}
	}

	return results, nil
}

func (c *GraphQLClient) fetchBatch(ctx context.Context, repos []string) (map[string]*FetchResult, error) {
	aliasToRepo := buildAliasMap(repos)
	query := buildBatchQuery(aliasToRepo)

	respData, err := c.doGraphQL(ctx, query)
	if err != nil {
		return nil, err
	}

	results := make(map[string]*FetchResult)

	// Log errors but don't fail the batch
	for _, gqlErr := range respData.Errors {
		fmt.Fprintf(os.Stderr, "GraphQL error: %s\n", gqlErr.Message)
	}

	// Parse rate limit
	if raw, ok := respData.Data["rateLimit"]; ok {
		var rl rateLimitPayload
		if err := json.Unmarshal(raw, &rl); err == nil {
			fmt.Fprintf(os.Stderr, "[graphql] cost=%d remaining=%d\n", rl.Cost, rl.Remaining)
		}
	}

	// Parse each repo's results
	for alias, repo := range aliasToRepo {
		raw, ok := respData.Data[alias]
		if !ok {
			// This repo had an error, skip it
			continue
		}

		var payload refsPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse response for %s: %v\n", repo, err)
			continue
		}

		tags := parseRefNodes(payload)

		// Handle pagination
		if payload.Refs.PageInfo.HasNextPage {
			parts := strings.SplitN(repo, "/", 2)
			moreTags, err := c.paginateRepo(ctx, parts[0], parts[1], payload.Refs.PageInfo.EndCursor, 1)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: pagination failed for %s: %v\n", repo, err)
			} else {
				tags = append(tags, moreTags...)
			}
		}

		results[repo] = &FetchResult{Tags: tags}
	}

	return results, nil
}

func (c *GraphQLClient) paginateRepo(ctx context.Context, owner, repo, cursor string, page int) ([]ResolvedTag, error) {
	if page >= maxPaginationPages {
		fmt.Fprintf(os.Stderr, "Warning: %s/%s has >%d tags, stopping pagination\n",
			owner, repo, maxPaginationPages*100)
		return nil, nil
	}

	query := buildPaginationQuery(owner, repo, cursor)
	respData, err := c.doGraphQL(ctx, query)
	if err != nil {
		return nil, err
	}

	raw, ok := respData.Data["repository"]
	if !ok {
		return nil, fmt.Errorf("no repository data in pagination response")
	}

	var payload refsPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parsing pagination response: %w", err)
	}

	tags := parseRefNodes(payload)

	if payload.Refs.PageInfo.HasNextPage {
		moreTags, err := c.paginateRepo(ctx, owner, repo, payload.Refs.PageInfo.EndCursor, page+1)
		if err != nil {
			return tags, err
		}
		tags = append(tags, moreTags...)
	}

	return tags, nil
}

func parseRefNodes(payload refsPayload) []ResolvedTag {
	var tags []ResolvedTag
	for _, node := range payload.Refs.Nodes {
		rt := ResolvedTag{Name: node.Name}
		switch node.Target.TypeName {
		case "Commit":
			rt.CommitSHA = node.Target.OID
			rt.TagSHA = node.Target.OID
			rt.IsAnnotated = false
		case "Tag":
			rt.TagSHA = node.Target.OID
			rt.IsAnnotated = true
			if node.Target.Target != nil {
				rt.CommitSHA = node.Target.Target.OID
			}
		}
		tags = append(tags, rt)
	}
	return tags
}

func (c *GraphQLClient) doGraphQL(ctx context.Context, query string) (*graphqlResponse, error) {
	reqBody, err := json.Marshal(graphqlRequest{Query: query})
	if err != nil {
		return nil, fmt.Errorf("marshaling query: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(reqBody))
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("GraphQL request: %w", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading response: %w", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("GraphQL API returned %d: %s", resp.StatusCode, string(body))
			continue
		}

		var gqlResp graphqlResponse
		if err := json.Unmarshal(body, &gqlResp); err != nil {
			return nil, fmt.Errorf("decoding response: %w", err)
		}

		return &gqlResp, nil
	}

	return nil, lastErr
}
