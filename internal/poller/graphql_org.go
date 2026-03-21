// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package poller

import (
	"context"
	"encoding/json"
	"fmt"
)

// OrgRepo represents a repository within an organization, including its workflow files.
type OrgRepo struct {
	Name          string
	IsArchived    bool
	IsFork        bool
	DefaultBranch string
	WorkflowFiles []WorkflowFile // nil if no .github/workflows
}

// WorkflowFile represents a single workflow file's content.
type WorkflowFile struct {
	Name    string
	Size    int
	Content string
}

type orgQueryResponse struct {
	Data struct {
		RateLimit struct {
			Cost      int `json:"cost"`
			Remaining int `json:"remaining"`
		} `json:"rateLimit"`
		Organization struct {
			Repositories struct {
				TotalCount int `json:"totalCount"`
				PageInfo   struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []struct {
					Name       string `json:"name"`
					IsArchived bool   `json:"isArchived"`
					IsFork     bool   `json:"isFork"`
					DefaultBranchRef *struct {
						Name string `json:"name"`
					} `json:"defaultBranchRef"`
					Workflows *struct {
						Entries []struct {
							Name   string `json:"name"`
							Object *struct {
								ByteSize int    `json:"byteSize"`
								Text     string `json:"text"`
							} `json:"object"`
						} `json:"entries"`
					} `json:"workflows"`
				} `json:"nodes"`
			} `json:"repositories"`
		} `json:"organization"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func buildOrgQuery(org string, cursor string) string {
	after := ""
	if cursor != "" {
		after = fmt.Sprintf(`, after: %q`, cursor)
	}
	return fmt.Sprintf(`{
  rateLimit { cost remaining }
  organization(login: %q) {
    repositories(first: 50, orderBy: {field: NAME, direction: ASC}%s) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes {
        name
        isArchived
        isFork
        defaultBranchRef { name }
        workflows: object(expression: "HEAD:.github/workflows") {
          ... on Tree {
            entries {
              name
              object {
                ... on Blob { byteSize text }
              }
            }
          }
        }
      }
    }
  }
}`, org, after)
}

// FetchOrgWorkflows returns all workflow file contents for repos in an org.
// Paginates at 50 repos per query. Progress is reported to the provided callback.
func (c *GraphQLClient) FetchOrgWorkflows(ctx context.Context, org string, progress func(fetched, total, cost, remaining int)) ([]OrgRepo, error) {
	var allRepos []OrgRepo
	cursor := ""
	page := 0

	for {
		page++
		query := buildOrgQuery(org, cursor)

		respData, err := c.doGraphQL(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("org query page %d: %w", page, err)
		}

		// Check for GraphQL errors
		for _, gqlErr := range respData.Errors {
			return nil, fmt.Errorf("GraphQL error: %s", gqlErr.Message)
		}

		// Re-parse as the org-specific response structure
		fullJSON, err := json.Marshal(respData)
		if err != nil {
			return nil, fmt.Errorf("re-marshaling response: %w", err)
		}

		var orgResp orgQueryResponse
		if err := json.Unmarshal(fullJSON, &orgResp); err != nil {
			return nil, fmt.Errorf("parsing org response: %w", err)
		}

		repos := orgResp.Data.Organization.Repositories
		totalCount := repos.TotalCount

		for _, node := range repos.Nodes {
			repo := OrgRepo{
				Name:       node.Name,
				IsArchived: node.IsArchived,
				IsFork:     node.IsFork,
			}
			if node.DefaultBranchRef != nil {
				repo.DefaultBranch = node.DefaultBranchRef.Name
			}

			if node.Workflows != nil {
				for _, entry := range node.Workflows.Entries {
					if entry.Object != nil {
						repo.WorkflowFiles = append(repo.WorkflowFiles, WorkflowFile{
							Name:    entry.Name,
							Size:    entry.Object.ByteSize,
							Content: entry.Object.Text,
						})
					}
				}
			}

			allRepos = append(allRepos, repo)
		}

		if progress != nil {
			progress(len(allRepos), totalCount,
				orgResp.Data.RateLimit.Cost,
				orgResp.Data.RateLimit.Remaining)
		}

		if !repos.PageInfo.HasNextPage {
			break
		}
		cursor = repos.PageInfo.EndCursor
	}

	return allRepos, nil
}
