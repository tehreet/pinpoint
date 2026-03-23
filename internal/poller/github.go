// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only
//
// This file is part of Pinpoint.
//
// Pinpoint is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, version 3.
//
// Pinpoint is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.

package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHubClient handles authenticated GitHub API requests with ETag caching.
type GitHubClient struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// NewGitHubClient creates a client for the GitHub REST API.
func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		token:      token,
		baseURL:    "https://api.github.com",
	}
}

// SetBaseURL overrides the base URL (for testing).
func (c *GitHubClient) SetBaseURL(url string) {
	c.baseURL = url
}

// TagRef represents a git tag reference from the GitHub API.
type TagRef struct {
	Ref    string `json:"ref"`
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
		URL  string `json:"url"`
	} `json:"object"`
}

// TagObject represents an annotated tag object (needs dereferencing).
type TagObject struct {
	Tag    string `json:"tag"`
	SHA    string `json:"sha"`
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// ResolvedTag holds the final commit SHA for a tag after dereferencing.
type ResolvedTag struct {
	Name      string
	CommitSHA string
	TagSHA    string // The ref SHA (may differ for annotated tags)
	IsAnnotated bool
}

// FetchResult wraps the result of a tag fetch, including cache status.
type FetchResult struct {
	Tags       []ResolvedTag
	NotModified bool   // True if ETag matched (304)
	ETag       string  // New ETag for caching
}

// FetchAllTags retrieves all tag refs for a repo, using ETag for conditional requests.
// Returns all tags with their resolved commit SHAs.
func (c *GitHubClient) FetchAllTags(ctx context.Context, owner, repo, etag string) (*FetchResult, error) {
	result := &FetchResult{}
	var allRefs []TagRef

	page := 1
	for {
		url := fmt.Sprintf("%s/repos/%s/%s/git/matching-refs/tags", c.baseURL, owner, repo)
		if page > 1 {
			url += fmt.Sprintf("?page=%d&per_page=100", page)
		} else {
			url += "?per_page=100"
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(req)
		if etag != "" && page == 1 {
			req.Header.Set("If-None-Match", etag)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching tags for %s/%s: %w", owner, repo, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotModified {
			result.NotModified = true
			result.ETag = etag
			return result, nil
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API returned %d for %s/%s: %s", resp.StatusCode, owner, repo, string(body))
		}

		if page == 1 {
			result.ETag = resp.Header.Get("ETag")
		}

		var refs []TagRef
		if err := json.NewDecoder(resp.Body).Decode(&refs); err != nil {
			return nil, fmt.Errorf("decoding tag refs: %w", err)
		}

		allRefs = append(allRefs, refs...)

		// Check for pagination via Link header
		if !hasNextPage(resp.Header.Get("Link")) {
			break
		}
		page++
	}

	// Resolve each tag to its final commit SHA
	for _, ref := range allRefs {
		tagName := strings.TrimPrefix(ref.Ref, "refs/tags/")
		resolved := ResolvedTag{
			Name:   tagName,
			TagSHA: ref.Object.SHA,
		}

		if ref.Object.Type == "tag" {
			// Annotated tag — dereference to commit
			commitSHA, err := c.dereferenceTag(ctx, owner, repo, ref.Object.SHA)
			if err != nil {
				return nil, fmt.Errorf("dereferencing annotated tag %s: %w", tagName, err)
			}
			resolved.CommitSHA = commitSHA
			resolved.IsAnnotated = true
		} else {
			// Lightweight tag — SHA is already the commit
			resolved.CommitSHA = ref.Object.SHA
		}

		result.Tags = append(result.Tags, resolved)
	}

	return result, nil
}

// dereferenceTag follows an annotated tag object to get the actual commit SHA.
func (c *GitHubClient) dereferenceTag(ctx context.Context, owner, repo, tagSHA string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/tags/%s", c.baseURL, owner, repo, tagSHA)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var tagObj TagObject
	if err := json.NewDecoder(resp.Body).Decode(&tagObj); err != nil {
		return "", err
	}

	// Handle (rare) nested tags by recursing
	if tagObj.Object.Type == "tag" {
		return c.dereferenceTag(ctx, owner, repo, tagObj.Object.SHA)
	}

	return tagObj.Object.SHA, nil
}

// CompareCommits checks if newSHA is a descendant of oldSHA on the default branch.
func (c *GitHubClient) CompareCommits(ctx context.Context, owner, repo, oldSHA, newSHA string) (isDescendant bool, ahead int, behind int, err error) {
	url := fmt.Sprintf("%s/repos/%s/%s/compare/%s...%s", c.baseURL, owner, repo, oldSHA, newSHA)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, 0, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, 0, fmt.Errorf("compare returned %d", resp.StatusCode)
	}

	var result struct {
		Status      string `json:"status"`
		AheadBy     int    `json:"ahead_by"`
		BehindBy    int    `json:"behind_by"`
		TotalCommits int   `json:"total_commits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, 0, 0, err
	}

	// "ahead" means newSHA is ahead of oldSHA (descendant)
	// "behind" means newSHA is behind (ancestor)
	// "diverged" means they share a common ancestor but diverged
	isDescendant = result.Status == "ahead"
	return isDescendant, result.AheadBy, result.BehindBy, nil
}

// GetCommitInfo retrieves metadata about a specific commit.
type CommitInfo struct {
	SHA         string    `json:"sha"`
	AuthorName  string
	AuthorEmail string
	CommitDate  time.Time
	Message     string
	ParentSHA   string // First parent SHA, empty if root commit
	GPGVerified bool   // Whether the commit has a verified GPG signature
	GPGSigner   string // Committer login when GPG-verified
}

func (c *GitHubClient) GetCommitInfo(ctx context.Context, owner, repo, sha string) (*CommitInfo, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", c.baseURL, owner, repo, sha)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("commit info returned %d", resp.StatusCode)
	}

	var raw struct {
		SHA    string `json:"sha"`
		Commit struct {
			Author struct {
				Name  string    `json:"name"`
				Email string    `json:"email"`
				Date  time.Time `json:"date"`
			} `json:"author"`
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
			Message      string `json:"message"`
			Verification struct {
				Verified bool `json:"verified"`
			} `json:"verification"`
		} `json:"commit"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
		Committer *struct {
			Login string `json:"login"`
		} `json:"committer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	info := &CommitInfo{
		SHA:         raw.SHA,
		AuthorName:  raw.Commit.Author.Name,
		AuthorEmail: raw.Commit.Author.Email,
		CommitDate:  raw.Commit.Committer.Date,
		Message:     raw.Commit.Message,
		GPGVerified: raw.Commit.Verification.Verified,
	}
	if len(raw.Parents) > 0 {
		info.ParentSHA = raw.Parents[0].SHA
	}
	if raw.Committer != nil && raw.Commit.Verification.Verified {
		info.GPGSigner = raw.Committer.Login
	}
	return info, nil
}

// GetFileSize retrieves the size of a file at a specific ref.
func (c *GitHubClient) GetFileSize(ctx context.Context, owner, repo, path, ref string) (int64, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s", c.baseURL, owner, repo, path, ref)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return -1, nil // File doesn't exist at this ref
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("contents API returned %d", resp.StatusCode)
	}

	var content struct {
		Size int64 `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return 0, err
	}

	return content.Size, nil
}

// RateLimit returns current GitHub API rate limit status.
type RateLimitInfo struct {
	Remaining int
	Limit     int
	ResetsAt  time.Time
}

func (c *GitHubClient) GetRateLimit(ctx context.Context) (*RateLimitInfo, error) {
	url := fmt.Sprintf("%s/rate_limit", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Rate struct {
			Limit     int   `json:"limit"`
			Remaining int   `json:"remaining"`
			Reset     int64 `json:"reset"`
		} `json:"rate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &RateLimitInfo{
		Remaining: result.Rate.Remaining,
		Limit:     result.Rate.Limit,
		ResetsAt:  time.Unix(result.Rate.Reset, 0),
	}, nil
}

// OrgPolicy holds the GitHub Actions policy settings for an organization.
type OrgPolicy struct {
	SHAPinningRequired bool   `json:"sha_pinning_required"`
	AllowedActions     string `json:"allowed_actions"`
}

// CheckImmutableRelease checks if the latest release of a repo is immutable.
// Returns true/false, or nil if the repo has no releases.
func (c *GitHubClient) CheckImmutableRelease(ctx context.Context, owner, repo string) (*bool, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=1", c.baseURL, owner, repo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching releases for %s/%s: %w", owner, repo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("releases API returned %d for %s/%s: %s", resp.StatusCode, owner, repo, string(body))
	}

	var releases []struct {
		Immutable bool `json:"immutable"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("decoding releases: %w", err)
	}

	if len(releases) == 0 {
		return nil, nil
	}

	return &releases[0].Immutable, nil
}

// CheckOrgPolicy checks if the org has SHA pinning enforcement enabled.
// Returns nil if the token doesn't have admin:org scope (403).
func (c *GitHubClient) CheckOrgPolicy(ctx context.Context, org string) (*OrgPolicy, error) {
	url := fmt.Sprintf("%s/orgs/%s/actions/permissions", c.baseURL, org)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking org policy for %s: %w", org, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("org policy API returned %d for %s: %s", resp.StatusCode, org, string(body))
	}

	var policy OrgPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return nil, fmt.Errorf("decoding org policy: %w", err)
	}

	return &policy, nil
}

func (c *GitHubClient) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func hasNextPage(linkHeader string) bool {
	if linkHeader == "" {
		return false
	}
	return strings.Contains(linkHeader, `rel="next"`)
}
