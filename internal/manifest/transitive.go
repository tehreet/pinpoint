// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// actionYAML is a minimal struct for parsing action.yml.
type actionYAML struct {
	Runs struct {
		Using string `yaml:"using"`
	} `yaml:"runs"`
}

// compositeYAML is a minimal struct for parsing composite action.yml steps.
type compositeYAML struct {
	Runs struct {
		Steps []struct {
			Uses string `yaml:"uses"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

// ParseActionType parses YAML content of an action.yml and returns the action type.
// Returns "composite", "node16", "node20", "node24", "docker", or "unknown".
func ParseActionType(content []byte) string {
	var a actionYAML
	if err := yaml.Unmarshal(content, &a); err != nil {
		return "unknown"
	}

	using := strings.Trim(a.Runs.Using, "'\"")
	switch using {
	case "composite", "node16", "node20", "node24", "docker":
		return using
	default:
		return "unknown"
	}
}

// ExtractUsesFromComposite parses a composite action.yml and extracts all runs.steps[].uses values.
// Filters out empty strings and local references (starting with "./").
func ExtractUsesFromComposite(content []byte) []string {
	var c compositeYAML
	if err := yaml.Unmarshal(content, &c); err != nil {
		return nil
	}

	var refs []string
	for _, step := range c.Runs.Steps {
		uses := strings.TrimSpace(step.Uses)
		if uses == "" {
			continue
		}
		if strings.HasPrefix(uses, "./") {
			continue
		}
		refs = append(refs, uses)
	}
	return refs
}

var shaRegexp40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// contentAPIResponse represents the GitHub contents API response.
type contentAPIResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// gitRefResponse represents the GitHub git/ref API response.
type gitRefResponse struct {
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
	} `json:"object"`
}

// gitTagResponse represents the GitHub git/tags API response for annotated tag dereferencing.
type gitTagResponse struct {
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

// ResolveTransitiveDeps fetches an action's action.yml and discovers
// inner uses: directives for composite actions.
// Returns the list of transitive dependencies, the action type, and any error.
func ResolveTransitiveDeps(ctx context.Context, client *http.Client, baseURL, graphqlURL, token, action, sha string, depth int) ([]TransitiveDep, string, []byte, error) {
	if depth > 5 {
		return nil, "unknown", nil, fmt.Errorf("transitive dependency depth exceeded (max 5)")
	}

	// Fetch action.yml (try action.yml first, then action.yaml)
	content, err := fetchActionFileForRepo(ctx, client, baseURL, token, action, sha)
	if err != nil {
		return nil, "unknown", nil, nil
	}

	actionType := ParseActionType(content)
	if actionType == "docker" {
		return nil, "docker", content, nil
	}
	if actionType != "composite" {
		return nil, actionType, content, nil
	}

	// Extract uses directives from composite action
	refs := ExtractUsesFromComposite(content)
	if len(refs) == 0 {
		return nil, "composite", content, nil
	}

	var deps []TransitiveDep
	for _, raw := range refs {
		owner, repo, ref, err := parseTransitiveRef(raw)
		if err != nil {
			continue // Skip local/docker refs
		}

		resolvedSHA := ref
		if !shaRegexp40.MatchString(ref) {
			resolved, resolveErr := resolveRefToSHA(ctx, client, baseURL, token, owner, repo, ref)
			if resolveErr != nil {
				continue
			}
			resolvedSHA = resolved
		}

		// Get integrity hash
		integrity, _ := DownloadAndHash(ctx, client, baseURL, token, owner, repo, resolvedSHA)

		// Recurse for this dependency's own transitive deps
		innerDeps, innerType, _, _ := ResolveTransitiveDeps(ctx, client, baseURL, graphqlURL, token, owner+"/"+repo, resolvedSHA, depth+1)

		deps = append(deps, TransitiveDep{
			Action:       owner + "/" + repo,
			Ref:          resolvedSHA,
			Integrity:    integrity,
			Type:         innerType,
			Dependencies: innerDeps,
		})
	}

	return deps, "composite", content, nil
}

// fetchActionFile fetches a file from a repo at a specific SHA using the GitHub Contents API.
func fetchActionFile(ctx context.Context, client *http.Client, baseURL, token, action, sha, filename string) ([]byte, error) {
	url := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", baseURL, action, filename, sha)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found: %s", filename)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, filename)
	}

	var cr contentAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, err
	}

	cleaned := strings.ReplaceAll(cr.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return decoded, nil
}

// fetchActionFileForRepo fetches action.yml or action.yaml from a repo at a specific SHA.
func fetchActionFileForRepo(ctx context.Context, client *http.Client, baseURL, token, repo, sha string) ([]byte, error) {
	content, err := fetchActionFile(ctx, client, baseURL, token, repo, sha, "action.yml")
	if err != nil {
		content, err = fetchActionFile(ctx, client, baseURL, token, repo, sha, "action.yaml")
	}
	return content, err
}

// parseTransitiveRef parses an "owner/repo@ref" string from a uses directive.
// Returns error for local (./) and docker:// refs.
func parseTransitiveRef(raw string) (owner, repo, ref string, err error) {
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "docker://") {
		return "", "", "", fmt.Errorf("local or docker ref: %s", raw)
	}

	parts := strings.SplitN(raw, "@", 2)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("no @ in ref: %s", raw)
	}
	ref = parts[1]
	repoPath := parts[0]

	segments := strings.SplitN(repoPath, "/", 3)
	if len(segments) < 2 {
		return "", "", "", fmt.Errorf("invalid ref: %s", raw)
	}
	return segments[0], segments[1], ref, nil
}

// resolveRefToSHA resolves a tag or branch ref to a commit SHA using the GitHub REST API.
// Tries tags first, then falls back to branches.
func resolveRefToSHA(ctx context.Context, client *http.Client, baseURL, token, owner, repo, ref string) (string, error) {
	// Try tags first (most common for action refs)
	sha, err := resolveGitRef(ctx, client, baseURL, token, owner, repo, "tags/"+ref)
	if err == nil {
		return sha, nil
	}

	// Fall back to branches
	sha, branchErr := resolveGitRef(ctx, client, baseURL, token, owner, repo, "heads/"+ref)
	if branchErr == nil {
		return sha, nil
	}

	return "", fmt.Errorf("ref %q not found as tag or branch: %w", ref, err)
}

// resolveGitRef resolves a fully-qualified git ref (e.g., "tags/v1" or "heads/main") to a commit SHA.
func resolveGitRef(ctx context.Context, client *http.Client, baseURL, token, owner, repo, qualifiedRef string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/ref/%s", baseURL, owner, repo, qualifiedRef)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d resolving ref %s", resp.StatusCode, qualifiedRef)
	}

	var gr gitRefResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", err
	}

	if gr.Object.Type == "tag" {
		return dereferenceAnnotatedTag(ctx, client, baseURL, token, owner, repo, gr.Object.SHA)
	}

	return gr.Object.SHA, nil
}

// dereferenceAnnotatedTag resolves an annotated tag object to its target commit SHA.
func dereferenceAnnotatedTag(ctx context.Context, client *http.Client, baseURL, token, owner, repo, tagSHA string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/tags/%s", baseURL, owner, repo, tagSHA)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d dereferencing tag %s", resp.StatusCode, tagSHA)
	}

	var gt gitTagResponse
	if err := json.NewDecoder(resp.Body).Decode(&gt); err != nil {
		return "", err
	}

	return gt.Object.SHA, nil
}
