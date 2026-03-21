// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/poller"
)

// GateResult holds the verification outcome.
type GateResult struct {
	Verified   int
	Skipped    int
	Violations []Violation
	Warnings   []Warning
	Duration   time.Duration
}

// Violation represents an integrity violation (tag repointed vs manifest).
type Violation struct {
	Action      string // "aquasecurity/trivy-action"
	Tag         string // "0.35.0"
	ExpectedSHA string // from manifest
	ActualSHA   string // from live API
}

// Warning represents a non-fatal issue.
type Warning struct {
	Action  string
	Ref     string
	Message string // "not in manifest", "branch-pinned", etc.
}

// Manifest represents the .pinpoint-manifest.json file.
type Manifest struct {
	Version     int                                 `json:"version"`
	GeneratedAt string                              `json:"generated_at"`
	Actions     map[string]map[string]ManifestEntry `json:"actions"`
}

// ManifestEntry holds a single tag→SHA mapping.
type ManifestEntry struct {
	SHA        string `json:"sha"`
	RecordedAt string `json:"recorded_at,omitempty"`
}

// GateOptions holds configuration for the gate check.
type GateOptions struct {
	Repo           string // "owner/repo"
	SHA            string // commit SHA
	WorkflowRef    string // "owner/repo/.github/workflows/ci.yml@refs/heads/main"
	ManifestPath   string // ".pinpoint-manifest.json"
	Token          string
	APIURL         string // "https://api.github.com"
	GraphQLURL     string // "https://api.github.com/graphql"
	FailOnMissing  bool
	FailOnUnpinned bool
}

var shaRegexp = regexp.MustCompile(`^[0-9a-f]{40}$`)

// knownBranches is a set of common branch names used to detect branch-pinned refs.
var knownBranches = map[string]bool{
	"main": true, "master": true, "develop": true, "dev": true,
	"trunk": true, "release": true, "staging": true, "production": true,
}

// RunGate performs the pre-execution verification.
func RunGate(ctx context.Context, opts GateOptions) (*GateResult, error) {
	start := time.Now()
	result := &GateResult{}

	client := &httpClient{
		token:   opts.Token,
		baseURL: opts.APIURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}

	// Step 1: Parse workflow path from GITHUB_WORKFLOW_REF
	workflowPath, err := parseWorkflowPath(opts.WorkflowRef, opts.Repo)
	if err != nil {
		return nil, fmt.Errorf("parse workflow ref: %w", err)
	}

	// Step 2: Fetch workflow file
	wfContent, err := client.fetchFileContent(ctx, opts.Repo, workflowPath, opts.SHA)
	if err != nil {
		return nil, fmt.Errorf("fetch workflow file %q: %w\n\nEnsure GITHUB_TOKEN has contents:read permission and the workflow file exists at the specified commit.", workflowPath, err)
	}

	// Step 3: Fetch manifest
	manifestContent, err := client.fetchFileContent(ctx, opts.Repo, opts.ManifestPath, opts.SHA)
	if err != nil {
		if isNotFound(err) {
			if opts.FailOnMissing {
				result.Violations = append(result.Violations, Violation{
					Action:      "manifest",
					Tag:         opts.ManifestPath,
					ExpectedSHA: "exists",
					ActualSHA:   "missing",
				})
				result.Duration = time.Since(start)
				return result, nil
			}
			fmt.Fprintf(messageWriter, "⚠ No manifest found at %s, skipping verification. Generate one with: pinpoint audit --org <name> --output manifest\n", opts.ManifestPath)
			result.Duration = time.Since(start)
			return result, nil
		}
		return nil, fmt.Errorf("fetch manifest %q: %w", opts.ManifestPath, err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w\n\nThe manifest file at %s is not valid JSON. Regenerate with: pinpoint audit --org <name> --output manifest", err, opts.ManifestPath)
	}

	// Step 4: Extract action references from workflow
	rawRefs := ExtractUsesDirectives(string(wfContent))

	// Step 5: Classify, parse, and deduplicate
	type actionRef struct {
		Owner    string
		Repo     string
		Ref      string
		Raw      string
		IsSHA    bool
		IsBranch bool
	}

	var tagRefs []actionRef
	repoSet := make(map[string]bool)

	for _, raw := range rawRefs {
		owner, repo, ref, _, err := ParseActionRef(raw)
		if err != nil {
			continue // skip local/docker
		}

		key := owner + "/" + repo

		if shaRegexp.MatchString(ref) {
			// SHA-pinned: inherently safe
			result.Skipped++
			fmt.Fprintf(messageWriter, "  ● %s@%s... → SHA-pinned (inherently safe)\n", key, ref[:7])
			continue
		}

		isBranch := knownBranches[ref]
		tagRefs = append(tagRefs, actionRef{
			Owner: owner, Repo: repo, Ref: ref, Raw: raw,
			IsSHA: false, IsBranch: isBranch,
		})
		repoSet[key] = true
	}

	totalRefs := len(tagRefs) + result.Skipped
	fmt.Fprintf(messageWriter, "pinpoint gate: verifying %d action references against manifest...\n", totalRefs)

	// Step 6: Resolve current tag SHAs via GraphQL (reuse existing poller)
	var tagMap map[string]map[string]string // repo → tag → sha
	if len(repoSet) > 0 {
		repos := make([]string, 0, len(repoSet))
		for r := range repoSet {
			repos = append(repos, r)
		}

		graphqlClient := poller.NewGraphQLClient(opts.Token)
		graphqlClient.SetEndpoint(opts.GraphQLURL)

		fetchResults, err := graphqlClient.FetchTagsBatch(ctx, repos)
		if err != nil {
			return nil, fmt.Errorf("resolve tags via GraphQL: %w\n\nEnsure GITHUB_TOKEN has read access to the action repositories.", err)
		}

		tagMap = make(map[string]map[string]string)
		for repo, fr := range fetchResults {
			if fr == nil {
				continue
			}
			tagMap[repo] = make(map[string]string)
			for _, tag := range fr.Tags {
				tagMap[repo][tag.Name] = tag.CommitSHA
			}
		}
	}

	// Step 7: Compare against manifest
	for _, ar := range tagRefs {
		key := ar.Owner + "/" + ar.Repo

		if ar.IsBranch {
			result.Warnings = append(result.Warnings, Warning{
				Action: key, Ref: ar.Ref, Message: "branch-pinned (mutable)",
			})
			if opts.FailOnUnpinned {
				result.Violations = append(result.Violations, Violation{
					Action:      key,
					Tag:         ar.Ref,
					ExpectedSHA: "SHA-pinned",
					ActualSHA:   "branch:" + ar.Ref,
				})
				fmt.Fprintf(messageWriter, "  ✗ %s@%s → branch-pinned (mutable ref, use --fail-on-unpinned to enforce)\n", key, ar.Ref)
			} else {
				fmt.Fprintf(messageWriter, "  ⚠ %s@%s → branch-pinned (mutable ref)\n", key, ar.Ref)
			}
			continue
		}

		// Look up in manifest
		manifestAction, ok := manifest.Actions[key]
		if !ok {
			result.Warnings = append(result.Warnings, Warning{
				Action: key, Ref: ar.Ref, Message: "not in manifest",
			})
			if opts.FailOnMissing {
				result.Violations = append(result.Violations, Violation{
					Action:      key,
					Tag:         ar.Ref,
					ExpectedSHA: "in manifest",
					ActualSHA:   "missing",
				})
				fmt.Fprintf(messageWriter, "  ✗ %s@%s → not in manifest\n", key, ar.Ref)
			} else {
				fmt.Fprintf(messageWriter, "  ⊘ %s@%s → not in manifest (skipping, use --fail-on-missing to enforce)\n", key, ar.Ref)
			}
			continue
		}

		manifestEntry, ok := manifestAction[ar.Ref]
		if !ok {
			result.Warnings = append(result.Warnings, Warning{
				Action: key, Ref: ar.Ref, Message: "tag not in manifest",
			})
			if opts.FailOnMissing {
				result.Violations = append(result.Violations, Violation{
					Action:      key,
					Tag:         ar.Ref,
					ExpectedSHA: "in manifest",
					ActualSHA:   "missing",
				})
				fmt.Fprintf(messageWriter, "  ✗ %s@%s → tag not in manifest\n", key, ar.Ref)
			} else {
				fmt.Fprintf(messageWriter, "  ⊘ %s@%s → tag not in manifest (skipping, use --fail-on-missing to enforce)\n", key, ar.Ref)
			}
			continue
		}

		// Look up current SHA from GraphQL
		repoTags := tagMap[key]
		currentSHA := ""
		if repoTags != nil {
			currentSHA = repoTags[ar.Ref]
		}
		if currentSHA == "" {
			result.Warnings = append(result.Warnings, Warning{
				Action: key, Ref: ar.Ref, Message: "tag not found on remote",
			})
			fmt.Fprintf(messageWriter, "  ⚠ %s@%s → tag not found on remote\n", key, ar.Ref)
			continue
		}

		if currentSHA != manifestEntry.SHA {
			result.Violations = append(result.Violations, Violation{
				Action:      key,
				Tag:         ar.Ref,
				ExpectedSHA: manifestEntry.SHA,
				ActualSHA:   currentSHA,
			})
			fmt.Fprintf(messageWriter, "  ✗ %s@%s\n", key, ar.Ref)
			fmt.Fprintf(messageWriter, "    EXPECTED: %s (from manifest", manifestEntry.SHA)
			if manifestEntry.RecordedAt != "" {
				fmt.Fprintf(messageWriter, ", recorded %s", manifestEntry.RecordedAt)
			}
			fmt.Fprintf(messageWriter, ")\n")
			fmt.Fprintf(messageWriter, "    ACTUAL:   %s (resolved just now)\n", currentSHA)
			fmt.Fprintf(messageWriter, "    ⚠ TAG HAS BEEN REPOINTED — possible supply chain attack\n")
		} else {
			result.Verified++
			fmt.Fprintf(messageWriter, "  ✓ %s@%s → %s... (matches manifest)\n", key, ar.Ref, currentSHA[:7])
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// parseWorkflowPath extracts the workflow file path from GITHUB_WORKFLOW_REF.
// Input:  "coreweave/ml-platform/.github/workflows/ci.yml@refs/heads/main"
// Output: ".github/workflows/ci.yml"
func parseWorkflowPath(workflowRef, repo string) (string, error) {
	if workflowRef == "" {
		return "", fmt.Errorf("workflow ref is empty. Set GITHUB_WORKFLOW_REF or use --workflow-ref")
	}

	// Split on "@", take the first part
	parts := strings.SplitN(workflowRef, "@", 2)
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid workflow ref: %s", workflowRef)
	}
	fullPath := parts[0]

	// Strip the "{owner}/{repo}/" prefix
	prefix := repo + "/"
	if !strings.HasPrefix(fullPath, prefix) {
		return "", fmt.Errorf("workflow ref %q does not start with repo %q", workflowRef, repo)
	}

	return strings.TrimPrefix(fullPath, prefix), nil
}

// ExtractUsesDirectives extracts all `uses:` values from workflow YAML.
func ExtractUsesDirectives(workflowContent string) []string {
	re := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*['"]?([^'"#\s]+)['"]?`)
	matches := re.FindAllStringSubmatch(workflowContent, -1)
	var refs []string
	for _, m := range matches {
		refs = append(refs, m[1])
	}
	return refs
}

// ParseActionRef parses "owner/repo@ref" or "owner/repo/path@ref".
// Returns owner, repo, ref, and whether it's a reusable workflow.
func ParseActionRef(raw string) (owner, repo, ref string, isWorkflow bool, err error) {
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "docker://") {
		return "", "", "", false, fmt.Errorf("local or docker action: %s", raw)
	}

	parts := strings.SplitN(raw, "@", 2)
	if len(parts) != 2 {
		return "", "", "", false, fmt.Errorf("no @ in ref: %s", raw)
	}
	ref = parts[1]
	repoPath := parts[0]

	// Check for reusable workflow: owner/repo/.github/workflows/file.yml
	if strings.Contains(repoPath, "/.github/workflows/") {
		segments := strings.SplitN(repoPath, "/", 3)
		if len(segments) < 2 {
			return "", "", "", false, fmt.Errorf("invalid reusable workflow ref: %s", raw)
		}
		return segments[0], segments[1], ref, true, nil
	}

	// Standard action: owner/repo or owner/repo/subpath
	segments := strings.SplitN(repoPath, "/", 3)
	if len(segments) < 2 {
		return "", "", "", false, fmt.Errorf("invalid action ref: %s", raw)
	}
	return segments[0], segments[1], ref, false, nil
}

// httpClient is a minimal REST client for fetching files from the GitHub API.
type httpClient struct {
	token   string
	baseURL string
	http    *http.Client
}

// contentResponse represents the GitHub contents API response.
type contentResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// notFoundError is returned when the API returns 404.
type notFoundError struct {
	path string
}

func (e *notFoundError) Error() string {
	return fmt.Sprintf("not found: %s", e.path)
}

func isNotFound(err error) bool {
	_, ok := err.(*notFoundError)
	return ok
}

// fetchFileContent fetches a file from a repo at a specific commit.
func (c *httpClient) fetchFileContent(ctx context.Context, repo, path, sha string) ([]byte, error) {
	url := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", c.baseURL, repo, path, sha)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &notFoundError{path: path}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d for %s: %s", resp.StatusCode, path, string(body))
	}

	var cr contentResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if cr.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q for %s (expected base64)", cr.Encoding, path)
	}

	// GitHub base64 content has newlines; use StdEncoding after stripping them
	cleaned := strings.ReplaceAll(cr.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 content: %w", err)
	}

	return decoded, nil
}

// messageWriter is the destination for gate status messages.
// Defaults to os.Stderr. Tests can override this.
var messageWriter io.Writer = os.Stderr
