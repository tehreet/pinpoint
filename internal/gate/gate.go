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
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/integrity"
	manifestpkg "github.com/tehreet/pinpoint/internal/manifest"
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
	SHA           string          `json:"sha"`
	Integrity     string          `json:"integrity,omitempty"`
	DiskIntegrity string          `json:"disk_integrity,omitempty"`
	GPGSigned     *bool           `json:"gpg_signed,omitempty"`
	GPGSigner     string          `json:"gpg_signer,omitempty"`
	RecordedAt    string          `json:"recorded_at,omitempty"`
	Type          string          `json:"type,omitempty"`
	Dependencies  []TransitiveDep `json:"dependencies,omitempty"`
}

// TransitiveDep represents a dependency discovered in a composite action.
type TransitiveDep struct {
	Action        string          `json:"action"`
	Ref           string          `json:"ref"`
	Integrity     string          `json:"integrity,omitempty"`
	DiskIntegrity string          `json:"disk_integrity,omitempty"`
	Type          string          `json:"type,omitempty"`
	Dependencies  []TransitiveDep `json:"dependencies"`
}

// GateOptions holds configuration for the gate check.
type GateOptions struct {
	Repo                  string // "owner/repo"
	SHA                   string // commit SHA
	WorkflowRef           string // "owner/repo/.github/workflows/ci.yml@refs/heads/main"
	ManifestPath          string // ".github/actions-lock.json" (default) or ".pinpoint-manifest.json" (legacy)
	Token                 string
	APIURL                string // "https://api.github.com"
	GraphQLURL            string // "https://api.github.com/graphql"
	FailOnMissing         bool
	FailOnMissingExplicit bool   // true if --fail-on-missing was explicitly passed
	FailOnUnpinned        bool
	Integrity             bool   // opt-in: re-download tarballs and verify SHA-256 integrity
	SkipTransitive        bool   // skip transitive dependency verification
	OnDisk                bool   // verify on-disk action content against lockfile
	ActionsDir            string // override for actions cache path
	EventName             string // "push", "pull_request", etc. From GITHUB_EVENT_NAME
	BaseRef               string // "main", "develop", etc. From GITHUB_BASE_REF
	AllWorkflows          bool   // fetch all workflows from .github/workflows/ instead of single workflow
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

	// Step 1-2: Fetch workflow content
	var wfContent []byte
	if opts.AllWorkflows {
		// Fetch all workflow files from .github/workflows/
		fmt.Fprintf(messageWriter, "  ℹ all-workflows mode: scanning all files in .github/workflows/\n")
		files, err := client.listDirectory(ctx, opts.Repo, ".github/workflows", opts.SHA)
		if err != nil {
			return nil, fmt.Errorf("list .github/workflows: %w\n\nEnsure GITHUB_TOKEN has contents:read permission.", err)
		}
		var allContent []byte
		fetched := 0
		for _, f := range files {
			if strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml") {
				content, err := client.fetchFileContent(ctx, opts.Repo, ".github/workflows/"+f, opts.SHA)
				if err != nil {
					fmt.Fprintf(messageWriter, "  ⚠ skipping %s: %v\n", f, err)
					continue
				}
				allContent = append(allContent, '\n')
				allContent = append(allContent, content...)
				fetched++
			}
		}
		if fetched == 0 {
			return nil, fmt.Errorf("no .yml/.yaml files found in .github/workflows/")
		}
		fmt.Fprintf(messageWriter, "  ℹ fetched %d workflow files\n", fetched)
		wfContent = allContent
	} else {
		// Original single-workflow path
		workflowPath, err := parseWorkflowPath(opts.WorkflowRef, opts.Repo)
		if err != nil {
			return nil, fmt.Errorf("parse workflow ref: %w", err)
		}
		wfContent, err = client.fetchFileContent(ctx, opts.Repo, workflowPath, opts.SHA)
		if err != nil {
			return nil, fmt.Errorf("fetch workflow file %q: %w\n\nEnsure GITHUB_TOKEN has contents:read permission and the workflow file exists at the specified commit.", workflowPath, err)
		}
	}

	// Step 3: Determine manifest ref
	// For pull_request events, fetch manifest from base branch to prevent
	// manifest poisoning via fork PRs (see spec 005, section 1.10).
	manifestRef := opts.SHA
	if isPullRequestEvent(opts.EventName) {
		if opts.BaseRef == "" {
			fmt.Fprintf(messageWriter, "⚠ Pull request detected but GITHUB_BASE_REF not set. Falling back to GITHUB_SHA for manifest.\n")
		} else {
			manifestRef = opts.BaseRef
			fmt.Fprintf(messageWriter, "  ℹ Pull request detected. Fetching manifest from base branch %q (not PR merge commit).\n", opts.BaseRef)
		}
	}

	// Step 4: Fetch manifest (using manifestRef, not necessarily opts.SHA)
	isLegacy := false
	manifestContent, err := client.fetchFileContent(ctx, opts.Repo, opts.ManifestPath, manifestRef)
	if err != nil && isNotFound(err) {
		// Try legacy path fallback if using the new default lockfile path
		if opts.ManifestPath == ".github/actions-lock.json" {
			legacyPath := ".pinpoint-manifest.json"
			legacyContent, legacyErr := client.fetchFileContent(ctx, opts.Repo, legacyPath, manifestRef)
			if legacyErr == nil {
				fmt.Fprintf(messageWriter, "ℹ Using legacy manifest path %s\n  Migrate with: pinpoint lock\n", legacyPath)
				manifestContent = legacyContent
				opts.ManifestPath = legacyPath
				isLegacy = true
				err = nil
			}
		}
	}
	if err != nil {
		if isNotFound(err) {
			// Determine effective FailOnMissing: new lockfile path enforces by default
			effectiveFailOnMissing := opts.FailOnMissing
			if !opts.FailOnMissingExplicit && opts.ManifestPath == ".github/actions-lock.json" {
				effectiveFailOnMissing = true
			}
			if effectiveFailOnMissing {
				result.Violations = append(result.Violations, Violation{
					Action:      "manifest",
					Tag:         opts.ManifestPath,
					ExpectedSHA: "exists",
					ActualSHA:   "missing",
				})
				result.Duration = time.Since(start)
				return result, nil
			}
			fmt.Fprintf(messageWriter, "⚠ No manifest found at %s, skipping verification. Generate one with: pinpoint lock\n", opts.ManifestPath)
			result.Duration = time.Since(start)
			return result, nil
		}
		return nil, fmt.Errorf("fetch manifest %q: %w", opts.ManifestPath, err)
	}

	// Apply FailOnMissing default based on lockfile path
	if !opts.FailOnMissingExplicit {
		if isLegacy || opts.ManifestPath != ".github/actions-lock.json" {
			opts.FailOnMissing = false
		} else {
			opts.FailOnMissing = true
		}
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w\n\nThe manifest file at %s is not valid JSON. Regenerate with: pinpoint audit --org <name> --output manifest", err, opts.ManifestPath)
	}

	// Warn if manifest is stale
	if manifest.GeneratedAt != "" {
		if genTime, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err == nil {
			age := time.Since(genTime)
			if age > 30*24*time.Hour {
				days := int(age.Hours() / 24)
				fmt.Fprintf(messageWriter, "  ⚠ Manifest is %d days old (generated %s). Consider regenerating:\n    pinpoint audit --org <name> --output manifest > .pinpoint-manifest.json\n", days, manifest.GeneratedAt)
			}
		}
	}

	// Step 5: Extract action references from workflow (deduplicated)
	allRefs := ExtractUsesDirectives(string(wfContent))
	seen := make(map[string]bool, len(allRefs))
	var rawRefs []string
	for _, r := range allRefs {
		if !seen[r] {
			seen[r] = true
			rawRefs = append(rawRefs, r)
		}
	}

	if len(rawRefs) == 0 {
		fmt.Fprintf(messageWriter, "pinpoint gate: no action references found in workflow. Nothing to verify.\n")
		result.Duration = time.Since(start)
		return result, nil
	}

	// Step 6: Classify, parse, and deduplicate
	type actionRef struct {
		Owner    string
		Repo     string
		Ref      string
		Raw      string
		IsSHA    bool
		IsBranch bool
	}

	var tagRefs []actionRef
	var shaRefs []actionRef
	repoSet := make(map[string]bool)

	for _, raw := range rawRefs {
		owner, repo, ref, _, err := ParseActionRef(raw)
		if err != nil {
			continue // skip local/docker
		}

		key := owner + "/" + repo

		if shaRegexp.MatchString(ref) {
			if opts.FailOnMissing {
				// Verify SHA-pinned refs against lockfile when fail-on-missing is active
				shaRefs = append(shaRefs, actionRef{
					Owner: owner, Repo: repo, Ref: ref, Raw: raw,
					IsSHA: true, IsBranch: false,
				})
			} else {
				// Legacy: trust SHA-pinned refs without verification
				result.Skipped++
				fmt.Fprintf(messageWriter, "  ● %s@%s... → SHA-pinned (inherently safe)\n", key, ref[:7])
			}
			continue
		}

		isBranch := knownBranches[ref]
		tagRefs = append(tagRefs, actionRef{
			Owner: owner, Repo: repo, Ref: ref, Raw: raw,
			IsSHA: false, IsBranch: isBranch,
		})
		repoSet[key] = true
	}

	totalRefs := len(tagRefs) + len(shaRefs) + result.Skipped
	fmt.Fprintf(messageWriter, "pinpoint gate: verifying %d action references against manifest...\n", totalRefs)

	// Step 7: Resolve current tag SHAs via GraphQL (reuse existing poller)
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
			if strings.Contains(err.Error(), "Could not resolve") {
				return nil, fmt.Errorf("resolve tags: %w\n\nOne or more action repositories could not be accessed.\nIf using private actions, ensure GITHUB_TOKEN has read access to those repos,\nor use a PAT with the 'repo' scope.", err)
			}
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

		// Check which requested repos are missing from results (inaccessible)
		for _, repo := range repos {
			if _, ok := fetchResults[repo]; !ok {
				for i, ar := range tagRefs {
					if ar.Owner+"/"+ar.Repo == repo {
						result.Warnings = append(result.Warnings, Warning{
							Action:  repo,
							Ref:     ar.Ref,
							Message: "repository not accessible (may be private or deleted)",
						})
						fmt.Fprintf(messageWriter, "  ⚠ %s@%s → repository not accessible. If private, ensure GITHUB_TOKEN has read access.\n", repo, ar.Ref)
						tagRefs[i].Owner = "" // sentinel: mark as handled
					}
				}
			}
		}
	}

	// Step 7b: Verify SHA-pinned refs against manifest (no API calls needed)
	for _, sr := range shaRefs {
		key := sr.Owner + "/" + sr.Repo
		actionEntry, exists := manifest.Actions[key]
		if !exists {
			result.Violations = append(result.Violations, Violation{
				Action:      key,
				Tag:         sr.Ref,
				ExpectedSHA: "in manifest",
				ActualSHA:   "missing",
			})
			fmt.Fprintf(messageWriter, "  ✗ %s@%s... → not in manifest\n", key, sr.Ref[:7])
			continue
		}

		// Check if any tag entry's SHA matches the pinned SHA
		matched := false
		for _, entry := range actionEntry {
			if entry.SHA == sr.Ref {
				matched = true
				result.Verified++
				fmt.Fprintf(messageWriter, "  ✓ %s@%s... → SHA matches manifest\n", key, sr.Ref[:7])
				break
			}
		}
		if !matched {
			var shas []string
			for tag, entry := range actionEntry {
				shas = append(shas, entry.SHA[:7]+"("+tag+")")
			}
			result.Violations = append(result.Violations, Violation{
				Action:      key,
				Tag:         sr.Ref,
				ExpectedSHA: strings.Join(shas, ", "),
				ActualSHA:   sr.Ref,
			})
			fmt.Fprintf(messageWriter, "  ✗ %s@%s... → SHA not in manifest (expected one of: %s)\n",
				key, sr.Ref[:7], strings.Join(shas, ", "))
		}
	}

	// Step 8: Compare against manifest
	for _, ar := range tagRefs {
		if ar.Owner == "" {
			continue // already handled as inaccessible
		}
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

			// Integrity verification (opt-in): re-download tarball and verify SHA-256
			if opts.Integrity && manifestEntry.Integrity != "" {
				integrityHash, err := manifestpkg.DownloadAndHash(ctx, client.http, opts.APIURL, opts.Token, ar.Owner, ar.Repo, currentSHA)
				if err != nil {
					fmt.Fprintf(messageWriter, "    ⚠ integrity check failed: %v\n", err)
				} else if integrityHash != manifestEntry.Integrity {
					result.Violations = append(result.Violations, Violation{
						Action:      key,
						Tag:         ar.Ref,
						ExpectedSHA: manifestEntry.Integrity,
						ActualSHA:   integrityHash,
					})
					fmt.Fprintf(messageWriter, "    ✗ Content integrity mismatch: tarball hash changed for %s@%s\n", key, ar.Ref)
					fmt.Fprintf(messageWriter, "      EXPECTED: %s\n", manifestEntry.Integrity)
					fmt.Fprintf(messageWriter, "      ACTUAL:   %s\n", integrityHash)
				} else {
					fmt.Fprintf(messageWriter, "    ✓ integrity verified (sha256 match)\n")
				}
			}

			// Transitive dependency verification
			if !opts.SkipTransitive && len(manifestEntry.Dependencies) > 0 {
				deps, _, err := manifestpkg.ResolveTransitiveDeps(ctx, client.http, opts.APIURL, opts.GraphQLURL, opts.Token, key, currentSHA, 0)
				if err != nil {
					fmt.Fprintf(messageWriter, "    ⚠ transitive check failed: %v\n", err)
				} else {
					checkTransitiveDeps(result, manifestEntry.Dependencies, deps, key, ar.Ref)
				}
			}
		}
	}

	// On-disk verification: hash files the runner actually downloaded
	if opts.OnDisk {
		actionsDir := opts.ActionsDir
		if actionsDir == "" {
			runnerWorkspace := os.Getenv("RUNNER_WORKSPACE")
			if runnerWorkspace == "" {
				return nil, fmt.Errorf("on-disk verification requires a GitHub Actions runner environment.\n" +
					"  Set RUNNER_WORKSPACE or use --actions-dir to specify the actions cache path.\n" +
					"  On GitHub-hosted runners: /home/runner/work/_actions\n" +
					"  On self-hosted runners: {runner_root}/_work/_actions")
			}
			actionsDir = filepath.Join(filepath.Dir(runnerWorkspace), "_actions")
		}

		fmt.Fprintf(messageWriter, "  On-disk verification (actions dir: %s)\n", actionsDir)

		for _, ar := range tagRefs {
			if ar.Owner == "" {
				continue
			}
			key := ar.Owner + "/" + ar.Repo

			manifestAction, ok := manifest.Actions[key]
			if !ok {
				continue
			}
			manifestEntry, ok := manifestAction[ar.Ref]
			if !ok {
				continue
			}

			// Check for disk_integrity field
			if manifestEntry.DiskIntegrity == "" {
				result.Warnings = append(result.Warnings, Warning{
					Action:  key,
					Ref:     ar.Ref,
					Message: "disk_integrity not recorded",
				})
				fmt.Fprintf(messageWriter, "    ⚠ %s@%s → disk_integrity not recorded. Regenerate lockfile with: pinpoint lock\n", key, ar.Ref)
				continue
			}

			// Construct expected path
			actionPath := filepath.Join(actionsDir, ar.Owner, ar.Repo, ar.Ref)
			if _, err := os.Stat(actionPath); os.IsNotExist(err) {
				result.Warnings = append(result.Warnings, Warning{
					Action:  key,
					Ref:     ar.Ref,
					Message: fmt.Sprintf("action not found on disk (expected at %s)", actionPath),
				})
				fmt.Fprintf(messageWriter, "    ⚠ %s@%s → not found on disk at %s\n", key, ar.Ref, actionPath)
				continue
			}

			computed, err := integrity.ComputeTreeHash(actionPath)
			if err != nil {
				fmt.Fprintf(messageWriter, "    ⚠ %s@%s → on-disk hash failed: %v\n", key, ar.Ref, err)
				continue
			}

			if computed != manifestEntry.DiskIntegrity {
				result.Violations = append(result.Violations, Violation{
					Action:      key,
					Tag:         ar.Ref,
					ExpectedSHA: manifestEntry.DiskIntegrity,
					ActualSHA:   computed,
				})
				fmt.Fprintf(messageWriter, "    ✗ ON-DISK INTEGRITY MISMATCH: %s@%s\n", key, ar.Ref)
				fmt.Fprintf(messageWriter, "      Expected: %s\n", manifestEntry.DiskIntegrity)
				fmt.Fprintf(messageWriter, "      Actual:   %s\n", computed)
				fmt.Fprintf(messageWriter, "      Path:     %s\n", actionPath)
				fmt.Fprintf(messageWriter, "      The code on disk does not match what was recorded in the lockfile.\n")
				fmt.Fprintf(messageWriter, "      This could indicate tampering, a stale cache, or a supply chain compromise.\n")
			} else {
				fmt.Fprintf(messageWriter, "    ✓ %s@%s → on-disk integrity verified\n", key, ar.Ref)
			}
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

// directoryEntry represents a single entry from the GitHub Contents API directory listing.
type directoryEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

// listDirectory lists files in a directory via the GitHub Contents API.
func (c *httpClient) listDirectory(ctx context.Context, repo, path, sha string) ([]string, error) {
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

	var entries []directoryEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decoding directory listing: %w", err)
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names, nil
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

// isPullRequestEvent returns true for PR-like events where the manifest
// should be fetched from the base branch to prevent manifest poisoning.
func isPullRequestEvent(eventName string) bool {
	return eventName == "pull_request" ||
		eventName == "pull_request_target" ||
		eventName == "merge_group"
}

// checkTransitiveDeps compares expected transitive deps against discovered ones.
func checkTransitiveDeps(result *GateResult, expected []TransitiveDep, discovered []manifestpkg.TransitiveDep, action, tag string) {
	// Build map of expected deps by action
	expectedMap := make(map[string]TransitiveDep)
	for _, dep := range expected {
		expectedMap[dep.Action] = dep
	}

	// Check for changed or new deps
	for _, dep := range discovered {
		if exp, ok := expectedMap[dep.Action]; ok {
			if dep.Ref != exp.Ref {
				result.Violations = append(result.Violations, Violation{
					Action:      action,
					Tag:         tag,
					ExpectedSHA: exp.Ref,
					ActualSHA:   dep.Ref,
				})
				fmt.Fprintf(messageWriter, "    ✗ Transitive dependency changed: %s was %s now %s\n", dep.Action, exp.Ref[:7], dep.Ref[:7])
			}
		}
	}
}

// messageWriter is the destination for gate status messages.
// Defaults to os.Stderr. Tests can override this.
var messageWriter io.Writer = os.Stderr
