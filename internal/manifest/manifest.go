// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/discover"
	"github.com/tehreet/pinpoint/internal/poller"
)

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

// Change describes a single modification found during refresh/verify.
type Change struct {
	Action string
	Tag    string
	Type   string // "updated", "added", "missing_tag"
	OldSHA string
	NewSHA string
	Source string // workflow file where discovered (for added)
}

// RefreshResult holds the outcome of a refresh or verify operation.
type RefreshResult struct {
	Unchanged int
	Updated   int
	Added     int
	Missing   int
	Changes   []Change
}

// IntegrityOptions controls whether integrity hashing and transitive
// dependency resolution are performed during refresh.
// Pass nil to skip integrity (SHA-only lockfile, version 1).
type IntegrityOptions struct {
	HTTPClient        *http.Client
	BaseURL           string // e.g. "https://api.github.com"
	GraphQLURL        string
	Token             string
	SkipDiskIntegrity bool // when true, only compute tarball integrity (no tree hash)
}

// LoadManifest reads and parses a manifest file from disk.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest %s: %w\n\nTo create a manifest, run: pinpoint audit --org <name> --output manifest > .pinpoint-manifest.json", path, err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", path, err)
	}

	if m.Actions == nil {
		m.Actions = make(map[string]map[string]ManifestEntry)
	}

	return &m, nil
}

// SaveManifest writes the manifest to disk atomically.
func SaveManifest(path string, m *Manifest) error {
	m.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming manifest: %w", err)
	}

	return nil
}

// Refresh updates an existing manifest in-place by resolving current tag SHAs.
// If discover is true, it also scans workflowDir for new action references.
// If integrityOpts is non-nil, tarball integrity hashes and transitive deps are computed.
func Refresh(ctx context.Context, manifestPath string, workflowDir string, doDiscover bool, client *poller.GraphQLClient, integrityOpts ...*IntegrityOptions) (*RefreshResult, error) {
	var iOpts *IntegrityOptions
	if len(integrityOpts) > 0 {
		iOpts = integrityOpts[0]
	}
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}

	// Track which entries were newly discovered (empty SHA = needs first resolution)
	discoverSources := make(map[string]string) // "repo@tag" → source file

	// Discover new actions from workflows if requested
	if doDiscover && workflowDir != "" {
		refs, err := discover.FromWorkflowDir(workflowDir)
		if err != nil {
			return nil, fmt.Errorf("discovering actions: %w", err)
		}
		for _, ref := range refs {
			repo := ref.Full()
			tag := ref.Ref
			if ref.IsPinned {
				continue // Skip SHA-pinned refs
			}
			if _, ok := m.Actions[repo]; !ok {
				m.Actions[repo] = make(map[string]ManifestEntry)
			}
			if _, exists := m.Actions[repo][tag]; !exists {
				// Will be resolved below; mark as new with empty SHA
				m.Actions[repo][tag] = ManifestEntry{}
				discoverSources[repo+"@"+tag] = ref.Source
			}
		}
	}

	// Collect unique repos
	repos := make([]string, 0, len(m.Actions))
	for repo := range m.Actions {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	if len(repos) == 0 {
		return &RefreshResult{}, nil
	}

	// Resolve current tags via GraphQL
	tagResults, err := client.FetchTagsBatch(ctx, repos)
	if err != nil {
		return nil, fmt.Errorf("resolving tags: %w", err)
	}

	result := &RefreshResult{}
	now := time.Now().UTC().Format(time.RFC3339)

	for _, repo := range repos {
		tags := m.Actions[repo]
		fetchResult := tagResults[repo]

		// Build lookup from fetched tags
		liveTags := make(map[string]string) // tag name → commit SHA
		if fetchResult != nil {
			for _, t := range fetchResult.Tags {
				liveTags[t.Name] = t.CommitSHA
			}
		}

		for tag, entry := range tags {
			liveSHA, found := liveTags[tag]
			if !found {
				// Tag doesn't exist on remote
				if entry.SHA == "" {
					// Was a newly discovered tag that doesn't resolve — remove it
					delete(tags, tag)
				} else {
					result.Missing++
					result.Changes = append(result.Changes, Change{
						Action: repo,
						Tag:    tag,
						Type:   "missing_tag",
						OldSHA: entry.SHA,
					})
				}
				continue
			}

			if entry.SHA == "" {
				// Newly discovered action being resolved for the first time
				entry.SHA = liveSHA
				entry.RecordedAt = now
				tags[tag] = entry
				result.Added++
				result.Changes = append(result.Changes, Change{
					Action: repo,
					Tag:    tag,
					Type:   "added",
					NewSHA: liveSHA,
					Source: discoverSources[repo+"@"+tag],
				})
			} else if entry.SHA != liveSHA {
				// Tag SHA changed
				result.Updated++
				result.Changes = append(result.Changes, Change{
					Action: repo,
					Tag:    tag,
					Type:   "updated",
					OldSHA: entry.SHA,
					NewSHA: liveSHA,
				})
				entry.SHA = liveSHA
				entry.RecordedAt = now
				tags[tag] = entry
			} else {
				result.Unchanged++
			}
		}
	}

	// Compute integrity hashes and transitive deps if requested
	if iOpts != nil {
		m.Version = 2

		// Collect all unique action+SHA pairs for batch tarball hashing
		var actionRefs []ActionRef
		seen := make(map[string]bool)
		for _, repo := range repos {
			tags := m.Actions[repo]
			for _, entry := range tags {
				if entry.SHA == "" {
					continue
				}
				parts := strings.SplitN(repo, "/", 2)
				if len(parts) != 2 {
					continue
				}
				key := repo + "@" + entry.SHA
				if !seen[key] {
					seen[key] = true
					actionRefs = append(actionRefs, ActionRef{
						Owner: parts[0],
						Repo:  parts[1],
						SHA:   entry.SHA,
					})
				}
			}
		}

		// Batch download and hash all tarballs concurrently
		// Use dual-hash (tarball + tree) unless SkipDiskIntegrity is set
		type hashEntry struct {
			integrity     string
			diskIntegrity string
		}
		hashMap := make(map[string]hashEntry)

		if iOpts.SkipDiskIntegrity {
			results := DownloadAndHashBatch(ctx, iOpts.HTTPClient, iOpts.BaseURL, iOpts.Token, actionRefs)
			for key, hr := range results {
				if hr.Err == nil {
					hashMap[key] = hashEntry{integrity: hr.Integrity}
				}
			}
		} else {
			results := DownloadExtractAndTreeHashBatch(ctx, iOpts.HTTPClient, iOpts.BaseURL, iOpts.Token, actionRefs)
			for key, hr := range results {
				if hr.Err == nil {
					hashMap[key] = hashEntry{integrity: hr.Integrity, diskIntegrity: hr.DiskIntegrity}
				}
			}
		}

		// Apply integrity hashes and resolve transitive deps
		for _, repo := range repos {
			tags := m.Actions[repo]
			for tag, entry := range tags {
				if entry.SHA == "" {
					continue
				}

				// Look up integrity hash from batch results
				key := repo + "@" + entry.SHA
				if he, ok := hashMap[key]; ok {
					entry.Integrity = he.integrity
					entry.DiskIntegrity = he.diskIntegrity
				}

				// Resolve transitive deps and action type
				deps, actionType, err := ResolveTransitiveDeps(ctx, iOpts.HTTPClient, iOpts.BaseURL, iOpts.GraphQLURL, iOpts.Token, repo, entry.SHA, 0)
				if err == nil {
					entry.Type = actionType
					entry.Dependencies = deps
				}

				tags[tag] = entry
			}
		}
	}

	// Write updated manifest
	if err := SaveManifest(manifestPath, m); err != nil {
		return nil, err
	}

	return result, nil
}

// PrintDependencyTree prints the lockfile dependency tree to the given writer.
func PrintDependencyTree(m *Manifest, lockfilePath string, w io.Writer) {
	// Count actions and transitive deps
	totalActions := 0
	totalTransitive := 0
	for _, tags := range m.Actions {
		for _, entry := range tags {
			totalActions++
			totalTransitive += countTransitiveDeps(entry.Dependencies)
		}
	}

	fmt.Fprintf(w, "%s (%d actions, %d transitive)\n\n", lockfilePath, totalActions, totalTransitive)

	// Collect and sort action+tag pairs
	type actionTag struct {
		action string
		tag    string
		entry  ManifestEntry
	}
	var items []actionTag
	for action, tags := range m.Actions {
		for tag, entry := range tags {
			items = append(items, actionTag{action, tag, entry})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].action != items[j].action {
			return items[i].action < items[j].action
		}
		return items[i].tag < items[j].tag
	})

	for _, item := range items {
		sha := item.entry.SHA
		if len(sha) > 7 {
			sha = sha[:7]
		}
		actionType := item.entry.Type
		if actionType == "" {
			actionType = "unknown"
		}
		fmt.Fprintf(w, "%s@%s (%s...) [%s]\n", item.action, item.tag, sha, actionType)
		printDeps(w, item.entry.Dependencies, "  ")
	}
}

func printDeps(w io.Writer, deps []TransitiveDep, indent string) {
	for _, dep := range deps {
		ref := dep.Ref
		if len(ref) > 7 {
			ref = ref[:7]
		}
		depType := dep.Type
		if depType == "" {
			depType = "unknown"
		}
		// Extract tag from ref if it looks like a version, otherwise use SHA
		fmt.Fprintf(w, "%s└── %s (%s...) [%s]\n", indent, dep.Action, ref, depType)
		printDeps(w, dep.Dependencies, indent+"    ")
	}
}

func countTransitiveDeps(deps []TransitiveDep) int {
	count := len(deps)
	for _, dep := range deps {
		count += countTransitiveDeps(dep.Dependencies)
	}
	return count
}

// Verify checks if the manifest matches current live tag SHAs without modifying it.
func Verify(ctx context.Context, manifestPath string, client *poller.GraphQLClient) (*RefreshResult, error) {
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}

	// Collect unique repos
	repos := make([]string, 0, len(m.Actions))
	for repo := range m.Actions {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	if len(repos) == 0 {
		return &RefreshResult{}, nil
	}

	// Resolve current tags via GraphQL
	tagResults, err := client.FetchTagsBatch(ctx, repos)
	if err != nil {
		return nil, fmt.Errorf("resolving tags: %w", err)
	}

	result := &RefreshResult{}

	for _, repo := range repos {
		tags := m.Actions[repo]
		fetchResult := tagResults[repo]

		liveTags := make(map[string]string)
		if fetchResult != nil {
			for _, t := range fetchResult.Tags {
				liveTags[t.Name] = t.CommitSHA
			}
		}

		for tag, entry := range tags {
			liveSHA, found := liveTags[tag]
			if !found {
				result.Missing++
				result.Changes = append(result.Changes, Change{
					Action: repo,
					Tag:    tag,
					Type:   "missing_tag",
					OldSHA: entry.SHA,
				})
				continue
			}

			if entry.SHA != liveSHA {
				result.Updated++
				result.Changes = append(result.Changes, Change{
					Action: repo,
					Tag:    tag,
					Type:   "updated",
					OldSHA: entry.SHA,
					NewSHA: liveSHA,
				})
			} else {
				result.Unchanged++
			}
		}
	}

	return result, nil
}
