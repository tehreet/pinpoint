// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
	SHA        string `json:"sha"`
	RecordedAt string `json:"recorded_at,omitempty"`
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
func Refresh(ctx context.Context, manifestPath string, workflowDir string, doDiscover bool, client *poller.GraphQLClient) (*RefreshResult, error) {
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

	// Write updated manifest
	if err := SaveManifest(manifestPath, m); err != nil {
		return nil, err
	}

	return result, nil
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
