// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ActionRef represents a GitHub Action reference found in a workflow file.
type ActionRef struct {
	Owner    string
	Repo     string
	Ref      string // Tag, branch, or SHA
	IsPinned bool   // True if ref looks like a full SHA
	IsBranch bool   // True if ref looks like a branch name
	Source   string // Workflow file where it was found
	Raw      string // The full uses: string
}

// Full returns the "owner/repo" string.
func (a ActionRef) Full() string {
	return a.Owner + "/" + a.Repo
}

var (
	// Matches: uses: owner/repo@ref or uses: owner/repo/path@ref
	usesRe = regexp.MustCompile(`uses:\s*['"]?([a-zA-Z0-9\-_.]+)/([a-zA-Z0-9\-_.]+)(?:/[^@\s'"]*)?@([a-zA-Z0-9\-_.]+)['"]?`)
	// Full 40-char hex SHA
	shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// tagLikeRe matches refs that look like version tags: v1, v1.2, v1.2.3, 1.0
	tagLikeRe = regexp.MustCompile(`^v?\d+(\.\d+)*$`)
)

// looksLikeBranch returns true if a non-SHA ref appears to be a branch.
func looksLikeBranch(ref string) bool {
	switch ref {
	case "main", "master", "develop", "dev", "trunk", "release", "staging", "production":
		return true
	}
	if strings.Contains(ref, "/") {
		return true
	}
	if !tagLikeRe.MatchString(ref) {
		return true
	}
	return false
}

// FromWorkflowDir scans a directory of workflow files and extracts all Action references.
func FromWorkflowDir(dir string) ([]ActionRef, error) {
	var refs []ActionRef
	seen := make(map[string]bool) // Dedupe by owner/repo@ref

	patterns := []string{
		filepath.Join(dir, "*.yml"),
		filepath.Join(dir, "*.yaml"),
	}

	for _, pattern := range patterns {
		files, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("globbing %s: %w", pattern, err)
		}

		for _, file := range files {
			fileRefs, err := fromFile(file)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", file, err)
			}
			for _, ref := range fileRefs {
				key := ref.Raw
				if !seen[key] {
					seen[key] = true
					refs = append(refs, ref)
				}
			}
		}
	}

	return refs, nil
}

// FromFile extracts Action references from a single workflow file.
func fromFile(path string) ([]ActionRef, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var refs []ActionRef
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		matches := usesRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		ref := ActionRef{
			Owner:    matches[1],
			Repo:     matches[2],
			Ref:      matches[3],
			IsPinned: shaRe.MatchString(matches[3]),
			IsBranch: !shaRe.MatchString(matches[3]) && looksLikeBranch(matches[3]),
			Source:   filepath.Base(path),
			Raw:      matches[0],
		}

		// Skip GitHub's own actions (actions/checkout, etc.) — they have
		// immutable tags and are managed by GitHub. Optional: make configurable.
		// For now, include everything — users can filter in config.
		refs = append(refs, ref)
	}

	return refs, scanner.Err()
}

// GroupByRepo groups discovered refs by owner/repo, collecting all unique tags.
func GroupByRepo(refs []ActionRef) map[string][]string {
	repoTags := make(map[string]map[string]bool)
	for _, ref := range refs {
		full := ref.Full()
		if _, ok := repoTags[full]; !ok {
			repoTags[full] = make(map[string]bool)
		}
		if !ref.IsPinned {
			repoTags[full][ref.Ref] = true
		}
	}

	result := make(map[string][]string)
	for repo, tags := range repoTags {
		var tagList []string
		for tag := range tags {
			tagList = append(tagList, tag)
		}
		sort.Strings(tagList)
		result[repo] = tagList
	}
	return result
}

// Summary prints a human-readable summary of discovered actions.
func Summary(refs []ActionRef) string {
	grouped := GroupByRepo(refs)
	var b strings.Builder

	var repos []string
	for repo := range grouped {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	pinned := 0
	unpinned := 0
	for _, ref := range refs {
		if ref.IsPinned {
			pinned++
		} else {
			unpinned++
		}
	}

	fmt.Fprintf(&b, "Discovered %d action references across %d repos\n", len(refs), len(grouped))
	fmt.Fprintf(&b, "  SHA-pinned: %d (safe from tag repointing)\n", pinned)
	fmt.Fprintf(&b, "  Tag-based:  %d (vulnerable to tag repointing)\n\n", unpinned)

	for _, repo := range repos {
		tags := grouped[repo]
		if len(tags) == 0 {
			fmt.Fprintf(&b, "  %s — all references SHA-pinned ✓\n", repo)
		} else {
			fmt.Fprintf(&b, "  %s — monitoring tags: %s\n", repo, strings.Join(tags, ", "))
		}
	}

	return b.String()
}

// GenerateConfig produces a YAML config snippet from discovered actions.
func GenerateConfig(refs []ActionRef) string {
	grouped := GroupByRepo(refs)
	var b strings.Builder

	b.WriteString("actions:\n")

	var repos []string
	for repo := range grouped {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	for _, repo := range repos {
		tags := grouped[repo]
		if len(tags) == 0 {
			continue // All pinned, nothing to monitor
		}
		b.WriteString(fmt.Sprintf("  - repo: %s\n", repo))
		b.WriteString("    tags:\n")
		for _, tag := range tags {
			b.WriteString(fmt.Sprintf("      - %q\n", tag))
		}
	}

	return b.String()
}
