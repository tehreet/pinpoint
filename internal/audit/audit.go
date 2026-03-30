// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/poller"
)

// AuditResult holds the complete audit output.
type AuditResult struct {
	Org                  string
	ScannedAt            time.Time
	TotalRepos           int
	ActiveRepos          int
	ArchivedSkipped      int
	ForkedSkipped        int
	ReposWithWorkflows   int
	TotalWorkflowFiles   int
	TotalRefs            int
	SHAPinned            int
	TagPinned            int
	BranchPinned         int
	UniqueActions        []ActionSummary
	OrgPolicy            *poller.OrgPolicy // nil if couldn't check
	WorkflowsWithGate    int
	WorkflowsWithoutGate int
	UnprotectedWorkflows []string // "repo-name/.github/workflows/ci.yml"
	DangerousTriggers    []DangerousTriggerFinding
}

// ActionSummary describes a unique upstream action's usage and risk.
type ActionSummary struct {
	Repo             string
	UsedInRepos      int
	Refs             []RefSummary
	ImmutableRelease *bool
	Risk             string
	Notes            []string
}

// RefSummary describes a specific ref used for an action.
type RefSummary struct {
	Ref   string
	Type  string // "sha", "tag", "branch"
	Count int
}

// Options controls audit behavior.
type Options struct {
	Org           string
	Output        string // "report", "config", "manifest", "json"
	SkipUpstream  bool
	ProgressFunc  func(format string, args ...any) // writes to stderr
}

var (
	usesRe = regexp.MustCompile(`uses:\s*['"]?([a-zA-Z0-9\-_.]+)/([a-zA-Z0-9\-_.]+)(?:/[^@\s'"]*)?@([a-zA-Z0-9\-_.]+)['"]?`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// tagRe matches version tags: v1, v1.2, v1.2.3, 1.0.0
	// Must be ONLY digits, dots, and optional v prefix — no hyphens, no letters after.
	tagRe = regexp.MustCompile(`^v?\d+(\.\d+)*$`)
)

// knownCompromised is a hardcoded list of previously compromised actions.
var knownCompromised = map[string]string{
	"tj-actions/changed-files":  "Compromised March 2025 (CVE-2025-30066)",
	"reviewdog/action-setup":    "Compromised March 2025",
	"aquasecurity/trivy-action": "Compromised Feb+March 2026 (CVE-2026-28353)",
}

// actionRef is an internal type for parsed action references.
type actionRef struct {
	Owner string
	Repo  string
	Ref   string
	Type  string // "sha", "tag", "branch"
}

// RunAudit performs a full org-wide security posture scan.
func RunAudit(ctx context.Context, opts Options, graphqlClient *poller.GraphQLClient, restClient *poller.GitHubClient) (*AuditResult, error) {
	progress := opts.ProgressFunc
	if progress == nil {
		progress = func(string, ...any) {}
	}

	result := &AuditResult{
		Org:       opts.Org,
		ScannedAt: time.Now().UTC(),
	}

	// Phase 1: Fetch all org repos + workflow contents
	progress("Scanning %s...\n", opts.Org)

	repos, err := graphqlClient.FetchOrgWorkflows(ctx, opts.Org, func(fetched, total, cost, remaining int) {
		pages := (total + 49) / 50
		currentPage := (fetched + 49) / 50
		progress("  [%d/%d] Fetched %d/%d repos (cost: %d point, remaining: %d)\n",
			currentPage, pages, fetched, total, cost, remaining)
	})
	if err != nil {
		return nil, fmt.Errorf("fetching org repos: %w", err)
	}

	result.TotalRepos = len(repos)

	// Filter and count repos
	var activeRepos []poller.OrgRepo
	for _, repo := range repos {
		if repo.IsArchived {
			result.ArchivedSkipped++
			continue
		}
		if repo.IsFork {
			result.ForkedSkipped++
			continue
		}
		activeRepos = append(activeRepos, repo)
	}
	result.ActiveRepos = len(activeRepos)

	// Phase 2: Extract action references
	// Track per-repo usage and per-ref counts
	type refKey struct {
		owner string
		repo  string
		ref   string
	}

	refCounts := make(map[refKey]int)                    // ref → total count
	actionRepos := make(map[string]map[string]bool)      // owner/repo → set of org repos using it

	for _, repo := range activeRepos {
		if len(repo.WorkflowFiles) == 0 {
			continue
		}
		result.ReposWithWorkflows++
		result.TotalWorkflowFiles += len(repo.WorkflowFiles)

		// Track which actions this repo uses (for UsedInRepos count)
		repoActions := make(map[string]bool)

		for _, wf := range repo.WorkflowFiles {
			if hasGateStep(wf.Content) {
				result.WorkflowsWithGate++
			} else {
				result.WorkflowsWithoutGate++
				result.UnprotectedWorkflows = append(result.UnprotectedWorkflows, repo.Name+"/.github/workflows/"+wf.Name)
			}

			refs := extractRefs(wf.Content)
			for _, ref := range refs {
				result.TotalRefs++
				switch ref.Type {
				case "sha":
					result.SHAPinned++
				case "tag":
					result.TagPinned++
				case "branch":
					result.BranchPinned++
				}

				full := ref.Owner + "/" + ref.Repo
				repoActions[full] = true

				key := refKey{owner: ref.Owner, repo: ref.Repo, ref: ref.Ref}
				refCounts[key]++
			}
		}

		for action := range repoActions {
			if actionRepos[action] == nil {
				actionRepos[action] = make(map[string]bool)
			}
			actionRepos[action][repo.Name] = true
		}
	}

	// Phase 2.5: Detect dangerous triggers
	for _, repo := range activeRepos {
		for _, wf := range repo.WorkflowFiles {
			findings := DetectDangerousTriggers(repo.Name, wf.Name, wf.Content)
			result.DangerousTriggers = append(result.DangerousTriggers, findings...)
		}
	}

	progress("\nAnalyzing %d workflow files...\n", result.TotalWorkflowFiles)
	progress("  Found %d action references across %d unique actions.\n", result.TotalRefs, len(actionRepos))

	// Build ActionSummary list
	for action, repoSet := range actionRepos {
		parts := strings.SplitN(action, "/", 2)
		summary := ActionSummary{
			Repo:        action,
			UsedInRepos: len(repoSet),
		}

		// Collect refs for this action
		refsMap := make(map[string]*RefSummary)
		for key, count := range refCounts {
			if key.owner == parts[0] && key.repo == parts[1] {
				if existing, ok := refsMap[key.ref]; ok {
					existing.Count += count
				} else {
					refsMap[key.ref] = &RefSummary{
						Ref:   key.ref,
						Type:  classifyRef(key.ref),
						Count: count,
					}
				}
			}
		}
		for _, rs := range refsMap {
			summary.Refs = append(summary.Refs, *rs)
		}
		sort.Slice(summary.Refs, func(i, j int) bool {
			return summary.Refs[i].Count > summary.Refs[j].Count
		})

		// Check known compromised
		if note, ok := knownCompromised[action]; ok {
			summary.Notes = append(summary.Notes, note)
		}

		result.UniqueActions = append(result.UniqueActions, summary)
	}

	// Sort by usage (most used first)
	sort.Slice(result.UniqueActions, func(i, j int) bool {
		return result.UniqueActions[i].UsedInRepos > result.UniqueActions[j].UsedInRepos
	})

	// Phase 3: Check upstream action security (immutable releases)
	if !opts.SkipUpstream {
		progress("\nChecking upstream action security (%d actions)...\n", len(result.UniqueActions))
		for i := range result.UniqueActions {
			if (i+1)%50 == 0 || i+1 == len(result.UniqueActions) {
				progress("  [%d/%d] checking immutable releases...\n", i+1, len(result.UniqueActions))
			}
			parts := strings.SplitN(result.UniqueActions[i].Repo, "/", 2)
			if len(parts) != 2 {
				continue
			}
			immutable, err := restClient.CheckImmutableRelease(ctx, parts[0], parts[1])
			if err != nil {
				// Non-fatal: log and continue
				progress("  Warning: could not check %s: %v\n", result.UniqueActions[i].Repo, err)
				continue
			}
			result.UniqueActions[i].ImmutableRelease = immutable
		}
	}

	// Score all actions
	for i := range result.UniqueActions {
		result.UniqueActions[i].Risk = scoreAction(result.UniqueActions[i])
	}

	// Phase 4: Check org policy
	progress("\nChecking org policy...\n")
	policy, err := restClient.CheckOrgPolicy(ctx, opts.Org)
	if err != nil {
		progress("  Warning: could not check org policy: %v\n", err)
	} else if policy == nil {
		progress("  admin:org scope not available, skipping policy check.\n")
	} else {
		result.OrgPolicy = policy
	}

	return result, nil
}

// hasGateStep checks if a workflow contains a pinpoint gate step.
func hasGateStep(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "pinpoint gate") ||
		strings.Contains(lower, "pinpoint@")
}

// extractRefs parses workflow content and returns all action references.
func extractRefs(content string) []actionRef {
	var refs []actionRef
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		matches := usesRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		refs = append(refs, actionRef{
			Owner: matches[1],
			Repo:  matches[2],
			Ref:   matches[3],
			Type:  classifyRef(matches[3]),
		})
	}
	return refs
}

// classifyRef determines if a ref is a SHA, tag, or branch.
func classifyRef(ref string) string {
	if shaRe.MatchString(ref) {
		return "sha"
	}
	// Refs with slashes are always branches (release/v1.0, feature/foo)
	if strings.Contains(ref, "/") {
		return "branch"
	}
	if tagRe.MatchString(ref) {
		return "tag"
	}
	return "branch"
}

func isKnownCompromised(repo string) bool {
	_, ok := knownCompromised[repo]
	return ok
}

func countSHAPinned(refs []RefSummary) int {
	total := 0
	for _, r := range refs {
		if r.Type == "sha" {
			total += r.Count
		}
	}
	return total
}

func countTotalRefs(refs []RefSummary) int {
	total := 0
	for _, r := range refs {
		total += r.Count
	}
	return total
}

func hasBranchRef(refs []RefSummary) bool {
	for _, r := range refs {
		if r.Type == "branch" {
			return true
		}
	}
	return false
}

func scoreAction(action ActionSummary) string {
	score := 0

	// High usage + no pinning = high risk
	if action.UsedInRepos > 10 {
		total := countTotalRefs(action.Refs)
		if total > 0 {
			pinRate := float64(countSHAPinned(action.Refs)) / float64(total)
			if pinRate < 0.1 {
				score += 30
			}
		}
	}

	// No immutable releases
	if action.ImmutableRelease != nil && !*action.ImmutableRelease {
		score += 20
	}

	// Branch-pinned refs exist
	if hasBranchRef(action.Refs) {
		score += 40
	}

	// Previously compromised
	if isKnownCompromised(action.Repo) {
		score += 30
	}

	switch {
	case score >= 50:
		return "critical"
	case score >= 30:
		return "high"
	case score >= 15:
		return "medium"
	default:
		return "low"
	}
}

// FormatReport produces the human-readable audit report.
func FormatReport(r *AuditResult) string {
	var b strings.Builder

	// Header box
	b.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(&b, "║  PINPOINT AUDIT: %-43s║\n", r.Org)
	b.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(&b, "║  Repos scanned:           %-34s║\n", fmtInt(r.TotalRepos))
	fmt.Fprintf(&b, "║  Repos with workflows:    %-34s║\n", fmtInt(r.ReposWithWorkflows))
	fmt.Fprintf(&b, "║  Repos skipped:           %-34s║\n",
		fmt.Sprintf("%s (archived: %s, fork: %s)", fmtInt(r.ArchivedSkipped+r.ForkedSkipped), fmtInt(r.ArchivedSkipped), fmtInt(r.ForkedSkipped)))
	fmt.Fprintf(&b, "║  Total workflow files:    %-34s║\n", fmtInt(r.TotalWorkflowFiles))
	fmt.Fprintf(&b, "║  Total action references: %-34s║\n", fmtInt(r.TotalRefs))
	b.WriteString("║                                                              ║\n")
	b.WriteString("║  PINNING STATUS                                              ║\n")

	total := r.TotalRefs
	if total == 0 {
		total = 1 // avoid division by zero
	}
	fmt.Fprintf(&b, "║  SHA-pinned:     %s  (%4.1f%%)                              ║\n",
		padLeft(fmtInt(r.SHAPinned), 6), float64(r.SHAPinned)/float64(total)*100)
	fmt.Fprintf(&b, "║  Tag-pinned:    %s  (%4.1f%%)  <- vulnerable to repointing  ║\n",
		padLeft(fmtInt(r.TagPinned), 7), float64(r.TagPinned)/float64(total)*100)
	fmt.Fprintf(&b, "║  Branch-pinned:    %s  (%4.1f%%)  <- DANGEROUS                 ║\n",
		padLeft(fmtInt(r.BranchPinned), 4), float64(r.BranchPinned)/float64(total)*100)
	b.WriteString("║                                                              ║\n")

	// Unique actions + immutable stats
	immutableCount := 0
	notImmutableCount := 0
	for _, a := range r.UniqueActions {
		if a.ImmutableRelease != nil {
			if *a.ImmutableRelease {
				immutableCount++
			} else {
				notImmutableCount++
			}
		}
	}
	fmt.Fprintf(&b, "║  UNIQUE UPSTREAM ACTIONS: %-34s║\n", fmtInt(len(r.UniqueActions)))
	if immutableCount+notImmutableCount > 0 {
		fmt.Fprintf(&b, "║  With immutable releases:  %s (%4.1f%%)                        ║\n",
			padLeft(fmtInt(immutableCount), 4),
			float64(immutableCount)/float64(immutableCount+notImmutableCount)*100)
		fmt.Fprintf(&b, "║  Without immutable releases: %s (%4.1f%%)                      ║\n",
			padLeft(fmtInt(notImmutableCount), 4),
			float64(notImmutableCount)/float64(immutableCount+notImmutableCount)*100)
	}

	// Org policy
	b.WriteString("║                                                              ║\n")
	b.WriteString("║  ORG POLICY                                                  ║\n")
	if r.OrgPolicy != nil {
		enforced := "No"
		if r.OrgPolicy.SHAPinningRequired {
			enforced = "Yes"
		}
		fmt.Fprintf(&b, "║  SHA pinning enforced: %-37s║\n", enforced)
	} else {
		b.WriteString("║  SHA pinning enforced: (could not check - needs admin:org)   ║\n")
	}
	b.WriteString("╚══════════════════════════════════════════════════════════════╝\n")

	// Top 20 most used actions
	b.WriteString("\nTOP 20 MOST USED ACTIONS (by repo count):\n")
	limit := 20
	if len(r.UniqueActions) < limit {
		limit = len(r.UniqueActions)
	}
	for i := 0; i < limit; i++ {
		a := r.UniqueActions[i]
		totalRefs := countTotalRefs(a.Refs)
		shaCount := countSHAPinned(a.Refs)
		tagCount := 0
		for _, ref := range a.Refs {
			if ref.Type == "tag" {
				tagCount += ref.Count
			}
		}
		shaPercent := 0.0
		tagPercent := 0.0
		if totalRefs > 0 {
			shaPercent = float64(shaCount) / float64(totalRefs) * 100
			tagPercent = float64(tagCount) / float64(totalRefs) * 100
		}
		immutableStr := "N/A"
		if a.ImmutableRelease != nil {
			if *a.ImmutableRelease {
				immutableStr = "YES"
			} else {
				immutableStr = "NO"
			}
		}
		fmt.Fprintf(&b, "  %-35s %4d repos  tag-pinned:%.0f%% sha-pinned:%.0f%%  immutable:%s\n",
			a.Repo, a.UsedInRepos, tagPercent, shaPercent, immutableStr)
	}

	// High risk actions
	var highRisk []ActionSummary
	for _, a := range r.UniqueActions {
		if (a.Risk == "critical" || a.Risk == "high") && a.UsedInRepos > 10 {
			highRisk = append(highRisk, a)
		}
	}
	if len(highRisk) > 0 {
		b.WriteString("\nHIGH RISK ACTIONS (unpinned + no immutable releases + used in >10 repos):\n")
		for _, a := range highRisk {
			totalRefs := countTotalRefs(a.Refs)
			shaCount := countSHAPinned(a.Refs)
			shaPercent := 0.0
			if totalRefs > 0 {
				shaPercent = float64(shaCount) / float64(totalRefs) * 100
			}
			immutableStr := "N/A"
			if a.ImmutableRelease != nil {
				if *a.ImmutableRelease {
					immutableStr = "YES"
				} else {
					immutableStr = "NO"
				}
			}
			noteStr := ""
			if len(a.Notes) > 0 {
				noteStr = "   " + strings.Join(a.Notes, ", ")
			}
			fmt.Fprintf(&b, "  ⚠ %-33s %4d repos  %.0f%% pinned  immutable:%s%s\n",
				a.Repo, a.UsedInRepos, shaPercent, immutableStr, noteStr)
		}
	}

	// Branch-pinned actions
	var branchPinned []ActionSummary
	for _, a := range r.UniqueActions {
		if hasBranchRef(a.Refs) {
			branchPinned = append(branchPinned, a)
		}
	}
	if len(branchPinned) > 0 {
		b.WriteString("\nBRANCH-PINNED ACTIONS (immediate risk):\n")
		for _, a := range branchPinned {
			for _, ref := range a.Refs {
				if ref.Type == "branch" {
					fmt.Fprintf(&b, "  🚨 %s@%s   %d repos  <- mutable branch ref\n",
						a.Repo, ref.Ref, a.UsedInRepos)
				}
			}
		}
	}

	// Dangerous triggers
	if len(r.DangerousTriggers) > 0 {
		b.WriteString("\nDANGEROUS WORKFLOW TRIGGERS:\n")
		for _, f := range r.DangerousTriggers {
			var icon string
			switch f.Risk {
			case "critical":
				icon = "CRITICAL"
			case "high":
				icon = "HIGH"
			default:
				icon = "MEDIUM"
			}
			fmt.Fprintf(&b, "  %-8s  %s/%s    %s\n", icon, f.Repo, f.WorkflowFile, f.Reason)
		}
	}

	// Recommendations
	b.WriteString("\nRECOMMENDATIONS:\n")
	if r.OrgPolicy == nil || !r.OrgPolicy.SHAPinningRequired {
		b.WriteString("  1. Enable SHA pinning enforcement at the org level\n")
	}
	b.WriteString(fmt.Sprintf("  2. Pin the top 20 actions by repo count (covers majority of attack surface)\n"))
	if r.BranchPinned > 0 {
		b.WriteString(fmt.Sprintf("  3. Replace branch-pinned refs immediately (%d references)\n", r.BranchPinned))
	}
	fmt.Fprintf(&b, "  4. Enable pinpoint monitoring for %d upstream actions\n", len(r.UniqueActions))
	fmt.Fprintf(&b, "     -> Run: pinpoint audit --org %s --output config > .pinpoint.yml\n", r.Org)

	// Unprotected workflows
	if r.WorkflowsWithoutGate > 0 {
		fmt.Fprintf(&b, "\nUNPROTECTED WORKFLOWS (no pinpoint gate detected):\n")
		fmt.Fprintf(&b, "  %d of %d workflows have no gate step.\n",
			r.WorkflowsWithoutGate, r.WorkflowsWithGate+r.WorkflowsWithoutGate)
		limit := 20
		if len(r.UnprotectedWorkflows) < limit {
			limit = len(r.UnprotectedWorkflows)
		}
		for i := 0; i < limit; i++ {
			fmt.Fprintf(&b, "  %s\n", r.UnprotectedWorkflows[i])
		}
		if len(r.UnprotectedWorkflows) > 20 {
			fmt.Fprintf(&b, "  ... and %d more.\n", len(r.UnprotectedWorkflows)-20)
		}
	}

	return b.String()
}

// FormatConfig produces a .pinpoint.yml config from audit results.
func FormatConfig(r *AuditResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Generated by: pinpoint audit --org %s\n", r.Org)
	fmt.Fprintf(&b, "# Date: %s\n", r.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "# Repos scanned: %d\n", r.TotalRepos)
	fmt.Fprintf(&b, "# Unique actions: %d\n", len(r.UniqueActions))
	b.WriteString("\nactions:\n")

	// High risk first
	var highRisk, standard []ActionSummary
	for _, a := range r.UniqueActions {
		if a.Risk == "critical" || a.Risk == "high" {
			highRisk = append(highRisk, a)
		} else {
			standard = append(standard, a)
		}
	}

	if len(highRisk) > 0 {
		b.WriteString("  # HIGH RISK — previously compromised or no immutable releases\n")
		for _, a := range highRisk {
			writeConfigAction(&b, a)
		}
		b.WriteString("\n")
	}

	if len(standard) > 0 {
		b.WriteString("  # STANDARD — popular actions\n")
		for _, a := range standard {
			writeConfigAction(&b, a)
		}
	}

	return b.String()
}

func writeConfigAction(b *strings.Builder, a ActionSummary) {
	fmt.Fprintf(b, "  - repo: %s\n", a.Repo)
	b.WriteString("    tags: [\"*\"]\n")

	totalRefs := countTotalRefs(a.Refs)
	shaPercent := 0.0
	if totalRefs > 0 {
		shaPercent = float64(countSHAPinned(a.Refs)) / float64(totalRefs) * 100
	}
	fmt.Fprintf(b, "    # Used in %d repos, %.0f%% SHA-pinned", a.UsedInRepos, shaPercent)

	if a.ImmutableRelease != nil {
		if *a.ImmutableRelease {
			b.WriteString(", immutable releases: YES")
		} else {
			b.WriteString(", immutable releases: NO")
		}
	}
	b.WriteString("\n")

	for _, note := range a.Notes {
		fmt.Fprintf(b, "    # WARNING: %s\n", note)
	}
}

// FormatManifest produces a .pinpoint-manifest.json from audit results.
// It resolves the tags using the provided GraphQL client.
func FormatManifest(r *AuditResult, tagResults map[string]*poller.FetchResult) (string, error) {
	type tagEntry struct {
		SHA       string `json:"sha"`
		Immutable bool   `json:"immutable"`
	}

	manifest := struct {
		Version     int                           `json:"version"`
		GeneratedAt string                        `json:"generated_at"`
		GeneratedBy string                        `json:"generated_by"`
		Actions     map[string]map[string]tagEntry `json:"actions"`
	}{
		Version:     1,
		GeneratedAt: r.ScannedAt.Format(time.RFC3339),
		GeneratedBy: fmt.Sprintf("pinpoint audit --org %s", r.Org),
		Actions:     make(map[string]map[string]tagEntry),
	}

	// Collect which tag refs are actually used per action
	usedTags := make(map[string]map[string]bool) // action → set of tag refs
	for _, a := range r.UniqueActions {
		for _, ref := range a.Refs {
			if ref.Type == "tag" {
				if usedTags[a.Repo] == nil {
					usedTags[a.Repo] = make(map[string]bool)
				}
				usedTags[a.Repo][ref.Ref] = true
			}
		}
	}

	for _, a := range r.UniqueActions {
		fetchResult, ok := tagResults[a.Repo]
		if !ok || fetchResult == nil {
			continue
		}

		tags := usedTags[a.Repo]
		if len(tags) == 0 {
			continue
		}

		actionTags := make(map[string]tagEntry)
		for _, resolved := range fetchResult.Tags {
			if tags[resolved.Name] {
				immutable := false
				if a.ImmutableRelease != nil {
					immutable = *a.ImmutableRelease
				}
				actionTags[resolved.Name] = tagEntry{
					SHA:       resolved.CommitSHA,
					Immutable: immutable,
				}
			}
		}

		if len(actionTags) > 0 {
			manifest.Actions[a.Repo] = actionTags
		}
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling manifest: %w", err)
	}

	return string(data) + "\n", nil
}

// FormatJSON produces the machine-readable JSON report.
func FormatJSON(r *AuditResult) (string, error) {
	type refOut struct {
		Ref   string `json:"ref"`
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	type actionOut struct {
		Repo             string   `json:"repo"`
		UsedInRepos      int      `json:"used_in_repos"`
		Refs             []refOut `json:"refs"`
		ImmutableRelease *bool    `json:"immutable_releases"`
		Risk             string   `json:"risk"`
	}
	type policyOut struct {
		SHAPinningRequired bool `json:"sha_pinning_required"`
		Checked            bool `json:"checked"`
	}

	output := struct {
		Org       string `json:"org"`
		ScannedAt string `json:"scanned_at"`
		Repos     struct {
			Total           int `json:"total"`
			WithWorkflows   int `json:"with_workflows"`
			ArchivedSkipped int `json:"archived_skipped"`
			ForkedSkipped   int `json:"forked_skipped"`
		} `json:"repos"`
		References struct {
			Total        int `json:"total"`
			SHAPinned    int `json:"sha_pinned"`
			TagPinned    int `json:"tag_pinned"`
			BranchPinned int `json:"branch_pinned"`
		} `json:"references"`
		UniqueActions     []actionOut             `json:"unique_actions"`
		DangerousTriggers []DangerousTriggerFinding `json:"dangerous_triggers,omitempty"`
		OrgPolicy         policyOut               `json:"org_policy"`
	}{}

	output.Org = r.Org
	output.ScannedAt = r.ScannedAt.Format(time.RFC3339)
	output.Repos.Total = r.TotalRepos
	output.Repos.WithWorkflows = r.ReposWithWorkflows
	output.Repos.ArchivedSkipped = r.ArchivedSkipped
	output.Repos.ForkedSkipped = r.ForkedSkipped
	output.References.Total = r.TotalRefs
	output.References.SHAPinned = r.SHAPinned
	output.References.TagPinned = r.TagPinned
	output.References.BranchPinned = r.BranchPinned

	for _, a := range r.UniqueActions {
		ao := actionOut{
			Repo:             a.Repo,
			UsedInRepos:      a.UsedInRepos,
			ImmutableRelease: a.ImmutableRelease,
			Risk:             a.Risk,
		}
		for _, ref := range a.Refs {
			ao.Refs = append(ao.Refs, refOut{
				Ref:   ref.Ref,
				Type:  ref.Type,
				Count: ref.Count,
			})
		}
		output.UniqueActions = append(output.UniqueActions, ao)
	}

	output.DangerousTriggers = r.DangerousTriggers

	if r.OrgPolicy != nil {
		output.OrgPolicy = policyOut{
			SHAPinningRequired: r.OrgPolicy.SHAPinningRequired,
			Checked:            true,
		}
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling JSON report: %w", err)
	}
	return string(data) + "\n", nil
}

func fmtInt(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%d,%03d", n/1000, n%1000)
}

func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}
