// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package audit

import (
	"strings"

	"github.com/tehreet/pinpoint/internal/util"
)

// DangerousTriggerFinding represents a risky workflow trigger configuration.
type DangerousTriggerFinding struct {
	Repo         string `json:"repo"`
	WorkflowFile string `json:"workflow_file"`
	Trigger      string `json:"trigger"`        // "pull_request_target"
	Risk         string `json:"risk"`           // "critical", "high", "medium"
	Reason       string `json:"reason"`
	Line         int    `json:"line,omitempty"` // approximate line number
}

// Known dangerous checkout ref patterns
var dangerousRefPatterns = []string{
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.sha",
	"github.head_ref",
}

// testRepoPatterns matches repos that are intentionally vulnerable (CTF/goat/playground).
var testRepoPatterns = []string{
	"goat", "playground", "vulnerable", "damn-vulnerable",
	"dvga", "dvwa", "juice-shop", "webgoat",
}

// DetectDangerousTriggers scans workflow content for risky trigger configurations.
func DetectDangerousTriggers(repo, workflowName, content string) []DangerousTriggerFinding {
	// Only match pull_request_target in the on: trigger section, not in if: conditions
	if !hasPullRequestTargetTrigger(content) {
		return nil
	}

	// Filter out intentionally vulnerable test repos
	if isTestRepo(repo) {
		return nil
	}

	// Check if all jobs using dangerous patterns are guarded by if: false
	if allJobsDisabled(content) {
		return nil
	}

	// Check for checkout of PR head (CRITICAL)
	// But only in jobs that are NOT disabled with if: false
	if hasLiveCheckoutPRHead(content) {
		return []DangerousTriggerFinding{{
			Repo:         repo,
			WorkflowFile: workflowName,
			Trigger:      "pull_request_target",
			Risk:         "critical",
			Reason:       "pull_request_target with checkout of PR head ref — attacker-controlled code runs with repo secrets",
		}}
	}

	// Check for run steps with PR event interpolation (HIGH)
	if hasRunWithPRInterpolation(content) {
		return []DangerousTriggerFinding{{
			Repo:         repo,
			WorkflowFile: workflowName,
			Trigger:      "pull_request_target",
			Risk:         "high",
			Reason:       "pull_request_target with PR data interpolated in run step — potential command injection",
		}}
	}

	// pull_request_target present but no obvious dangerous pattern (MEDIUM)
	return []DangerousTriggerFinding{{
		Repo:         repo,
		WorkflowFile: workflowName,
		Trigger:      "pull_request_target",
		Risk:         "medium",
		Reason:       "pull_request_target trigger requires manual review — grants write token on external PRs",
	}}
}

// hasPullRequestTargetTrigger checks if pull_request_target appears as an actual
// trigger in the on: section, NOT in if: conditions or comments elsewhere.
func hasPullRequestTargetTrigger(content string) bool {
	lines := strings.Split(content, "\n")
	inOnBlock := false
	onIndent := -1

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := util.LeadingSpaces(line)

		// Detect the on: block
		if trimmed == "on:" || strings.HasPrefix(trimmed, "on:") {
			inOnBlock = true
			onIndent = indent
			// Check for inline form: on: pull_request_target
			if strings.Contains(trimmed, "pull_request_target") {
				return true
			}
			continue
		}

		// If we're in the on: block
		if inOnBlock {
			// Exit on: block when we hit a top-level key at same or lesser indent
			if indent <= onIndent && trimmed != "" && !strings.HasPrefix(trimmed, "-") {
				inOnBlock = false
				continue
			}
			// Match pull_request_target as a trigger key (indented under on:)
			if strings.Contains(trimmed, "pull_request_target") {
				return true
			}
		}
	}
	return false
}

// isTestRepo checks if a repo is an intentionally vulnerable test/demo/goat repo.
func isTestRepo(repo string) bool {
	lower := strings.ToLower(repo)
	for _, pattern := range testRepoPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// allJobsDisabled checks if every job in the workflow has `if: false`.
func allJobsDisabled(content string) bool {
	lines := strings.Split(content, "\n")
	inJobs := false
	jobsIndent := -1
	jobCount := 0
	disabledCount := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := util.LeadingSpaces(line)

		// Find jobs: section
		if trimmed == "jobs:" || strings.HasPrefix(trimmed, "jobs:") {
			inJobs = true
			jobsIndent = indent
			continue
		}

		if !inJobs {
			continue
		}

		// Exit jobs: when we hit a top-level key at same or lesser indent
		if indent <= jobsIndent && trimmed != "" {
			break
		}

		// Detect job names (indented exactly 1 level under jobs:)
		if indent == jobsIndent+2 && !strings.HasPrefix(trimmed, "-") && strings.HasSuffix(trimmed, ":") {
			jobCount++
			// Look ahead for if: false in the next few lines at the right indent
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				nextTrimmed := strings.TrimSpace(lines[j])
				nextIndent := util.LeadingSpaces(lines[j])
				if nextIndent <= indent && nextTrimmed != "" {
					break // hit next job or section
				}
				if nextIndent == indent+2 && (nextTrimmed == "if: false" || nextTrimmed == "if: 'false'" || nextTrimmed == `if: "false"`) {
					disabledCount++
					break
				}
			}
		}
	}

	return jobCount > 0 && jobCount == disabledCount
}

// hasLiveCheckoutPRHead checks for actions/checkout with a dangerous ref,
// but only in jobs that are NOT disabled with if: false.
func hasLiveCheckoutPRHead(content string) bool {
	lines := strings.Split(content, "\n")
	inCheckout := false
	currentJobDisabled := false
	inJobs := false
	jobsIndent := -1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := util.LeadingSpaces(line)

		// Track jobs section
		if trimmed == "jobs:" || strings.HasPrefix(trimmed, "jobs:") {
			inJobs = true
			jobsIndent = indent
			continue
		}

		if !inJobs {
			continue
		}

		// Detect job boundaries and check for if: false
		if indent == jobsIndent+2 && !strings.HasPrefix(trimmed, "-") && strings.HasSuffix(trimmed, ":") {
			currentJobDisabled = false
			// Look ahead for if: false
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				nextTrimmed := strings.TrimSpace(lines[j])
				nextIndent := util.LeadingSpaces(lines[j])
				if nextIndent <= indent && nextTrimmed != "" {
					break
				}
				if nextIndent == indent+2 && (nextTrimmed == "if: false" || nextTrimmed == "if: 'false'" || nextTrimmed == `if: "false"`) {
					currentJobDisabled = true
					break
				}
			}
			inCheckout = false
			continue
		}

		// Skip disabled jobs entirely
		if currentJobDisabled {
			continue
		}

		if strings.Contains(trimmed, "actions/checkout") {
			inCheckout = true
			continue
		}

		// Reset on next step or job boundary
		if inCheckout && (strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "jobs:")) {
			inCheckout = false
		}

		if inCheckout && strings.Contains(trimmed, "ref:") {
			for _, pattern := range dangerousRefPatterns {
				if strings.Contains(trimmed, pattern) {
					return true
				}
			}
		}
	}
	return false
}

// hasRunWithPRInterpolation checks for run steps that interpolate PR event data.
// Handles both single-line (run: echo "${{ ... }}") and multi-line (run: |) blocks.
func hasRunWithPRInterpolation(content string) bool {
	lines := strings.Split(content, "\n")
	inRunBlock := false
	runIndent := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check if this line starts a run directive
		isRunLine := strings.HasPrefix(trimmed, "run:") ||
			strings.HasPrefix(trimmed, "run :") ||
			strings.HasPrefix(trimmed, "- run:") ||
			strings.HasPrefix(trimmed, "- run :")

		if isRunLine {
			if strings.Contains(trimmed, "github.event.pull_request") {
				return true
			}
			if strings.Contains(trimmed, "|") || strings.Contains(trimmed, ">") {
				inRunBlock = true
				runIndent = util.LeadingSpaces(line)
			}
			continue
		}

		if inRunBlock {
			if trimmed == "" {
				continue
			}
			if util.LeadingSpaces(line) > runIndent {
				if strings.Contains(line, "github.event.pull_request") {
					return true
				}
			} else {
				inRunBlock = false
			}
		}
	}
	return false
}

