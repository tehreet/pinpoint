// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package audit

import (
	"strings"
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

// DetectDangerousTriggers scans workflow content for risky trigger configurations.
func DetectDangerousTriggers(repo, workflowName, content string) []DangerousTriggerFinding {
	if !hasPullRequestTarget(content) {
		return nil
	}

	// Check for checkout of PR head (CRITICAL)
	if hasCheckoutPRHead(content) {
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

// hasPullRequestTarget checks if the workflow uses pull_request_target trigger.
// Uses string matching rather than full YAML parse to match existing audit patterns.
func hasPullRequestTarget(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "pull_request_target") {
			return true
		}
	}
	return false
}

// hasCheckoutPRHead checks for actions/checkout with a dangerous ref.
func hasCheckoutPRHead(content string) bool {
	lines := strings.Split(content, "\n")
	inCheckout := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
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
			// Single-line run: the interpolation is on this same line
			if strings.Contains(trimmed, "github.event.pull_request") {
				return true
			}
			// Multi-line run block starts with run: | or run: >
			if strings.Contains(trimmed, "|") || strings.Contains(trimmed, ">") {
				inRunBlock = true
				// Record the indentation of the "run:" key itself so we know
				// when a subsequent line exits the block (same or lesser indent)
				runIndent = leadingSpaces(line)
			}
			continue
		}

		// If we're inside a multi-line run block, check continuation lines
		if inRunBlock {
			// A blank line doesn't end a YAML block scalar
			if trimmed == "" {
				continue
			}
			// Block continues while indented deeper than the run: key
			if leadingSpaces(line) > runIndent {
				if strings.Contains(line, "github.event.pull_request") {
					return true
				}
			} else {
				// Indentation returned to or past the run: level — block ended
				inRunBlock = false
			}
		}
	}
	return false
}

// leadingSpaces counts the number of leading space characters in a line.
func leadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2 // treat tab as 2 spaces for comparison purposes
		} else {
			break
		}
	}
	return count
}
