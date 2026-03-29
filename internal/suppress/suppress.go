// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package suppress

import (
	"path/filepath"
	"regexp"

	"github.com/tehreet/pinpoint/internal/config"
	"github.com/tehreet/pinpoint/internal/risk"
)

var majorVersionRe = regexp.MustCompile(`^v?\d+$`)

// Result holds the outcome of filtering alerts through allow-list rules.
type Result struct {
	Allowed    []risk.Alert
	Suppressed []SuppressedAlert
}

// SuppressedAlert pairs a suppressed alert with the rule that matched it.
type SuppressedAlert struct {
	Alert  risk.Alert
	Rule   config.AllowRule
	Reason string
}

// Filter applies allow-list rules to a set of alerts. Each alert is checked
// against every rule; the first matching rule suppresses it. Alerts that
// match no rule pass through to Allowed.
//
// contexts maps "repo@tag" to the ScoreContext used when scoring the alert,
// providing ancestry and author data needed by conditions.
func Filter(alerts []risk.Alert, rules []config.AllowRule, contexts map[string]risk.ScoreContext) *Result {
	result := &Result{}

	for _, a := range alerts {
		key := a.Action + "@" + a.Tag
		ctx := contexts[key]

		matched := false
		for _, rule := range rules {
			if ruleMatches(rule, a, ctx) {
				result.Suppressed = append(result.Suppressed, SuppressedAlert{
					Alert:  a,
					Rule:   rule,
					Reason: rule.Reason,
				})
				matched = true
				break
			}
		}

		if !matched {
			result.Allowed = append(result.Allowed, a)
		}
	}

	return result
}

func ruleMatches(rule config.AllowRule, a risk.Alert, ctx risk.ScoreContext) bool {
	// Check repo pattern
	if rule.Repo != "" && !globMatch(rule.Repo, a.Action) {
		return false
	}

	// Check tag patterns
	if len(rule.Tags) > 0 && !anyGlobMatch(rule.Tags, a.Tag) {
		return false
	}

	// Check actor
	if rule.Actor != "" && rule.Actor != ctx.CommitAuthor {
		return false
	}

	// If suppress:true, no condition check needed — suppress everything matching
	if rule.Suppress {
		return true
	}

	// Check condition
	switch rule.Condition {
	case "major_tag_advance":
		return majorVersionRe.MatchString(a.Tag) && ctx.IsDescendant
	case "descendant":
		return ctx.IsDescendant
	case "release_within_5m":
		return false // ReleaseExists field was removed (never populated)
	case "any", "":
		return true
	}

	return false
}

func globMatch(pattern, value string) bool {
	matched, _ := filepath.Match(pattern, value)
	return matched
}

func anyGlobMatch(patterns []string, value string) bool {
	for _, p := range patterns {
		if globMatch(p, value) {
			return true
		}
	}
	return false
}
