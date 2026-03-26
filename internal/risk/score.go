// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package risk

import (
	"regexp"
	"strings"
	"time"
)

// Severity levels for alerts.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityCritical Severity = "CRITICAL"
)

// Alert represents a detected tag integrity issue.
type Alert struct {
	Severity    Severity          `json:"severity"`
	Type        string            `json:"type"` // TAG_REPOINTED, TAG_DELETED, MASS_REPOINT
	Action      string            `json:"action"`
	Tag         string            `json:"tag"`
	PreviousSHA string            `json:"previous_sha,omitempty"`
	CurrentSHA  string            `json:"current_sha,omitempty"`
	DetectedAt  time.Time         `json:"detected_at"`
	Enrichment  map[string]string `json:"enrichment,omitempty"`
	Signals     []string          `json:"signals"` // Human-readable risk signals
	SelfHosted  bool              `json:"self_hosted_runners"`
}

// ScoreContext provides the data needed to score a tag repointing event.
type ScoreContext struct {
	TagName         string
	IsDescendant    bool   // Is the new commit a descendant of the old?
	AheadBy         int
	BehindBy        int
	CommitAuthor    string
	CommitEmail     string
	CommitDate      time.Time
	OldCommitDate   time.Time
	EntryPointOld   int64  // File size at old SHA (-1 if not found)
	EntryPointNew   int64  // File size at new SHA (-1 if not found)
	ReleaseExists   bool
	SelfHosted      bool
	BatchSize       int    // Number of tags repointed in same polling interval
	ParentSHA       string    // SHA of the new commit's first parent
	ParentDate      time.Time // Date of the parent commit
	WasGPGSigned    bool   // Was the commit GPG-signed at lock time?
	IsGPGSigned     bool   // Is the current commit GPG-signed?
	VerifiedSigner  string // e.g. "web-flow" — who signed the original

	// Behavioral anomaly fields (spec 025)
	NewContributors      []string      // Logins not seen in previous releases (nil = first lock)
	SuspiciousFiles      []string      // Files in the diff matching suspicious patterns
	DiffOnly             bool          // True if ONLY suspicious files changed
	MeanReleaseInterval  time.Duration // Average time between releases
	TimeSinceLastRelease time.Duration // Time since previous release
	ReleasesLast24h      int           // Number of releases in last 24 hours
	ReleaseHistoryLen    int           // Number of entries in release history
}

var (
	// Major version tags like v1, v2, v3 — these are routinely moved
	majorVersionRe = regexp.MustCompile(`^v?\d+$`)
	// Exact semver tags like v1.2.3 — these should NEVER move
	semverExactRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+`)
)

// Score evaluates a tag repointing event and returns severity + signals.
func Score(ctx ScoreContext) (Severity, []string) {
	var signals []string
	score := 0

	// === CRITICAL SIGNALS ===

	// Mass repointing: >5 tags in one interval (signature of Trivy/tj-actions attacks)
	if ctx.BatchSize > 5 {
		score += 100
		signals = append(signals, "MASS_REPOINT: %d tags repointed in same polling interval")
	}

	// New commit is NOT a descendant of old commit (diverged history)
	if !ctx.IsDescendant && ctx.AheadBy == 0 {
		score += 80
		signals = append(signals, "OFF_BRANCH: new commit is not a descendant of previous commit")
	}

	// Commit date precedes its parent commit's date (fabricated metadata)
	if !ctx.ParentDate.IsZero() && ctx.CommitDate.Before(ctx.ParentDate) {
		score += 70
		signals = append(signals, formatSignal(
			"IMPOSSIBLE_TIMESTAMP: commit dated %s but parent dated %s (child predates parent)",
			ctx.CommitDate.Format("2006-01-02"),
			ctx.ParentDate.Format("2006-01-02"),
		))
	}

	// Entry point size changed >50%
	if ctx.EntryPointOld > 0 && ctx.EntryPointNew > 0 {
		ratio := float64(ctx.EntryPointNew) / float64(ctx.EntryPointOld)
		if ratio > 1.5 || ratio < 0.5 {
			score += 60
			pctChange := (ratio - 1.0) * 100
			signals = append(signals, formatSignal("SIZE_ANOMALY: entry point size changed %.0f%% (%d → %d bytes)", pctChange, ctx.EntryPointOld, ctx.EntryPointNew))
		}
	}

	// Exact semver tag was repointed (these should never move)
	if semverExactRe.MatchString(ctx.TagName) {
		score += 50
		signals = append(signals, "SEMVER_REPOINT: exact version tag should never be moved")
	}

	// Commit date is backdated (>30 days before detection)
	if time.Since(ctx.CommitDate) > 30*24*time.Hour {
		score += 40
		signals = append(signals, "BACKDATED_COMMIT: commit date is >30 days old")
	}

	// GPG signature was present at lock time but absent now
	if ctx.WasGPGSigned && !ctx.IsGPGSigned {
		score += 45
		signals = append(signals, "SIGNATURE_DROPPED: commit was GPG-signed at lock time, replacement is unsigned")
	}

	// === BEHAVIORAL ANOMALY SIGNALS (spec 025) ===

	// New contributor in release diff
	if ctx.NewContributors != nil && len(ctx.NewContributors) > 0 {
		score += 35
		signals = append(signals, "CONTRIBUTOR_ANOMALY: release includes commits from new contributor(s): "+strings.Join(ctx.NewContributors, ", "))
	}

	// Suspicious files in release diff
	if ctx.SuspiciousFiles != nil && len(ctx.SuspiciousFiles) > 0 {
		if ctx.DiffOnly {
			score += 50
			signals = append(signals, "DIFF_ANOMALY: release changes suspicious files only (no normal code changes): "+strings.Join(ctx.SuspiciousFiles, ", "))
		} else {
			score += 40
			signals = append(signals, "DIFF_ANOMALY: release mixes suspicious files with normal changes: "+strings.Join(ctx.SuspiciousFiles, ", "))
		}
	}

	// Release cadence anomaly
	if ctx.ReleaseHistoryLen >= 3 && ctx.MeanReleaseInterval > 7*24*time.Hour {
		fired := false
		reason := ""

		// Burst: released in < 10% of mean interval
		if ctx.TimeSinceLastRelease > 0 && ctx.TimeSinceLastRelease < ctx.MeanReleaseInterval/10 {
			fired = true
			reason = "burst release (time since last release far below average)"
		}

		// Rapid-fire: > 3 releases in 24h
		if ctx.ReleasesLast24h > 3 {
			fired = true
			reason = "rapid-fire releases in last 24 hours"
		}

		// Dormant: > 3× mean interval and mean < 90 days
		if ctx.MeanReleaseInterval < 90*24*time.Hour &&
			ctx.TimeSinceLastRelease > 3*ctx.MeanReleaseInterval {
			fired = true
			reason = "dormant action suddenly releasing (time since last release exceeds 3× average)"
		}

		if fired {
			score += 25
			signals = append(signals, "RELEASE_CADENCE_ANOMALY: "+reason)
		}
	}

	// === MEDIUM SIGNALS ===

	// No corresponding release
	if !ctx.ReleaseExists {
		score += 20
		signals = append(signals, "NO_RELEASE: no GitHub Release associated with this tag")
	}

	// Self-hosted runners affected
	if ctx.SelfHosted {
		score += 15
		signals = append(signals, "SELF_HOSTED: this action runs on self-hosted runners (elevated blast radius)")
	}

	// === LOW SIGNALS (informational) ===

	// Major version tag moved forward to descendant (expected behavior)
	if majorVersionRe.MatchString(ctx.TagName) && ctx.IsDescendant {
		score -= 30
		signals = append(signals, "MAJOR_TAG_ADVANCE: major version tag moved forward (routine)")
	}

	// SIZE_ANOMALY floor: if the entry point changed dramatically,
	// no deduction should reduce this below CRITICAL.
	hasSizeAnomaly := false
	for _, s := range signals {
		if strings.HasPrefix(s, "SIZE_ANOMALY") {
			hasSizeAnomaly = true
			break
		}
	}
	if hasSizeAnomaly && score < 50 {
		score = 50
		signals = append(signals, "SCORE_FLOOR: SIZE_ANOMALY enforces minimum CRITICAL severity")
	}

	// Determine severity from score
	severity := SeverityLow
	if score >= 50 {
		severity = SeverityCritical
	} else if score >= 20 {
		severity = SeverityMedium
	}

	return severity, signals
}

// MeetsThreshold checks if a severity meets the configured minimum.
func MeetsThreshold(severity Severity, threshold string) bool {
	levels := map[string]int{
		"low":      0,
		"medium":   1,
		"critical": 2,
	}
	sevLevel := levels[strings.ToLower(string(severity))]
	threshLevel := levels[strings.ToLower(threshold)]
	return sevLevel >= threshLevel
}

func formatSignal(format string, args ...interface{}) string {
	// Simple formatting without importing fmt to keep it clean
	result := format
	for _, arg := range args {
		switch v := arg.(type) {
		case float64:
			result = strings.Replace(result, "%.0f%%", strings.TrimRight(strings.TrimRight(formatFloat(v), "0"), ".")+"%", 1)
		case int64:
			result = strings.Replace(result, "%d", formatInt(v), 1)
		case string:
			result = strings.Replace(result, "%s", v, 1)
		}
	}
	return result
}

func formatFloat(f float64) string {
	if f < 0 {
		return "-" + formatFloat(-f)
	}
	whole := int64(f)
	return formatInt(whole)
}

func formatInt(i int64) string {
	if i < 0 {
		return "-" + formatInt(-i)
	}
	s := ""
	if i == 0 {
		return "0"
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
