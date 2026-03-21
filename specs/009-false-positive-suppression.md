# Spec 009: False Positive Suppression

## Problem

Major version tags (v1, v2, v4) are DESIGNED to move. Every patch release
of actions/checkout moves the v4 tag forward. At scale (200+ actions), this
generates dozens of LOW-severity alerts per day. Alert fatigue kills adoption.

## Solution: Allow-Lists in Config

Add an `allow` section to `.pinpoint.yml`:

```yaml
actions:
  - repo: actions/checkout
    tags: ["*"]
  - repo: docker/build-push-action
    tags: ["*"]

allow:
  # Suppress alerts for major version tag advances by GitHub's bot
  - repo: actions/*
    tags: ["v*"]
    condition: major_tag_advance
    reason: "GitHub-maintained actions routinely advance major tags"

  # Suppress alerts for this specific bot account
  - actor: "github-actions[bot]"
    condition: descendant
    reason: "Release automation advances tags to descendants"

  # Suppress alerts for specific repos entirely (internal actions you control)
  - repo: coreweave/internal-action
    suppress: true
    reason: "Internal action, we control the tags"
```

### Allow-List Fields

```go
type AllowRule struct {
    Repo      string `yaml:"repo"`      // Glob pattern: "actions/*", "docker/build-push-action"
    Tags      []string `yaml:"tags"`    // Glob patterns: ["v*"], ["v1", "v2"]
    Actor     string `yaml:"actor"`     // Committer/pusher: "github-actions[bot]"
    Condition string `yaml:"condition"` // "major_tag_advance", "descendant", "any"
    Suppress  bool   `yaml:"suppress"`  // true = suppress ALL alerts for this match
    Reason    string `yaml:"reason"`    // Human-readable justification (required)
}
```

### Conditions

- `major_tag_advance`: Tag matches `^v?\d+$` AND new commit is a descendant
- `descendant`: New commit is a descendant of old commit (regardless of tag pattern)
- `release_within_5m`: A GitHub Release was created within 5 minutes of the tag change
- `any`: Suppress all alerts matching the repo/tag pattern (same as suppress: true)

### Matching Logic

When an alert is generated, before emitting it:

```go
func (r *AllowRule) Matches(alert risk.Alert, ctx ScoreContext) bool {
    // Check repo pattern (glob)
    if r.Repo != "" && !globMatch(r.Repo, alert.Action) {
        return false
    }
    // Check tag pattern (glob)
    if len(r.Tags) > 0 && !anyGlobMatch(r.Tags, alert.Tag) {
        return false
    }
    // Check actor
    if r.Actor != "" && r.Actor != ctx.CommitAuthor {
        return false
    }
    // Check condition
    switch r.Condition {
    case "major_tag_advance":
        return majorVersionRe.MatchString(alert.Tag) && ctx.IsDescendant
    case "descendant":
        return ctx.IsDescendant
    case "release_within_5m":
        return ctx.ReleaseExists // simplified; ideally check timing
    case "any", "":
        return true
    }
    return false
}
```

### Suppressed Alert Handling

Suppressed alerts are NOT silently dropped. They are:
1. Logged at DEBUG level: `[suppressed] actions/checkout@v4 repointed (rule: "GitHub-maintained actions...")`
2. Counted in summary: `"3 alerts suppressed by allow-list rules"`
3. Included in JSON output with `"suppressed": true` field
4. NOT included in SARIF output (they'd clutter the Security tab)
5. NOT counted toward exit code 2 (they don't fail CI)

## Implementation

### Changes to `internal/config/config.go`

Add AllowRule to Config:

```go
type Config struct {
    Actions    []ActionConfig `yaml:"actions"`
    AllowRules []AllowRule   `yaml:"allow"`
    // ... existing fields
}

type AllowRule struct {
    Repo      string   `yaml:"repo"`
    Tags      []string `yaml:"tags"`
    Actor     string   `yaml:"actor"`
    Condition string   `yaml:"condition"`
    Suppress  bool     `yaml:"suppress"`
    Reason    string   `yaml:"reason"`
}
```

### New file: `internal/suppress/suppress.go`

```go
package suppress

import (
    "path/filepath"
    "github.com/tehreet/pinpoint/internal/config"
    "github.com/tehreet/pinpoint/internal/risk"
)

type Result struct {
    Allowed    []risk.Alert // alerts that passed through
    Suppressed []SuppressedAlert
}

type SuppressedAlert struct {
    Alert  risk.Alert
    Rule   config.AllowRule
    Reason string
}

// Filter applies allow-list rules to a set of alerts.
func Filter(alerts []risk.Alert, rules []config.AllowRule, contexts map[string]risk.ScoreContext) *Result

// globMatch does filepath.Match-style glob matching
func globMatch(pattern, value string) bool {
    matched, _ := filepath.Match(pattern, value)
    return matched
}
```

### New file: `internal/suppress/suppress_test.go`

Tests:
- TestSuppressMajorTagAdvance — v4 advance by bot, rule matches, suppressed
- TestNoSuppressForSemver — v1.2.3 repoint, rule for major only, NOT suppressed
- TestSuppressByActor — github-actions[bot] matched, suppressed
- TestSuppressEntireRepo — suppress:true for internal action
- TestGlobMatching — "actions/*" matches "actions/checkout" but not "docker/build-push-action"
- TestReasonRequired — rule without reason field is rejected during config parse
- TestSuppressedAlertsCounted — verify count in summary output

### Changes to `cmd/pinpoint/main.go`

In `runScan`, after alerts are generated but before emitting:

```go
if len(cfg.AllowRules) > 0 {
    filterResult := suppress.Filter(alerts, cfg.AllowRules, scoreContexts)
    alerts = filterResult.Allowed
    if len(filterResult.Suppressed) > 0 {
        fmt.Fprintf(os.Stderr, "%d alert(s) suppressed by allow-list rules\n", len(filterResult.Suppressed))
    }
}
```

## Files to Create/Modify

- CREATE: `internal/suppress/suppress.go`
- CREATE: `internal/suppress/suppress_test.go`
- MODIFY: `internal/config/config.go` — add AllowRule type and parsing
- MODIFY: `cmd/pinpoint/main.go` — apply filter in runScan before emitting
