# Spec 018: pull_request_target Detection in Audit

## Problem

`pull_request_target` is the root cause of both major GitHub Actions supply chain
attacks in 2025-2026:

1. **tj-actions chain (March 2025):** spotbugs/sonar-findbugs had a `pull_request_target`
   workflow that checked out the PR head ref, allowing PAT theft via a malicious PR.
   This cascaded through reviewdog → tj-actions → 23,000+ repos.

2. **Trivy hackerbot-claw (Feb 2026):** aquasecurity/trivy's `apidiff.yaml` used
   `pull_request_target` with checkout of `${{ github.event.pull_request.head.ref }}`,
   granting an AI bot access to `ORG_REPO_TOKEN` with write access across 33+ workflows.
   This token was later used by TeamPCP to execute the March 19 tag-poisoning attack.

Pinpoint's `audit` command already parses workflow YAML and reports on pinning status.
Adding detection for dangerous `pull_request_target` patterns is high-value, low-effort,
and addresses a gap no competitor covers.

## Design

### New finding type in audit results

Add a `DangerousTrigger` finding type alongside the existing action-level findings:

```go
// DangerousTriggerFinding represents a risky workflow trigger configuration.
type DangerousTriggerFinding struct {
    Repo         string `json:"repo"`
    WorkflowFile string `json:"workflow_file"`
    Trigger      string `json:"trigger"`       // "pull_request_target"
    Risk         string `json:"risk"`          // "critical", "high", "medium"
    Reason       string `json:"reason"`
    Line         int    `json:"line,omitempty"` // approximate line number
}
```

### Detection patterns (ordered by severity)

**CRITICAL — pull_request_target + checkout of PR head:**

The most dangerous pattern. The workflow runs with the base repo's secrets but
checks out attacker-controlled code from the PR head. This is exactly what enabled
both the spotbugs and trivy breaches.

Detection: workflow has `pull_request_target` in `on:` block AND contains a step
that does `actions/checkout` with `ref:` containing any of:
- `${{ github.event.pull_request.head.ref }}`
- `${{ github.event.pull_request.head.sha }}`
- `${{ github.head_ref }}`
- `refs/pull/` patterns

```yaml
# CRITICAL: This is the exact pattern that caused both breaches
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # DANGER
      - run: make test  # Runs attacker's Makefile with repo's secrets
```

**HIGH — pull_request_target + any `run:` step:**

Even without explicit checkout of the PR head, workflows triggered by
`pull_request_target` that execute shell commands may be exploitable if any
input from the PR (title, body, branch name, labels) is interpolated into
the run command.

Detection: workflow has `pull_request_target` AND has `run:` steps that
reference `github.event.pull_request.*` in their content.

**MEDIUM — pull_request_target exists at all:**

Any workflow using `pull_request_target` should be flagged as requiring manual
review, even if no obvious dangerous pattern is detected. The trigger is
inherently risky because it grants write tokens to a workflow that fires on
external PRs.

### Implementation

**New file: `internal/audit/triggers.go`**

```go
package audit

import (
    "regexp"
    "strings"
)

// Known dangerous checkout ref patterns
var dangerousRefPatterns = []string{
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.sha",
    "github.head_ref",
}

// checkoutRefRe matches checkout steps with ref parameters
var checkoutRefRe = regexp.MustCompile(
    `uses:\s*['"]?actions/checkout[^@]*@[^\s'"]+[^}]*ref:\s*\$\{\{[^}]*(?:` +
    strings.Join(dangerousRefPatterns, "|") +
    `)`,
)

// Actually, the checkout ref is usually on a separate line. Better approach:
// parse the YAML enough to find pull_request_target trigger + checkout ref patterns.

// DetectDangerousTriggers scans workflow content for risky trigger configurations.
func DetectDangerousTriggers(repo, workflowName, content string) []DangerousTriggerFinding {
    var findings []DangerousTriggerFinding

    if !hasPullRequestTarget(content) {
        return nil
    }

    lower := strings.ToLower(content)

    // Check for checkout of PR head (CRITICAL)
    if hasCheckoutPRHead(content) {
        findings = append(findings, DangerousTriggerFinding{
            Repo:         repo,
            WorkflowFile: workflowName,
            Trigger:      "pull_request_target",
            Risk:         "critical",
            Reason:       "pull_request_target with checkout of PR head ref — attacker-controlled code runs with repo secrets",
        })
        return findings // Critical subsumes lower severities for same workflow
    }

    // Check for run steps with PR event interpolation (HIGH)
    if hasRunWithPRInterpolation(content) {
        findings = append(findings, DangerousTriggerFinding{
            Repo:         repo,
            WorkflowFile: workflowName,
            Trigger:      "pull_request_target",
            Risk:         "high",
            Reason:       "pull_request_target with PR data interpolated in run step — potential command injection",
        })
        return findings
    }

    // pull_request_target present but no obvious dangerous pattern (MEDIUM)
    findings = append(findings, DangerousTriggerFinding{
        Repo:         repo,
        WorkflowFile: workflowName,
        Trigger:      "pull_request_target",
        Risk:         "medium",
        Reason:       "pull_request_target trigger requires manual review — grants write token on external PRs",
    })

    return findings
}

// hasPullRequestTarget checks if the workflow uses pull_request_target trigger.
// Uses string matching rather than full YAML parse to match existing audit patterns.
func hasPullRequestTarget(content string) bool {
    // Match "pull_request_target" as a trigger, not in comments
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
func hasRunWithPRInterpolation(content string) bool {
    lines := strings.Split(content, "\n")
    for _, line := range lines {
        trimmed := strings.TrimSpace(line)
        if strings.HasPrefix(trimmed, "#") {
            continue
        }
        if strings.HasPrefix(trimmed, "run:") || strings.HasPrefix(trimmed, "run :") {
            if strings.Contains(trimmed, "github.event.pull_request") {
                return true
            }
        }
    }
    return false
}
```

### Integration into audit/audit.go

In `RunAudit`, after the workflow content is available:

```go
// Phase 2.5: Detect dangerous triggers
var triggerFindings []DangerousTriggerFinding
for _, repo := range activeRepos {
    for _, wf := range repo.WorkflowFiles {
        findings := DetectDangerousTriggers(repo.Name, wf.Name, wf.Content)
        triggerFindings = append(triggerFindings, findings...)
    }
}
result.DangerousTriggers = triggerFindings
```

Add to AuditResult:

```go
type AuditResult struct {
    // ... existing fields ...
    DangerousTriggers []DangerousTriggerFinding
}
```

### Report output

Add a new section to FormatReport after "BRANCH-PINNED ACTIONS":

```
DANGEROUS WORKFLOW TRIGGERS:
  🚨 CRITICAL  myorg/api-server/apidiff.yml    pull_request_target with checkout of PR head ref
  ⚠  HIGH      myorg/frontend/label.yml        pull_request_target with PR data in run step
  ℹ  MEDIUM    myorg/docs/auto-merge.yml       pull_request_target requires manual review
```

### SARIF output

Add a new rule to the SARIF output:

```go
// In sarif/sarif.go, add rule:
{
    ID:               "PNPT-TRIGGER-001",
    ShortDescription: "Dangerous pull_request_target trigger",
    FullDescription:  "Workflow uses pull_request_target which runs with write tokens on external PRs",
    HelpURI:          "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
}
```

Map finding risk levels to SARIF severity: critical→error, high→warning, medium→note.

### JSON output

Include in the JSON report as a top-level array:

```json
{
  "dangerous_triggers": [
    {
      "repo": "myorg/api-server",
      "workflow_file": "apidiff.yml",
      "trigger": "pull_request_target",
      "risk": "critical",
      "reason": "pull_request_target with checkout of PR head ref..."
    }
  ]
}
```

## Tests

### Unit tests: internal/audit/triggers_test.go

- TestCritical_CheckoutPRHead — workflow with pull_request_target + checkout of
  github.event.pull_request.head.sha → critical finding
- TestCritical_CheckoutHeadRef — uses github.head_ref variant → critical
- TestHigh_RunWithPRInterpolation — run step contains github.event.pull_request.title → high
- TestMedium_PullRequestTargetOnly — pull_request_target with no dangerous patterns → medium
- TestClean_PullRequest — regular `pull_request` trigger (not target) → no findings
- TestClean_CommentedOut — pull_request_target in a comment → no findings
- TestTrivyAPIDiffReplay — exact replica of trivy's apidiff.yaml → critical finding
- TestSpotbugsReplay — replica of spotbugs/sonar-findbugs workflow → critical finding

### Integration tests

- TestAuditIncludesTriggerFindings — run audit against test org, verify findings
  appear in report, JSON, and SARIF outputs

## Why this matters for Pinpoint's positioning

No tool in the competitive landscape (gh-actions-lockfile, ghasum, zizmor, StepSecurity)
currently flags `pull_request_target` as an org-wide audit finding with risk scoring.
zizmor checks individual workflows but doesn't do org-wide scanning. StepSecurity's
Harden-Runner detects exploitation at runtime but doesn't flag the misconfiguration
proactively.

This makes Pinpoint the first tool that can scan an entire GitHub org and surface the
exact configuration weakness that enabled both the tj-actions and Trivy supply chain
attacks — before an attacker exploits it.

## Files to create/modify

- CREATE: `internal/audit/triggers.go` — trigger detection logic
- CREATE: `internal/audit/triggers_test.go` — unit tests
- MODIFY: `internal/audit/audit.go` — add DangerousTriggerFinding type, call detection
  in RunAudit, add to FormatReport/FormatJSON/FormatConfig
- MODIFY: `internal/sarif/sarif.go` — add PNPT-TRIGGER-001 rule, emit findings
