# Spec 003: pinpoint audit — Org-Wide Security Posture Scanner

## Summary

One command that scans an entire GitHub org, discovers every GitHub Action
dependency across all repos, and produces a security posture report.

```bash
pinpoint audit --org coreweave
```

Zero config. Zero YAML. One flag. This is the enterprise entry point.

## Why This Matters

Right now, using pinpoint requires manually listing repos in a config file.
That's fine for 10 actions. At CoreWeave with 2,000 repos, nobody's doing that.
The audit command automates discovery and outputs everything needed to start
monitoring: the report, the config file, and the manifest for the gate.

## Verified API Contracts

All API calls verified against live GitHub API on 2026-03-21.

### Phase 1: List Org Repos + Fetch Workflow Contents (GraphQL)

**Single query lists repos AND returns full workflow file text content.**

```graphql
{
  rateLimit { cost remaining }
  organization(login: "actions") {
    repositories(first: 50, orderBy: {field: NAME, direction: ASC}, after: CURSOR) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes {
        name
        isArchived
        isFork
        defaultBranchRef { name }
        workflows: object(expression: "HEAD:.github/workflows") {
          ... on Tree {
            entries {
              name
              object {
                ... on Blob { byteSize text }
              }
            }
          }
        }
      }
    }
  }
}
```

**Verified response (50 repos, 1 point):**
```
Cost: 1 point
Repos returned: 50/82
Repos with workflows: 43
Workflow files: 248
Total content: 459 KB
Action refs found: 948
```

**Edge cases verified:**
- Repo with no `.github/workflows`: `workflows` field is `null`. Not an error.
- Archived repos: `isArchived: true`. Skip these.
- Forked repos: `isFork: true`. Skip these (they inherit upstream workflows).

**Pagination:** Use `pageInfo.endCursor` with `after:` parameter.
For 2,000 repos at 50/page = 40 pages = 40 GraphQL points.

### Phase 2: Extract Action References (Local Parsing)

Parse the `text` field of each workflow blob using the same regex from
`internal/discover/discover.go`:

```
uses:\s*['"]?([a-zA-Z0-9\-_.]+)/([a-zA-Z0-9\-_.]+)(?:/[^@\s'"]*)?@([a-zA-Z0-9\-_.]+)['"]?
```

Classify each reference:
- **SHA-pinned:** ref matches `^[0-9a-f]{40}$`
- **Tag-pinned:** ref matches semver-like pattern (v1, v1.2.3, etc.)
- **Branch-pinned:** everything else (main, master, etc.) — DANGEROUS

Deduplicate by `owner/repo` to get the unique set of upstream actions.

### Phase 3: Check Upstream Action Security (REST)

For each unique upstream action, check:

**Immutable releases:**
```
GET /repos/{owner}/{repo}/releases?per_page=1
```

Response field: `.[0].immutable` — boolean.

**Verified values:**
- `actions/checkout`: `immutable: false`
- `aquasecurity/trivy-action`: `immutable: true`
- `docker/build-push-action` v7: `immutable: true`, older: `false`

If the repo has zero releases, or the latest release is not immutable, flag it.

**Rate limit:** 1 REST call per unique upstream action. For ~200 unique
actions: 200 REST calls. Well within limits. NOT on the continuous poll
path — one-time audit only.

### Phase 4: Check Org Policy (REST, Optional)

```
GET /orgs/{org}/actions/permissions
```

Response:
```json
{
  "enabled_repositories": "all",
  "allowed_actions": "selected",
  "sha_pinning_required": true
}
```

The `sha_pinning_required` field indicates whether the org enforces SHA pinning.

**Requires `admin:org` scope.** If the token doesn't have this scope, skip
this check and note it in the report. Do NOT fail the audit.

## Implementation

### New File: `cmd/pinpoint/audit.go`

Separate file from `main.go` to keep things clean. Export a `cmdAudit()`
function that `main.go` calls.

### CLI Interface

```
pinpoint audit --org <name> [--output report|config|manifest|json] [--skip-upstream]
```

Flags:
- `--org` (required): GitHub organization to audit
- `--output`: What to produce. Default: `report` (human-readable to stderr).
  - `report` — human-readable security posture report
  - `config` — `.pinpoint.yml` config file to stdout
  - `manifest` — `.pinpoint-manifest.json` to stdout
  - `json` — machine-readable JSON report to stdout
- `--skip-upstream`: Skip the Phase 3 REST calls to check immutable releases.
  Useful if you only want internal inventory, not upstream security assessment.

### Zero-Config DX

No YAML file needed. No config file. The org name is the only input.
If `GITHUB_TOKEN` is not set, print:

```
Error: GITHUB_TOKEN is required for org audit.

Set a token with read access to your organization's repositories:
  export GITHUB_TOKEN=ghp_...

Create a token at: https://github.com/settings/tokens
Required scopes: repo (or read:org for public repos only)
Optional scope: admin:org (enables SHA pinning policy check)
```

### Audit Report Format (Human-Readable)

```
╔══════════════════════════════════════════════════════════════╗
║  PINPOINT AUDIT: coreweave                                  ║
╠══════════════════════════════════════════════════════════════╣
║  Repos scanned:           2,047                              ║
║  Repos with workflows:    1,823                              ║
║  Repos skipped:           224 (archived: 189, fork: 35)      ║
║  Total workflow files:    4,291                              ║
║  Total action references: 12,847                             ║
║                                                              ║
║  PINNING STATUS                                              ║
║  SHA-pinned:     1,284  (10.0%)                              ║
║  Tag-pinned:    11,102  (86.4%)  ← vulnerable to repointing  ║
║  Branch-pinned:    461  ( 3.6%)  ← DANGEROUS                 ║
║                                                              ║
║  UNIQUE UPSTREAM ACTIONS: 187                                ║
║  With immutable releases:  43 (23.0%)                        ║
║  Without immutable releases: 144 (77.0%)                     ║
║                                                              ║
║  ORG POLICY                                                  ║
║  SHA pinning enforced: No                                    ║
╚══════════════════════════════════════════════════════════════╝

TOP 20 MOST USED ACTIONS (by repo count):
  actions/checkout             1,823 repos  tag-pinned:89% sha-pinned:11%  immutable:NO
  actions/setup-node             412 repos  tag-pinned:95% sha-pinned:5%   immutable:NO
  docker/build-push-action       387 repos  tag-pinned:92% sha-pinned:8%   immutable:PARTIAL
  aquasecurity/trivy-action      298 repos  tag-pinned:100% sha-pinned:0%  immutable:YES
  ...

HIGH RISK ACTIONS (unpinned + no immutable releases + used in >10 repos):
  ⚠ tj-actions/changed-files    87 repos   0% pinned  immutable:NO   PREVIOUSLY COMPROMISED
  ⚠ reviewdog/action-setup      34 repos   0% pinned  immutable:NO   PREVIOUSLY COMPROMISED
  ⚠ softprops/action-gh-release 56 repos   0% pinned  immutable:NO
  ...

BRANCH-PINNED ACTIONS (immediate risk):
  🚨 internal/deploy-action@main   23 repos  ← mutable branch ref
  🚨 custom/lint-action@develop    12 repos  ← mutable branch ref
  ...

RECOMMENDATIONS:
  1. Enable SHA pinning enforcement at the org level
     → https://docs.github.com/en/actions/reference/security/secure-use
  2. Pin the top 20 actions by repo count (covers 80% of attack surface)
  3. Replace branch-pinned refs immediately (461 references in 203 repos)
  4. Enable pinpoint monitoring for 187 upstream actions
     → Run: pinpoint audit --org coreweave --output config > .pinpoint.yml
```

### Config Output Format

When `--output config` is specified, output a `.pinpoint.yml` to stdout:

```yaml
# Generated by: pinpoint audit --org coreweave
# Date: 2026-03-21T08:00:00Z
# Repos scanned: 2,047
# Unique actions: 187

actions:
  # HIGH RISK — previously compromised or no immutable releases
  - repo: tj-actions/changed-files
    tags: ["*"]
    # Used in 87 repos, 0% SHA-pinned, NO immutable releases
    # WARNING: This action was compromised in March 2025

  - repo: aquasecurity/trivy-action
    tags: ["*"]
    self_hosted_runners: true  # Detected in self-hosted runner workflows
    # Used in 298 repos, 0% SHA-pinned, immutable releases: YES
    # WARNING: This action was compromised in March 2026

  # STANDARD — popular actions, tag-pinned
  - repo: actions/checkout
    tags: ["*"]
    # Used in 1,823 repos, 11% SHA-pinned

  - repo: docker/build-push-action
    tags: ["*"]
    # Used in 387 repos, 8% SHA-pinned
  # ... all 187 actions
```

### Manifest Output Format

When `--output manifest` is specified, resolve all tags for all discovered
actions and output a `.pinpoint-manifest.json`:

```json
{
  "version": 1,
  "generated_at": "2026-03-21T08:00:00Z",
  "generated_by": "pinpoint audit --org coreweave",
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "immutable": false
      }
    },
    "aquasecurity/trivy-action": {
      "0.35.0": {
        "sha": "57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
        "immutable": true
      }
    }
  }
}
```

The manifest only includes tags that are actually referenced in the org's
workflows — not all tags on every upstream repo. This keeps it focused.

### JSON Output Format

When `--output json` is specified, output the full structured report:

```json
{
  "org": "coreweave",
  "scanned_at": "2026-03-21T08:00:00Z",
  "repos": {
    "total": 2047,
    "with_workflows": 1823,
    "archived_skipped": 189,
    "forked_skipped": 35
  },
  "references": {
    "total": 12847,
    "sha_pinned": 1284,
    "tag_pinned": 11102,
    "branch_pinned": 461
  },
  "unique_actions": [
    {
      "repo": "actions/checkout",
      "used_in_repos": 1823,
      "refs": [
        {"ref": "v4", "type": "tag", "count": 1650},
        {"ref": "34e114876b...", "type": "sha", "count": 173}
      ],
      "immutable_releases": false,
      "risk": "medium"
    }
  ],
  "org_policy": {
    "sha_pinning_required": false,
    "checked": true
  }
}
```

## Internal Architecture

### New Types

```go
// AuditResult holds the complete audit output.
type AuditResult struct {
    Org              string
    ScannedAt        time.Time
    TotalRepos       int
    ActiveRepos      int
    ArchivedSkipped  int
    ForkedSkipped    int
    ReposWithWorkflows int
    TotalWorkflowFiles int
    TotalRefs        int
    SHAPinned        int
    TagPinned        int
    BranchPinned     int
    UniqueActions    []ActionSummary
    OrgPolicy        *OrgPolicy // nil if couldn't check
}

type ActionSummary struct {
    Repo             string
    UsedInRepos      int
    Refs             []RefSummary  // Deduplicated refs with counts
    ImmutableRelease *bool         // nil if not checked
    Risk             string        // "critical", "high", "medium", "low"
    Notes            []string      // "Previously compromised", etc.
}

type RefSummary struct {
    Ref   string // "v4", "abc123...", "main"
    Type  string // "sha", "tag", "branch"
    Count int    // How many workflow files use this exact ref
}

type OrgPolicy struct {
    SHAPinningRequired bool
    AllowedActions     string // "all", "selected", etc.
}
```

### GraphQL Org Scanner

Reuse the alias/batching pattern from `internal/poller/graphql.go` but with
the `organization.repositories` query shape.

```go
// FetchOrgWorkflows returns all workflow file contents for repos in an org.
// Paginates at 50 repos per query.
func (c *GraphQLClient) FetchOrgWorkflows(ctx context.Context, org string) ([]OrgRepo, error)

type OrgRepo struct {
    Name           string
    IsArchived     bool
    IsFork         bool
    DefaultBranch  string
    WorkflowFiles  []WorkflowFile  // nil if no .github/workflows
}

type WorkflowFile struct {
    Name     string
    Size     int
    Content  string  // Full text content
}
```

### GraphQL Query Builder for Org Scan

```go
func buildOrgQuery(org string, cursor string) string {
    after := ""
    if cursor != "" {
        after = fmt.Sprintf(`, after: %q`, cursor)
    }
    return fmt.Sprintf(`{
  rateLimit { cost remaining }
  organization(login: %q) {
    repositories(first: 50, orderBy: {field: NAME, direction: ASC}%s) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes {
        name
        isArchived
        isFork
        defaultBranchRef { name }
        workflows: object(expression: "HEAD:.github/workflows") {
          ... on Tree {
            entries {
              name
              object {
                ... on Blob { byteSize text }
              }
            }
          }
        }
      }
    }
  }
}`, org, after)
}
```

### GraphQL Response Types

```go
type orgQueryResponse struct {
    Data struct {
        RateLimit struct {
            Cost      int `json:"cost"`
            Remaining int `json:"remaining"`
        } `json:"rateLimit"`
        Organization struct {
            Repositories struct {
                TotalCount int `json:"totalCount"`
                PageInfo   struct {
                    HasNextPage bool   `json:"hasNextPage"`
                    EndCursor   string `json:"endCursor"`
                } `json:"pageInfo"`
                Nodes []struct {
                    Name       string `json:"name"`
                    IsArchived bool   `json:"isArchived"`
                    IsFork     bool   `json:"isFork"`
                    DefaultBranchRef *struct {
                        Name string `json:"name"`
                    } `json:"defaultBranchRef"`
                    Workflows *struct {
                        Entries []struct {
                            Name   string `json:"name"`
                            Object *struct {
                                ByteSize int    `json:"byteSize"`
                                Text     string `json:"text"`
                            } `json:"object"`
                        } `json:"entries"`
                    } `json:"workflows"`
                } `json:"nodes"`
            } `json:"repositories"`
        } `json:"organization"`
    } `json:"data"`
    Errors []struct {
        Message string `json:"message"`
    } `json:"errors"`
}
```

### Immutable Release Checker

```go
// CheckImmutableRelease checks if the latest release of a repo is immutable.
// Returns true/false, or nil if the repo has no releases.
func (c *GitHubClient) CheckImmutableRelease(ctx context.Context, owner, repo string) (*bool, error) {
    url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=1", c.baseURL, owner, repo)
    // ... standard GET request ...
    // Parse response: []struct { Immutable bool `json:"immutable"` }
    // If len(releases) == 0, return nil
    // Return &releases[0].Immutable
}
```

### Org Policy Checker

```go
// CheckOrgPolicy checks if the org has SHA pinning enforcement enabled.
// Returns nil if the token doesn't have admin:org scope (403).
func (c *GitHubClient) CheckOrgPolicy(ctx context.Context, org string) (*OrgPolicy, error) {
    url := fmt.Sprintf("%s/orgs/%s/actions/permissions", c.baseURL, org)
    // ... standard GET request ...
    // If 403: return nil, nil (not an error, just insufficient scope)
    // Parse: { "sha_pinning_required": bool, "allowed_actions": string }
}
```

### Risk Scoring for Actions

```go
func scoreAction(action ActionSummary) string {
    score := 0

    // High usage + no pinning = high risk
    if action.UsedInRepos > 10 {
        pinRate := countSHAPinned(action.Refs) / float64(countTotal(action.Refs))
        if pinRate < 0.1 {
            score += 30
        }
    }

    // No immutable releases
    if action.ImmutableRelease != nil && !*action.ImmutableRelease {
        score += 20
    }

    // Branch-pinned refs exist
    for _, ref := range action.Refs {
        if ref.Type == "branch" {
            score += 40  // Branch pinning is always critical
            break
        }
    }

    // Previously compromised (hardcoded known-bad list)
    if isKnownCompromised(action.Repo) {
        score += 30
    }

    switch {
    case score >= 50: return "critical"
    case score >= 30: return "high"
    case score >= 15: return "medium"
    default: return "low"
    }
}

// Known compromised actions — hardcoded, updated with each release
var knownCompromised = map[string]string{
    "tj-actions/changed-files":    "Compromised March 2025 (CVE-2025-30066)",
    "reviewdog/action-setup":      "Compromised March 2025",
    "aquasecurity/trivy-action":   "Compromised Feb+March 2026 (CVE-2026-28353)",
}
```

### Progress Output

The audit takes time (2,000 repos ≈ 40 queries ≈ 2 minutes). Show progress:

```
Scanning coreweave...
  [1/40] Fetched 50/2,047 repos (cost: 1 point, remaining: 4,999)
  [2/40] Fetched 100/2,047 repos (cost: 1 point, remaining: 4,998)
  ...
  [40/40] Fetched 2,047/2,047 repos (cost: 1 point, remaining: 4,960)

Analyzing 4,291 workflow files...
  Found 12,847 action references across 187 unique actions.

Checking upstream action security (187 actions)...
  [50/187] checking immutable releases...
  [100/187] checking immutable releases...
  [187/187] done.

Checking org policy...
  ⚠ admin:org scope not available, skipping policy check.
```

All progress goes to stderr. Report/config/manifest goes to stdout.
This means you can pipe the output cleanly:

```bash
pinpoint audit --org coreweave --output config > .pinpoint.yml
pinpoint audit --org coreweave --output manifest > .pinpoint-manifest.json
pinpoint audit --org coreweave --output json | jq '.unique_actions | length'
```

## Rate Limit Budget

Phase 1 (repo list + workflow content): 2,000 repos / 50 per page = 40 points
Phase 2 (parsing): zero (local regex on already-fetched content)
Phase 3 (immutable check): 187 REST calls = 187 points
Phase 4 (org policy): 1 REST call

**Total: ~228 API calls for a full org audit of 2,000 repos.**
That's 4.6% of the GraphQL budget + 3.7% of the REST budget.
Run time estimate: ~3 minutes.

## Test Cases

### Test 1: Org Scanning

Scan `pinpoint-testing` org (has test-scale-attack repo with workflows: no).
Verify:
- totalCount matches actual repo count
- Repos without workflows are counted but not errored
- Archived and forked repos are skipped

### Test 2: Action Reference Extraction

Given workflow content:
```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5
  - uses: docker/build-push-action@v5
  - uses: ./.github/actions/local-action
  - uses: some-org/some-action@main
```

Expected extraction:
- `actions/checkout@v4` → type: tag
- `actions/setup-go@40f158...` → type: sha
- `docker/build-push-action@v5` → type: tag
- `./.github/actions/local-action` → SKIP (local action)
- `some-org/some-action@main` → type: branch

### Test 3: Immutable Release Check

Call `CheckImmutableRelease` for:
- `aquasecurity/trivy-action` → `true`
- `actions/checkout` → `false`
- Repo with no releases → `nil`

### Test 4: Config Generation

Given discovered actions, `--output config` must produce valid YAML that
pinpoint can parse with `config.Load()`. Round-trip test:
1. Run audit, capture config output
2. Load config with `config.Load()`
3. Verify all actions are present

### Test 5: Report Contains All Sections

Human-readable report must contain:
- Repo counts (total, with workflows, skipped)
- Pinning status breakdown (SHA, tag, branch with percentages)
- Unique action count
- Top actions by usage
- High risk actions
- Branch-pinned actions (if any)
- Recommendations

## Files to Create/Modify

- CREATE: `internal/poller/graphql_org.go` — `FetchOrgWorkflows` method
- CREATE: `internal/poller/graphql_org_test.go` — unit tests with mocked responses
- CREATE: `internal/audit/audit.go` — `RunAudit`, `AuditResult`, scoring, report formatting
- CREATE: `internal/audit/audit_test.go` — unit tests for parsing, scoring, formatting
- MODIFY: `cmd/pinpoint/main.go` — add `audit` subcommand routing
- MODIFY: `internal/poller/github.go` — add `CheckImmutableRelease`, `CheckOrgPolicy`
- DO NOT create a separate binary or CLI framework

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
./pinpoint audit --help  # Must show usage
```

Integration test (manual):
```bash
GITHUB_TOKEN=$(gh auth token) ./pinpoint audit --org pinpoint-testing
GITHUB_TOKEN=$(gh auth token) ./pinpoint audit --org pinpoint-testing --output config
GITHUB_TOKEN=$(gh auth token) ./pinpoint audit --org pinpoint-testing --output json
```
