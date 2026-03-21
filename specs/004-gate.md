# Spec 004: pinpoint gate — Pre-Execution Action Integrity Verification

## Summary

A GitHub Actions step that verifies all action tag→SHA mappings against a
known-good manifest BEFORE any other action's code executes. If any tag has
been repointed, the job aborts. The attacker's code never runs.

```yaml
steps:
  - uses: tehreet/pinpoint@PINPOINT_SHA  # Must be SHA-pinned
    with:
      manifest: .pinpoint-manifest.json

  - uses: actions/checkout@v4         # Only runs if gate passed
  - uses: actions/setup-go@v5         # Only runs if gate passed
  - uses: docker/build-push-action@v5 # Only runs if gate passed
```

This is the leap from detection to prevention.

## The Fundamental Constraint

The gate itself is a GitHub Action referenced via `uses:`. If the gate's
tag is repointed, the attacker controls the verifier. Therefore:

**The gate MUST be SHA-pinned.** This is non-negotiable and documented as
the one action you must pin. The gate checks everything else for you.

We also document a maximally secure alternative that uses no `uses:`
directive at all (see "Self-Verifying Bootstrap" below).

## How GitHub Actions Execution Works

Understanding the runner's lifecycle is critical to this design:

1. Workflow is triggered
2. Runner parses the workflow YAML
3. Runner downloads ALL actions for the job to `_work/_actions/{owner}/{repo}/{ref}/`
4. Steps execute IN ORDER
5. If any step exits non-zero, subsequent steps are SKIPPED (unless `if: always()`)

**Key insight:** Between steps 3 and 4, all action code is on disk but NONE
has executed. The gate runs as step 1. If it fails, steps 2+ never run.
Download ≠ execution. Secrets are not exposed. The runner is clean.

## Verified API Contracts

All API calls verified against live GitHub API on 2026-03-21.

### Fetch Workflow File (REST)

The gate needs the workflow file to know which actions to verify. It runs
BEFORE checkout, so the file isn't on disk. Fetch it from the API:

```
GET /repos/{owner}/{repo}/contents/.github/workflows/{filename}?ref={sha}
```

**Verified:**
```bash
gh api '/repos/tehreet/pinpoint/contents/.github/workflows/ci.yml?ref=main' \
  --jq '{name, size, encoding}'
# {"encoding":"base64","name":"ci.yml","size":741}
```

Content is base64-encoded. Decode with `base64 -d` or `encoding/base64` in Go.

### Fetch Manifest File (REST)

Same endpoint, different path:

```
GET /repos/{owner}/{repo}/contents/{manifest_path}?ref={sha}
```

If the manifest doesn't exist, the API returns 404. The gate should handle
this gracefully (see "Missing Manifest" below).

### Resolve Current Tag SHAs (GraphQL)

Reuse the existing GraphQL poller query from `internal/poller/graphql.go`.
Batch all unique action repos into one query:

```graphql
{
  rateLimit { cost remaining }
  r0: repository(owner: "actions", name: "checkout") {
    refs(refPrefix: "refs/tags/", first: 100) {
      nodes {
        name
        target { __typename oid ... on Tag { target { oid } } }
      }
    }
  }
  r1: repository(owner: "actions", name: "setup-go") {
    refs(refPrefix: "refs/tags/", first: 100) {
      nodes {
        name
        target { __typename oid ... on Tag { target { oid } } }
      }
    }
  }
}
```

**Verified:** 50 repos per query, 1 GraphQL point. For a typical job with
5-15 unique action repos, this is a single query costing 1 point.

### Available Environment Variables

The following are set by the runner before any step executes:

| Variable | Example Value | Use |
|---|---|---|
| `GITHUB_REPOSITORY` | `coreweave/ml-platform` | Fetch workflow + manifest |
| `GITHUB_SHA` | `7d39f806b85c...` | Pin to exact commit |
| `GITHUB_WORKFLOW_REF` | `coreweave/ml-platform/.github/workflows/ci.yml@refs/heads/main` | Parse workflow filename |
| `GITHUB_TOKEN` | `ghs_...` (automatic) | API authentication |
| `GITHUB_API_URL` | `https://api.github.com` | API base URL |
| `GITHUB_GRAPHQL_URL` | `https://api.github.com/graphql` | GraphQL endpoint |

**Parse workflow filename from `GITHUB_WORKFLOW_REF`:**
```
coreweave/ml-platform/.github/workflows/ci.yml@refs/heads/main
                      ^--- extract this part ---^
```
Split on `@`, take the first part, strip the `{owner}/{repo}/` prefix.
Result: `.github/workflows/ci.yml`

## Implementation

### New Subcommand: `pinpoint gate`

```
pinpoint gate [flags]
```

Flags:
- `--repo` (string): Repository in `owner/repo` format.
  Default: `$GITHUB_REPOSITORY`
- `--sha` (string): Commit SHA to verify against.
  Default: `$GITHUB_SHA`
- `--workflow-ref` (string): Full workflow ref.
  Default: `$GITHUB_WORKFLOW_REF`
- `--manifest` (string): Path to manifest file in the repo.
  Default: `.pinpoint-manifest.json`
- `--fail-on-missing` (bool): Fail if an action is referenced but not in
  the manifest. Default: `false` (warn only).
- `--fail-on-unpinned` (bool): Fail if any action uses a mutable ref
  (tag or branch) instead of SHA. Default: `false`.

Exit codes:
- `0` — All verified, clean
- `1` — Error (API failure, parse error, etc.)
- `2` — Integrity violation detected (tag repointed vs manifest)

### Gate Logic

```
INPUTS:
  repo     = $GITHUB_REPOSITORY (or --repo)
  sha      = $GITHUB_SHA (or --sha)
  wf_ref   = $GITHUB_WORKFLOW_REF (or --workflow-ref)
  manifest = .pinpoint-manifest.json (or --manifest)
  token    = $GITHUB_TOKEN

STEP 1: Parse workflow filename from wf_ref
  Split wf_ref on "@", take first segment
  Strip "{owner}/{repo}/" prefix
  Result: ".github/workflows/ci.yml"

STEP 2: Fetch workflow file
  GET /repos/{repo}/contents/{workflow_path}?ref={sha}
  Decode base64 content
  If 404: fatal error, exit 1

STEP 3: Fetch manifest file
  GET /repos/{repo}/contents/{manifest}?ref={sha}
  Parse JSON
  If 404: 
    if --fail-on-missing: exit 2
    else: warn "No manifest found, skipping verification", exit 0

STEP 4: Extract action references from workflow
  Parse YAML, extract all `uses:` directives
  Skip local actions (starts with "./")
  Skip Docker actions (starts with "docker://")
  For each ref, classify:
    SHA-pinned:    ref matches ^[0-9a-f]{40}$
    Tag-pinned:    everything else that's not a branch
    Branch-pinned: known branch names (main, master, develop, etc.)
  Deduplicate by {owner}/{repo}

STEP 5: Resolve current tag SHAs
  Build GraphQL query for all unique {owner}/{repo} pairs
  Execute query (1 point per 50 repos)
  Map: {owner}/{repo} -> {tag_name -> current_sha}

STEP 6: Compare against manifest
  For each tag-pinned reference:
    current_sha = resolved from GraphQL
    expected_sha = manifest.actions[owner/repo][tag].sha
    If current_sha != expected_sha:
      VIOLATION: tag repointed
      Record: {action, tag, expected, actual}
    If tag not in manifest:
      If --fail-on-missing: VIOLATION
      Else: WARNING

  For each SHA-pinned reference:
    If --fail-on-missing and SHA not in manifest: WARNING
    Else: PASS (SHA pins are inherently safe)

  For each branch-pinned reference:
    If --fail-on-unpinned: VIOLATION
    Else: WARNING

STEP 7: Report and exit
  If any VIOLATIONS: print report, exit 2
  If only WARNINGS: print warnings, exit 0
  If clean: print "✓ All actions verified", exit 0
```

### Gate Output Format

**Clean (exit 0):**
```
pinpoint gate: verifying 6 action references against manifest...
  ✓ actions/checkout@v4 → abc123... (matches manifest)
  ✓ actions/setup-go@v5 → def456... (matches manifest)
  ✓ docker/build-push-action@v5 → 789abc... (matches manifest)
  ⊘ actions/cache@v3 → not in manifest (skipping, use --fail-on-missing to enforce)
  ✓ aquasecurity/trivy-action@0.35.0 → fed321... (matches manifest)
  ● actions/upload-artifact@a824008... → SHA-pinned (inherently safe)

✓ All action integrity checks passed (5 verified, 1 skipped, 0 violations)
```

**Violation (exit 2):**
```
pinpoint gate: verifying 6 action references against manifest...
  ✓ actions/checkout@v4 → abc123... (matches manifest)
  ✓ actions/setup-go@v5 → def456... (matches manifest)
  ✗ aquasecurity/trivy-action@0.35.0
    EXPECTED: fed321... (from manifest, recorded 2026-03-20T08:00:00Z)
    ACTUAL:   bad999... (resolved just now)
    ⚠ TAG HAS BEEN REPOINTED — possible supply chain attack

✗ INTEGRITY VIOLATION: 1 action tag does not match manifest
  Job will not continue. Investigate immediately.
  Dashboard: https://github.com/{repo}/security
```

### API Cost

For a typical CI workflow with 5-10 unique action repos:

| Phase | Calls | Cost |
|---|---|---|
| Fetch workflow file | 1 REST | 1 |
| Fetch manifest | 1 REST | 1 |
| Resolve all tag SHAs | 1 GraphQL | 1 point |
| **Total** | **3 calls** | **~2 seconds** |

This adds <3 seconds to every CI run. For context, `actions/checkout` alone
takes 2-5 seconds.

## Composite Action: `action.yml`

Lives at the root of the `tehreet/pinpoint` repo.

```yaml
name: 'Pinpoint Gate'
description: 'Verify GitHub Action tag integrity before execution'
branding:
  icon: 'shield'
  color: 'red'
inputs:
  manifest:
    description: 'Path to manifest file in the repository'
    required: false
    default: '.pinpoint-manifest.json'
  fail-on-missing:
    description: 'Fail if an action reference is not in the manifest'
    required: false
    default: 'false'
  fail-on-unpinned:
    description: 'Fail if any action uses a mutable ref (tag/branch)'
    required: false
    default: 'false'
  version:
    description: 'Pinpoint version to use'
    required: false
    default: '1.0.0'
runs:
  using: 'composite'
  steps:
    - name: Download pinpoint
      shell: bash
      run: |
        VERSION="${{ inputs.version }}"
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        ARCH=$(uname -m)
        case "$ARCH" in
          x86_64)       ARCH="amd64" ;;
          aarch64|arm64) ARCH="arm64" ;;
        esac
        BINARY="pinpoint-${OS}-${ARCH}"
        URL="https://github.com/tehreet/pinpoint/releases/download/v${VERSION}/${BINARY}"

        curl -sSL "$URL" -o "${{ runner.temp }}/pinpoint"
        curl -sSL "${URL}.sha256" -o "${{ runner.temp }}/pinpoint.sha256"

        cd "${{ runner.temp }}"
        sha256sum -c pinpoint.sha256
        chmod +x pinpoint

    - name: Verify action integrity
      shell: bash
      env:
        GITHUB_TOKEN: ${{ github.token }}
      run: |
        ARGS="--manifest ${{ inputs.manifest }}"
        if [ "${{ inputs.fail-on-missing }}" = "true" ]; then
          ARGS="$ARGS --fail-on-missing"
        fi
        if [ "${{ inputs.fail-on-unpinned }}" = "true" ]; then
          ARGS="$ARGS --fail-on-unpinned"
        fi

        "${{ runner.temp }}/pinpoint" gate $ARGS
```

### Why Download at Runtime?

Committing multi-platform binaries (5 platforms × ~10MB each = 50MB) to the
action repo bloats every clone. Downloading from GitHub Releases:
- Keeps the action repo lightweight
- Enables version pinning via the `version` input
- SHA256 verification ensures binary integrity
- GitHub Releases are served from a CDN, fast worldwide

The download adds ~1 second. Total gate time: ~3 seconds.

## Self-Verifying Bootstrap (Maximum Security)

For users who want zero `uses:` directives for the gate itself:

```yaml
steps:
  - name: Pinpoint Gate (self-verifying)
    env:
      GITHUB_TOKEN: ${{ github.token }}
    run: |
      PINPOINT_VERSION="1.0.0"
      PINPOINT_SHA256="abc123...expected_hash_here..."

      curl -sSL "https://github.com/tehreet/pinpoint/releases/download/v${PINPOINT_VERSION}/pinpoint-linux-amd64" \
        -o /tmp/pinpoint
      echo "${PINPOINT_SHA256}  /tmp/pinpoint" | sha256sum -c
      chmod +x /tmp/pinpoint

      /tmp/pinpoint gate --manifest .pinpoint-manifest.json

  - uses: actions/checkout@v4
  # ...
```

This pattern has NO `uses:` directive for the gate. The binary is
downloaded and hash-verified inline. Even if every action tag in the
ecosystem is compromised, this step runs only code you've explicitly
hash-pinned.

We publish the SHA256 hashes in:
- GitHub Release assets (`pinpoint-linux-amd64.sha256`)
- The README
- A signed SLSA provenance attestation (future)

## Manifest File Format

The manifest is generated by `pinpoint audit --output manifest` or
`pinpoint scan --emit-manifest`. Format (from spec 003):

```json
{
  "version": 1,
  "generated_at": "2026-03-21T08:00:00Z",
  "generated_by": "pinpoint audit --org coreweave",
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "recorded_at": "2026-03-21T08:00:00Z"
      },
      "v4.2.2": {
        "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "recorded_at": "2026-03-21T08:00:00Z"
      }
    },
    "aquasecurity/trivy-action": {
      "0.35.0": {
        "sha": "57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
        "recorded_at": "2026-03-21T08:00:00Z"
      }
    }
  }
}
```

The gate reads this file and compares `actions[owner/repo][tag].sha`
against the live-resolved SHA from the GraphQL API.

## Manifest Lifecycle

```
pinpoint audit --org coreweave --output manifest > .pinpoint-manifest.json
git add .pinpoint-manifest.json
git commit -m "Add pinpoint manifest"
git push
```

The manifest is committed to the repo. It's versioned with the code.
When you add new actions or update versions, regenerate:

```
pinpoint audit --org coreweave --output manifest > .pinpoint-manifest.json
```

For automated updates, run `pinpoint scan --emit-manifest` on a schedule
and create a PR when the manifest changes (Dependabot-style).

## Handling Edge Cases

### Missing Manifest (404)

Default: warn and exit 0 (don't block CI if manifest hasn't been set up).
With `--fail-on-missing`: exit 2.

### Action Not in Manifest

Default: skip with warning. With `--fail-on-missing`: exit 2.
This handles new actions added to workflows before the manifest is updated.

### SHA-Pinned Actions

SHA-pinned actions are inherently safe — the SHA is immutable. The gate
logs them as "inherently safe" and moves on. No API call needed for these.

### Branch-Pinned Actions (e.g., `@main`)

Default: warn. With `--fail-on-unpinned`: exit 2.
Branch pins can't be verified against a manifest because they're expected
to change. The gate can only flag them as risky.

### Reusable Workflows (`uses: owner/repo/.github/workflows/x.yml@ref`)

The `uses:` directive for reusable workflows has a different format but
follows the same `@ref` pattern. The gate handles both:
- `owner/repo@ref` (actions)
- `owner/repo/.github/workflows/file.yml@ref` (reusable workflows)

Parse rule: split on `@`, take the ref. For the repo, split the pre-`@`
part: if it contains `.github/workflows/`, it's a reusable workflow —
extract `owner/repo` from the prefix.

### Rate Limiting

The gate adds 3 API calls per job. For an org running 1,000 CI jobs/hour:
- 1,000 REST calls for workflow files (no rate limit concern, these are cached)
- 1,000 REST calls for manifests (same)
- 1,000 GraphQL points (20% of 5,000/hour budget)

At high scale, the GraphQL calls are the constraint. Mitigation: cache
tag resolutions in the manifest with a TTL. If the manifest was generated
<5 minutes ago, trust it without re-resolving. This reduces GraphQL usage
to zero for fresh manifests.

### GHES / GHE.com

The gate uses `GITHUB_API_URL` and `GITHUB_GRAPHQL_URL` instead of
hardcoding `api.github.com`. This makes it compatible with GitHub
Enterprise Server and GHE.com out of the box.

## Internal Architecture

### New File: `internal/gate/gate.go`

```go
package gate

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "regexp"
    "strings"
    "time"
)

// GateResult holds the verification outcome.
type GateResult struct {
    Verified   int
    Skipped    int
    Violations []Violation
    Warnings   []Warning
    Duration   time.Duration
}

type Violation struct {
    Action      string // "aquasecurity/trivy-action"
    Tag         string // "0.35.0"
    ExpectedSHA string // from manifest
    ActualSHA   string // from live API
}

type Warning struct {
    Action  string
    Ref     string
    Message string // "not in manifest", "branch-pinned", etc.
}

// Manifest represents the .pinpoint-manifest.json file.
type Manifest struct {
    Version     int                                  `json:"version"`
    GeneratedAt string                               `json:"generated_at"`
    Actions     map[string]map[string]ManifestEntry  `json:"actions"`
}

type ManifestEntry struct {
    SHA        string `json:"sha"`
    RecordedAt string `json:"recorded_at,omitempty"`
}

// RunGate performs the pre-execution verification.
func RunGate(ctx context.Context, opts GateOptions) (*GateResult, error)

type GateOptions struct {
    Repo          string // "owner/repo"
    SHA           string // commit SHA
    WorkflowRef   string // "owner/repo/.github/workflows/ci.yml@refs/heads/main"
    ManifestPath  string // ".pinpoint-manifest.json"
    Token         string
    APIURL        string // "https://api.github.com"
    GraphQLURL    string // "https://api.github.com/graphql"
    FailOnMissing bool
    FailOnUnpinned bool
}
```

### Workflow Parser

The gate needs to parse workflow YAML to extract `uses:` directives.
We don't need a full YAML parser — a targeted extraction is sufficient
and avoids pulling in a heavy YAML library for a runtime-critical path.

```go
// ExtractUsesDirectives extracts all `uses:` values from workflow YAML.
// Returns a slice of raw reference strings like:
//   "actions/checkout@v4"
//   "docker/build-push-action@v5"
//   "./.github/actions/local"
func ExtractUsesDirectives(workflowContent string) []string {
    // Regex: captures the value after `uses:` (with optional quotes)
    re := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*['"]?([^'"#\s]+)['"]?`)
    matches := re.FindAllStringSubmatch(workflowContent, -1)
    var refs []string
    for _, m := range matches {
        refs = append(refs, m[1])
    }
    return refs
}

// ParseActionRef parses "owner/repo@ref" or "owner/repo/path@ref"
// Returns owner, repo, ref, and whether it's a reusable workflow.
func ParseActionRef(raw string) (owner, repo, ref string, isWorkflow bool, err error) {
    if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "docker://") {
        return "", "", "", false, fmt.Errorf("local or docker action: %s", raw)
    }
    parts := strings.SplitN(raw, "@", 2)
    if len(parts) != 2 {
        return "", "", "", false, fmt.Errorf("no @ in ref: %s", raw)
    }
    ref = parts[1]
    repoPath := parts[0]

    // Check for reusable workflow: owner/repo/.github/workflows/file.yml
    if strings.Contains(repoPath, "/.github/workflows/") {
        segments := strings.SplitN(repoPath, "/", 3)
        return segments[0], segments[1], ref, true, nil
    }

    // Standard action: owner/repo or owner/repo/subpath
    segments := strings.SplitN(repoPath, "/", 3)
    if len(segments) < 2 {
        return "", "", "", false, fmt.Errorf("invalid action ref: %s", raw)
    }
    return segments[0], segments[1], ref, false, nil
}
```

### Content Fetcher

```go
// FetchFileContent fetches a file from a repo at a specific commit.
// Uses: GET /repos/{owner}/{repo}/contents/{path}?ref={sha}
func (c *GitHubClient) FetchFileContent(ctx context.Context, repo, path, sha string) ([]byte, error) {
    url := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", c.baseURL, repo, path, sha)
    // GET request with Authorization header
    // Parse response: { "content": "base64...", "encoding": "base64" }
    // Decode base64
    // Return raw bytes
}
```

### Gate Execution Flow (Go)

```go
func RunGate(ctx context.Context, opts GateOptions) (*GateResult, error) {
    start := time.Now()
    client := NewGitHubClient(opts.Token, opts.APIURL)
    gql := NewGraphQLClient(opts.Token, opts.GraphQLURL)

    // Step 1: Parse workflow path from GITHUB_WORKFLOW_REF
    workflowPath := parseWorkflowPath(opts.WorkflowRef, opts.Repo)

    // Step 2: Fetch workflow file
    wfContent, err := client.FetchFileContent(ctx, opts.Repo, workflowPath, opts.SHA)
    if err != nil {
        return nil, fmt.Errorf("fetch workflow: %w", err)
    }

    // Step 3: Fetch manifest
    manifestContent, err := client.FetchFileContent(ctx, opts.Repo, opts.ManifestPath, opts.SHA)
    if err != nil {
        if isNotFound(err) {
            if opts.FailOnMissing {
                return &GateResult{Violations: []Violation{{Action: "manifest", Tag: opts.ManifestPath, ExpectedSHA: "exists", ActualSHA: "missing"}}}, nil
            }
            fmt.Fprintf(os.Stderr, "⚠ No manifest found at %s, skipping verification\n", opts.ManifestPath)
            return &GateResult{Duration: time.Since(start)}, nil
        }
        return nil, fmt.Errorf("fetch manifest: %w", err)
    }
    var manifest Manifest
    json.Unmarshal(manifestContent, &manifest)

    // Step 4: Extract action references
    rawRefs := ExtractUsesDirectives(string(wfContent))

    // Step 5: Classify and deduplicate
    type actionRef struct {
        Owner, Repo, Ref string
        IsSHA            bool
        IsBranch         bool
    }
    var tagRefs []actionRef
    repoSet := map[string]bool{}

    for _, raw := range rawRefs {
        owner, repo, ref, _, err := ParseActionRef(raw)
        if err != nil { continue } // skip local/docker

        key := owner + "/" + repo
        isSHA := regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(ref)

        if isSHA {
            // SHA-pinned: inherently safe, log and skip
            result.Skipped++
            continue
        }

        tagRefs = append(tagRefs, actionRef{owner, repo, ref, false, isBranch(ref)})
        repoSet[key] = true
    }

    // Step 6: Resolve current SHAs via GraphQL
    repos := mapToSlice(repoSet)
    tagMap, err := gql.FetchTagSHAs(ctx, repos) // reuse existing poller
    if err != nil {
        return nil, fmt.Errorf("resolve tags: %w", err)
    }

    // Step 7: Compare
    for _, ar := range tagRefs {
        key := ar.Owner + "/" + ar.Repo

        if ar.IsBranch {
            result.Warnings = append(result.Warnings, Warning{
                Action: key, Ref: ar.Ref, Message: "branch-pinned (mutable)",
            })
            if opts.FailOnUnpinned {
                result.Violations = append(result.Violations, Violation{
                    Action: key, Tag: ar.Ref,
                    ExpectedSHA: "SHA-pinned",
                    ActualSHA:   "branch:" + ar.Ref,
                })
            }
            continue
        }

        // Look up in manifest
        manifestAction, ok := manifest.Actions[key]
        if !ok {
            result.Warnings = append(result.Warnings, Warning{
                Action: key, Ref: ar.Ref, Message: "not in manifest",
            })
            if opts.FailOnMissing {
                result.Violations = append(result.Violations, Violation{
                    Action: key, Tag: ar.Ref,
                    ExpectedSHA: "in manifest",
                    ActualSHA:   "missing",
                })
            }
            continue
        }
        manifestEntry, ok := manifestAction[ar.Ref]
        if !ok {
            result.Warnings = append(result.Warnings, Warning{
                Action: key, Ref: ar.Ref, Message: "tag not in manifest",
            })
            continue
        }

        // Look up current SHA from GraphQL
        currentSHA := tagMap[key][ar.Ref]
        if currentSHA == "" {
            result.Warnings = append(result.Warnings, Warning{
                Action: key, Ref: ar.Ref, Message: "tag not found on remote",
            })
            continue
        }

        if currentSHA != manifestEntry.SHA {
            result.Violations = append(result.Violations, Violation{
                Action:      key,
                Tag:         ar.Ref,
                ExpectedSHA: manifestEntry.SHA,
                ActualSHA:   currentSHA,
            })
        } else {
            result.Verified++
        }
    }

    result.Duration = time.Since(start)
    return result, nil
}
```

## Workflow Integration Examples

### Basic (Recommended)

```yaml
name: CI
on: push

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tehreet/pinpoint@FULL_40_CHAR_SHA  # SHA-pinned
        with:
          manifest: .pinpoint-manifest.json

      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - run: go build ./...
      - run: go test ./...
```

### Strict Mode

```yaml
      - uses: tehreet/pinpoint@FULL_40_CHAR_SHA
        with:
          manifest: .pinpoint-manifest.json
          fail-on-missing: 'true'
          fail-on-unpinned: 'true'
```

### Self-Hosted Runners (Maximum Security)

```yaml
      - name: Pinpoint Gate
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          curl -sSL "https://github.com/tehreet/pinpoint/releases/download/v1.0.0/pinpoint-linux-amd64" \
            -o /tmp/pinpoint
          echo "EXPECTED_SHA256  /tmp/pinpoint" | sha256sum -c
          chmod +x /tmp/pinpoint
          /tmp/pinpoint gate --manifest .pinpoint-manifest.json
```

### Reusable Workflow (Org-Wide)

For orgs that want the gate on EVERY workflow without editing each one:

```yaml
# .github/workflows/gate.yml (reusable)
name: Security Gate
on:
  workflow_call:
    inputs:
      manifest:
        type: string
        default: '.pinpoint-manifest.json'

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: tehreet/pinpoint@FULL_40_CHAR_SHA
        with:
          manifest: ${{ inputs.manifest }}
```

Then in every CI workflow:

```yaml
jobs:
  gate:
    uses: ./.github/workflows/gate.yml

  build:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ...
```

## Release Process for Binaries

The gate downloads binaries from GitHub Releases. Each release needs:

```
pinpoint-linux-amd64
pinpoint-linux-amd64.sha256
pinpoint-linux-arm64
pinpoint-linux-arm64.sha256
pinpoint-darwin-amd64
pinpoint-darwin-amd64.sha256
pinpoint-darwin-arm64
pinpoint-darwin-arm64.sha256
pinpoint-windows-amd64.exe
pinpoint-windows-amd64.exe.sha256
```

Build with:
```bash
GOOS=linux GOARCH=amd64 go build -o pinpoint-linux-amd64 ./cmd/pinpoint/
sha256sum pinpoint-linux-amd64 > pinpoint-linux-amd64.sha256
# ... repeat for each platform
```

Automate with a GitHub Actions workflow that builds on tag push and
uploads to the release.

## Test Cases

### Test 1: Clean Verification

Given a workflow with 3 tag-pinned actions and a manifest that matches:
- Expected: exit 0, "All action integrity checks passed"

### Test 2: Tag Repointed

Given a workflow with `aquasecurity/trivy-action@0.35.0` and a manifest
where the SHA is different from the live-resolved SHA:
- Expected: exit 2, violation message with expected vs actual SHAs

### Test 3: Missing Manifest

Given `--manifest .pinpoint-manifest.json` but the file doesn't exist:
- Default: exit 0 with warning
- With `--fail-on-missing`: exit 2

### Test 4: Action Not in Manifest

Given a workflow referencing an action not in the manifest:
- Default: exit 0 with warning ("not in manifest")
- With `--fail-on-missing`: exit 2

### Test 5: SHA-Pinned Actions (Passthrough)

Given a workflow where all actions are SHA-pinned:
- Expected: exit 0, all marked "inherently safe", no GraphQL calls needed

### Test 6: Branch-Pinned Actions

Given a workflow with `some-action@main`:
- Default: exit 0 with warning
- With `--fail-on-unpinned`: exit 2

### Test 7: Reusable Workflow Reference

Given `uses: org/repo/.github/workflows/build.yml@v1`:
- Expected: parsed correctly, verified against manifest like any other ref

### Test 8: GITHUB_WORKFLOW_REF Parsing

Input: `"coreweave/ml-platform/.github/workflows/ci.yml@refs/heads/main"`
Expected: workflow path = `.github/workflows/ci.yml`

Input: `"tehreet/pinpoint/.github/workflows/ci.yml@refs/tags/v1.0.0"`
Expected: workflow path = `.github/workflows/ci.yml`

### Test 9: End-to-End with Mock Servers

Stand up mock HTTP servers for REST and GraphQL.
- REST serves workflow file and manifest
- GraphQL returns tag SHAs (one tag repointed)
- Expected: gate detects the repointed tag, exit 2

## Files to Create/Modify

- CREATE: `internal/gate/gate.go` — RunGate, Manifest types, parsing, comparison
- CREATE: `internal/gate/gate_test.go` — unit tests with mock servers
- CREATE: `action.yml` — composite action definition (at repo root)
- MODIFY: `cmd/pinpoint/main.go` — add `gate` subcommand
- MODIFY: `internal/poller/graphql.go` — export FetchTagSHAs if not already
- DO NOT modify existing scan/watch/audit functionality

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
./pinpoint gate --help
```

Integration test (manual):
```bash
# Create a test manifest
echo '{"version":1,"actions":{"actions/checkout":{"v4":{"sha":"34e114876b0b11c390a56381ad16ebd13914f8d5"}}}}' > /tmp/test-manifest.json

# Test against real repo (note: manifest must be in the repo for --manifest to work,
# or pass content directly; for testing, we can use the REST path override)
GITHUB_TOKEN=$(gh auth token) \
  ./pinpoint gate \
    --repo tehreet/pinpoint \
    --sha $(git rev-parse HEAD) \
    --workflow-ref "tehreet/pinpoint/.github/workflows/ci.yml@refs/heads/main" \
    --manifest .pinpoint-manifest.json
```
