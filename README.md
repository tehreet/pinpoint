# Pinpoint

GitHub Actions tag integrity monitor. Detects and prevents supply chain
attacks that repoint action version tags to malicious commits.

Built in response to the [Trivy supply chain attack](https://github.com/aquasecurity/trivy/discussions/10425) of March 2026,
where 75 tags were force-pushed to credential-stealing commits across 10,000+ dependent workflows.

## The Problem

GitHub Actions uses mutable git tags as version references. When you write
`uses: actions/checkout@v4`, you're trusting that `v4` still points to the
same commit it did yesterday. Anyone with write access can silently repoint it
to a malicious commit. 95%+ of the ecosystem uses tags, not SHA pins. The
Trivy and tj-actions attacks exploited exactly this.

## What Pinpoint Does

**Detection:** Monitors tag→SHA mappings for upstream actions. Alerts when
tags are repointed, with risk scoring that distinguishes routine major-version
advances from supply chain attacks.

**Prevention:** The gate (`pinpoint gate`) runs as the first step in your CI
job. It verifies every action's tag against a known-good manifest before any
untrusted code executes. Mismatch = job aborts.

## Quick Start

### Install

```bash
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest
```

Or download a binary from [Releases](https://github.com/tehreet/pinpoint/releases).

### Discover Your Actions

```bash
pinpoint discover --workflows .github/workflows/
```

### Generate a Manifest

```bash
export GITHUB_TOKEN=ghp_...
pinpoint audit --org your-org --output manifest > .pinpoint-manifest.json
```

### Add the Gate to Your Workflow

```yaml
steps:
  - uses: tehreet/pinpoint@SHA_HERE  # Always SHA-pin the gate itself
    with:
      manifest: .pinpoint-manifest.json

  - uses: actions/checkout@v4
  # ... your steps run only if all tags verified
```

### Continuous Monitoring

```bash
pinpoint watch --config .pinpoint.yml --interval 5m
```

## Commands

| Command | Description |
|---------|-------------|
| `pinpoint scan` | One-shot: poll all monitored actions, report changes |
| `pinpoint watch` | Continuous: poll on interval, alert on changes |
| `pinpoint discover` | Find actions in local workflow files |
| `pinpoint audit --org <name>` | Org-wide security posture scan |
| `pinpoint gate` | Pre-execution integrity verification |
| `pinpoint manifest refresh` | Update manifest with current tag SHAs |
| `pinpoint manifest verify` | Check manifest against live tags (read-only) |
| `pinpoint manifest init` | Bootstrap manifest + workflow files |

## Gate: How It Works

The gate runs as the first step in your CI job. It fetches the workflow file
that triggered the run from the GitHub API, extracts all `uses:` directives,
resolves current tag SHAs via GraphQL, and compares them against your
`.pinpoint-manifest.json`. If any tag has been repointed, the job fails before
any untrusted code reaches the runner. Typical overhead: 3 API calls, <2
seconds.

## Audit: Org-Wide Visibility

```bash
pinpoint audit --org your-org
```

One command scans every repo in your org. It discovers all action dependencies,
classifies each reference (SHA-pinned, tag-pinned, branch-pinned), checks
upstream immutable release status, and reports your org's overall pinning
posture. Output formats: human report, YAML config, JSON manifest, SARIF.

## Risk Scoring

Not every tag movement is malicious. Pinpoint scores each event:

| Signal | Description | Score |
|--------|-------------|-------|
| MASS_REPOINT | >5 tags repointed at once | +100 |
| OFF_BRANCH | New commit not a descendant | +80 |
| SIZE_ANOMALY | Entry point size changed >50% | +60 |
| SEMVER_REPOINT | Exact version tag moved (e.g. v1.2.3) | +50 |
| BACKDATED_COMMIT | Commit date >30 days old | +40 |
| NO_RELEASE | No corresponding GitHub Release | +20 |
| SELF_HOSTED | Self-hosted runners affected | +15 |
| MAJOR_TAG_ADVANCE | Major tag moved forward to descendant | -30 |

Score ≥50 = CRITICAL, ≥20 = MEDIUM, <20 = LOW.

## Scale

| Metric | Value |
|--------|-------|
| 142 repos, 7,736 tags | 3 GraphQL points, 34 seconds |
| 2,000 repos (full poll cycle) | 40 GraphQL points |
| Gate per CI run | 2 REST + 1 GraphQL call, <2 seconds |

GraphQL batches 50 repos per query at 1 point each. The 5,000 points/hour
budget supports continuous monitoring of thousands of repos.

## Configuration

```yaml
# .pinpoint.yml
actions:
  - repo: aquasecurity/trivy-action
    tags: ["0.35.0"]
    self_hosted_runners: true

  - repo: actions/checkout
    tags: ["*"]

allow:
  - repo: actions/*
    tags: ["v*"]
    condition: major_tag_advance
    reason: "GitHub-maintained actions routinely advance major tags"

alerts:
  min_severity: medium
  slack_webhook: https://hooks.slack.com/services/T.../B.../xxx

store:
  path: .pinpoint-state.json
```

## SARIF Integration

Output scan or audit results in SARIF format for GitHub's Security tab:

```yaml
- name: Pinpoint Scan
  run: pinpoint scan --config .pinpoint.yml --output sarif > pinpoint.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pinpoint.sarif
```

## Limitations

See [STEELMAN.md](STEELMAN.md) for a brutally honest assessment of what
pinpoint can and cannot do, including polling gaps, gate TOCTOU races,
adversarial evasion techniques, and scale constraints.

## License

GPL-3.0. Copyright (C) 2026 CoreWeave, Inc.

Supply chain security monitoring should be free.
