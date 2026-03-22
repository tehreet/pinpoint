# Pinpoint

GitHub Actions tag integrity monitor. Detects and prevents supply chain
attacks that repoint action version tags to malicious commits.

Built in response to the [Trivy supply chain attack](https://github.com/aquasecurity/trivy/discussions/10425) of March 2026,
where 75 tags were force-pushed to credential-stealing commits across 10,000+
dependent workflows.

## The Problem

GitHub Actions uses mutable git tags as version references. When you write
`uses: actions/checkout@v4`, you're trusting that `v4` still points to the
same commit it did yesterday. Anyone with write access can silently repoint it
to a malicious commit.

[98% of workflows don't pin to SHAs](https://www.legitsecurity.com/blog/github-actions-security-risks) (Legit Security, 2025).
Even among the [top 100 security projects on GitHub, only 3% properly pin everything](https://www.paloaltonetworks.com/blog/prisma-cloud/github-actions-supply-chain-vulnerabilities/) (Alvarez, 2025).
The Trivy and tj-actions attacks exploited exactly this.

SHA pinning alone doesn't solve the problem. Composite actions can internally
reference unpinned actions — your workflow is pinned, but the action you pinned
pulls in unverified transitive dependencies.

## Quick Start

```bash
# Install
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

# Generate lockfile
cd your-repo
pinpoint lock

# Commit
git add .github/actions-lock.json
git commit -m "Add actions lockfile"

# See your dependency tree
pinpoint lock --list
```

Add the gate to your workflow:

```yaml
steps:
  - uses: tehreet/pinpoint@SHA_HERE
    with:
      on-disk: true  # recommended: verify what the runner actually downloaded
  - uses: actions/checkout@v4
  # ... your steps run only after integrity verification
```

### Continuous Monitoring

```bash
pinpoint watch --config .pinpoint.yml --interval 5m
```

## Commands

| Command | What it does |
|---------|--------------|
| `pinpoint lock` | Generate .github/actions-lock.json with SHA, integrity hash, type, and transitive deps |
| `pinpoint lock --list` | Show the full dependency tree including transitive deps |
| `pinpoint lock --verify` | Check lockfile against live tags without modifying |
| `pinpoint gate` | Pre-execution integrity verification (3 API calls, <2s) |
| `pinpoint gate --on-disk` | Verify what the runner actually downloaded (+28ms, zero API calls) |
| `pinpoint gate --integrity` | Re-download tarballs and verify SHA-256 hashes (periodic audit mode) |
| `pinpoint scan` | One-shot: poll all monitored actions, report tag changes with risk scoring |
| `pinpoint watch` | Continuous monitoring on interval |
| `pinpoint discover` | Find actions in local workflow files |
| `pinpoint audit --org <name>` | Org-wide security posture scan |
| `pinpoint verify` | Retroactive integrity check (works day-one, no baseline needed) |

## Lockfile Format

```json
{
  "version": 2,
  "generated": "2026-03-20T12:00:00Z",
  "actions": {
    "actions/checkout@v4": {
      "sha": "11bd71901bbe5b1630ceea73d27597364c9af683",
      "integrity": "sha256-abc123...",
      "disk_integrity": "sha256-def456...",
      "type": "annotated",
      "dependencies": {
        "actions/toolkit@v1": {
          "sha": "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15",
          "integrity": "sha256-ghi789..."
        }
      }
    }
  }
}
```

| Field | Meaning |
|-------|---------|
| `sha` | The commit SHA the tag pointed to at lock time |
| `integrity` | SHA-256 hash of the tarball downloaded from GitHub |
| `disk_integrity` | SHA-256 hash of the extracted action directory tree |
| `type` | Tag type: `lightweight` or `annotated` |
| `dependencies` | Transitive `uses:` references found inside composite actions |

## Gate Verification Levels

Three levels, from fastest to most thorough:

1. **SHA-only (default)**: Tag→SHA matches lockfile. 3 API calls, <2 seconds.
   Catches tag repointing.

2. **On-disk (`--on-disk`)**: Hashes what the runner actually downloaded at
   `_actions/`. +28ms disk I/O, zero additional API calls. Catches TOCTOU
   races, cache poisoning, disk tampering. Recommended for security-sensitive
   workflows.

3. **Integrity (`--integrity`)**: Re-downloads tarballs from GitHub, recomputes
   SHA-256. +3-5s. For periodic audits, not every CI run.

These are independent flags. Use `--on-disk` for daily CI, `--integrity` as a
weekly cron.

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

## Verify: Day-One Integrity Check

`pinpoint verify` performs retroactive integrity checks without needing a prior
baseline. Run it right now on any repo — no setup required.

Four signals:

- **Release SHA match**: Compares the release object's tag commit to the
  current tag SHA. A mismatch means the tag moved after the release was cut.
- **GPG signature continuity**: Flags if a previously-signed action stops
  publishing signed commits.
- **Chronology check**: Catches backdated commits — a commit authored months
  ago but tagged today is suspicious.
- **Advisory database**: Cross-references against known compromised actions.

This doesn't guarantee the current state is clean, but it surfaces the most
common indicators of compromise.

## Real-World Findings

Scanning real repos with pinpoint revealed:

- 3 popular actions with GPG signing discontinuities: `aws-actions/configure-aws-credentials`, `hashicorp/setup-terraform`, `golangci/golangci-lint-action`
- Grafana pins shared workflows to `@main` (branch-pinned, mutable)
- Repos still referencing known-compromised tj-actions and reviewdog versions over a year after the attack
- Kubernetes: 139 workflows with zero gate protection

## Scale

| Metric | Value |
|--------|-------|
| 142 repos, 7,736 tags | 3 GraphQL points, 34 seconds |
| Gate per CI run (SHA-only) | 3 API calls, <2 seconds |
| Gate per CI run (on-disk) | 3 API calls + 28ms disk I/O |
| Lock (15 actions, parallel) | ~15 seconds, 16MB RSS |
| Org audit (277 repos) | 6 points, <2 minutes |
| GraphQL wall | ~20,000 repos at 5-min intervals |

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
pinpoint can and cannot do.

## Stats

151 tests. 15,000+ lines of Go. Single binary, one dependency
(`gopkg.in/yaml.v3`). GPL-3.0.

## License

GPL-3.0. Copyright (C) 2026 CoreWeave, Inc.

Supply chain security monitoring should be free.
