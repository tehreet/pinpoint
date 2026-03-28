# Pinpoint

GitHub Actions supply chain security. Detects and prevents attacks that
repoint action version tags to malicious commits — including Docker image
tag repointing.

Built in response to the [Trivy supply chain attack](https://github.com/aquasecurity/trivy/discussions/10425) of March 2026,
where 75 tags were force-pushed to credential-stealing commits across 10,000+
dependent workflows.

## The Problem

GitHub Actions uses mutable git tags as version references. When you write
`uses: actions/checkout@v4`, you're trusting that `v4` still points to the
same commit it did yesterday. Anyone with write access can silently repoint it
to a malicious commit.

[98% of workflows don't pin to SHAs](https://www.legitsecurity.com/blog/github-actions-security-risks) (Legit Security, 2025).
Even among the [top 100 security projects, only 3% properly pin everything](https://www.paloaltonetworks.com/blog/prisma-cloud/github-actions-supply-chain-vulnerabilities/) (Alvarez, 2025).

SHA pinning alone doesn't solve it. Composite actions can internally reference
unpinned actions. Docker-based actions can have their container image tags
repointed at the registry level, completely invisible to Git-based verification.

## Quick Start

```bash
# Install
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

# Generate lockfile (captures SHAs, integrity hashes, Docker digests)
cd your-repo
pinpoint lock

# See your dependency tree
pinpoint lock --list

# Commit
git add .github/actions-lock.json
git commit -m "Add actions lockfile"
```

### GitHub Actions Gate

Add the gate as the first step in every job:

```yaml
steps:
  - uses: tehreet/pinpoint-action@v1
    with:
      mode: enforce
  - uses: actions/checkout@v4
  # ... your steps run only after integrity verification
```

Or use a reusable workflow for org-wide enforcement:

```yaml
jobs:
  gate:
    uses: your-org/shared-workflows/.github/workflows/pinpoint-gate.yml@SHA
    with:
      warn: false
    secrets:
      PINPOINT_APP_ID: ${{ secrets.PINPOINT_APP_ID }}
      PINPOINT_APP_PRIVATE_KEY: ${{ secrets.PINPOINT_APP_PRIVATE_KEY }}
```

### Continuous Monitoring

```bash
pinpoint watch --config .pinpoint.yml --interval 5m
```

## Commands

| Command | What it does |
|---------|--------------|
| `pinpoint lock` | Generate .github/actions-lock.json with SHA, integrity hash, type, transitive deps, and Docker digests |
| `pinpoint lock --list` | Show the full dependency tree including transitive deps |
| `pinpoint lock --verify` | Check lockfile against live tags without modifying |
| `pinpoint gate` | Pre-execution integrity verification (3 API calls, <2s) |
| `pinpoint gate --on-disk` | Verify what the runner actually downloaded (+28ms, zero API calls) |
| `pinpoint gate --integrity` | Re-download tarballs + re-resolve Docker digests from registries |
| `pinpoint gate --all-workflows` | Scan all workflow files, not just the triggering one |
| `pinpoint gate --fail-on-missing` | Block actions not in lockfile (auto-enabled with new lockfile path) |
| `pinpoint gate --fail-on-unpinned` | Block branch-pinned mutable refs like @main |
| `pinpoint gate --warn` | Log violations without blocking (for phased rollout) |
| `pinpoint scan` | One-shot: poll all monitored actions, report tag changes with risk scoring |
| `pinpoint watch` | Continuous monitoring on interval |
| `pinpoint discover` | Find actions in local workflow files |
| `pinpoint audit --org <n>` | Org-wide security posture scan |
| `pinpoint verify` | Retroactive integrity check (works day-one, no baseline needed) |
| `pinpoint inject` | Add pinpoint gate steps to workflow files |

## Lockfile Format

```json
{
  "version": 2,
  "generated_at": "2026-03-25T15:34:18Z",
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "integrity": "sha256-UlGCnzY7dZN4sxU3GGTQCA0YKten/lxUvKg9ewr7MBY=",
        "disk_integrity": "sha256-KF8ESThHAzRkevRzFQs4+j/xzSl7FnfxtvFpgjkm1Iw=",
        "type": "node20",
        "dependencies": []
      }
    },
    "org/docker-scanner": {
      "v1": {
        "sha": "ed25bc16b3183ce51d9082f980910da61c8337bb",
        "integrity": "sha256-...",
        "type": "docker",
        "docker": {
          "image": "docker.io/org/scanner",
          "tag": "v1",
          "digest": "sha256:94dc72fb825fb2be77f32b132874c0fccbd6078e...",
          "source": "action.yml"
        }
      }
    }
  }
}
```

## What It Catches

Pinpoint blocks 10 distinct attack vectors:

| Attack | Detection |
|--------|-----------|
| Tag repointing (e.g., Trivy attack) | SHA mismatch in lockfile |
| Unknown/new actions in PRs | `--fail-on-missing` |
| Branch-pinned refs (@main, @master) | `--fail-on-unpinned` |
| SHA swap to malicious commit | SHA-pinned ref verification against lockfile |
| Removing gate from workflow | Separate enforced gate workflow |
| Typosquatted actions (check0ut vs checkout) | `--fail-on-missing` |
| Version bumps without lockfile update | Tag not in lockfile |
| Lockfile poisoning via PR | Gate reads lockfile from base branch |
| New malicious workflow files | `--all-workflows` + `--fail-on-missing` |
| Specific semver tags not in lockfile | Tag key mismatch |
| Docker image tag repointing | `--integrity` Docker digest verification |

## Docker Action Verification

Pinpoint is the first GitHub Actions security tool to verify Docker image digests.

Docker-based actions can reference pre-built container images by mutable tag
(e.g., `docker://alpine:3.19`). An attacker can push a malicious image to the
same tag at the registry level — completely invisible to Git-based verification.

`pinpoint lock` captures the image digest from the OCI registry.
`pinpoint gate --integrity` re-resolves the digest and detects changes:

```
✗ DOCKER IMAGE REPOINTED: docker.io/org/scanner:v1
  Expected digest: sha256:94dc72fb825fb2be77f32b132874c0fccbd6078e...
  Current digest:  sha256:a3c656dd4146273612d82c6d22889b65cc1177ec...
  The Docker image tag has been repointed to a different image — possible supply chain attack.
```

Supports ghcr.io, Docker Hub, quay.io, and any OCI-compliant registry.
Also parses Dockerfile `FROM` instructions to capture base image digests.

## Gate Verification Levels

1. **SHA-only (default):** 3 API calls, <2 seconds. Catches tag repointing and SHA swaps.
2. **On-disk (`--on-disk`):** +28ms disk I/O, zero network. Hashes what the runner actually downloaded. Catches TOCTOU, cache poisoning, MITM.
3. **Integrity (`--integrity`):** +N REST calls, 3-5s. Re-downloads tarballs and re-resolves Docker digests from registries. For periodic audits.

These are independent flags, not a staircase. `--on-disk` does not imply `--integrity`.

## Risk Scoring

| Signal | Score | Description |
|--------|-------|-------------|
| MASS_REPOINT | +100 | >5 tags repointed at once |
| OFF_BRANCH | +80 | New commit not a descendant |
| SIZE_ANOMALY | +60 | Entry point size changed >50% |
| SEMVER_REPOINT | +50 | Exact version tag moved |
| BACKDATED_COMMIT | +40 | Commit date >30 days old |
| NO_RELEASE | +20 | No corresponding GitHub Release |
| SELF_HOSTED | +15 | Self-hosted runners affected |
| MAJOR_TAG_ADVANCE | -30 | Major tag moved forward to descendant |

Score ≥50 = CRITICAL, ≥20 = MEDIUM, <20 = LOW.

## Verify: Day-One Integrity Check

`pinpoint verify` performs retroactive integrity checks without needing a prior
baseline. Run it right now on any repo — no setup required.

Four signals: release SHA match, GPG signature continuity, chronology check
(backdated commits), and advisory database cross-reference.

## Scale

| Metric | Value |
|--------|-------|
| 142 repos, 7,736 tags | 3 GraphQL points, 34 seconds |
| Gate per CI run (SHA-only) | 3 API calls, <2 seconds |
| Gate per CI run (on-disk) | 3 API calls + 28ms disk I/O |
| Lock (15 actions, parallel) | ~15 seconds, 16MB RSS |
| Org audit (277 repos) | 6 points, <2 minutes |
| GraphQL wall | ~20,000 repos at 5-min intervals |

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
pinpoint can and cannot do, including the polling gap, scale limits, and
Docker verification caveats.

## Stats

Single binary, one dependency (`gopkg.in/yaml.v3`). GPL-3.0.

## License

GPL-3.0. Copyright (C) 2026 CoreWeave, Inc.

Supply chain security should be free.
