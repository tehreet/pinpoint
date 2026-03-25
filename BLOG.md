# We Got Hit by the Trivy Supply Chain Attack. So We Built the Tool That Would Have Stopped It.

*March 21, 2026 — Updated March 25, 2026*

Two days ago, 75 version tags in `aquasecurity/trivy-action` — one of the most widely used security scanners in the GitHub Actions ecosystem — were silently repointed to malicious commits containing a credential stealer. Over 10,000 workflow files reference this action. The malicious code ran before the real scanner, produced normal-looking output, and exfiltrated secrets from CI/CD runners via AES-256 encrypted payloads to a typosquatted C2 domain.

We were among the organizations affected.

CrowdStrike Falcon caught the malicious behavior on our self-hosted runners at runtime — after the code was already executing. The script exhibited behaviors inconsistent with CI/CD, including credential collection, encrypted data staging, and outbound exfiltration. CrowdStrike killed it. That's what good EDR does.

But here's the thing: the malicious code should never have executed in the first place.

## The Gap Nobody Filled

Between the moment an attacker force-pushes a tag and the moment your pipeline executes it, there's a window. If you have SHA-pinned actions, you're safe — the tag movement doesn't affect you. But the vast majority of the ecosystem doesn't pin to SHAs. They trust that `@v1.2.3` means the same thing today as it did yesterday.

There are three layers of defense against this:

**Layer 1 (Prevention):** SHA pinning. Eliminates the attack surface. Terrible developer experience. Adoption is glacial — we scanned 40 GitHub organizations and found that 41.5% of action references are still tag or branch-pinned.

**Layer 2 (Early Detection):** Monitor tag→SHA mappings. Alert when they change. Catch the attack before any runner executes anything. **This layer didn't exist as open source.**

**Layer 3 (Runtime Detection):** EDR on runners. CrowdStrike, StepSecurity Harden-Runner. Catches malicious behavior during execution. This is what saved us — but the code was already running.

Layer 2 is where the Trivy attack should have been caught. Tag repointing is observable. The GitHub API tells you exactly what commit SHA a tag points to. If you recorded that mapping yesterday and check it today, you'd see the change instantly. The tool to do this simply hadn't been built as free, open-source software.

So we built it.

## Introducing Pinpoint

[**Pinpoint**](https://github.com/tehreet/pinpoint) is a GitHub Actions supply chain integrity tool. It locks, gates, monitors, and audits your action dependencies — including Docker-based actions. Single Go binary. One dependency. Zero configuration. GPL-3.0.

### What it does

| Command | What it does |
|---|---|
| `pinpoint lock` | Generates an immutable lockfile (SHA + integrity hash + transitive deps + Docker digests) |
| `pinpoint gate` | Pre-execution verification — blocks builds if a tag has been repointed |
| `pinpoint gate --integrity` | Also verifies Docker image digests against OCI registries |
| `pinpoint watch` | Continuous monitoring with multi-signal risk scoring |
| `pinpoint audit --org` | Org-wide security posture scan with SARIF output |
| `pinpoint verify` | Retroactive integrity check (4 signals, no baseline needed) |
| `pinpoint inject` | Add gate steps to existing workflow files |

### Risk scoring: not just "tag moved"

The top 20 most-used GitHub Actions generate ~195 legitimate tag movements per year. A naive "tag changed" alert fires constantly and is useless. Pinpoint scores each event across independent signals:

| Signal | Score | What it catches |
|---|---|---|
| MASS_REPOINT | +100 | >5 tags moved at once (the Trivy signature) |
| OFF_BRANCH | +80 | New commit isn't a descendant (diverged history) |
| SIZE_ANOMALY | +60 | Entry point file size changed >50% |
| SEMVER_REPOINT | +50 | Exact version tag moved (should never happen) |
| BACKDATED_COMMIT | +40 | Commit date >30 days old |
| NO_RELEASE | +20 | No corresponding GitHub Release |
| SELF_HOSTED | +15 | Self-hosted runners affected (elevated blast radius) |
| MAJOR_TAG_ADVANCE | -30 | Major tag moved forward to descendant (routine, suppressed) |

A legitimate v4 patch release scores -30 (LOW, auto-suppressed). The Trivy attack scores +465 (CRITICAL, immediate alert). That's a 495-point gap between normal and attack.

### Gate: the firewall your CI doesn't have

`pinpoint gate` runs before your actions execute. It compares every action reference in your workflows against the lockfile. If a tag has been repointed, the build fails. The attacker's code never touches the runner.

We deployed gate across 28 repositories and ran a 10-attack battery:

```
  BLOCKED: Tag repoint detected, build blocked
  BLOCKED: Unknown action blocked
  BLOCKED: Branch-pinned ref blocked
  BLOCKED: SHA swap blocked (spec 023 fix)
  BLOCKED: Separate gate still runs (removing inline doesn't help)
  BLOCKED: Typosquat blocked
  BLOCKED: Version bump blocked
  BLOCKED: Lockfile poisoning blocked (gate reads base branch)
  BLOCKED: New evil workflow blocked
  BLOCKED: Specific semver blocked

  10 blocked, 0 bypassed out of 10 attacks
```

Gate catches tag repoints, unknown actions, typosquats, SHA swaps, version bumps without lockfile updates, lockfile poisoning via PR, new malicious workflow files, branch-pinned mutable refs, and specific semver tags not in the lockfile. Zero bypasses.

### Docker verification: the attack vector nobody else checks

Docker-based actions can reference pre-built container images by mutable tag. An attacker can push a malicious image to the same tag at the registry level — completely invisible to Git-based verification. The action.yml doesn't change. The Git SHA doesn't change. Only the Docker image changes.

No existing tool checks for this. Pinpoint does.

`pinpoint lock` captures the image digest from the OCI registry. `pinpoint gate --integrity` re-resolves the digest and detects changes:

```
✗ DOCKER IMAGE REPOINTED: docker.io/org/scanner:v1
  Expected digest: sha256:94dc72fb825fb2be77f32b132874c0fccbd6078e...
  Current digest:  sha256:a3c656dd4146273612d82c6d22889b65cc1177ec...
  The Docker image tag has been repointed to a different image — possible supply chain attack.
```

We verified this against a live Docker Hub registry: pushed a legitimate image, locked the digest, pushed an evil image to the same tag, and ran the gate. Caught immediately. Supports ghcr.io, Docker Hub, quay.io, and any OCI-compliant registry.

## We Scanned 40 GitHub Organizations. Nobody Follows Their Own Advice.

We ran `pinpoint audit --org` against 40 GitHub organizations that should know better — security companies, cloud providers, CNCF projects, and DevOps tool vendors.

Key findings across 1,847 repositories:

- **41.5%** of action references use mutable tags (v1, v2) instead of SHA pins
- **23.8%** reference actions with known security advisories
- **12.4%** use branch-pinned refs (@main, @master) — completely mutable
- **3 popular actions** had GPG signing discontinuities: `aws-actions/configure-aws-credentials`, `hashicorp/setup-terraform`, `golangci/golangci-lint-action`
- **Zero organizations** had complete SHA pinning across all workflows
- Repos still referencing known-compromised tj-actions and reviewdog versions over a year after the attack

The gap between security advice and security practice is enormous. Everybody says "pin to SHAs." Nobody does it.

## Actions Watchdog: Live Monitoring for Everyone

We're running `pinpoint watch` continuously against the top 50 most-used GitHub Actions. The results are published to a live dashboard, updated every 5 minutes:

**[tehreet.github.io/actions-watchdog](https://tehreet.github.io/actions-watchdog/)**

67 action tags verified and monitored. If any tag gets repointed — including `actions/checkout@v4`, `docker/login-action@v3`, or `aws-actions/configure-aws-credentials@v4` — the dashboard goes red within 5 minutes.

## One Line to Protect Any Repo

```yaml
- uses: tehreet/pinpoint-action@v1
  with:
    mode: enforce
```

Add this step to any workflow. It downloads the binary, runs gate with `--all-workflows --fail-on-missing`, and verifies every action reference in your repo. Supports `warn` mode for phased rollout.

For org-wide enforcement, use a shared reusable workflow with `--fail-on-unpinned` and `--fail-on-missing`. We deployed this across 28 repos in an afternoon.

## Why Not Just Pin to SHAs?

SHA pinning is the right policy. But it has structural limitations:

1. **Nobody does it.** Four attacks in five years. The same advice after each one. 41.5% of refs are still tag-pinned across 40 major organizations. Education has failed. Enforcement works.

2. **Pinning during an active attack locks in the compromise.** If you run a pinning tool while trivy-action's tags are poisoned, you pin the malicious SHA. Pinpoint's lockfile is generated before the attack. During the attack, `pinpoint gate` refuses to run the new SHA because it doesn't match the lockfile.

3. **Pinning doesn't cover Docker images.** Docker-based actions can have their container image tags repointed at the registry level. Git SHA pinning is blind to this. Pinpoint captures Docker digests in the lockfile and verifies them against the live registry.

4. **Pinning doesn't catch transitive dependency changes.** A composite action you've pinned to a SHA can internally reference other actions by mutable tag. Pinpoint resolves and locks the full dependency tree, including transitive refs.

5. **GitHub declined to build this.** `actions/runner#2195` — "Support lock file equivalent for GitHub Actions." Filed October 2022. Closed November 2023 as "not planned." The platform vendor looked at this problem and said no. Someone else has to build the enforcement layer. That's Pinpoint.

Pinpoint's model is the same as the rest of the ecosystem: your workflow files stay readable with version tags, and the lockfile provides the immutable verification layer. `package.json` → `package-lock.json`. `go.mod` → `go.sum`. `.github/workflows/` → `.github/actions-lock.json`.

## Get Started

### Quick start

```yaml
- uses: tehreet/pinpoint-action@v1
```

### Full setup

```bash
# Install
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

# Generate lockfile (captures SHAs, integrity hashes, Docker digests)
pinpoint lock --workflows .github/workflows/

# See your dependency tree
pinpoint lock --list

# Verify (one-shot)
pinpoint lock --verify

# Gate (in CI — default mode)
pinpoint gate --all-workflows --fail-on-missing

# Gate (with Docker digest verification)
pinpoint gate --all-workflows --fail-on-missing --integrity

# Watch (continuous monitoring)
pinpoint watch --config .pinpoint.yml --interval 5m

# Audit your org
pinpoint audit --org your-org-name
```

### Links

- **GitHub:** [github.com/tehreet/pinpoint](https://github.com/tehreet/pinpoint)
- **Action:** [github.com/tehreet/pinpoint-action](https://github.com/tehreet/pinpoint-action)
- **Live Watchdog:** [tehreet.github.io/actions-watchdog](https://tehreet.github.io/actions-watchdog/)
- **License:** GPL-3.0-only
- **Language:** Go — single binary, 1 dependency (gopkg.in/yaml.v3), no CGo
- **Version:** v0.7.0 — 264 tests, 24 specs implemented, 10/10 attack battery

---

*Pinpoint was built at CoreWeave in response to the March 2026 Trivy supply chain compromise. We believe the tools that protect the software supply chain should be free and open.*
