# We Got Hit by the Trivy Supply Chain Attack. So We Built the Tool That Would Have Stopped It.

*March 21, 2026 — Updated March 23, 2026*

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

[**Pinpoint**](https://github.com/tehreet/pinpoint) is a GitHub Actions supply chain integrity tool. It locks, gates, monitors, and audits your action dependencies. Single Go binary. One dependency. Zero configuration. GPL-3.0.

### What it does now

| Command | What it does |
|---|---|
| `pinpoint lock` | Generates an immutable lockfile (SHA + integrity hash + GPG status + transitive deps) |
| `pinpoint gate` | Pre-execution verification in CI — blocks builds if a tag has been repointed |
| `pinpoint watch` | Continuous monitoring with multi-signal risk scoring |
| `pinpoint audit --org` | Org-wide security posture scan with SARIF output |
| `pinpoint verify` | Retroactive integrity check (4 signals, no baseline needed) |

### Risk scoring: 10 signals, not just "tag moved"

The top 20 most-used GitHub Actions generate ~195 legitimate tag movements per year. A naive "tag changed" alert fires constantly and is useless. Pinpoint scores each event across 10 independent signals:

| Signal | Score | What it catches |
|---|---|---|
| MASS_REPOINT | +100 | >5 tags moved at once (the Trivy signature) |
| OFF_BRANCH | +80 | New commit isn't a descendant (diverged history) |
| IMPOSSIBLE_TIMESTAMP | +70 | Commit predates its own parent (fabricated metadata) |
| SIZE_ANOMALY | +60 | Entry point file size changed >50% |
| SEMVER_REPOINT | +50 | Exact version tag moved (should never happen) |
| SIGNATURE_DROPPED | +45 | GPG signature present at lock time, absent now |
| BACKDATED_COMMIT | +40 | Commit date >30 days old |
| NO_RELEASE | +20 | No corresponding GitHub Release |
| SELF_HOSTED | +15 | Self-hosted runners affected (elevated blast radius) |
| MAJOR_TAG_ADVANCE | -30 | Major tag moved forward to descendant (routine, suppressed) |

A legitimate v4 patch release scores -30 (LOW, auto-suppressed). The Trivy attack scores +465 (CRITICAL, immediate alert). That's not a tunable threshold — it's a 495-point gap between normal and attack.

### Gate: the firewall your CI doesn't have

`pinpoint gate` runs before your actions execute. It compares every action reference in your workflows against the lockfile. If a tag has been repointed, the build fails. The attacker's code never touches the runner.

We deployed gate across 29 repositories in our test org and ran a live attack simulation: we repointed a custom action's tag to a malicious commit. Gate caught it:

```
  ✗ pinpoint-testing/custom-action@v1
    EXPECTED: 6ee388cb3071e022581c8372c8ad08e7ab5891b7 (from manifest, recorded 2026-03-23T03:43:22Z)
    ACTUAL:   d530db3e9e9045314aa85f65d8ca6a1d464e44f8 (resolved just now)
    ⚠ TAG HAS BEEN REPOINTED — possible supply chain attack

⚠ 1 action integrity violations detected (warn mode — not blocking)
```

After reverting the tag, the next PR passed clean:

```
  ✓ actions/checkout@v4 → 34e1148... (matches manifest)
  ✓ actions/setup-go@v5 → 40f1582... (matches manifest)
  ✓ golangci/golangci-lint-action@v6 → 55c2c14... (matches manifest)
  ✓ pinpoint-testing/custom-action@v1 → 6ee388c... (matches manifest)

✓ All action integrity checks passed (4 verified, 2 skipped, 0 violations) in 1.109s
```

Gate supports `--warn` mode for phased rollout. Log violations without blocking builds. Tune your allow-list. Flip to enforce when ready. We did this across 29 repos in an afternoon.

## We Scanned 40 GitHub Organizations. Nobody Follows Their Own Advice.

After building Pinpoint, we used `pinpoint audit` to scan 40 public GitHub organizations — including every security vendor that published analysis of the Trivy attack. The results:

**76,863 action references analyzed. 41.5% still vulnerable to tag repointing.**

The security vendors who wrote the blog posts recommending SHA pinning:

| Organization | Role in Trivy Response | SHA Pinning Rate |
|---|---|---|
| Snyk | Published comprehensive analysis | 2.4% |
| GitHub (actions org) | Hosts the platform | 7.0% |
| Endor Labs | Published attack breakdown | 8.8% |
| Aqua Security | Got hacked — twice | 35.6% |
| CrowdStrike | Most detailed forensic report | 59.4% |
| StepSecurity | Detected the attack via Harden-Runner | 79.8% |
| Socket | First automated threat detection | 82.7% |
| Wiz | Named the TeamPCP threat actor | 100% |

The pattern is clear: four supply chain attacks in five years (Codecov 2021, tj-actions 2025, reviewdog 2025, Trivy 2026), each followed by blog posts recommending the same fix, and the fix still hasn't happened.

### The credential actions that should keep you up at night

These actions handle your most sensitive secrets. They are widely depended on by tag, not SHA:

- **aws-actions/configure-aws-credentials** — 685 tag-pinned refs across 9 orgs. If `v4` gets repointed, every workflow hands its AWS credentials to the attacker.
- **docker/login-action** — 240 tag-pinned refs across 27 orgs. Docker Hub, GHCR, ECR tokens exposed.
- **codecov/codecov-action** — Breached in 2021. Still 126 tag-pinned refs across 18 orgs in 2026.
- **actions-rs/toolchain** — Abandoned since 2022. No active maintainer. 100% tag-pinned across 10 orgs including Facebook and AWS.

Every number is independently verifiable by running `pinpoint audit --org <name>` against the public repos.

## Actions Watchdog: Live Monitoring for Everyone

We're running `pinpoint watch` continuously against the top 50 most-used GitHub Actions. The results are published to a live dashboard, updated every 5 minutes:

**[tehreet.github.io/actions-watchdog](https://tehreet.github.io/actions-watchdog/)**

67 action tags verified and monitored. If any tag gets repointed — including `actions/checkout@v4`, `docker/login-action@v3`, or `aws-actions/configure-aws-credentials@v4` — the dashboard goes red within 5 minutes. Bookmark it. It's the smoke detector the ecosystem doesn't have.

## One Line to Protect Any Repo

We published Pinpoint as a GitHub Action:

```yaml
- uses: tehreet/pinpoint-action@v1
```

Add this step to any workflow. It downloads the binary, runs gate with `--all-workflows`, and verifies every action reference in your repo. Warn mode by default. Switch to enforce when you're ready:

```yaml
- uses: tehreet/pinpoint-action@v1
  with:
    mode: enforce
```

## Why Not Just Pin to SHAs?

SHA pinning is the right policy. But it has structural limitations:

1. **Nobody does it.** Four attacks in five years. The same advice after each one. 41.5% of refs are still tag-pinned across 40 major organizations. Education has failed. Enforcement works.

2. **Pinning during an active attack locks in the compromise.** If you run `pinact` while trivy-action's tags are poisoned, you pin the malicious SHA. Pinpoint's lockfile is generated before the attack. During the attack, `pinpoint gate` refuses to run the new SHA because it doesn't match the lockfile.

3. **Pinning doesn't catch what Pinpoint catches.** 195 legitimate tag movements per year across the top 20 actions. A "tag moved" alert is useless noise. Pinpoint's 10-signal risk scoring distinguishes attack from release with a 495-point gap. It detects commit timestamp fabrication, GPG signature removal, and on-disk file tampering that no SHA-pinning tool checks for.

4. **GitHub declined to build this.** `actions/runner#2195` — "Support lock file equivalent for GitHub Actions." Filed October 2022. Closed November 2023 as "not planned." The platform vendor looked at this problem and said no. Someone else has to build the enforcement layer. That's Pinpoint.

Pinpoint's model is the same as the rest of the ecosystem: your workflow files stay readable with version tags, and the lockfile provides the immutable verification layer. `package.json` → `package-lock.json`. `go.mod` → `go.sum`. `.github/workflows/` → `.github/actions-lock.json`.

## Get Started

### Quick start (one line)

```yaml
- uses: tehreet/pinpoint-action@v1
```

### Full setup

```bash
# Install
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

# Generate lockfile
pinpoint lock --workflows .github/workflows/

# Verify (one-shot)
pinpoint lock --verify

# Gate (in CI)
pinpoint gate --warn --all-workflows

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
- **Version:** v0.6.0 — 10 risk signals, 170+ tests, 22 specs implemented

---

*Pinpoint was built at CoreWeave in response to the March 2026 Trivy supply chain compromise. We believe the tools that protect the software supply chain should be free and open.*
