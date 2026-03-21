# pinpoint

**Detect GitHub Actions tag repointing attacks before malicious code reaches your runners.**

pinpoint monitors the commit SHAs behind GitHub Action version tags and alerts the moment they change. It's the missing layer between "someone force-pushed 75 tags" and "your CI/CD pipeline executed a credential stealer."

---

## Why this exists

On March 19, 2026, threat actors compromised Aqua Security's `trivy-action` by force-pushing 75 of 76 version tags to point at malicious commits containing a credential stealer. The malicious code ran silently *before* the real scanner, so workflows appeared to complete normally. Over 10,000 workflow files on GitHub reference trivy-action.

Detection came from EDR sensors catching anomalous script execution on CI/CD runners — **after the malicious code was already executing.** The tag repointing itself went undetected for hours.

pinpoint catches the tag movement within minutes, before any runner executes anything.

This is not the first time this has happened. The `tj-actions/changed-files` compromise (March 2025) used the same technique. It won't be the last.

### The problem

GitHub Actions uses **mutable git tags** as version references. When you write:

```yaml
uses: aquasecurity/trivy-action@0.24.0
```

You're trusting that tag `0.24.0` still points to the same commit it did yesterday. Anyone with write access can silently repoint it:

```bash
git tag -f 0.24.0 <malicious-commit>
git push -f origin refs/tags/0.24.0
```

Every workflow that runs after that moment executes attacker-controlled code with full access to your pipeline's secrets, credentials, and infrastructure.

### The fix

Record what commit SHA every tag points to. Check periodically. Alert if anything changes.

## Quick start

### Install

```bash
# From source
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

# Or clone and build
git clone https://github.com/tehreet/pinpoint.git
cd pinpoint
go build ./cmd/pinpoint/
```

### Discover what you're using

Point pinpoint at your workflow directory to see what actions you depend on and which are vulnerable to tag repointing:

```bash
pinpoint discover --workflows .github/workflows/
```

Output:

```
Discovered 14 action references across 8 repos
  SHA-pinned: 3 (safe from tag repointing)
  Tag-based:  11 (vulnerable to tag repointing)

  actions/checkout — monitoring tags: v4
  actions/setup-go — monitoring tags: v5
  aquasecurity/trivy-action — monitoring tags: 0.24.0, 0.35.0
  docker/build-push-action — monitoring tags: v5
```

Generate a config file:

```bash
pinpoint discover --workflows .github/workflows/ --config > .pinpoint.yml
```

### Scan (one-shot)

```bash
export GITHUB_TOKEN=ghp_your_token_here
pinpoint scan --config .pinpoint.yml
```

Clean output:

```
✓ All 11 tracked tags verified. No repointing detected.
```

If a tag has been repointed:

```
[CRITICAL] TAG_REPOINTED
  Action: aquasecurity/trivy-action
  Tag:    0.24.0
  Before: e0198fd3c332
  After:  a1b2c3d4e5f6
  Signals:
    • MASS_REPOINT: 75 tags repointed in same scan cycle
    • OFF_BRANCH: new commit is not a descendant of previous commit
    • SEMVER_REPOINT: exact version tag should never be moved
    • SIZE_ANOMALY: entry point size changed +516% (2855 → 17592 bytes)
  ⚠ SELF-HOSTED RUNNERS: Assume persistent compromise. Rotate all credentials.
```

Exit code 2 on detection — plug it into CI as a gate.

### Watch (continuous)

```bash
pinpoint watch --config .pinpoint.yml --interval 5m
```

Polls on interval, uses ETag conditional requests (unchanged repos cost zero API rate limit), alerts via stdout, Slack, or webhook.

## Configuration

```yaml
# .pinpoint.yml
actions:
  # Monitor specific tags
  - repo: aquasecurity/trivy-action
    tags: ["0.35.0"]
    self_hosted_runners: true  # Elevates alert severity

  # Monitor ALL tags on a repo
  - repo: actions/checkout
    tags: ["*"]

alerts:
  min_severity: medium    # low | medium | critical
  stdout: true
  slack_webhook: https://hooks.slack.com/services/T.../B.../xxx
  webhook_url: https://your-pagerduty-or-opsgenie-endpoint

store:
  path: .pinpoint-state.json
```

## Risk scoring

Not every tag movement is malicious. Maintainers routinely move major version tags forward. pinpoint scores each event:

| Signal | Severity | Example |
|--------|----------|---------|
| Mass repointing (>5 tags) | Critical | Trivy: 75 tags at once |
| Commit not on default branch | Critical | Orphan/diverged commit |
| Entry point size change >50% | Critical | 2.8KB → 17.6KB |
| Exact semver tag moved | High | `v1.2.3` should never move |
| Backdated commit (>30 days) | High | Forged `GIT_AUTHOR_DATE` |
| No corresponding release | Medium | Tag exists without Release |
| Self-hosted runners flagged | Medium | Elevated blast radius |
| Major version tag advanced | Low | `v1` → descendant (routine) |

## Self-hosted runners

If you flag an action with `self_hosted_runners: true`, pinpoint escalates alert severity and adds specific response guidance.

Self-hosted runners are persistent, often over-privileged, and frequently shared across workflows. A compromised action on a self-hosted runner isn't just a secret leak — it's a potential persistent foothold. The Trivy attacker dropped a systemd-based backdoor at `~/.config/sysmon.py` on developer machines that polled a blockchain-hosted C2. On self-hosted runners, the payload harvested credentials from 50+ filesystem paths including SSH keys, cloud provider credentials, Kubernetes tokens, and Terraform state.

EDR tools like CrowdStrike Falcon catch this at runtime — after the code is executing. pinpoint catches the tag repointing before the code ever reaches your runner.

## How it works

1. **Poll** — Fetches all tag refs via GitHub's git refs API with ETag caching. Unchanged repos return `304 Not Modified` and cost zero rate limit.
2. **Dereference** — Resolves annotated tags through the tag object to the underlying commit SHA. Lightweight tags are resolved directly.
3. **Compare** — Checks current commit SHA against stored state for each tracked tag.
4. **Enrich** — On change: checks whether the new commit is a descendant of the old one, retrieves commit author/date metadata, compares entry point file sizes, and checks for a corresponding GitHub Release.
5. **Score** — Applies risk heuristics to produce a severity rating (low/medium/critical).
6. **Alert** — Emits to stdout, Slack, or generic webhook. Exit code 2 for CI integration.

State is persisted as a JSON file with atomic writes. Each tag change is appended to a history array for forensic review.

## API rate limits

pinpoint uses the bulk `matching-refs` endpoint (1 API call per repo, not per tag) plus ETag conditional requests. Monitoring 100 repos at 5-minute intervals uses ~1,200 calls/hour, well within GitHub's 5,000/hour authenticated limit.

Unauthenticated requests are limited to 60/hour and not recommended. Set `GITHUB_TOKEN` for any real usage.

## What this doesn't do

pinpoint is a **detection** tool, not a prevention tool. It tells you when tags have moved. It doesn't:

- Pin your actions to SHAs (use [StepSecurity secure-repo](https://github.com/step-security/secure-repo) or Dependabot for that)
- Monitor runtime behavior on runners (use [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) or CrowdStrike for that)
- Scan action source code for malware (use [Socket.dev](https://socket.dev) for that)

pinpoint fills the gap between prevention (SHA pinning) and runtime detection (EDR). It's Layer 2 in a defense-in-depth strategy.

## Background

This project was motivated by firsthand experience with the March 2026 Trivy supply chain compromise. For a detailed technical analysis of the attack, the threat model, and the gaps in existing tooling, see:

- [Wiz: Trivy Compromised by "TeamPCP"](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)
- [CrowdStrike: From Scanner to Stealer](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- [Socket: Trivy Under Attack Again](https://socket.dev/blog/trivy-under-attack-again-github-actions-compromise)
- [StepSecurity: Trivy Compromised a Second Time](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release)
- [Aqua Security: Trivy Security Incident 2026-03-19](https://github.com/aquasecurity/trivy/discussions/10425)

## License

Copyright (C) 2026 CoreWeave, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](LICENSE) for more details.
