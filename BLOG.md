# We Got Hit by the Trivy Supply Chain Attack. So We Built the Tool That Would Have Stopped It.

*March 21, 2026*

Two days ago, 75 version tags in `aquasecurity/trivy-action` — one of the most widely used security scanners in the GitHub Actions ecosystem — were silently repointed to malicious commits containing a credential stealer. Over 10,000 workflow files reference this action. The malicious code ran before the real scanner, produced normal-looking output, and exfiltrated secrets from CI/CD runners via AES-256 encrypted payloads to a typosquatted C2 domain.

We were among the organizations affected.

CrowdStrike Falcon caught the malicious behavior on our self-hosted runners at runtime — after the code was already executing. The script exhibited behaviors inconsistent with CI/CD, including credential collection, encrypted data staging, and outbound exfiltration. CrowdStrike killed it. That's what good EDR does.

But here's the thing: the malicious code should never have executed in the first place.

## The Gap Nobody Filled

Between the moment an attacker force-pushes a tag and the moment your pipeline executes it, there's a window. If you have SHA-pinned actions, you're safe — the tag movement doesn't affect you. But less than 5% of the ecosystem uses SHA pinning. The other 95% trusts that `@v1.2.3` means the same thing today as it did yesterday.

There are three layers of defense against this:

**Layer 1 (Prevention):** SHA pinning. Eliminates the attack surface. Has terrible developer experience. Adoption is glacial.

**Layer 2 (Early Detection):** Monitor tag→SHA mappings. Alert when they change. Catch the attack before any runner executes anything. **This layer didn't exist as open source.**

**Layer 3 (Runtime Detection):** EDR on runners. CrowdStrike, StepSecurity Harden-Runner. Catches malicious behavior during execution. This is what saved us — but the code was already running.

Layer 2 is where the Trivy attack should have been caught. Tag repointing is observable. The GitHub API tells you exactly what commit SHA a tag points to. If you recorded that mapping yesterday and check it today, you'd see the change instantly. The tool to do this simply hadn't been built as free, open-source software.

So we built it.

## Introducing Pinpoint

[**Pinpoint**](https://github.com/tehreet/pinpoint) is a GitHub Actions tag integrity monitor. It tracks the commit SHAs behind action version tags and alerts the moment they change. It's a single Go binary. It's free. It's GPL-3.0.

```bash
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest
pinpoint discover --workflows .github/workflows/
pinpoint scan --config .pinpoint.yml
```

### What it does

Point it at your workflow directory. It discovers every GitHub Action you depend on, resolves every version tag to its commit SHA via the GitHub GraphQL API, and stores the mapping. On subsequent scans, it compares. If a tag's SHA has changed, it fires an alert with risk scoring.

### How it scales

The conventional approach — one REST API call per repo per tag — doesn't scale. At 200 repos, you'd burn through GitHub's rate limit in minutes.

Pinpoint uses GitHub's GraphQL API to batch 50 repositories into a single query. One query. One API point. All tags resolved, annotated tags auto-dereferenced through inline fragments.

We tested it against 142 real GitHub Action repos. The results:

| Metric | Value |
|--------|-------|
| Repos monitored | 142 |
| Tags tracked | 7,736 |
| GraphQL API cost | 3 points |
| Scan time | 34 seconds |
| State file | 2.1 MB |

GitHub's GraphQL budget is 5,000 points/hour. Pinpoint uses 3. At 5-minute polling intervals, that's 36 points/hour — less than 1% of the budget. You could monitor your entire org's action dependencies and barely register on the API.

### What it catches

Pinpoint doesn't just tell you "a tag moved." It scores the event across multiple risk signals:

- **Mass repointing** — >5 tags changed in one scan cycle (the Trivy signature: 75 tags at once)
- **Off-branch commits** — the new commit isn't a descendant of the old one on the default branch
- **Entry point size anomaly** — the main script file changed size dramatically (Trivy: 2,855 → 17,592 bytes, +516%)
- **Semver tag repointing** — exact version tags like `v1.2.3` should never move
- **Backdated commits** — forged `GIT_AUTHOR_DATE` to make malicious commits look old
- **Self-hosted runner awareness** — if you flag actions that run on self-hosted runners, severity is escalated because the blast radius is fundamentally different

### What it would have caught

We ran pinpoint's detection logic against the actual Trivy attack timeline. The attack repointed 75 tags between 22:06 and 22:08 UTC on March 19. With a 5-minute polling interval, pinpoint would have detected the repointing by 22:13 UTC at the latest — approximately 5 hours before the community detected it through payload analysis.

Every signal would have fired simultaneously: MASS_REPOINT, OFF_BRANCH, SEMVER_REPOINT, SIZE_ANOMALY, NO_RELEASE. The alert would have been unmistakably CRITICAL.

## Battle-Tested Against Real Attacks

We didn't just build it and ship it. We created a dedicated GitHub org ([pinpoint-testing](https://github.com/pinpoint-testing)) and ran real attack scenarios against real repositories:

1. **Single tag repoint** — semver tag force-pushed to malicious commit ✅ Detected
2. **Mass repoint (75 tags)** — all tags pointed to single evil commit ✅ Detected
3. **Tag delete + recreate** — tag removed and recreated with new SHA ✅ Detected
4. **Annotated tag repoint** — annotated tag swapped through delete/recreate ✅ Detected
5. **Legitimate major version advance** — `v1` moved forward to descendant ✅ Correctly scored LOW (no false positive)
6. **Entry point size change** — small file replaced with large payload ✅ SIZE_ANOMALY detected

6 for 6. Then we ran the scale test: 142 real repos with one attack target buried in the noise. Pinpoint found it in 34 seconds.

## Why GPL-3.0

Supply chain security monitoring should not be behind a paywall. StepSecurity's Artifact Monitor does tag monitoring — for their Enterprise Tier customers, across a curated list of ~3,000 actions. If your org depends on action number 3,001, you're unprotected.

Pinpoint is GPL-3.0. Free as in freedom. Anyone can use it, modify it, and distribute it. If someone forks it and improves it, those improvements flow back to the community. The only thing you can't do is close-source it and sell it without sharing the code.

The ecosystem is safer when monitoring is distributed, not centralized behind a vendor.

## What's Next

Pinpoint today is a detection tool. It tells you when tags move. The next milestone is **pinpoint gate** — an inline pre-job verification action that checks every `uses:` directive against a known-good manifest *before* any third-party action executes. If a tag's SHA doesn't match the manifest, the job aborts. The attacker's code never touches the runner.

That's the leap from detection to prevention. We're building it now.

## Get Started

```bash
# Install
go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

# Discover what you're using
pinpoint discover --workflows .github/workflows/

# Scan
export GITHUB_TOKEN=ghp_...
pinpoint scan --config .pinpoint.yml

# Watch (continuous)
pinpoint watch --config .pinpoint.yml --interval 5m
```

GitHub: [github.com/tehreet/pinpoint](https://github.com/tehreet/pinpoint)
License: GPL-3.0
Language: Go
Dependencies: 1 (gopkg.in/yaml.v3)

---

*Pinpoint was built at CoreWeave in response to the March 2026 Trivy supply chain compromise. We believe the tools that protect the software supply chain should be free and open.*
