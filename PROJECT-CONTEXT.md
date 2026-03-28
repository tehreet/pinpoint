# Pinpoint — Project Instructions for Claude

# Development Workflow

## Environments

### VPS (ubuntu-32gb-hil-1, Hetzner US, IP 5.78.91.92)
- **Access:** Sloperations MCP (public endpoint + token auth, code: https://github.com/tehreet/claude-bridge)
- **Use for:** Infrastructure (org-audit cron), deployments, other projects, always-on services
- **Pinpoint repo:** `/home/joshf/pinpoint` (has both `origin` = tehreet/pinpoint and `org` = pinpoint-testing/pinpoint remotes)
- **Go:** 1.24.1 at /usr/local/go/bin
- **Docker:** Installed, logged into ghcr.io + Docker Hub as tehreet

### Chrome Extension
- **Use for:** GitHub browser tasks (releases, PR reviews, action run checks, repo management)
- **Rule:** Always suggest using it when a task is browser-oriented. Never auto-execute — confirm with Josh first.

## Claude Code Handoff Workflow
1. **Plan & spec** — discuss in Claude App, write PROMPT-xxx.md to `/home/joshf/pinpoint/` via Desktop Commander
2. **Build** — Josh runs `claude` in the pinpoint dir in WSL2, Claude Code picks up the prompt
3. **Review** — Claude App reads changed files and test output via Desktop Commander
4. No copy-paste at any step.

## Tool Priority
- **Internal/local tasks** → Desktop Commander (WSL2)
- **VPS ops** → Sloperations
- **Browser tasks** → Chrome extension (with confirmation)
- **External info** → Web search

## IMPORTANT WORKING STYLE

- **Do not be eager.** When Josh brings up something new, present the plan and options first. Wait for approval before building anything.
- **Check in on the full plan** rather than jumping straight to code.
- **Be direct and concise.** Josh prefers straight talk, no filler.

## What Pinpoint Is

Single Go binary, one dependency (gopkg.in/yaml.v3). Detects and prevents GitHub Actions supply chain attacks where version tags are repointed to malicious commits. Built in response to the March 2026 Trivy attack (75 tags force-pushed). CoreWeave was directly affected.

## Repositories

- **Canonical:** `tehreet/pinpoint` (private, Josh's personal account)
- **Test org mirror:** `pinpoint-testing/pinpoint` (private, org copy with action.yml pointing to org releases)
- **Test org:** `pinpoint-testing` — 32 repos (all private), realistic workflows for testing
- **VPS:** ubuntu-32gb-hil-1, user joshf, IP 5.78.91.92
- **Project path on VPS:** /home/joshf/pinpoint
- **Go version:** 1.24.1 (at /usr/local/go/bin)

## Current State (v0.7.0 released)

- v0.7.0 tagged and released with 5-platform binaries on both repos
- 24 specs written (001-024), all implemented
- 28 repos in pinpoint-testing org with gate enforced
- 10/10 attack battery passing, Docker digest attack verified against live Docker Hub

## Commands (all implemented)

| Command | Description |
|---|---|
| `pinpoint lock` | Generate .github/actions-lock.json (v2 format: SHA + integrity hash + disk_integrity + type + transitive deps + Docker digests) |
| `pinpoint lock --list` | Show dependency tree including transitive deps |
| `pinpoint lock --verify` | Check lockfile against live tags (read-only) |
| `pinpoint gate` | Pre-execution verification (3 API calls, <2s) |
| `pinpoint gate --on-disk` | Verify runner's downloaded files against lockfile (+28ms, 0 API calls) |
| `pinpoint gate --integrity` | Re-download tarballs and verify SHA-256 + Docker digests (audit mode, +3-5s) |
| `pinpoint gate --all-workflows` | Scan all workflow files, not just the triggering one |
| `pinpoint gate --fail-on-missing` | Block actions not in lockfile (auto-enabled with new lockfile path) |
| `pinpoint gate --fail-on-unpinned` | Block branch-pinned mutable refs (e.g., @main) |
| `pinpoint gate --warn` | Log violations without blocking (for phased rollout) |
| `pinpoint scan` | One-shot poll with risk scoring and alerting |
| `pinpoint watch` | Continuous monitoring on interval |
| `pinpoint discover` | Find actions in local workflow files |
| `pinpoint audit --org <n>` | Org-wide security posture scan (report/json/config/manifest/sarif output) |
| `pinpoint verify` | Retroactive integrity check (4 signals, no baseline needed) |
| `pinpoint inject` | Add pinpoint gate steps to workflow files |

## Architecture

```
cmd/pinpoint/main.go           — CLI routing, all subcommands
internal/
  alert/alert.go               — Stdout/Slack/webhook alerting
  audit/audit.go               — Org-wide scanner
  config/config.go             — YAML config with AllowRule support
  discover/discover.go         — Workflow file parser
  gate/gate.go                 — Pre-execution verification, PR poisoning protection, SHA-pinned ref verification, Docker digest verification
  inject/inject.go             — Workflow file modification (add gate steps)
  integrity/treehash.go        — On-disk tree hashing (ComputeTreeHash)
  manifest/manifest.go         — Lockfile refresh, verify, save, load
  manifest/integrity.go        — Tarball download+hash, batch with worker pool
  manifest/transitive.go       — Composite action.yml parsing, transitive resolution
  manifest/docker.go           — OCI registry client, Docker digest resolution, Dockerfile FROM parsing
  manifest/lockpath.go         — ResolveLockfilePath (new/legacy path detection)
  manifest/templates.go        — Embedded workflow YAML templates
  poller/github.go             — REST API client
  poller/graphql.go            — GraphQL client (50 repos/query, 1 point)
  poller/graphql_org.go        — FetchOrgWorkflows for audit
  risk/score.go                — Risk scoring (13 signals)
  sarif/sarif.go               — SARIF 2.1.0 output
  store/store.go               — JSON state with atomic writes
  suppress/suppress.go         — Allow-list false positive suppression
  verify/verify.go             — Retroactive integrity check (4 signals)
tests/
  harness/                     — Integration tests (attack scenarios + real-world replays + live tests)
  perf/                        — Performance benchmarks + memory pressure tests
scripts/
  attack-battery.sh            — 10+ attack automated regression test (v2, SHA-matched gate runs)
  chaos-test.sh                — 5 attack scenarios against deployed infrastructure
```

## Lockfile Format (v2)

```json
{
  "version": 2,
  "generated_at": "2026-03-25T15:34:18Z",
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "integrity": "sha256-UlGCnzY7dZN4sxU3GGTQCA...",
        "disk_integrity": "sha256-KF8ESThHAzRkevRzFQs4...",
        "recorded_at": "2026-03-22T06:04:25Z",
        "type": "node20",
        "dependencies": []
      }
    },
    "pinpoint-testing/docker-scanner": {
      "v1": {
        "sha": "ed25bc16b3183ce51d9082f980910da61c8337bb",
        "integrity": "sha256-...",
        "disk_integrity": "sha256-...",
        "type": "docker",
        "docker": {
          "image": "docker.io/tehreet/pinpoint-test-scanner",
          "tag": "v1",
          "digest": "sha256:94dc72fb825fb2be77f32b132874c0fccbd6078e8339712b9ae28b1b3f3e841d",
          "source": "action.yml"
        },
        "dependencies": []
      }
    }
  }
}
```

## Gate Verification Levels

1. **SHA-only (default):** 3 API calls, <2 seconds. Catches tag repointing. SHA-pinned refs verified against lockfile.
2. **On-disk (`--on-disk`):** +28ms disk I/O, zero network. Hashes what the runner actually downloaded. Catches TOCTOU, cache poisoning, MITM.
3. **Integrity (`--integrity`):** +N REST calls, 3-5s. Re-downloads tarballs + re-resolves Docker digests from registries. For periodic audits.

These are INDEPENDENT flags, not a staircase. --on-disk does NOT imply --integrity.

## Gate Enforcement Flags

- `--fail-on-missing` — Block actions not in lockfile. Auto-enabled for `.github/actions-lock.json` path. Catches: unknown actions, typosquats, version bumps without lockfile update, new malicious workflows.
- `--fail-on-unpinned` — Block branch-pinned mutable refs (e.g., `@main`, `@master`). Catches: mutable ref attacks.
- `--all-workflows` — Scan all `.github/workflows/*.yml` files, not just the triggering workflow. Required for comprehensive coverage.
- `--warn` — Log violations without blocking. For phased rollout.

## Docker Action Verification (v0.7.0)

Pinpoint is the **first GitHub Actions security tool** that verifies Docker image digests.

- `pinpoint lock` resolves Docker image digests from OCI registries (ghcr.io, Docker Hub, quay.io)
- `pinpoint gate --integrity` detects when a Docker image tag has been repointed to a different image
- Supports both `docker://` image references and Dockerfile `FROM` parsing
- Verified against live Docker Hub: pushed evil image to same tag, gate caught `DOCKER IMAGE REPOINTED`

## Attack Battery (10/10 blocked)

| # | Attack | How Pinpoint Catches It |
|---|---|---|
| 1 | Tag repoint (custom-action@v1 → evil SHA) | SHA mismatch in lockfile |
| 2 | Unknown action (super-linter not in lockfile) | `--fail-on-missing` |
| 3 | Branch-pinned ref (@main) | `--fail-on-unpinned` |
| 4 | SHA swap (checkout@wrong-SHA) | SHA-pinned ref verification (spec 023) |
| 5 | Remove inline gate from CI | Separate gate workflow still enforced |
| 6 | Typosquat (actions/check0ut) | `--fail-on-missing` |
| 7 | Version bump (v6→v7 without lockfile update) | Tag not in lockfile |
| 8 | Lockfile poisoning via PR | Gate reads lockfile from base branch, not PR |
| 9 | New workflow with evil action | `--fail-on-missing` + `--all-workflows` |
| 10 | Specific semver (v4.2.2 vs v4) | Tag key not in lockfile |
| 11 | Docker image tag repoint | `--integrity` Docker digest verification |

## Risk Scoring Signals

| Signal | Score | Description |
|---|---|---|
| MASS_REPOINT | +100 | >5 tags repointed at once |
| OFF_BRANCH | +80 | New commit not a descendant |
| IMPOSSIBLE_TIMESTAMP | +70 | Commit timestamp precedes parent |
| SIZE_ANOMALY | +60 | Entry point size changed >50% (has floor, can't be cancelled) |
| SEMVER_REPOINT | +50 | Exact version tag moved |
| SIGNATURE_DROPPED | +45 | Release was signed, new one is not |
| BACKDATED_COMMIT | +40 | Commit date >30 days old |
| DIFF_ANOMALY | +40/+50 | Suspicious files in release diff (entrypoint, Dockerfile, action.yml) |
| CONTRIBUTOR_ANOMALY | +35 | New contributor appeared in release commits |
| RELEASE_CADENCE_ANOMALY | +25 | Release interval is a statistical outlier |
| NO_RELEASE | +20 | No corresponding GitHub Release |
| SELF_HOSTED | +15 | Self-hosted runners affected |
| MAJOR_TAG_ADVANCE | -30 | Major tag moved forward to descendant |

## Test Org Deployment Status

### All 4 Phases COMPLETE and OPERATIONAL:

**Phase 1: Audit cron** — Runs daily 8am UTC + manual trigger on `pinpoint-testing/pinpoint`

**Phase 2: Lockfile generation** — Deployed to all 28 repos. Uses GitHub App (`pinpoint-test-bot`, App ID 3160618) for cross-repo auth. Creates PRs when lockfile changes.

**Phase 3+4: Gate enforced** — All 28 repos running enforced gate via shared reusable workflow at `pinpoint-testing/shared-workflows`. Flags: `--all-workflows --fail-on-missing --fail-on-unpinned`. Shared workflow pinned to SHA.

### GitHub App: pinpoint-test-bot (App ID 3160618)
- Installed on `pinpoint-testing` org, all repositories
- Permissions: Contents R/W, Actions RO, Members RO
- Org secrets: `PINPOINT_APP_ID`, `PINPOINT_APP_PRIVATE_KEY`
- VPS key: `/home/joshf/.config/pinpoint/app.pem`
- Two tokens minted per gate run: one scoped to pinpoint repo (binary download), one org-wide (gate verification)

### Shared Reusable Workflow
- Location: `pinpoint-testing/shared-workflows/.github/workflows/pinpoint-gate.yml`
- All 28 repos call it via SHA-pinned reference
- When updating: change shared workflow → get new SHA → update all 28 repos' gate.yml with new SHA → regen lockfiles → merge lockfile PRs

## Competitive Landscape

| Tool | Language | What it does | What it doesn't |
|---|---|---|---|
| gh-actions-lockfile (gjtorikian) | TypeScript | Transitive deps, SHA-256 integrity, advisory check | No monitoring, no risk scoring, requires Node.js 24+ |
| ghasum (chains-project/KTH) | Go | Checksums, on-disk cache verification | No monitoring, no SARIF, no org audit |
| pinpoint | Go | Everything above + continuous monitoring, risk scoring, org audit, SARIF, on-disk TOCTOU elimination, retroactive verify, **Docker action verification** | — |

## Research & Stats (cite-worthy)

- 98% of action references don't pin to SHAs (Legit Security, Aug 2025)
- Only 3/96 security projects pin everything (Alvarez study, March 2025)
- 54% of JavaScript Actions have at least one security weakness (MSR 2024)
- 60% of popular actions use mutable dependencies (SoftwareSeni, Feb 2026)
- 99.7% of repos execute externally developed Actions (USENIX Security 2022)
- GitHub closed the lockfile feature request as "not planned" (actions/runner#2195)

## Blog Post

Written, saved at /home/joshf/pinpoint/BLOG.md and as a secret gist:
https://gist.github.com/tehreet/f53ff5690454e93ccdfa50d57329e182

## EVP One-Pager

Written, saved at /mnt/user-data/outputs/pinpoint-one-pager.docx
Framing: "We can either be known as a company that got hit, or as the company that got hit and built the open-source fix."

## Architecture Diagram

Interactive HTML with 4 tabs (lock, gate, attack detection, scaling):
https://gist.github.com/tehreet/ded6584acb8c1fba372dd46b9aef9a45

## Go Conventions

- Module: github.com/tehreet/pinpoint
- No CGo, no frameworks, no CLI libs
- One external dep: gopkg.in/yaml.v3
- Copyright header: CoreWeave, Inc. GPL-3.0-only
- Errors: fmt.Errorf with actionable messages
- Tests: table-driven, httptest.NewServer for mocks, //go:build integration for live API tests
- Build: `export PATH=$PATH:/usr/local/go/bin && go build ./cmd/pinpoint/`

## VPS Setup

- zsh + oh-my-zsh + powerlevel10k (ASCII mode)
- Plugins: git, zsh-autosuggestions, zsh-syntax-highlighting, golang, docker, tmux
- tmux auto-starts on SSH login (ZSH_TMUX_AUTOSTART=true)
- Aliases: `pp` (cd ~/pinpoint), `cc` (claude --dangerously-skip-permissions), `gs`, `gl`, `gp`
- Docker installed (v29.3.0), logged into ghcr.io + Docker Hub as tehreet
- mosh installed but caused Blink stuck session issues — use plain SSH instead
- Claude Code prompts saved as PROMPT-*.md files (gitignored)
