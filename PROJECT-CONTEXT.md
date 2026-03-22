# Pinpoint — Project Instructions for Claude

You are helping Josh Frantz (joshf) build pinpoint, a GitHub Actions tag integrity monitor. You have access to the VPS via the sloperations MCP server.

## IMPORTANT WORKING STYLE

- **Do not be eager.** When Josh brings up something new, present the plan and options first. Wait for approval before building anything.
- **Check in on the full plan** rather than jumping straight to code.
- **Be direct and concise.** Josh prefers straight talk, no filler.

## What Pinpoint Is

Single Go binary, one dependency (gopkg.in/yaml.v3). Detects and prevents GitHub Actions supply chain attacks where version tags are repointed to malicious commits. Built in response to the March 2026 Trivy attack (75 tags force-pushed). CoreWeave was directly affected.

## Repositories

- **Canonical:** `tehreet/pinpoint` (private, Josh's personal account)
- **Test org mirror:** `pinpoint-testing/pinpoint` (private, org copy with action.yml pointing to org releases)
- **Test org:** `pinpoint-testing` — 30+ repos with realistic workflows for testing
- **VPS:** ubuntu-32gb-hil-1, user joshf, IP 5.78.91.92
- **Project path on VPS:** /home/joshf/pinpoint
- **Go version:** 1.24.1 (at /usr/local/go/bin)

## Current State (v0.5.0 released)

- 151 tests (all passing), 15,317 lines of Go, 42+ commits
- v0.5.0 tagged and released with 5-platform binaries on both repos
- README rewritten, STEELMAN updated with mitigations
- 16 specs written (001-016), all implemented

## Commands (all implemented)

| Command | Description |
|---|---|
| `pinpoint lock` | Generate .github/actions-lock.json (v2 format: SHA + integrity hash + disk_integrity + type + transitive deps) |
| `pinpoint lock --list` | Show dependency tree including transitive deps |
| `pinpoint lock --verify` | Check lockfile against live tags (read-only) |
| `pinpoint gate` | Pre-execution verification (3 API calls, <2s) |
| `pinpoint gate --on-disk` | Verify runner's downloaded files against lockfile (+28ms, 0 API calls) |
| `pinpoint gate --integrity` | Re-download tarballs and verify SHA-256 (audit mode, +3-5s) |
| `pinpoint scan` | One-shot poll with risk scoring and alerting |
| `pinpoint watch` | Continuous monitoring on interval |
| `pinpoint discover` | Find actions in local workflow files |
| `pinpoint audit --org <n>` | Org-wide security posture scan (report/json/config/manifest/sarif output) |
| `pinpoint verify` | Retroactive integrity check (4 signals, no baseline needed) |

## Architecture

```
cmd/pinpoint/main.go           — CLI routing, all subcommands
internal/
  alert/alert.go               — Stdout/Slack/webhook alerting
  audit/audit.go               — Org-wide scanner
  config/config.go             — YAML config with AllowRule support
  discover/discover.go         — Workflow file parser
  gate/gate.go                 — Pre-execution verification, PR poisoning protection
  integrity/treehash.go        — On-disk tree hashing (ComputeTreeHash)
  manifest/manifest.go         — Lockfile refresh, verify, save, load
  manifest/integrity.go        — Tarball download+hash, batch with worker pool
  manifest/transitive.go       — Composite action.yml parsing, transitive resolution
  manifest/lockpath.go         — ResolveLockfilePath (new/legacy path detection)
  manifest/templates.go        — Embedded workflow YAML templates
  poller/github.go             — REST API client
  poller/graphql.go            — GraphQL client (50 repos/query, 1 point)
  poller/graphql_org.go        — FetchOrgWorkflows for audit
  risk/score.go                — Risk scoring (8 signals)
  sarif/sarif.go               — SARIF 2.1.0 output
  store/store.go               — JSON state with atomic writes
  suppress/suppress.go         — Allow-list false positive suppression
  verify/verify.go             — Retroactive integrity check (4 signals)
tests/
  harness/                     — 13 integration tests (6 attack scenarios + 4 real-world replays + 3 live tests)
  perf/                        — Performance benchmarks + memory pressure tests
```

## Lockfile Format (v2)

```json
{
  "version": 2,
  "generated_at": "2026-03-22T06:04:30Z",
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
    "actions/upload-pages-artifact": {
      "v4": {
        "sha": "7b1f4a764d45...",
        "integrity": "sha256-...",
        "disk_integrity": "sha256-...",
        "type": "composite",
        "dependencies": [
          {
            "action": "actions/upload-artifact",
            "ref": "ea165f8d65b6...",
            "integrity": "sha256-...",
            "type": "node20",
            "dependencies": []
          }
        ]
      }
    }
  }
}
```

## Gate Verification Levels

1. **SHA-only (default):** 3 API calls, <2 seconds. Catches tag repointing.
2. **On-disk (`--on-disk`):** +28ms disk I/O, zero network. Hashes what the runner actually downloaded. Catches TOCTOU, cache poisoning, MITM.
3. **Integrity (`--integrity`):** +N REST calls, 3-5s. Re-downloads tarballs. For periodic audits.

These are INDEPENDENT flags, not a staircase. --on-disk does NOT imply --integrity.

## Risk Scoring Signals

| Signal | Score | Description |
|---|---|---|
| MASS_REPOINT | +100 | >5 tags repointed at once |
| OFF_BRANCH | +80 | New commit not a descendant |
| SIZE_ANOMALY | +60 | Entry point size changed >50% (has floor, can't be cancelled) |
| SEMVER_REPOINT | +50 | Exact version tag moved |
| BACKDATED_COMMIT | +40 | Commit date >30 days old |
| NO_RELEASE | +20 | No corresponding GitHub Release |
| SELF_HOSTED | +15 | Self-hosted runners affected |
| MAJOR_TAG_ADVANCE | -30 | Major tag moved forward to descendant |

## Verified Performance Data

All measured on VPS (8-core EPYC-Milan, Hetzner US). Runner performance would be faster for network ops (inside Azure network), slightly slower for CPU ops (4 vCPU).

| Operation | VPS Measured | Runner Predicted |
|---|---|---|
| Single tarball download | 1.5-2.0s | 0.3-0.5s |
| 10 parallel tarballs | 1.4s | 0.4-0.6s |
| Tree hash 15 dirs (2715 files) | 28ms | 50-60ms |
| Gate SHA-only | <2s | <1s |
| Lock 15 actions (parallel) | ~15s | ~8s |

Worker pool: 10 goroutines, semaphore pattern. Deduplication before downloading.

GraphQL scaling: 1,800 repos = 432 pts/hr (8.6%). Wall at ~20,000 repos.

## Key Technical Facts

- Tarball downloads are latency-bound, not bandwidth-bound
- Tarball hashes are deterministic (verified)
- Streaming: io.Copy to sha256.New(), never buffer whole tarball (16MB RSS for 5MB tarball)
- GitHub API: tarball endpoint redirects from api.github.com to codeload.github.com
- Tree hash algorithm: walk files, SHA-256 each, sort "path\x00hash" entries, hash concatenation
- Composite action detection: parse action.yml `runs.using` field, recurse up to depth 5
- Gate fork PR protection: fetches manifest from GITHUB_BASE_REF for pull_request events

## Competitive Landscape

| Tool | Language | What it does | What it doesn't |
|---|---|---|---|
| gh-actions-lockfile (gjtorikian) | TypeScript | Transitive deps, SHA-256 integrity, advisory check | No monitoring, no risk scoring, requires Node.js 24+ |
| ghasum (chains-project/KTH) | Go | Checksums, on-disk cache verification | No monitoring, no SARIF, no org audit |
| pinpoint | Go | Everything above + continuous monitoring, risk scoring, org audit, SARIF, on-disk TOCTOU elimination, retroactive verify | No Docker action verification |

## Test Org Deployment Status

### Phase 1: Audit cron (DEPLOYED, WORKING)
- Workflow at `pinpoint-testing/pinpoint/.github/workflows/org-audit.yml`
- Runs daily 8am UTC + manual trigger
- Successfully ran: https://github.com/pinpoint-testing/pinpoint/actions/runs/23406577974

### Phase 2: Lockfile generation (DEPLOYED, FAILING)
- Workflow deployed to 5 repos: go-api, platform-api, monorepo-services, franken-pipeline, secure-api
- **FAILING** because binary download can't authenticate cross-repo
- **FIX NEEDED:** Create a GitHub App for the org to mint short-lived tokens for downloading the pinpoint binary
- Use `actions/create-github-app-token@v3` (SHA-pinned) in workflows
- App needs: Repository Contents read-only on pinpoint-testing/pinpoint

### Phase 3: Gate in warn mode (NOT YET DEPLOYED)
### Phase 4: Gate enforced (NOT YET DEPLOYED)

## Research & Stats (cite-worthy)

- 98% of action references don't pin to SHAs (Legit Security, Aug 2025)
- Only 3/96 security projects pin everything (Alvarez study, March 2025)
- 54% of JavaScript Actions have at least one security weakness (MSR 2024)
- 60% of popular actions use mutable dependencies (SoftwareSeni, Feb 2026)
- 99.7% of repos execute externally developed Actions (USENIX Security 2022)
- GitHub closed the lockfile feature request as "not planned" (actions/runner#2195)

## Blog Post

Written, fact-checked, saved at /home/joshf/pinpoint/BLOG.md and as a secret gist:
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
- mosh installed but caused Blink stuck session issues — use plain SSH instead
- Claude Code prompts saved as PROMPT-*.md files (gitignored)
