# Pinpoint Session Journal — 2026-03-22 (Session 2)

## Context

Continuation of pinpoint development. This session focused on competitive
analysis, specs 014-016, performance architecture, visualization, and
Blink/VPS troubleshooting.

## What Got Implemented This Session

### Spec 012: Actions Lockfile (DONE, committed ec08e35)
- `pinpoint lock` command — alias for manifest refresh with --discover
- Default path: `.github/actions-lock.json` (was `.pinpoint-manifest.json`)
- Gate auto-enforces (fail-on-missing=true) when new lockfile exists
- Backwards compat: falls back to legacy `.pinpoint-manifest.json`
- ResolveLockfilePath helper in internal/manifest/lockpath.go
- 13 integration tests all passing

## Specs Written This Session (NOT YET IMPLEMENTED)

### Spec 014: Content Integrity Hashes + Transitive Dependencies
**File:** specs/014-integrity-transitive.md

Two features:
1. **SHA-256 content integrity hashes** — download tarball from
   `/repos/{owner}/{repo}/tarball/{sha}`, stream through sha256.New(),
   store as SRI format `sha256-XXXX...` in lockfile `integrity` field.
   
   API CONTRACT VERIFIED:
   - URL: `https://api.github.com/repos/actions/checkout/tarball/{sha}`
   - Redirects to: `https://codeload.github.com/actions/checkout/legacy.tar.gz/{sha}`
   - Deterministic: two downloads produce identical SHA-256
   - Size: 428KB for actions/checkout (typical range: 100KB-5MB)
   - Memory: 16MB RSS when streaming (io.Copy to hasher, never buffer)

2. **Transitive dependency resolution** — fetch action.yml at locked SHA,
   check `runs.using` for "composite", parse `steps[].uses` directives,
   recurse up to depth 5. Lockfile gains `type` and `dependencies` fields.
   
   API CONTRACT VERIFIED:
   - `actions/upload-pages-artifact` is composite, internally uses
     `actions/upload-artifact@ea165f8d...`
   - `actions/setup-node` uses `node24` (no transitive deps)
   - Fetch via: `GET /repos/{owner}/{repo}/contents/action.yml?ref={sha}`
   - Try action.yml first, fall back to action.yaml

**Lockfile v2 format:**
```json
{
  "version": 2,
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "34e1148...",
        "integrity": "sha256-UlGCnzY7...",
        "type": "node24",
        "dependencies": []
      }
    }
  }
}
```

**Concurrency architecture (from spec 016 performance analysis):**
- Worker pool: 10 goroutines, buffered channel semaphore
- Deduplication: 1800 repos using same action → download tarball ONCE
- Batch function: DownloadAndHashBatch with ActionRef slice input
- 10 parallel downloads measured at 1.4s total (vs ~15s sequential)

**CRITICAL: --integrity is NOT the default gate behavior.** It's opt-in.
Default gate remains SHA-only (3 API calls, <2s).

### Spec 015: On-Disk Content Verification (TOCTOU Elimination)
**File:** specs/015-ondisk-verification.md

Novel feature — first tool to verify what the runner ACTUALLY downloaded.

**Tree hash algorithm:**
1. Walk directory with filepath.WalkDir
2. Skip .git/, skip non-regular files (symlinks)
3. For each file: SHA-256 of content, store as "relPath\x00hexHash"
4. Sort entries lexicographically
5. Hash the sorted concatenation → disk_integrity

**Runner actions cache path:**
- GitHub-hosted: `/home/runner/work/_actions/{owner}/{repo}/{ref}/`
- Self-hosted: `{runner_root}/_work/_actions/{owner}/{repo}/{ref}/`
- Container: `/__w/_actions/{owner}/{repo}/{ref}/`
- Derived from: `$(dirname $RUNNER_WORKSPACE)/_actions`

**Gate flag hierarchy (revised after performance analysis):**
- Level 1: SHA-only (default) — 3 API calls, <2s
- Level 2: --on-disk — +0 API calls, +28ms disk I/O. RECOMMENDED.
- Level 3: --integrity — +N REST calls, +3-5s. Paranoia/audit mode.
- --on-disk does NOT imply --integrity. They are INDEPENDENT.

**TOCTOU race this solves:**
```
T0: Runner downloads abc123 (good)
T1: Attacker repoints tag to deadbeef
T2: Gate asks API → gets deadbeef → FAIL (false positive)
  OR
T0: Runner downloads deadbeef (bad, attacker already repointed)
T1: Attacker reverts tag to abc123 (covers tracks)
T2: Gate asks API → gets abc123 → PASS (false negative!)
```
On-disk verification eliminates both by hashing what's actually on disk.

### Spec 016: Performance Testing
**File:** specs/016-performance-testing.md

**Measured baselines (VPS: 8-core EPYC-Milan, 30GB, Hetzner US):**

| Operation | Measured | On Runner (predicted) |
|---|---|---|
| Single tarball download | 1.5-2.0s | 0.3-0.5s |
| 10 parallel tarballs | 1.4s | 0.4-0.6s |
| Tree hash 15 dirs (2715 files) | 28ms parallel | 50-60ms |
| Streaming hash 5MB tarball | 16MB RSS | Same |
| Gate SHA-only | <2s | <1s |

**VPS vs Runner network difference:**
- VPS → api.github.com: 147ms TCP + 151ms TLS = ~300ms overhead
- Runner (Azure) → GitHub: single-digit ms (same network)
- Tarball downloads 3-5x faster on real runners

**Scaling projections (GraphQL budget):**
- 1,800 repos (CW today): 432 pts/hr (8.6%)
- 5,000 repos: 1,200 pts/hr (24%)
- 10,000 repos: 2,400 pts/hr (48%)
- 20,000 repos (wall): 4,800 pts/hr (96%)

**Addendum:** specs/016-addendum-runner-benchmarks.md
- CI benchmark workflow that runs on real runners
- Captures: hardware specs, network latency, real tarball times, on-disk hashing

## Competitive Analysis (Key Findings)

### gh-actions-lockfile (gjtorikian, TypeScript, AGPL-3.0)
- 53 stars, v1.2.0 (Dec 2025)
- Resolves transitive deps from composite actions
- SHA-256 integrity hashes of tarballs (SRI format)
- GitHub Advisory Database check
- `list` command shows dependency tree
- WEAKNESS: Requires Node.js 24+, hundreds of npm transitive deps
- WEAKNESS: Verification runs AFTER checkout (actions already downloaded)

### ghasum (chains-project/KTH, Go, Apache 2.0)
- Academic backing (CHAINS research project at KTH)
- `gha.sum` file with checksums
- Can verify against runner's on-disk `_work/_actions/` cache (-cache flag)
- Offline verification mode
- WEAKNESS: No continuous monitoring, no risk scoring, no SARIF

### What we stole from them:
1. Content integrity hashes (from gh-actions-lockfile) → spec 014
2. Transitive dependency resolution (from both) → spec 014
3. Advisory database check during verify (from gh-actions-lockfile) → already in spec 013

### What neither of them has that we built:
- Continuous monitoring (scan/watch)
- Risk scoring with 8 signals
- Org-wide audit
- Retroactive verify (day-one, no baseline)
- SARIF output
- PR poisoning protection (gate fetches from GITHUB_BASE_REF)
- On-disk TOCTOU elimination (spec 015 — novel)

### What we're NOT doing:
- Docker-based action verification (different supply chain)
- SHA-256 content hashing at the commit object level (go.sum style)

## Architecture Decisions Made This Session

### Why NOT Rust
- Pinpoint is a 2-30 second CLI tool, not a long-running service
- Go's GC is non-issue for short-lived processes
- One dependency (gopkg.in/yaml.v3) vs Rust's ~10+ crates
- CW infra team writes Go, contributor accessibility matters
- WASM embedding is a solution looking for a problem

### Gate Performance Architecture
- Default gate MUST stay at 3 API calls, <2 seconds
- On-disk (--on-disk) is the recommended upgrade: +28ms, zero network
- Tarball integrity (--integrity) is opt-in audit mode: +3-5s
- These are INDEPENDENT flags, not a staircase
- Worker pool: 10 goroutines, semaphore pattern
- Deduplication before downloading (critical at org scale)

### Tarball Download Key Properties
- Latency-bound, not bandwidth-bound (400KB and 5MB take same time)
- Deterministic: same SHA → same hash across downloads
- Streaming: io.Copy to sha256.New(), never buffer whole tarball
- Redirects: api.github.com → codeload.github.com (follow automatically)
- Some action tarballs 404 (e.g. aquasecurity/trivy-action at certain SHAs)

## Files Created/Modified This Session

### New specs
- specs/014-integrity-transitive.md (13KB)
- specs/015-ondisk-verification.md (18KB)
- specs/016-performance-testing.md (13KB)
- specs/016-addendum-runner-benchmarks.md (7KB)
- specs/claude-code-prompts-014-015.md (29KB) — prompts for all 3 specs

### New docs
- docs/architecture.html (26KB) — standalone interactive architecture diagram
  - Gist: https://gist.github.com/tehreet/ded6584acb8c1fba372dd46b9aef9a45
  - 4 tabs: lock pipeline, gate levels, attack detection, scaling
  - Full dark mode support, self-contained HTML+SVG+CSS

## Claude Code Prompt Queue

### COMPLETED: Spec 012 (committed ec08e35)

### IN PROGRESS: Spec 014 (Claude Code running now, PID 20017)
Prompt location: specs/claude-code-prompts-014-015.md → "Prompt 1"
6 phases: types, tarball hashing, transitive resolution, lock integration,
gate integration, dependency tree display

### NEXT: Spec 015
Prompt location: specs/claude-code-prompts-014-015.md → "Prompt 2"
5 phases: tree hash function, disk_integrity during lock, gate on-disk,
tests, action.yml update

### AFTER THAT: Spec 016
Prompt location: specs/claude-code-prompts-014-015.md → "Prompt 3"
4 phases: tarball benchmarks, tree hash benchmarks, memory tests, shell script

### THEN: Tag v0.5.0, build release binaries, push

## VPS Notes

- Blink mosh sessions can get permanently stuck if server dies
- Fix: delete and reinstall Blink app to clear saved session state
- VPS IP: 5.78.91.92
- Use plain SSH instead of mosh when debugging: `ssh joshf@5.78.91.92`
- mosh UDP ports: 60000-60010

## Current Repo Stats (post spec-012)
- Commit: ec08e35
- Tests: 140+ (13 integration tests in harness)
- Lines of Go: ~12,000+
- Specs: 16 (012 implemented, 014-016 written but pending)
- Commits: ~38
