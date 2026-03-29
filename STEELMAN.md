# STEELMAN.md — Honest Limitations of Pinpoint

Every tool has failure modes. This document is a brutally honest assessment of
where pinpoint breaks, doesn't scale, can be evaded, or creates new problems.
Written from reading every line of code, every test, and every spec — not from
marketing materials.

If you're evaluating pinpoint for your organization, read this first.

---

## 1. Fundamental Architectural Constraints

These are inherent to pinpoint's design. They cannot be fixed without
rebuilding from scratch.

### 1a. The Polling Gap

Pinpoint's monitor (`watch`) polls on an interval. Even at 5 minutes, an
attacker can repoint a tag, wait for one CI run to trigger, and revert — all
before the next poll. The attacker is invisible to the monitor.

The Trivy attacker left malicious tags up for ~5.5 hours. The tj-actions
attacker left them for ~3 hours. Pinpoint catches smash-and-grab. A
nation-state actor who repoints for 90 seconds and reverts? The monitor
misses it completely.

**The gate eliminates this.** `pinpoint gate` verifies at execution time, not
poll time. If every workflow has the gate, the polling gap is irrelevant for
CI runs. The monitor alone is a smoke detector; the gate is the circuit
breaker. Deploy both.

### 1b. GitHub API as Single Source of Truth

Pinpoint trusts the GitHub API to return correct data. Every verification —
tag resolution, workflow content, manifest fetching — goes through GitHub's
REST or GraphQL endpoints. If GitHub's API is compromised, returns stale data,
or behaves inconsistently between CDN edges, pinpoint inherits that blindness.

The gate fetches workflow content from the API, not from the runner's disk.
If the API returns different content than what `actions/checkout` actually
downloaded, there is a semantic gap between what pinpoint verified and what
executes. On-disk verification (`--on-disk`) partially closes this for action
source code, but the workflow YAML itself is always API-sourced.

### 1c. Regex-Based Workflow Parsing

Both `discover` and `audit` extract action references using regex, not a YAML
parser:

```
uses:\s*['"]?([a-zA-Z0-9\-_.]+)/([a-zA-Z0-9\-_.]+)(?:/[^@\s'"]*)?@([a-zA-Z0-9\-_.]+)['"]?
```

This works for the common case but breaks on:
- YAML anchors and aliases (`<<: *base-steps`)
- Multiline `uses:` values with folded/literal block scalars
- Conditional inclusion via matrix expressions
- `uses:` inside comments that don't start at column 0
- Action references constructed from `${{ }}` expressions

The gate's `--all-workflows` mode concatenates all workflow YAML files into a
single blob before regex extraction. If one file's trailing content creates a
valid `uses:` match with the next file's leading content, phantom actions could
be extracted. In practice this is unlikely but architecturally unsound.

The audit's dangerous trigger detection (`pull_request_target`) also uses
regex. An attacker who formats their workflow YAML to avoid the regex pattern
while remaining valid YAML can evade trigger detection.

### 1d. The Gate Is a Step, Not Infrastructure

The gate runs as a workflow step. It has no special privileges — it's just
Go code that calls the GitHub API and returns an exit code. This means:

- **Removing the gate is trivial.** Any developer with write access can delete
  the gate step from a workflow. Branch protection on workflow files mitigates
  this but most orgs don't enforce it.

- **The gate can't prevent its own removal.** Unlike GitHub's required status
  checks (which are enforced at the platform level), the gate is advisory
  unless paired with external enforcement.

- **Reusable workflows help but aren't bulletproof.** The shared workflow
  pattern (`org/shared-workflows/.github/workflows/pinpoint-gate.yml@SHA`)
  centralizes the gate. But the calling workflow still has to reference it.
  If the caller removes the `uses:` line, the gate doesn't run.

- **The gate itself must be SHA-pinned.** If referenced as `@v1`, an attacker
  who compromises pinpoint can ship a gate that approves everything.

---

## 2. Detection Blind Spots

Things that happen in the real world that pinpoint cannot detect.

### 2a. Compromised Maintainer Accounts

The CONTRIBUTOR_ANOMALY signal (+35) fires when new contributors appear in a
release. If the attacker IS a known maintainer — as in the tj-actions attack
where a maintainer's account was compromised — their commits won't trigger
this signal. The contributor is already in the `known_contributors` set.

This is the most dangerous class of supply chain attack and pinpoint has
limited defense against it. The DIFF_ANOMALY and RELEASE_CADENCE_ANOMALY
signals provide partial coverage (even a known maintainer pushing suspicious
files at unusual times will fire), but a patient attacker who mimics normal
development patterns can evade all three behavioral signals.

### 2b. Subtle Payload Injection

SIZE_ANOMALY fires when the entry point changes by >50%. An attacker who
adds 10 lines of malicious code to a 500-line file changes size by ~2%.
This is invisible to size-based detection.

The file classification for DIFF_ANOMALY uses a hardcoded list of suspicious
filenames: `action.yml`, `Makefile`, `Dockerfile`, `entrypoint.sh`,
`setup.py`, `dist/`, and workflow files. An attacker who injects payload into
a file named `utils.js` or `lib/helper.go` won't trigger the suspicious file
signal.

### 2c. Actions with >300 Tags

GraphQL pagination for tag fetching caps at 3 pages of 100 tags (300 total
per repo). Repos with more than 300 tags will have incomplete tag data. An
attacker could create many decoy tags to push the real attack beyond the
pagination boundary.

This is uncommon — most actions have <100 tags — but repos like
`actions/checkout` accumulate tags over time.

### 2d. Transitive Dependencies Beyond Depth 5

Composite action resolution recurses to a maximum depth of 5. A malicious
composite action nested 6 levels deep won't have its dependencies verified.
The attacker would need to control a chain of 6 composite actions, which is
unlikely but possible in a targeted supply chain attack.

### 2e. Non-GitHub Registries Without Credentials

Docker digest resolution for actions using private registries (ECR,
Artifactory, private ghcr.io) will fail silently if pinpoint doesn't have
credentials. The action is still verified by Git SHA, but the Docker image
integrity is unchecked. Pinpoint logs a warning to stderr but does not fail —
the operator may not notice.

### 2f. Build-Arg Parameterized Docker Images

Dockerfile actions using `ARG` before `FROM` have parameterized base images.
Pinpoint's `ParseDockerfile` skips `FROM` lines containing `${`. This means
actions that construct their base image reference from build arguments have
no digest verification at all.

### 2g. Chronology Tolerance Window

The verify command's impossible chronology check uses a 48-hour tolerance.
A backdated commit that's less than 48 hours older than its parent won't
trigger. An attacker who backdates by 24 hours — plausible for timezone
differences — evades this signal entirely.

### 2h. Advisory Database Coverage

The verify command's known-bad SHA check has exactly 4 hardcoded SHAs
(tj-actions, reviewdog, trivy). The advisory database fetch queries GitHub's
`/advisories` endpoint filtered to the `actions` ecosystem, which has limited
coverage. Novel compromises won't appear in either source until after
discovery and disclosure.

---

## 3. Evasion Techniques

Once an attacker knows pinpoint exists, these are the adaptation strategies.

### 3a. Timing Attacks

Repoint the tag, wait for exactly one CI run to trigger on a target repo,
revert. The gate catches this IF the target repo has the gate. The monitor
misses it if the revert happens within the poll interval. If the attacker
knows which repos have the gate (by checking for `.github/actions-lock.json`
in public repos), they can target repos without it.

**Defense:** Deploy the gate on every workflow, not just critical ones. Use
`--all-workflows` mode so even workflows that don't reference the action
directly are covered.

### 3b. Gradual Rotation

Repoint one tag per day. Each event scores individually. A single tag
repoint of a major version tag (e.g., `v4`) to a descendant commit scores
-30 (MAJOR_TAG_ADVANCE deduction). If the attacker maintains ancestry and
keeps entry point size similar, the risk score can be LOW or even negative.

**Defense:** Alert on ANY tag movement, not just high-severity. Review all
tag changes weekly. The 495-point gap between normal (-30) and full attack
(+465) means a careful attacker who maintains ancestry and minimal size
change lands around +15 to +30 — enough for MEDIUM but not CRITICAL. Tune
your alert threshold to match your risk tolerance.

### 3c. Tag-Delete-Recreate

Delete a tag and create a new one with the same name pointing to a different
commit. Depending on API timing and caching, this may register as a new tag
rather than a repointed tag, potentially getting a lower risk score.

**Defense:** `--fail-on-missing` catches this because the recreated tag will
either match the lockfile SHA (safe) or not (violation). The monitor's state
tracking records tag deletions separately.

### 3d. Compromise the Monitoring Tool

If pinpoint runs as a GitHub Action, compromise pinpoint itself. Ship a gate
that silently approves all checks.

**Defense:** Pin the shared workflow to a SHA. Limit write access to the
shared-workflows repo to 1-2 people. Run `pinpoint watch` on infrastructure
you control (VPS, dedicated container), not in GitHub Actions.

### 3e. Exploit the Regex Parser

Construct a workflow file that is valid YAML but structures the `uses:`
directive in a way the regex doesn't match. Examples:
- Use YAML anchors to define the action reference elsewhere
- Use multiline folded scalars (`>-`) for the `uses:` value
- Place action references in reusable workflow inputs that get passed through

**Defense:** None currently. A proper YAML parser would fix this but would
add dependencies (or significant code). The regex covers >99% of real-world
workflow syntax.

### 3f. Target the Lockfile Update Process

The lockfile is regenerated by `pinpoint lock`, typically in a scheduled
workflow. If the attacker times their tag repoint to coincide with the lock
regeneration, the malicious SHA gets recorded as the new "known good" baseline.
Future gate runs verify against the poisoned lockfile.

**Defense:** Lockfile regeneration creates a PR for human review. The reviewer
must check SHA changes against expected releases. Automate this with a
comparison against the action's GitHub Releases page. But in practice, most
reviewers merge lockfile PRs without scrutiny.

### 3g. Multi-Architecture Image Substitution

Docker actions using multi-arch manifest lists get their manifest list digest
verified. An attacker with registry write access could replace the
linux/amd64 image within the manifest list while keeping the list digest
unchanged (by also updating the manifest list). This requires registry
compromise and manifest list manipulation but would bypass digest
verification.

**Defense:** Verify individual platform digests by running
`pinpoint gate --integrity` on runners of each architecture. Not yet
implemented as an automatic check.

---

## 4. Scale Limitations

Where pinpoint breaks as usage grows.

### 4a. State File Is JSON

The `watch` command persists state as a single JSON file. At 2,000 repos
with 50 tags each (100,000 entries), loading and saving this on every poll
cycle becomes expensive. The atomic write pattern (write to `.tmp`, rename)
means the entire file is rewritten every cycle.

There is no SQLite backend, no PostgreSQL backend, no incremental update.
This is fine for <500 repos. Beyond that, poll cycles slow down and the
state file can reach 50-100MB.

**Mitigation:** Monitor unique actions (typically 100-200) rather than all
repos (2,000+). The audit deduplicates across repos.

### 4b. REST API Doesn't Scale

REST tag fetching costs 1 API call per repo per poll. At 2,000 repos with
5-minute intervals: 24,000 requests/hour. The authenticated rate limit is
5,000/hour. REST is 5x over budget.

GraphQL solves this (50 repos per query, ~480 points/hour for 2,000 repos),
but REST is the fallback for environments where GraphQL is unavailable
(some GHES configurations). If you fall back to REST at scale, monitoring
stops working.

### 4c. GraphQL Tag Pagination

Each repo gets 3 pages of 100 tags maximum (300 tags). This is hardcoded
(`maxPaginationPages=3`). Repos that accumulate hundreds of tags over years
will have incomplete data. The pagination continues from where it left off
using cursors, so which 300 tags you get depends on GraphQL's ordering.

### 4d. Enrichment Uses REST

GraphQL handles tag resolution, but commit comparison (`CompareCommits`),
commit metadata (`GetCommitInfo`), release immutability checks, and org
policy checks all use REST. At 2,000 repos, enrichment calls accumulate.
ETag caching helps (304 responses are free), but the first enrichment cycle
after a restart hits REST hard.

### 4e. Integrity Hashing at Scale

`pinpoint lock` with integrity enabled downloads every action's tarball and
computes SHA-256. With 200 unique actions averaging 500KB each, that's
100MB of downloads per lockfile regeneration. The 10-goroutine worker pool
is hardcoded — not tunable for faster networks or rate-limited environments.

For large orgs with 500+ unique actions, lockfile regeneration can take
several minutes and consume significant bandwidth.

### 4f. Audit GraphQL Cost

Org-wide audit fetches every repo's `.github/workflows/` directory content
inline via GraphQL. For orgs with thousands of repos, this is multiple
paginated queries at 50 repos per page. The content of every workflow file
is transferred in the GraphQL response. A 5,000-repo org with 3 workflows
per repo transfers ~15,000 workflow files worth of content in a single
audit run.

---

## 5. Operational Footguns

Ways pinpoint can hurt you if deployed carelessly.

### 5a. Stale Lockfile = Blind Gate

The lockfile is only as fresh as the last `pinpoint lock`. If nobody
regenerates it for months, legitimate tag advances cause SHA mismatches.
With `--fail-on-missing` (the default for new lockfile paths), the gate
blocks the build. The developer who sees "SHA mismatch" doesn't know if
it's an attack or just a stale lockfile.

If this happens often enough, developers learn to work around the gate
(removing it, switching to `--warn` mode permanently, or auto-merging
lockfile PRs without review). Alert fatigue is the real threat model.

**Automate lockfile regeneration.** Run `pinpoint lock` on a schedule
(weekly) and on workflow file changes. The PR-based update flow creates
human review checkpoints.

### 5b. State Poisoning

The state file (`.pinpoint-state.json`) is plain JSON on disk with no
integrity protection — no HMAC, no signature, no checksum. If an attacker
can modify it, they can pre-seed malicious SHAs as the "known good"
baseline.

The lockfile (`.github/actions-lock.json`) is the real source of truth and
is protected by Git's content-addressable storage + branch protection. The
state file is only for `watch` mode. But if you use `watch` as your primary
defense (without the gate), state poisoning is a viable attack.

### 5c. Actions Cache Eviction

GitHub's Actions cache evicts entries not accessed within 7 days. If
`pinpoint watch` runs in GitHub Actions and doesn't execute for a week,
the state file is lost. Fresh start means every tag looks new. If a tag
was repointed during the gap, the malicious SHA becomes the new baseline.

**Don't use Actions cache for state.** Run `watch` on dedicated
infrastructure with persistent storage, or commit the state file to the repo.

### 5d. The Token Is a High-Value Target

Pinpoint requires a token with `contents: read` across every repo it
monitors. This token is a map of your entire dependency surface.

If the runtime environment is compromised, the token reveals:
- Every action and tag you depend on
- The SHAs you consider "known good" (your lockfile contents)
- Your workflow structure and CI pipeline design

**Use GitHub App installation tokens** (short-lived, 1-hour expiry, scoped
to specific permissions). Never use long-lived PATs. Isolate the gate
workflow — no other third-party actions in the same job.

### 5e. Fork PR Manifest Poisoning (Handled, but Subtly)

An attacker submits a PR that modifies the lockfile, hoping the gate reads
their poisoned version. Pinpoint handles this: for `pull_request` and
`pull_request_target` events, the gate fetches the lockfile from
`GITHUB_BASE_REF`, not the PR branch.

But this depends on `GITHUB_BASE_REF` being set. If it's not (e.g., custom
CI runners, non-standard event types), the gate falls back to `GITHUB_SHA`
with a warning to stderr. The warning is easy to miss. The fallback trusts
the PR's lockfile.

### 5f. Warn Mode Inertia

`--warn` mode logs violations without blocking. It's designed for phased
rollout: run in warn mode for 1-2 weeks, review output, then switch to
enforce. In practice, warn mode becomes permanent because nobody schedules
the switchover. The gate runs, generates logs nobody reads, and provides
zero actual protection.

### 5g. Pinpoint Adds Latency to Every CI Run

The gate makes 3+ API calls per run (fetch workflow, fetch manifest, resolve
tags via GraphQL). In warm-path mode (~2s), this is tolerable. With
`--integrity` (re-download tarballs, resolve Docker digests), it's 3-5s.
With `--on-disk` (hash runner's downloaded files), it's +28ms.

For orgs running thousands of CI jobs per hour, cumulative latency matters.
A 2-second gate on 1,000 daily jobs is 33 minutes of developer wait time
per day. Not catastrophic, but not free.

### 5h. Branch Detection Is a Hardcoded List

The gate identifies branch-pinned refs by checking against a fixed list:
`main`, `master`, `develop`, `dev`, `trunk`, `release`, `staging`,
`production`. An action pinned to `@my-feature-branch` won't be detected
as branch-pinned. It'll be treated as a tag reference and checked against
the manifest, where it likely won't exist — triggering a `--fail-on-missing`
violation for the wrong reason.

---

## 6. Trust Assumptions

Things pinpoint takes on faith that could be wrong.

### 6a. Tarball Determinism

Pinpoint assumes GitHub's tarball generation is deterministic — that the
same commit always produces the same tarball bytes. This is empirically
true today. If GitHub changes their tarball generation (compression
algorithm, file ordering, header format), every integrity hash in every
lockfile worldwide invalidates simultaneously. The gate would flag every
action as compromised.

### 6b. Tree Hash Portability

On-disk tree hashing uses `filepath.Walk` to enumerate files, then hashes
each file's content. The walk order depends on the filesystem's directory
ordering. On most filesystems this is deterministic and sorted, but the
Go standard library doesn't guarantee cross-platform ordering. A tree hash
computed on Linux may differ from one computed on macOS if the filesystem
returns entries in a different order.

In practice, GitHub-hosted runners are all Linux with ext4, so this is
consistent. Self-hosted runners on exotic filesystems could produce
different tree hashes.

### 6c. GitHub API Consistency

The gate fetches the manifest from one API call, then resolves tags from
another. Between these calls, the repository state can change. If a tag
is repointed after the manifest is fetched but before the tag is resolved,
the gate will correctly detect the mismatch — but only because the timing
favors detection. The reverse timing (tag resolved first, then manifest
fetched from a commit that already includes the updated lockfile) would
miss it.

This is a narrow window and not practically exploitable, but it means the
gate's verification is not truly atomic.

### 6d. GraphQL Tag Ordering

When paginating tags, pinpoint trusts that GraphQL returns tags in a
consistent order. If the ordering changes between requests (due to
concurrent tag creation/deletion), some tags could be missed or duplicated
across pages.

### 6e. One Dependency

Pinpoint has a single external dependency: `gopkg.in/yaml.v3`. If yaml.v3
is compromised (same attack vector pinpoint defends against, applied to
Go modules rather than GitHub Actions), pinpoint itself is compromised.
The Go module proxy and checksum database provide protection, but this
is still a supply chain trust assumption about your supply chain defender.

### 6f. Docker Registry Trust

Docker digest resolution trusts the registry's `Docker-Content-Digest`
response header. If a registry is compromised and returns a valid digest
for content it shouldn't, pinpoint accepts it. The OCI distribution spec
requires registries to set this header honestly, but compromised registries
don't follow specs.

---

## 7. Feature-Specific Limitations

### 7a. Docker Verification

**Only in `--integrity` mode.** The default gate does not re-resolve Docker
digests. This means the daily `--integrity` check catches Docker image
repointing, but per-run checks don't. An attacker who repoints a Docker
image between daily checks has a window.

**Registry rate limits.** Anonymous Docker Hub pulls are limited to 100/6hr.
Digest resolution uses HEAD requests (lighter than pulls), but for orgs
with many Docker actions, rate limits can prevent verification.

**Multi-arch manifest lists.** Pinpoint captures the manifest list digest.
Individual platform image substitution within the list is not detected.

### 7b. Behavioral Anomaly Signals

**Baseline requirement.** All three behavioral signals need historical data:
- CONTRIBUTOR_ANOMALY needs `known_contributors` (populated after first lock)
- RELEASE_CADENCE_ANOMALY needs `release_history` with 3+ entries
- DIFF_ANOMALY needs a previous SHA to compare against

The first lockfile after upgrading captures the initial baseline but cannot
detect anomalies until the second tag movement. There is no retroactive
population from git history.

**High-cadence exclusion.** RELEASE_CADENCE_ANOMALY excludes projects with
mean release intervals under 7 days. This prevents false positives on
actively developed projects but also means attackers targeting high-cadence
projects (nightly release actions, CI tooling) won't trigger cadence
anomalies.

**action.yml false positives.** DIFF_ANOMALY classifies all `action.yml`
modifications as suspicious because determining what changed within the
file would require fetching and diffing content — an additional API call
per detection. Actions that frequently update their action.yml metadata
will generate noise.

### 7c. Verify Command (Retroactive Checks)

The `verify` command runs 4 integrity signals without a prior baseline.
But each has gaps:

1. **Release/Tag SHA Mismatch** — If the action has no GitHub Releases
   (common for smaller actions), this signal returns "limited" not "failed."
   An attacker targeting an action without releases evades this check.

2. **GPG Signature Discontinuity** — If the action was never GPG-signed,
   signature dropping can't be detected. Most actions are unsigned.

3. **Impossible Chronology** — 48-hour tolerance. Timezone-aware backdating
   within this window is invisible.

4. **Known Compromised SHA** — Exactly 4 hardcoded SHAs. Scales by adding
   more to source code and recompiling. Not a dynamic database.

### 7d. SARIF Output

SARIF output maps to 6 rule IDs. Gate violations produce human-readable
text and JSON but NOT SARIF. SARIF is generated by the `audit` and `scan`
commands only. If you're integrating with GitHub's code scanning (which
consumes SARIF), you need to run `scan` or `audit` separately from the
gate.

### 7e. Injection System

`pinpoint inject` adds gate steps to workflow files using line-based
processing (not YAML parsing). It detects jobs, steps, and indentation
through string matching. Edge cases:

- Non-standard indentation (tabs mixed with spaces) can confuse detection
- Jobs with `uses:` at the job level (reusable workflows) are correctly
  skipped, but detection relies on the specific string pattern
- If a workflow uses non-standard YAML syntax, injection may produce
  invalid YAML

The injection is idempotent (checks for existing "pinpoint-action" in the
first step) but the check is string-based, not semantic. A step named
"Run pinpoint-action check" would also trigger the skip.

### 7f. Audit Dangerous Trigger Detection

The audit scans for `pull_request_target` workflows with dangerous patterns
(checkout of PR head ref, interpolation of PR data in run steps). But:

- **Test/playground repos are excluded** by name pattern matching
  (`goat`, `playground`, `vulnerable`, `test-`, `-test`). Attackers who
  name their repo normally evade this filter.

- **`if: false` detection** skips disabled jobs. But `if: false` as a
  string value in YAML is truthy. The detection checks for the literal
  string, not YAML boolean semantics. Edge cases exist.

- **Multiline run blocks** (`run: |`, `run: >`) are handled, but deeply
  nested interpolation across multiple lines could evade the regex.

---

## 8. The Bootstrap Problem

### 8a. No Historical Verification

If you deploy pinpoint today, `pinpoint lock` records current SHAs as the
baseline. It cannot tell you whether those SHAs were already compromised
yesterday. The `verify` command provides partial retroactive coverage (4
signals), but none of them are definitive.

**Run `pinpoint verify` before your first lockfile.** Cross-reference
critical actions against their GitHub Releases page. Generate your lockfile
during a known-clean period, not during or after an incident.

### 8b. First-Lock Blind Spot

The first `pinpoint lock` cannot detect behavioral anomalies because there's
no baseline. CONTRIBUTOR_ANOMALY returns nil (not empty), so it doesn't fire.
RELEASE_CADENCE_ANOMALY needs 3+ releases in history. DIFF_ANOMALY needs a
previous SHA.

An attacker who compromises an action BEFORE pinpoint is deployed gets a
free pass on the first lock. Their malicious SHA becomes the trusted
baseline. All subsequent verification operates on a poisoned foundation.

---

## 9. What Pinpoint Is and Isn't

### Pinpoint Is

- A meaningful improvement over nothing (which is what 95% of orgs have)
- Effective against the class of attacks we've actually seen: mass tag
  repointing (Trivy, tj-actions, reviewdog) where the attacker leaves
  malicious tags in place for hours
- Both detection (monitor) and prevention (gate) in a single binary
- The first open-source tool to verify Docker image digests in GitHub Actions
- Content integrity verification: SHA-256 tarball hashes, on-disk tree
  hashing, transitive dependency resolution to depth 5
- 13-signal risk scoring with a 495-point separation between normal
  operations and attack signatures
- 11/11 on a comprehensive attack battery including lockfile poisoning,
  typosquats, SHA swaps, Docker image repointing, and new malicious workflows
- Capable of monitoring 2,000+ repos via GraphQL batching at <10% of API
  budget
- Deployable in under 5 minutes: single binary, one dependency, zero config
  required for basic operation
- GPL-3.0, free, auditable, no vendor lock-in

### Pinpoint Is Not

- A substitute for SHA pinning. Immutable references are always stronger
  than monitoring mutable ones.
- Effective against patient, targeted adversaries who understand the
  detection signals and stay below thresholds.
- A guarantee that your CI/CD pipeline is safe. Pinpoint covers one attack
  surface (GitHub Actions supply chain). There are many others.
- A replacement for code review of action source code. Pinpoint verifies
  that the code hasn't changed, not that it's safe.
- A YAML parser. The regex-based extraction covers >99% of real-world
  workflows but is not semantically complete.
- Tamper-proof. The gate, the lockfile, the state file, and the binary
  itself can all be modified by anyone with write access.
- Real-time. There is always a window — between polls, between lock
  regeneration, between gate execution and actual code execution.

### The Right Deployment

1. `pinpoint gate --all-workflows --fail-on-missing --fail-on-unpinned` on
   every workflow — blocks known attacks in real-time
2. `pinpoint gate --integrity` on a daily schedule — catches Docker image
   repointing and tarball substitution
3. `pinpoint watch` on dedicated infrastructure — continuous monitoring with
   alerting for repos that don't have the gate
4. `pinpoint audit --org` quarterly — org-wide posture assessment, discovers
   unprotected repos and dangerous triggers
5. `pinpoint verify` on first deployment — retroactive integrity check
   before trusting the initial baseline
6. Automated `pinpoint lock` on schedule and on workflow changes — keeps
   the lockfile fresh, creates human review checkpoints for SHA changes

### The Honest Bottom Line

Pinpoint raises the cost of supply chain attacks from "trivial" (force-push
a tag, wait) to "requires understanding the detection system and staying
below multiple independent thresholds while maintaining ancestry, timestamp
plausibility, file size similarity, contributor consistency, and release
cadence norms."

That's a real improvement. It's not invulnerability.
