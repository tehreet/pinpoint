# STEELMAN.md — Honest Limitations of Pinpoint

Every tool has failure modes. This document is a brutally honest assessment of
where pinpoint breaks, doesn't scale, can be evaded, or creates new problems.
If you're evaluating pinpoint for your organization, read this first.

Each section includes concrete recommendations for how to handle the limitation.

---

## 1. The Polling Gap Is a Fundamental, Unfixable Limitation

Pinpoint polls on an interval. Even at the minimum useful interval (5 minutes),
there is a window where tags can be repointed, pipelines can execute malicious
code, and the tags can be *reverted back to legitimate SHAs* — all before
pinpoint's next poll. The attacker is invisible.

This isn't a bug; it's inherent to polling-based monitoring of third-party repos
you don't own. Webhooks would close this gap but require admin access to the
upstream repo, which you don't have for third-party actions.

**Realistic impact:** The Trivy attacker left the malicious tags in place for
~5.5 hours. The tj-actions attacker left them for ~3 hours. These are not
sophisticated timing attacks — they're smash-and-grab. Pinpoint catches
smash-and-grab. A nation-state actor who repoints for 90 seconds, waits for
one CI run to trigger, and reverts? Pinpoint misses that completely.

### Recommendations

1. **Always deploy the gate, not just the monitor.** `pinpoint gate` verifies
   tags at execution time, not at poll time. The polling gap is irrelevant for
   CI runs that have the gate. The monitor alone is a smoke detector; the gate
   is the circuit breaker.

2. **Run `pinpoint gate --on-disk` for self-hosted runners.** This hashes
   the actual files the runner downloaded, closing the TOCTOU window between
   runner download and gate verification. Zero additional API calls, ~28ms.

3. **Set up webhooks on repos you own.** For internal/private actions, configure
   GitHub webhooks to trigger a `pinpoint scan` on tag events. This eliminates
   the polling gap for repos under your control.

4. **Keep the poll interval at 5 minutes or less.** The shorter the interval,
   the smaller the window. At 5 minutes with GraphQL batching, 2,000 repos cost
   under 10% of your API budget.

5. **Combine with runtime detection.** Pinpoint is Layer 2 (pre-execution). Pair
   it with Layer 3 (StepSecurity Harden-Runner, CrowdStrike Falcon on self-hosted
   runners) for defense in depth. Neither alone is sufficient.

---

## 2. Scale: API Costs at 2,000 Repos

### 2a. API Rate Limits

**GraphQL (default):** Pinpoint batches 50 repos per GraphQL query at 1 point
per batch. Monitoring 2,000 repos costs 40 points per poll cycle. At 5-minute
intervals: 40 × 12 = 480 points/hour — under 10% of the 5,000 points/hour
GraphQL budget. This scales comfortably.

**REST (fallback):** The REST `matching-refs` endpoint costs 1 API call per
repo per poll. At 2,000 repos with a 5-minute interval: 24,000 requests/hour.
That's 5x the 5,000/hour REST rate limit. REST fallback does not scale.

### Recommendations

1. **Always use GraphQL (the default).** REST is a fallback for environments
   where GraphQL is unavailable. Don't use it at scale.

2. **Use a GitHub App, not a PAT.** GitHub Apps get their own rate limit bucket
   per installation. A PAT shares the rate limit with all other API usage by
   that user. The `pinpoint-test-bot` pattern (App ID + private key → short-lived
   token) is the production deployment model.

3. **For >5,000 repos, use tiered polling.** Poll critical repos every 2 minutes,
   standard repos every 10 minutes, inactive repos every hour. Pinpoint's config
   supports this via the `schedule` field. Budget: 5,000 repos at mixed intervals
   fits under 2,000 points/hour.

4. **Budget ~500 REST calls/hour for enrichment at scale.** GraphQL handles tag
   resolution, but enrichment (commit comparison, file size checks) uses REST.
   At 2,000 repos, most enrichment calls are cached via ETags (304 responses are
   free). Monitor your actual rate limit consumption with `pinpoint watch --json`
   and tune from there.

### 2b. Annotated Tag Dereferencing

GraphQL auto-dereferences annotated tags. No extra API call needed. REST fallback
requires a second call per annotated tag.

### Recommendations

1. **Use GraphQL.** This is a solved problem on the GraphQL path.
2. If you must use REST, implement tag-object SHA caching (store the tag→commit
   mapping locally so you only dereference once per tag per lifetime).

### 2c. State File Size

2,000 repos × 50 tags = 100,000 entries. With history, the JSON state file can
reach 50-100MB. Loading/saving this on every poll is too expensive.

### Recommendations

1. **For <500 repos, the JSON file store is fine.** No action needed.
2. **For 500-5,000 repos, use SQLite.** Add `store: sqlite` to your config.
   Pinpoint uses `modernc.org/sqlite` (pure Go, no CGo). This is on the roadmap
   but not yet implemented — track the issue.
3. **For >5,000 repos, use PostgreSQL.** External database with connection pooling.
   Same roadmap status.
4. **In the meantime:** Prune old history with `pinpoint prune --older-than 30d`.
   Keep the state file under 10MB by retaining only recent change events.

---

## 3. The Token Is a High-Value Target

Pinpoint requires a token with read access to every repo it monitors. If the
runtime environment is compromised, that token gives an attacker a map of every
action and tag you depend on — plus the SHAs you consider "known good."

### Recommendations

1. **Use a GitHub App with minimum permissions.** The app needs only
   `contents: read`. Not `admin`, not `write`. Create a dedicated app (like
   `pinpoint-test-bot`) rather than reusing an existing one with broader perms.

2. **Mint short-lived tokens.** GitHub App installation tokens expire in 1 hour.
   Use `actions/create-github-app-token` in workflows — the token is scoped and
   short-lived. Never store long-lived PATs.

3. **Isolate the gate workflow.** Run pinpoint in a dedicated workflow with
   minimal steps: checkout (SHA-pinned) → generate token → run gate. No other
   third-party actions in the same job. The reusable workflow pattern at
   `shared-workflows/pinpoint-gate.yml` enforces this.

4. **Pin the gate itself to a SHA.** Reference the shared workflow by
   `@<commit-SHA>`, not `@main`. Pinpoint can't protect itself if its own
   reference is mutable. All 28 repos in the test org use SHA-pinned references
   to the shared workflow.

5. **For maximum isolation:** Run `pinpoint watch` on a dedicated VM/container
   outside of GitHub Actions entirely. The VPS deployment pattern (cron + systemd)
   eliminates the risk of a compromised action stealing the monitoring token.

---

## 4. False Positive Fatigue Will Kill Adoption

Major version tags are designed to be moved. `actions/checkout@v4` moves forward
with every patch release. At 2,000 repos, this can generate dozens of low-severity
alerts per day. If operators learn to ignore pinpoint alerts, they'll also ignore
the one that matters.

### Recommendations

1. **Deploy gate in `--warn` mode first.** Run for 1-2 weeks. Review the output.
   Identify legitimate tag movements that trigger alerts. Add allow-list rules
   for those patterns. Then flip to enforce. We did this across 28 repos and
   caught zero false positives in enforce mode.

2. **Use allow-list rules aggressively.**
   ```yaml
   allow:
     - repo: actions/*
       tags: ["v*"]
       condition: major_tag_advance
       reason: "GitHub-maintained actions advance major tags on every release"
   ```
   This suppresses the ~195 legitimate tag movements per year across the top 20
   actions while still catching repoints, off-branch moves, and mass changes.

3. **Use `--fail-on-missing` instead of alerting on unknown actions.** Rather
   than alerting when an unknown action appears and hoping someone investigates,
   block the build. This eliminates the "alert that nobody reads" problem. The
   developer who added the action gets immediate feedback.

4. **Route gate failures to the PR author, not a security channel.** Gate
   violations should show up as a failing CI check on the PR, not as a Slack
   message to a security team. The person who made the change is the person who
   should fix it.

5. **Tune risk thresholds if needed.** The default scoring (≥50 = CRITICAL, ≥20
   = MEDIUM) works well for most orgs. If you're getting too many MEDIUM alerts,
   raise the threshold to 40. The 495-point gap between legitimate (−30) and
   attack (+465) means you have a wide tuning range.

---

## 5. State Poisoning: No Integrity Protection

The state file is a plain JSON file on disk. If an attacker can modify it, they
can pre-seed it with malicious SHAs as the "known good" baseline.

### Recommendations

1. **Use the lockfile, not the state file, as your source of truth.** The
   lockfile (`.github/actions-lock.json`) is committed to the repo and protected
   by Git's content-addressable storage + branch protection. The state file
   (`.pinpoint-state.json`) is only for the `watch` command's polling state.

2. **Protect the lockfile with branch protection.** Require PR review for changes
   to `.github/actions-lock.json`. The gate reads the lockfile from the base
   branch on PRs (not the PR branch), so an attacker can't poison it via a PR.
   This is already implemented and verified in Attack 8 of the battery.

3. **Use the lockfile workflow to manage updates.** Don't hand-edit the lockfile.
   `pinpoint lock` regenerates it, creates a PR, and a human reviews the SHA
   changes before merging. This creates an audit trail.

4. **For `watch` mode:** Store the state file outside the repo — on a dedicated
   volume, in an S3 bucket, or in a database. Don't put it in the Actions cache
   where other workflow steps can modify it.

5. **Not yet implemented but planned:** HMAC signing of the state file, and a
   `--verify-state` flag that checks the state file's integrity before using it.

---

## 6. Actions Cache Is Unreliable for State Persistence

GitHub's Actions cache evicts entries not accessed within 7 days. If `pinpoint
watch` doesn't run for a week, the state file is lost. When pinpoint starts
fresh, every tag looks new. If a tag was repointed during the gap, the malicious
SHA becomes the new "known good."

### Recommendations

1. **Don't use the Actions cache for pinpoint state.** This is a foot-gun.
   Instead:
   - **Commit the state file to the repo** (creates git history noise but is
     durable and auditable).
   - **Use workflow artifacts** (no 7-day eviction, but have retention limits).
   - **Store externally** (S3, GCS, a database) for production deployments.

2. **Run `pinpoint watch` on a dedicated VM, not in Actions.** The VPS
   deployment pattern (systemd timer or cron) has a persistent filesystem. No
   cache eviction. No state loss.

3. **Use the lockfile as the primary defense, not the state file.** The lockfile
   is in the repo and can't be evicted. `pinpoint gate` reads the lockfile, not
   the state file. The state file is only needed for `pinpoint watch` continuous
   monitoring — it's the secondary defense.

4. **If you must use Actions cache:** Schedule `pinpoint watch` to run at least
   every 3 days (well within the 7-day eviction window). Use a `schedule` trigger,
   not just `push` — repos with infrequent pushes will lose their cache otherwise.

---

## 7. The Gate: Prevention With Its Own Limitations

The gate runs as the first step in every workflow job. It fetches workflows,
extracts `uses:` directives, resolves SHAs, and compares against the lockfile.
If a tag has been repointed, the job aborts before untrusted code executes.

### 7a. The gate itself must be SHA-pinned

If you reference the gate as `@v1`, an attacker who compromises pinpoint can
ship a gate that suppresses its own alerts.

**Recommendation:** Pin the shared workflow reference to a SHA:
```yaml
uses: org/shared-workflows/.github/workflows/pinpoint-gate.yml@<SHA>
```
When the shared workflow changes, update the SHA across all repos. Automate this
with a script (we use `/tmp/update-all-repos.sh` pattern). Yes, this is manual
SHA management for one reference — but it's one reference vs. hundreds of
unpinned action references.

### 7b. TOCTOU race condition

The runner downloads action code before the job starts. The gate verifies
during the job. There is a time window between download and verification.

**Recommendation:** Use `pinpoint gate --on-disk`. This hashes the actual
downloaded files at `_actions/{owner}/{repo}/{ref}/` and compares against
`disk_integrity` in the lockfile. Even if a tag was repointed between download
and verification, on-disk verification catches it if the content doesn't match.
Cost: ~28ms, zero API calls.

### 7c. Stale manifest = blind gate

The lockfile is only as fresh as the last `pinpoint lock`. If nobody regenerates
it, legitimate tag advances cause false positives, and operators learn to ignore
gate failures.

**Recommendation:** Automate lockfile regeneration:
```yaml
# pinpoint-lock.yml — runs on workflow changes + weekly
on:
  push:
    paths: ['.github/workflows/**']
  schedule:
    - cron: "0 9 * * 1"  # Weekly Monday 9am
```
This is already deployed across all 28 test org repos. The workflow runs
`pinpoint lock`, creates a PR if the lockfile changed, and a human reviews
the SHA changes before merging.

### 7d. Fork PR manifest poisoning

An attacker submits a PR that modifies the lockfile. If the gate reads the
lockfile from the PR branch, the attacker controls what's "known good."

**Recommendation:** Already handled. The gate detects `pull_request` events
via `GITHUB_EVENT_NAME` and reads the lockfile from `GITHUB_BASE_REF` (the
target branch), not the PR branch. Verified in Attack 8 of the battery.

---

## 8. Adversarial Evasion Is Straightforward

Once tag monitoring becomes common, attackers will adapt:

**a) Timing attacks:** Repoint → wait for CI → revert within the poll interval.

**b) Gradual rotation:** Repoint one tag per day. Each event scores low.

**c) Tag-delete-recreate:** Delete the tag and create a new one with the same
name. May register as "new tag" rather than "repointed tag."

**d) Legitimate-looking commits:** Merge a PR with malicious code mixed into
legitimate changes, then advance the tag. Ancestry check says "descendant."
Size change is minimal.

**e) Compromise the monitoring tool:** If pinpoint is a GitHub Action,
compromise pinpoint itself.

### Recommendations

1. **For (a) timing attacks:** The gate eliminates this for CI runs. Every
   run verifies at execution time. The monitor alone doesn't catch sub-interval
   revert-after-use attacks — accept this limitation and ensure every workflow
   has the gate.

2. **For (b) gradual rotation:** Set up `pinpoint watch` with alerting on ANY
   tag movement, not just high-severity. Review all tag changes weekly. Use
   `pinpoint scan --json` to build dashboards that track tag movement frequency
   per action. A pattern of daily single-tag movements is anomalous and should
   trigger investigation.

3. **For (c) tag-delete-recreate:** Pinpoint tracks this — a deleted tag
   followed by a recreated tag with a different SHA generates a change event.
   The risk score may be lower than a direct repoint, so set your alert
   threshold accordingly. `--fail-on-missing` also catches this if the new tag
   doesn't match the lockfile entry.

4. **For (d) legitimate-looking commits:** This is the hardest to detect
   automatically. Pinpoint's `SIZE_ANOMALY` signal catches payload injections
   that significantly change file size. For subtle injections: pair pinpoint
   with code review requirements on action repos you control. For third-party
   actions, this is fundamentally unsolvable without reading every line of code
   in every dependency.

5. **For (e) compromising pinpoint:** Pin the gate to a SHA. Run the gate from
   a reusable workflow in a separate, tightly-controlled repo with branch
   protection and required reviews. Limit who has write access to that repo to
   1-2 security team members.

**Honest assessment:** Pinpoint raises the bar significantly for casual and
opportunistic attacks (Trivy, tj-actions). It does not meaningfully defend
against a patient, targeted adversary who understands the tool. Neither does
any other monitoring tool.

---

## 9. Bootstrapping Problem: No Historical Verification

If you deploy pinpoint today, it records current SHAs as the baseline. It
cannot tell you whether those SHAs were already compromised last week.

### Recommendations

1. **Run `pinpoint verify` before generating your first lockfile.** The verify
   command performs four retroactive checks without needing a prior baseline:
   - Release SHA match — does the tag point to the same commit as the Release?
   - GPG signature continuity — did signing suddenly stop?
   - Chronology check — is the commit backdated?
   - Advisory database lookup — is this a known-compromised version?

   This doesn't guarantee cleanliness, but it surfaces the most common
   indicators of compromise.

2. **Cross-reference against known-good sources.** Before trusting your lockfile,
   spot-check critical actions: visit the GitHub Releases page, verify the SHA
   matches the release, check the commit author is a known maintainer. Do this
   for your top 5-10 most sensitive dependencies.

3. **Generate your lockfile during a known-clean period.** Don't generate it
   during or immediately after an incident. Generate it when you have confidence
   that the actions you depend on are not currently compromised.

4. **Not yet implemented but planned:** A community-curated dataset of known-good
   tag→SHA mappings for popular actions, and integration with Sigstore
   transparency logs. These would automate the cross-referencing.

---

## 10. The Meta-Problem: You're Adding a Dependency

Pinpoint is a new piece of software in your CI/CD pipeline. It has bugs, it
will have CVEs, and it can crash, hang, or produce wrong results.

### Recommendations

1. **Deploy in `--warn` mode initially.** This lets pinpoint log violations
   without blocking builds. If pinpoint itself has a bug that causes false
   positives, your pipeline isn't broken — you just see warnings.

2. **Set a timeout on the gate step.**
   ```yaml
   - name: Pinpoint Gate
     timeout-minutes: 2
     uses: ...
   ```
   If pinpoint hangs (e.g., API timeout), the step fails after 2 minutes and
   your pipeline continues. This prevents pinpoint from becoming a single point
   of failure.

3. **Monitor pinpoint's own health.** In `watch` mode, pinpoint should emit
   metrics: poll latency, API rate limit consumption, error rate, state file
   size. Export these to your observability stack. If pinpoint stops polling,
   you should know.

4. **Keep pinpoint itself updated.** Pin the shared workflow to a SHA, but
   update it regularly. When a new version ships, update the SHA, regenerate
   lockfiles, and verify the gate passes clean. The test org update process
   (update shared workflow → update 28 repo SHA pins → regen lockfiles → merge)
   takes about 10 minutes with the automation scripts.

5. **Pin pinpoint's own dependencies.** Pinpoint has one dependency
   (`gopkg.in/yaml.v3`). The binary is statically compiled. There is no
   transitive dependency tree to worry about. This is intentional.

---

## Summary: What Pinpoint Is and Isn't

**Pinpoint is:**
- A meaningful improvement over the status quo (which is nothing)
- Effective against the class of attacks we've actually seen (Trivy, tj-actions)
- Both detection (monitor) AND prevention (gate) in a single binary
- The first tool to verify Docker image digests in GitHub Actions
- Low-cost, self-hostable, and honest about its threat model
- Content integrity verification (SHA-256 tarball hashes + on-disk tree hashing)
- Transitive dependency resolution for composite actions
- 10/10 on a comprehensive attack battery including lockfile poisoning,
  typosquats, SHA swaps, Docker image repointing, and new malicious workflows
- Suitable for monitoring 2,000+ repos with active gate enforcement

**Pinpoint is not:**
- A substitute for SHA pinning (prevention > detection, always)
- Effective against patient, targeted adversaries who understand polling gaps
- A guarantee that you'll catch every supply chain attack
- A replacement for code review of action source code

**The right deployment:**
1. `pinpoint gate` (enforced) on every CI workflow — blocks known attacks
2. `pinpoint gate --integrity` on a daily schedule — catches Docker image repointing
3. `pinpoint watch` on a dedicated VM — continuous monitoring + alerting
4. `pinpoint audit --org` quarterly — org-wide posture assessment
5. `pinpoint verify` on first deployment — retroactive integrity check

---

## 11. Docker Verification Limitations

Pinpoint v0.7.0 adds Docker image digest verification — the first tool in the
space to do this. But it has real limitations:

### 11a. Registry Authentication

Anonymous pulls from Docker Hub are rate-limited (100 pulls/6hr per IP). For
orgs with many Docker actions, the integrity check may hit rate limits.

**Recommendation:** Digest resolution uses HEAD requests (manifest only, not
full image pulls), which are lighter weight. For Docker Hub, authenticate with
a service account to get 200 pulls/6hr. For ghcr.io, use the same GitHub App
token. For private registries, configure registry credentials via environment
variables or a Docker config file.

### 11b. Multi-Architecture Images

Multi-arch images use manifest lists. Pinpoint captures the manifest list
digest. An attacker who replaces only the linux/amd64 image within a manifest
list while keeping the list digest unchanged would bypass detection.

**Recommendation:** This is an extremely sophisticated attack requiring write
access to the registry and knowledge of the manifest list structure. For
critical actions, verify individual platform digests by running `pinpoint gate
--integrity` on runners of each architecture. Not yet implemented as an
automatic check — tracked for a future spec.

### 11c. Only --integrity Mode

Docker digest verification only runs with `--integrity`. The default SHA-only
gate does not re-resolve Docker digests from registries.

**Recommendation:** Run two gate checks:
- `pinpoint gate --all-workflows --fail-on-missing` on every CI run (fast, <2s)
- `pinpoint gate --all-workflows --fail-on-missing --integrity` on a daily
  schedule via `workflow_dispatch` + `schedule` trigger

The daily integrity check catches Docker image repointing. The per-run SHA
check catches everything else. Combined, they cover all 11 attack vectors.

### 11d. Dockerfile Build Args

Dockerfile actions using `ARG` before `FROM` have parameterized base images.
Pinpoint captures the literal `FROM` value, which may contain unresolved args.

**Recommendation:** Avoid Docker actions that parameterize their base image
with build args. If you must use one, manually verify the base image digest
and add it to the lockfile. Pinpoint logs a warning when it encounters this
pattern.

### 11e. Private Registries

Actions pulling from private registries (ECR, Artifactory, etc.) may fail
digest resolution if pinpoint doesn't have credentials.

**Recommendation:** Pinpoint gracefully degrades — a missing digest means no
digest verification, but all other checks (SHA, integrity, on-disk) still run.
For private registries, mount Docker credentials (e.g., `~/.docker/config.json`)
in the environment where `pinpoint lock` runs. The registry client uses
standard Docker credential helpers.

## 12. Behavioral Anomaly Signal Limitations (Spec 025)

### 12a. Compromised Maintainer Bypass

CONTRIBUTOR_ANOMALY (+35) fires when new contributors appear in a release.
But if the attacker IS a known maintainer (as in the tj-actions attack where
a maintainer account was compromised), their commits won't trigger this signal.
The contributor is already in the `known_contributors` set.

**Recommendation:** CONTRIBUTOR_ANOMALY catches new/unknown accounts, not
insider threats. Layer it with DIFF_ANOMALY and RELEASE_CADENCE_ANOMALY —
even a known maintainer pushing suspicious files at unusual times will
trigger composite scoring. The three signals together are designed to catch
attacks that no single signal would flag.

### 12b. action.yml False Positives

DIFF_ANOMALY classifies all `action.yml` modifications as suspicious because
determining what changed within the file (description vs runs.main) would
require fetching and diffing content — an additional API call per detection.
Actions that frequently update their action.yml metadata will generate noise.

**Recommendation:** Suppress with allow rules for specific repos where
action.yml churn is expected. A `diff_ignore` config option is planned but
not yet implemented.

### 12c. Baseline Requirement

All three behavioral signals require historical data in the lockfile:
- CONTRIBUTOR_ANOMALY needs `known_contributors` (populated after first lock)
- RELEASE_CADENCE_ANOMALY needs `release_history` with ≥3 entries
- DIFF_ANOMALY needs a previous SHA to compare against

The first `pinpoint lock` after upgrading captures the initial baseline but
cannot detect anomalies until the second tag movement. There is no retroactive
population from git history.

**Recommendation:** Run `pinpoint lock` immediately after upgrading to v0.7+.
The behavioral signals activate automatically as tag movements are observed.
For critical actions, manually review the first release after baseline
establishment.

### 12d. High-Cadence Exclusion

RELEASE_CADENCE_ANOMALY excludes projects with mean release intervals under
7 days. This prevents false positives on actively developed projects but
also means attackers targeting high-cadence projects (nightly release actions,
CI tooling) won't trigger cadence anomalies.

**Recommendation:** High-cadence projects are partially protected by the
other two behavioral signals. CONTRIBUTOR_ANOMALY and DIFF_ANOMALY operate
independently of release cadence.
