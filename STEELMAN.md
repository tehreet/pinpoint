# STEELMAN.md — Honest Limitations of Pinpoint

Every tool has failure modes. This document is a brutally honest assessment of
where pinpoint breaks, doesn't scale, can be evaded, or creates new problems.
If you're evaluating pinpoint for your organization, read this first.

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

**Mitigation:** For repos you *do* own (internal actions), supplement polling
with webhook-based detection. For third-party repos, this gap is the cost of
not having SHA pinning. Pinpoint reduces the window from "forever" to "polling
interval" — that's real value, but it's not zero.

---

## 2. Scale: 2,000 Repos Will Hit You in Three Places

### 2a. API Rate Limits

GitHub's authenticated rate limit is 5,000 requests/hour. The `matching-refs`
bulk endpoint returns all tags for a repo in one paginated call, so the
baseline cost is 1 API call per repo per poll cycle. At 2,000 repos with a
5-minute interval:

    2,000 repos × 12 polls/hour = 24,000 requests/hour

That's 5x the rate limit. **Pinpoint cannot poll 2,000 repos every 5 minutes
with a single token.**

ETag caching helps: repos where nothing has changed return `304 Not Modified`
and don't count against the rate limit. In practice, the vast majority of
repos won't change between polls. But the *first* baseline scan (before you
have any ETags) hits all 2,000 repos, and any repos with active releases will
invalidate their ETags regularly.

**Real math for CoreWeave:**
- 2,000 repos, 5-min interval, single PAT: broken.
- 2,000 repos, 5-min interval, GitHub App installation token (15K/hour on
  Enterprise): feasible but tight, leaves no headroom for enrichment calls.
- 2,000 repos, staggered (200 repos per minute, full cycle every 10 min):
  works, but detection latency is 10 min not 5.
- Tiered polling: critical actions every 2 min, everything else every 30 min:
  the right answer, but not implemented yet.

### 2b. Annotated Tag Dereferencing Multiplies API Calls

The `matching-refs` endpoint returns the ref SHA. For annotated tags, this
points to a tag *object*, not the commit. Dereferencing requires a second API
call per annotated tag. A repo with 200 annotated tags costs 201 API calls,
not 1.

Many popular actions (actions/checkout, docker/build-push-action) use annotated
tags. At scale, this is the hidden multiplier that blows your rate budget.

**Mitigation needed:** Cache the tag-object-SHA → commit-SHA mapping. Tag
objects are immutable — once you've dereferenced a tag object SHA, the mapping
never changes. This is not implemented yet but would eliminate repeat
dereferencing entirely.

### 2c. State File Size

The JSON state file grows with every tracked tag and every change event.
2,000 repos × 50 tags average = 100,000 tag entries. With history arrays,
enrichment data, and ETags, this file could reach 50-100MB over months.

JSON marshaling/unmarshaling a 100MB file on every poll cycle is not
acceptable. The current implementation loads the entire file into memory and
writes it atomically on every save.

**Mitigation needed:** SQLite backend for the `watch` command. The JSON
file store is fine for <1,000 tags. Beyond that, switch to SQLite with indexed
lookups. This is explicitly in the Phase 2 roadmap but is not built yet.

---

## 3. The Token Is a High-Value Target

Pinpoint requires a `GITHUB_TOKEN` with read access to every repo it monitors.
For an org with 2,000 repos, that's a PAT or GitHub App token with broad read
scope. If pinpoint's runtime environment is compromised, that token is
exfiltrated.

Worse: if you run pinpoint as a GitHub Action (the lowest-friction deployment),
the `GITHUB_TOKEN` is available to the runner. A supply chain attack against
*any other action in the same workflow* could steal pinpoint's token.

You're concentrating monitoring capability behind a single credential that, if
stolen, gives an attacker a map of every action and tag you depend on — plus
the exact SHAs you consider "known good." That's an operational security gift
to an attacker.

**Mitigation:**
- Use a GitHub App with the minimum required permission (`contents: read`),
  not a PAT with broad scope.
- Run pinpoint in an isolated workflow with no other actions (besides
  SHA-pinned checkout).
- Rotate the token on a schedule.
- For maximum paranoia: run pinpoint outside of GitHub Actions entirely, on a
  dedicated VM/container with no other workloads.

---

## 4. False Positive Fatigue Will Kill Adoption

Major version tags (`v1`, `v2`, `v3`) are *designed* to be moved. Every time
`actions/checkout` releases a new patch version, the `v4` tag moves forward.
This is legitimate and expected.

At 2,000 repos, major version tag movements could generate dozens of
low-severity alerts per day. If operators learn to ignore pinpoint alerts
because they're always "just v4 moving forward," they'll also ignore the one
alert that matters.

The risk scoring tries to handle this (major version tag advancing to a
descendant commit = low severity), but the heuristics are not battle-tested.
Edge cases:

- A maintainer force-pushes a tag to fix a bad release → semver repoint alert
  fires → it's legitimate.
- A bot auto-bumps a tag as part of a release workflow → looks like a repoint
  from a "new contributor" because the bot account isn't in the maintainer list.
- A repo migrates from lightweight to annotated tags → every tag changes its
  ref-level SHA even though the commit SHA is identical.

**Mitigation needed:**
- Allow-listing known-good tag movements by actor (e.g., "github-actions[bot]
  is expected to move tags in this repo").
- Cooldown period: if a tag moves and a GitHub Release is created within 5
  minutes by the same actor, suppress the alert.
- Tuning mode: run for a week in observation-only mode to establish a baseline
  of normal tag movement patterns before enabling alerts.

None of this is implemented yet.

---

## 5. State Poisoning: No Integrity Protection

The state file is a plain JSON file on disk. If an attacker can modify it, they
can pre-seed it with malicious SHAs as the "known good" baseline. Pinpoint will
then compare future polls against the poisoned baseline and see no change.

In the GitHub Action deployment mode, the state file lives in the Actions cache
or as a workflow artifact. Both are writable by anyone with `actions: write`
permission on the repo. A compromised action earlier in the workflow could
silently modify the state file before pinpoint runs.

**Mitigation needed:**
- HMAC-sign the state file with a secret not available to other workflow steps.
- Store a hash of the state file outside the mutable environment (e.g., as a
  GitHub repository variable or in an external secret store).
- Support a "trust on first use" mode that alerts if the state file itself
  has been modified outside of pinpoint.

Not implemented.

---

## 6. Actions Cache Is Unreliable for State Persistence

In GitHub Action mode, state persists via the Actions cache. GitHub's cache has
a hard eviction policy: entries not accessed within 7 days are deleted. If your
pinpoint workflow doesn't run for a week (e.g., it's in a repo with infrequent
pushes and scheduled workflows are delayed), the cache is evicted.

When pinpoint starts with no state file, *every tag looks new*. It records
all current SHAs as the baseline. If a tag was repointed during the gap, the
malicious SHA becomes the new "known good."

This is a silent failure mode: no alert is generated, and the operator has no
indication that the baseline was re-established.

**Mitigation needed:**
- Use workflow artifacts instead of cache (artifacts don't have the 7-day
  eviction policy, but have their own retention limits).
- Commit the state file to the repo itself (creates noise in git history but
  is durable).
- Support an external state store (S3, GCS, a database) for production
  deployments.
- On state file recreation, log a prominent warning: "No previous state found.
  Establishing new baseline. Verification gap: [last known poll] to [now]."

The warning is not implemented. External state stores are Phase 3.

---

## 7. It Detects But Doesn't Prevent

Pinpoint tells you a tag moved. It does not stop your pipeline from running the
repointed code. By the time you read the Slack notification, open your laptop,
and figure out which workflows to disable, hundreds of pipeline runs may have
already executed the malicious action.

The `scan` command returns exit code 2 on detection, which lets you use it as a
CI gate — but only if you run pinpoint *before* every workflow that uses
third-party actions. This doubles your CI time and means every workflow depends
on pinpoint being available and fast.

**Mitigation needed:**
- A pre-job verification action that checks all subsequent actions against
  known-good SHAs and aborts the job before any untrusted code runs. This is
  the Phase 4 "fail-closed" mode. It's the most impactful feature pinpoint
  could have, and it doesn't exist yet.
- Webhook integration with GitHub's deployment protection rules to block
  deployments when a tag change is detected.
- Auto-PR to pin actions to SHAs when a repointing is detected (reactive, not
  preventive, but limits ongoing exposure).

---

## 8. Adversarial Evasion Is Straightforward

Once pinpoint (or any tag monitoring tool) becomes common, attackers will
adapt. The evasion techniques are not sophisticated:

**a) Timing attacks:** Repoint the tag, wait for the target org's CI to trigger
(e.g., right after a known cron job), revert the tag. If the revert happens
within the polling interval, pinpoint sees nothing. If the attacker can observe
the target's workflow run schedule (often visible in public repos), they can
time the window precisely.

**b) Gradual rotation:** Repoint one tag per day instead of 75 at once. Each
individual event scores low (single tag, possibly still a descendant). The
"mass repointing" signal never fires. After 60 days, all tags are compromised.

**c) Tag-delete-recreate:** Instead of force-pushing a tag (which is a ref
update), delete the tag and create a new one with the same name. Depending on
how pinpoint handles the delete+create sequence, this might register as a
"deleted tag" followed by a "new tag" rather than a "repointed tag" — and new
tags don't generate alerts because they're expected during releases.

**d) Legitimate-looking commits:** The attacker creates a commit on the default
branch (via a merged PR) that contains the malicious code mixed with legitimate
changes, then moves the tag forward to that commit. Pinpoint's ancestry check
shows the new commit is a descendant of the old one on the default branch. Size
changes are minimal if the payload is small. Every signal says "legitimate."

**e) Compromise the monitoring tool:** If pinpoint is distributed as a GitHub
Action, compromise pinpoint itself. A compromised pinpoint can suppress alerts
for other compromised actions.

**Honest assessment:** Pinpoint raises the bar significantly for casual and
opportunistic attacks (which is what Trivy and tj-actions were). It does not
meaningfully defend against a patient, targeted adversary. Neither does any
other monitoring tool. The only real defense against (d) and (e) is
comprehensive code review of every commit in every action you use — which is
impossible at scale.

---

## 9. Bootstrapping Problem: No Historical Verification

If you deploy pinpoint today, it records the *current* tag SHAs as the
baseline. It cannot tell you whether those SHAs are legitimate or whether a tag
was already repointed last week.

If you're already compromised when you start monitoring, pinpoint blesses the
malicious state as "known good."

**Mitigation needed:**
- A community-curated dataset of known-good tag→SHA mappings for popular
  actions. Pinpoint could cross-reference its initial baseline against this
  dataset and warn about discrepancies.
- Integration with the Sigstore transparency log to verify that recorded SHAs
  correspond to signed releases.
- A `verify` command that, given a repo, checks whether current tag SHAs match
  the GitHub Releases page and whether releases were created by expected
  maintainers.

The community dataset and verify command are not implemented.

---

## 10. The Meta-Problem: You're Adding a Dependency

Pinpoint is a new piece of software in your CI/CD pipeline. It has bugs. It
will have CVEs. It's a Go binary that makes HTTP requests, parses JSON, and
writes to disk — all things that can go wrong.

If pinpoint crashes, hangs, or produces false negatives, your security posture
silently degrades. If pinpoint produces false positives during an incident,
it creates noise that distracts from the real problem.

At CoreWeave's scale, the question isn't "does this tool work?" It's "what's
the operational cost of running, maintaining, debugging, and trusting this tool
across 2,000 repos, 24/7, with on-call coverage when it breaks?"

The honest answer: pinpoint as it exists today is an MVP suitable for
monitoring 10-50 critical actions. It is not ready for 2,000-repo enterprise
deployment without:

1. Tiered polling with configurable priority levels
2. SQLite or PostgreSQL state backend
3. Tag-object SHA caching to eliminate redundant dereferencing
4. Rate limit awareness with adaptive backoff
5. A tuning/learning period for false positive suppression
6. Monitoring of pinpoint itself (meta-monitoring / health checks)
7. Proper observability: metrics, structured logging, alerting on scan failures
8. Multi-token support (distribute API load across multiple credentials)

---

## Summary: What Pinpoint Is and Isn't

**Pinpoint is:**
- A meaningful improvement over the status quo (which is nothing)
- Effective against the class of attacks we've actually seen (Trivy, tj-actions)
- Low-cost, self-hostable, and honest about its threat model
- A Layer 2 detection tool that complements SHA pinning (Layer 1) and
  runtime EDR (Layer 3)

**Pinpoint is not:**
- A substitute for SHA pinning (prevention > detection, always)
- Effective against patient, targeted adversaries who understand polling gaps
- Ready for 2,000-repo enterprise deployment without significant additional
  engineering
- A guarantee that you'll catch every supply chain attack

**The right way to think about it:** Pinpoint is a smoke detector. It won't
stop an arsonist, but it'll wake you up before the house burns down. Most
houses don't have smoke detectors in the CI/CD room. That's the gap.
