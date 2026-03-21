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

**Mitigation:** The gate (`pinpoint gate`) closes this gap for CI runs — it
verifies tags at execution time, not at poll time. For continuous monitoring,
supplement polling with webhook-based detection on repos you own. For
third-party repos, the polling gap is the cost of not having SHA pinning.

---

## 2. Scale: API Costs at 2,000 Repos

### 2a. API Rate Limits

**GraphQL (default):** Pinpoint batches 50 repos per GraphQL query at 1 point
per batch. Monitoring 2,000 repos costs 40 points per poll cycle. At 5-minute
intervals: 40 × 12 = 480 points/hour — under 10% of the 5,000 points/hour
GraphQL budget. This scales comfortably.

**REST (fallback):** The REST `matching-refs` endpoint costs 1 API call per
repo per poll. At 2,000 repos with a 5-minute interval:

    2,000 repos × 12 polls/hour = 24,000 requests/hour

That's 5x the 5,000/hour REST rate limit. REST fallback does not scale to
2,000 repos without tiered polling or multi-token support.

ETag caching helps the REST path: repos where nothing has changed return
`304 Not Modified` and don't count against the rate limit. In practice, >90%
of repos won't change between polls. But the first baseline scan hits all
repos, and ETag caching doesn't apply to GraphQL.

**Real math for 2,000 repos (GraphQL):**
- 2,000 repos, 5-min interval: 480 points/hour. No problem.
- 2,000 repos, 2-min interval: 1,200 points/hour. Still fine.
- Enrichment calls (compare, commit info, file size) are REST and add up.
  Budget for ~500 REST calls/hour for enrichment at scale.

### 2b. Annotated Tag Dereferencing

**GraphQL auto-dereferences annotated tags** via `... on Tag { target { oid } }`
in the query. No second API call needed. This problem is solved for the
GraphQL path.

**REST fallback still has this issue.** The `matching-refs` endpoint returns
the ref SHA for annotated tags, which points to a tag object, not the commit.
Dereferencing requires a second API call per annotated tag. A repo with 200
annotated tags costs 201 API calls, not 1. At scale on the REST path, this is
the hidden multiplier that blows your rate budget.

**Mitigation:** Use GraphQL (the default). REST fallback is for environments
where GraphQL is unavailable. Tag-object SHA caching (not yet implemented)
would eliminate repeat dereferencing on the REST path.

### 2c. State File Size

The JSON state file grows with every tracked tag and every change event.
2,000 repos × 50 tags average = 100,000 tag entries. With history arrays,
enrichment data, and ETags, this file could reach 50-100MB over months.

JSON marshaling/unmarshaling a 100MB file on every poll cycle is not
acceptable. The current implementation loads the entire file into memory and
writes it atomically on every save.

**Mitigation needed:** SQLite backend for the `watch` command. The JSON
file store is fine for <1,000 tags. Beyond that, switch to SQLite with indexed
lookups. This is explicitly in the roadmap but is not built yet.

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

The risk scoring handles the common cases (major version tag advancing to a
descendant commit = low severity), and allow-list rules can suppress known-good
patterns. But edge cases remain:

- A maintainer force-pushes a tag to fix a bad release → semver repoint alert
  fires → it's legitimate.
- A bot auto-bumps a tag as part of a release workflow → looks like a repoint
  from a "new contributor" because the bot account isn't in the maintainer list.
- A repo migrates from lightweight to annotated tags → every tag changes its
  ref-level SHA even though the commit SHA is identical.

**Current mitigations (implemented):**
- Allow-list rules with glob matching, actor filtering, and conditions
  (`major_tag_advance`, `descendant`, `release_within_5m`)
- Suppressed alerts are logged and counted but don't trigger CI failure

**Not yet implemented:**
- Cooldown period: if a tag moves and a GitHub Release is created within 5
  minutes by the same actor, auto-suppress.
- Tuning mode: run for a week in observation-only mode to establish a baseline
  of normal tag movement patterns before enabling alerts.

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

## 7. The Gate: Prevention Exists, With Its Own Limitations

The gate (`pinpoint gate`) runs as the first step in every workflow job. It
fetches the workflow file from the GitHub API, extracts all `uses:` directives,
resolves current tag SHAs via GraphQL, and compares them against the manifest.
If any tag has been repointed, the job aborts before any untrusted code
executes. This is real prevention, not just detection.

**But the gate has its own failure modes:**

**a) Chicken-and-egg: the gate itself must be SHA-pinned.** If you reference
the gate as `tehreet/pinpoint@v1`, an attacker who compromises pinpoint can
ship a gate that suppresses its own alerts. The gate step must be pinned to a
commit SHA. This means at least one action in every workflow requires manual
SHA management — the very thing pinpoint is supposed to avoid.

**b) TOCTOU race condition.** The Actions runner downloads action code *before*
the job starts. The gate verifies tags *during* the job. There is a time
window between runner download and gate verification where a tag could be
repointed. In practice this window is milliseconds to seconds, but it exists.
A fail-closed pre-download hook (not available in GitHub Actions today) would
eliminate this.

**c) Stale manifest = blind gate.** The manifest is only as fresh as the last
`pinpoint manifest refresh`. If nobody refreshes it, legitimate tag advances
will cause the gate to fail (false positives) or — worse — the gate will
verify against outdated SHAs while the real tags have moved to compromised
commits that happen to differ from the manifest. The gate catches this as a
mismatch, but operators may learn to ignore "stale manifest" failures.

**d) Fork PR manifest poisoning.** If an attacker submits a PR from a fork
that modifies `.pinpoint-manifest.json`, and the gate reads the manifest from
the PR branch, the attacker controls what the gate considers "known good." The
gate mitigates this by checking `GITHUB_EVENT_NAME` and `GITHUB_BASE_REF` to
detect PR contexts, but this depends on correct environment variable
propagation.

---

## 7a. Gate-Specific Limitations

Beyond the gate's core failure modes, several classes of attacks are not
covered:

**Transitive dependency attacks.** The gate verifies the direct `uses:`
references in your workflow. If `actions/checkout@v4` itself depends on
another action or npm package that is compromised, the gate won't catch it.
The gate operates at the action reference layer, not the dependency tree layer.

**Dynamic action references.** Workflow files can construct action references
dynamically using expressions: `uses: ${{ matrix.action }}@${{ matrix.version }}`.
These are not statically parseable. The gate skips them and logs a warning.

**Composite action internals.** A composite action can `uses:` other actions
internally. The gate only verifies top-level `uses:` directives in your
workflow file, not the transitive `uses:` inside composite actions.

**Self-hosted runner binary verification.** The gate verifies that tags point
to expected SHAs. It does not verify that the code actually downloaded to the
runner matches those SHAs. On self-hosted runners with persistent tool caches,
a previously compromised action binary could persist across runs. Future work:
hash the on-disk action directory and compare against the expected commit tree.

---

## 8. Adversarial Evasion Is Straightforward

Once pinpoint (or any tag monitoring tool) becomes common, attackers will
adapt. The evasion techniques are not sophisticated:

**a) Timing attacks:** Repoint the tag, wait for the target org's CI to trigger
(e.g., right after a known cron job), revert the tag. If the revert happens
within the polling interval, pinpoint's monitor sees nothing. The gate *does*
catch this if it runs during the job — but only if the gate is present.

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

**Where pinpoint stands today:** With the gate providing active prevention, the
audit providing org-wide visibility, GraphQL batching eliminating the API cost
wall, and 72+ tests covering the core paths, pinpoint is suitable for
monitoring 200+ actions with active gate enforcement. It is not an MVP anymore.

The remaining gaps for enterprise deployment at 2,000+ repos are engineering
tasks, not architectural limitations:

1. Tiered polling with configurable priority levels
2. SQLite or PostgreSQL state backend
3. Multi-token support (distribute API load across multiple credentials)
4. Monitoring of pinpoint itself (meta-monitoring / health checks)
5. Proper observability: metrics, structured logging, alerting on scan failures

These are solvable. The architecture supports them. They just aren't built yet.

---

## Summary: What Pinpoint Is and Isn't

**Pinpoint is:**
- A meaningful improvement over the status quo (which is nothing)
- Effective against the class of attacks we've actually seen (Trivy, tj-actions)
- Both detection (monitor) AND prevention (gate) in a single binary
- Low-cost, self-hostable, and honest about its threat model
- Suitable for monitoring 200+ actions with active gate enforcement

**Pinpoint is not:**
- A substitute for SHA pinning (prevention > detection, always)
- Effective against patient, targeted adversaries who understand polling gaps
- Coverage for transitive dependencies or composite action internals
- A guarantee that you'll catch every supply chain attack

**The right way to think about it:** Pinpoint is a smoke detector AND a
circuit breaker. The monitor catches smash-and-grab attacks. The gate stops
them from executing. Most CI/CD pipelines have neither. That's the gap.
