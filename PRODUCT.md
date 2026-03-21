# PRODUCT.md — The Complete Pinpoint Product Vision

How to build a free, open-source GitHub Actions supply chain security platform
that works for a solo developer and for an org with 2,000 repos.

---

## The Core Thesis

SHA pinning is the correct long-term answer. GitHub knows it — they shipped
org-level SHA pinning enforcement in August 2025 and immutable releases in
October 2025. But adoption is glacial because SHA pinning has terrible DX:
hashes are unreadable, updates require tooling, and version context is lost.

The industry is stuck in a transition period where:
- The RIGHT answer (SHA pinning) has <5% adoption
- The EASY answer (version tags) has >95% adoption and is fundamentally broken
- GitHub's NEW answer (immutable releases) only protects repos that opt in,
  and upstream action maintainers adopt slowly

Pinpoint owns the transition period. It makes tag-based references safe enough
to use while the ecosystem migrates to immutable releases and SHA pinning.
And it becomes the verification layer even after that migration completes.

---

## Architecture: Three Products, One Binary

Pinpoint is not one tool. It's three products that share a core engine:

### Product 1: pinpoint monitor (what we built today)
External observer. Polls GitHub API, tracks tag→SHA mappings, alerts on change.
This is the smoke detector. It runs outside your pipeline.

### Product 2: pinpoint gate
Inline verifier. Runs as the FIRST step in every workflow. Before any
third-party action executes, gate checks every `uses:` directive against a
known-good manifest. If any action's tag resolves to an unexpected SHA, the job
aborts. Exit code 1. Nothing runs.

This is the circuit breaker. It runs INSIDE your pipeline.

### Product 3: pinpoint audit
Org-wide scanner. Discovers every workflow across every repo in your org,
inventories every action reference, identifies unpinned tags, checks which
actions have immutable releases enabled, and generates a prioritized
remediation plan.

This is the security posture dashboard. It runs on-demand or on schedule.

All three ship as the same Go binary. Same config format. Same state store.

---

## Solving the 2,000-Repo Scale Problem

The rate limit math from STEELMAN.md: 2,000 repos × 12 polls/hour = 24,000
requests/hour, 5x over the 5,000/hr authenticated limit.

Here are five strategies that, combined, make this work:

### Strategy 1: Don't Monitor 2,000 Repos — Monitor 200 Actions

CoreWeave has 2,000 repos. Those repos don't use 2,000 different third-party
actions. They use maybe 50-200 unique actions. The `pinpoint audit` command
scans all 2,000 repos' workflows, deduplicates, and produces a list of unique
action+tag combinations.

You don't poll 2,000 repos. You poll the ~100 upstream repos where those
actions live. That's 100 × 12 = 1,200 requests/hour. Well within limits.

### Strategy 2: ETag Conditional Requests

GitHub's `matching-refs` endpoint supports ETags. An unchanged repo returns
304 Not Modified and costs ZERO rate limit. In practice, >90% of repos won't
change between polls. Your effective API cost is the ~10% that had activity.

100 repos × 10% active × 12 polls/hour = 120 requests/hour.

### Strategy 3: Tag-Object SHA Caching

Annotated tag dereferencing (the hidden API multiplier) is fully cacheable.
A tag object SHA maps to a commit SHA immutably — once you've resolved it,
store the mapping forever. On subsequent polls, if the ref SHA matches your
cache, skip the dereference call entirely. Only dereference when the ref SHA
changes (which is the event you're detecting anyway).

### Strategy 4: Tiered Polling

Not all actions need 5-minute monitoring:

```yaml
tiers:
  critical:     # Actions on self-hosted runners, actions with write perms
    interval: 2m
    actions:
      - repo: aquasecurity/trivy-action
        self_hosted_runners: true
      - repo: docker/build-push-action

  standard:     # Common actions from trusted publishers
    interval: 15m
    actions:
      - repo: actions/checkout
      - repo: actions/setup-go

  long_tail:    # Everything else discovered via audit
    interval: 1h
```

Critical actions (maybe 10-20): 12 polls × 30 = 360/hr
Standard actions (maybe 50): 4 polls × 50 = 200/hr
Long tail (maybe 100): 1 poll × 100 = 100/hr
Total: 660 requests/hour. Trivial.

### Strategy 5: GraphQL Batching

GitHub's GraphQL API lets you fetch multiple repos' refs in a single request.
A single GraphQL query can resolve tags for up to 50 repos at once:

```graphql
query {
  repo1: repository(owner: "actions", name: "checkout") {
    refs(refPrefix: "refs/tags/", first: 100) {
      nodes { name target { oid } }
    }
  }
  repo2: repository(owner: "docker", name: "build-push-action") {
    refs(refPrefix: "refs/tags/", first: 100) {
      nodes { name target { oid } }
    }
  }
  # ... up to 50 repos per query
}
```

GraphQL has a separate rate limit (5,000 points/hour, each query costs 1
point base + complexity). A well-structured query fetching 50 repos costs
~50 points. To monitor 200 repos: 4 queries × 12 polls/hour = 48 points/hour.
That's <1% of the GraphQL budget.

Documentation: https://docs.github.com/en/graphql/overview/rate-limits-and-node-limits-for-the-graphql-api

THIS IS THE KILLER SCALING MECHANISM. The REST API was the wrong choice for
scale. GraphQL lets you monitor 200 repos with <50 API calls per poll cycle.
Phase 2 should rewrite the poller core to use GraphQL with REST as fallback.

---

## Product 2: The Gate (Inline Pre-Job Verification)

This is the feature that turns pinpoint from "nice detection tool" into
"essential security infrastructure." Here's how it works:

### The Manifest

`pinpoint gate` maintains a `.pinpoint-manifest.json` — a lockfile-style
document that maps every action+tag used in your org to its verified SHA:

```json
{
  "version": 1,
  "generated_at": "2026-03-21T06:00:00Z",
  "actions": {
    "actions/checkout@v4": {
      "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
      "verified_at": "2026-03-21T06:00:00Z",
      "immutable_release": true
    },
    "aquasecurity/trivy-action@0.35.0": {
      "sha": "57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
      "verified_at": "2026-03-21T06:00:00Z",
      "immutable_release": false
    }
  }
}
```

### How Gate Works

The gate runs as a composite action — the FIRST step in every job:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tehreet/pinpoint-gate@v1  # SHA-pinned in practice
        with:
          manifest: .pinpoint-manifest.json
          mode: enforce  # or 'warn'
      # All subsequent actions are verified before this point
      - uses: actions/checkout@v4
      - uses: aquasecurity/trivy-action@0.35.0
```

The gate action:
1. Reads the workflow file that triggered the current run
2. Extracts all `uses:` directives
3. For each action+tag, resolves the current commit SHA via GitHub API
4. Compares against the manifest
5. If ANY mismatch: fails the job (enforce mode) or annotates (warn mode)

The job fails BEFORE any untrusted action executes. The attacker's code
never touches the runner. This is prevention, not detection.

### Manifest Generation

```bash
# Generate from your workflows
pinpoint audit --org coreweave --generate-manifest > .pinpoint-manifest.json

# Refresh: re-resolve all tags and update SHAs
pinpoint manifest refresh --manifest .pinpoint-manifest.json

# Verify: check that no tags have been repointed since last refresh
pinpoint manifest verify --manifest .pinpoint-manifest.json
```

### Why This Is Better Than SHA Pinning

SHA pinning replaces `actions/checkout@v4` with
`actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5`.
This is correct but has terrible DX:
- You can't read the version at a glance
- Every repo needs to update every workflow file
- Dependabot/Renovate churn is enormous across 2,000 repos
- Developers hate it

The pinpoint manifest gives you the security of SHA pinning WITHOUT
modifying any workflow files. Developers keep writing `@v4`. The gate
verifies at runtime that `v4` still maps to the expected SHA. If someone
repoints `v4`, the gate catches it and the job fails.

You get immutable verification with mutable syntax. Best of both worlds.

### Scaling Gate Across 2,000 Repos

The manifest is a single JSON file stored in a central repo (e.g.,
`coreweave/.github` or `coreweave/security-manifests`). The gate action
fetches it at runtime. One manifest, 2,000 repos, zero per-repo config.

To roll it out: org-level reusable workflow that includes the gate step.
All repos inherit it. One PR to the central workflow repo, instant coverage
across the entire org.

Documentation on reusable workflows:
https://docs.github.com/en/actions/sharing-automations/reusing-workflows

Documentation on org-level starter workflows:
https://docs.github.com/en/actions/sharing-automations/creating-starter-workflows-for-your-organization

---

## Product 3: The Audit (Org-Wide Security Posture)

### What It Does

```bash
pinpoint audit --org coreweave --token $GITHUB_TOKEN
```

Scans every repo in the org. For each repo:
1. Lists all workflow files via Contents API
2. Extracts all `uses:` directives
3. Classifies each reference: SHA-pinned, tag-pinned, branch-pinned
4. Checks if the upstream action has immutable releases enabled
5. Checks if the org has SHA pinning enforcement enabled
6. Checks if the repo has tag protection rulesets

Outputs:
- Org-wide stats: "1,847 action references across 412 repos. 23% SHA-pinned,
  71% tag-pinned, 6% branch-pinned (DANGEROUS)."
- Per-action risk assessment: "trivy-action: used in 87 repos, 0% pinned,
  no immutable releases, self-hosted runners in 12 repos → HIGH RISK"
- Prioritized remediation: "Pin these 5 actions first — they run on
  self-hosted runners and cover 60% of your attack surface"
- Manifest generation for the gate

### Scaling Audit to 2,000 Repos

The GitHub REST API endpoint `GET /orgs/{org}/repos` lists all repos (paginated,
100 per page = 20 API calls for 2,000 repos). For each repo, fetching workflow
files via `GET /repos/{owner}/{repo}/contents/.github/workflows` costs 1 call.

2,000 repos: 20 (list) + 2,000 (contents) = 2,020 API calls. This is a
one-time batch operation, not continuous polling. Runs in ~10 minutes with
rate limit awareness. Completely feasible.

With GraphQL, you can batch this further — fetch the workflow directory
contents for multiple repos in a single query.

Documentation:
https://docs.github.com/en/rest/repos/repos#list-organization-repositories
https://docs.github.com/en/rest/repos/contents

### Integration With GitHub's Native Security Features

Audit should also check and report on:

**SHA Pinning Enforcement Policy (shipped August 2025):**
GitHub orgs can now require all actions to be SHA-pinned. Audit checks if
this policy is enabled and reports compliance.
Documentation: https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/

**Immutable Releases (GA October 2025):**
Audit checks whether each upstream action repo has immutable releases enabled.
Actions with immutable releases have protected tags that can't be moved.
Documentation: https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#immutable-releases

**Repository Rulesets (Tag Protection):**
GitHub rulesets can protect tags from deletion and force-push. Audit checks
if upstream action repos have tag rulesets via the REST API.
Documentation: https://docs.github.com/en/rest/repos/rules

**Dependency Graph for Actions:**
GitHub's dependency graph already tracks actions. Audit should leverage this
rather than re-parsing workflow files where possible.
Documentation: https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exploring-the-dependencies-of-a-repository

---

## The Community Baseline: Solving the Bootstrap Problem

When you deploy pinpoint, it records current SHAs as "known good." If a tag
was already compromised, you've blessed the malicious state.

Solution: a **community-maintained transparency ledger** of tag→SHA mappings
for the most popular GitHub Actions.

### How It Works

1. Pinpoint ships with a built-in list of the top 500 GitHub Actions
2. A GitHub Action runs daily on the pinpoint repo, resolves all tags for
   these 500 actions, and commits the results to a public `baseline/` directory
3. The baseline includes: tag name, commit SHA, commit author, commit date,
   whether the release is immutable, whether the tag is protected
4. When you run `pinpoint monitor` or `pinpoint gate` for the first time,
   it cross-references your initial state against the community baseline
5. If your local resolution differs from the baseline: WARNING. Something
   is wrong — either you're seeing a CDN cache issue, or the tag was
   repointed between the baseline snapshot and your first poll

### Why This Is Safe

The baseline is a git repo. Every change is a commit with a diff. Anyone can
audit the history. If the baseline itself is compromised (someone pushes a
malicious SHA into the baseline), the git history shows it.

For extra paranoia: sign each baseline commit with a GPG key. Publish the
baseline to a Sigstore transparency log. The community can independently
verify that the baseline reflects reality by resolving tags themselves.

### Crowdsourced Verification

Any pinpoint user can contribute their observations:

```bash
pinpoint baseline contribute --token $GITHUB_TOKEN
```

This resolves all tags the user monitors, compares against the community
baseline, and submits a PR with any discrepancies. Multiple independent
observers seeing the same SHA = high confidence. One observer seeing a
different SHA = alert.

This is the same trust model as Certificate Transparency for TLS certificates.
Multiple independent monitors, public log, anyone can verify.

---

## The Lockfile: What GitHub Should Build (And We Should Propose)

GitHub acknowledged in their community discussion that they considered an
Actions lockfile concept:

> "I also like the idea of a lockfile, but it's something we haven't dug
> into as we were focused on [immutable actions]"
> — GitHub Actions team, community discussion #181437

Here's what a lockfile would look like — and pinpoint should generate it
as a proof of concept to push GitHub toward building it natively:

```yaml
# .github/actions-lock.yml
# Auto-generated by pinpoint. Do not edit manually.
# Verify: pinpoint manifest verify
version: 1
locked_at: "2026-03-21T06:00:00Z"
actions:
  actions/checkout:
    v4:
      sha: 34e114876b0b11c390a56381ad16ebd13914f8d5
      immutable: true
      attestation: "sigstore:rekor:uuid:xxx"
  aquasecurity/trivy-action:
    "0.35.0":
      sha: 57a97c7e7821a5776cebc9bb87c984fa69cba8f1
      immutable: false
      attestation: null
```

If GitHub built native lockfile support, the Actions runtime would
automatically verify tags against the lockfile before execution — no
gate action needed. Pinpoint's lockfile/manifest is the existence proof
that demonstrates the UX and drives adoption of the concept.

**We should open a GitHub Community Discussion proposing this.** Link to
pinpoint as the reference implementation. This is how open source shapes
platform roadmaps.

---

## Ways GitHub Can Make This Easier (Documented Feature Requests)

### 1. Tag Change Webhooks / Events

Currently, GitHub fires a `create` event for new tags but NOT for tag
repointing (force-push of existing tags). The `push` event includes a
`forced` flag but doesn't fire for >3 tags at once.

**Request:** A dedicated `tag.updated` webhook event that fires when an
existing tag's target changes, including the old and new SHAs. This would
eliminate the need for polling entirely.

Relevant docs:
https://docs.github.com/en/webhooks/webhook-events-and-payloads#create
(Note the documented limitation: "This event will not occur when more than
three tags are created at once.")

### 2. Bulk Tag Resolution API

The `matching-refs` endpoint returns tag refs but requires a separate call
to dereference annotated tags. A single endpoint that returns fully-resolved
tag→commit mappings (pre-dereferenced) would cut API calls dramatically.

### 3. Actions Dependency API

GitHub's dependency graph already knows which actions your repos use. An API
endpoint that returns "all unique action references across my org's repos"
would eliminate the need for pinpoint to parse workflow files itself.

Relevant: The dependency graph UI shows actions, but there's no dedicated
API for "list all actions used by this org."
https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exploring-the-dependencies-of-a-repository

### 4. Native Lockfile Support

As discussed above. GitHub should support `.github/actions-lock.yml` natively
in the Actions runtime, with automatic verification before action execution.

---

## SQLite State Backend

The JSON file store works for <1,000 tags. Beyond that, SQLite.

Schema:

```sql
CREATE TABLE actions (
    id INTEGER PRIMARY KEY,
    owner TEXT NOT NULL,
    repo TEXT NOT NULL,
    etag TEXT,
    last_poll DATETIME,
    UNIQUE(owner, repo)
);

CREATE TABLE tags (
    id INTEGER PRIMARY KEY,
    action_id INTEGER REFERENCES actions(id),
    name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    tag_sha TEXT,
    is_annotated BOOLEAN DEFAULT FALSE,
    first_seen DATETIME NOT NULL,
    last_verified DATETIME NOT NULL,
    UNIQUE(action_id, name)
);

CREATE TABLE changes (
    id INTEGER PRIMARY KEY,
    tag_id INTEGER REFERENCES tags(id),
    previous_sha TEXT NOT NULL,
    new_sha TEXT NOT NULL,
    detected_at DATETIME NOT NULL,
    severity TEXT,
    signals TEXT  -- JSON array
);

CREATE TABLE tag_object_cache (
    tag_object_sha TEXT PRIMARY KEY,
    commit_sha TEXT NOT NULL,
    cached_at DATETIME NOT NULL
);

-- Indexes for fast lookups
CREATE INDEX idx_tags_action ON tags(action_id);
CREATE INDEX idx_changes_tag ON changes(tag_id);
CREATE INDEX idx_changes_detected ON changes(detected_at);
```

Go has `database/sql` + `modernc.org/sqlite` for a pure-Go SQLite driver —
no CGo needed, single binary stays fully static.

---

## Observability and Meta-Monitoring

At scale, the monitor itself needs monitoring:

```
pinpoint_polls_total{repo="actions/checkout", status="ok|not_modified|error"}
pinpoint_tags_tracked{repo="actions/checkout"}
pinpoint_alerts_fired{severity="low|medium|critical"}
pinpoint_api_rate_remaining
pinpoint_poll_duration_seconds
pinpoint_state_size_bytes
```

Expose as Prometheus metrics on `/metrics`. Standard. Every Kubernetes-native
org (including CoreWeave) already has Prometheus/Grafana. Zero adoption
friction.

Add a `/healthz` endpoint for liveness probes when running as a service.

---

## Complete Feature Roadmap

### v0.1 (SHIPPED — what we built today)
- CLI: scan, watch, discover
- REST API poller with ETag caching
- Annotated tag dereferencing
- JSON state store
- Risk scoring (mass repoint, off-branch, semver, size, backdated, self-hosted)
- Stdout + Slack + webhook alerting
- GPL-3.0

### v0.2 — Scale
- GraphQL poller (batch 50 repos per query)
- Tag-object SHA cache (eliminate redundant dereferencing)
- Tiered polling (critical/standard/long-tail intervals)
- SQLite state backend
- `pinpoint audit` command (org-wide workflow scanning)
- Manifest generation (.pinpoint-manifest.json)
- False positive suppression (allow-lists for known bot accounts)
- HMAC-signed state files

### v0.3 — Gate
- `pinpoint gate` composite action (pre-job verification)
- Manifest verify/refresh commands
- Org-level reusable workflow template
- Warn mode and enforce mode
- Integration with GitHub deployment protection rules

### v0.4 — Community
- Community baseline ledger (top 500 actions, daily snapshots)
- `pinpoint baseline contribute` command
- Immutable release detection (flag actions with/without immutable releases)
- GitHub SHA pinning policy detection
- Tag ruleset detection
- SARIF output for GitHub Security tab integration
- Dependency graph integration

### v0.5 — Enterprise
- Prometheus metrics endpoint
- Health check endpoint
- GitHub App packaging (org-wide installation)
- Multi-token support (distribute API load)
- Auto-PR for SHA pinning on detected repointing
- SBOM integration (CycloneDX/SPDX → extract action refs)
- GitHub Community Discussion: propose native lockfile support
- Report generation: PDF/HTML org security posture report

### v1.0 — Production
- Reproducible builds (Sigstore-signed binaries)
- OCI container image (for Kubernetes deployment)
- Helm chart
- GitHub Actions Marketplace listing
- Comprehensive test suite (unit + integration + simulated attacks)
- Documentation site
- Conference talk: "How We Caught the Trivy Attack 5 Hours Earlier"

---

## What "Revolutionary" Looks Like

No one has built the full stack:

    audit (posture) → monitor (detection) → gate (prevention) → lockfile (native)

StepSecurity has pieces of it behind a paywall. Socket has pieces of it in a
different product. GitHub has pieces of it in nascent features. Nobody has
assembled the complete pipeline as a single, free, open-source tool.

Pinpoint does. One binary. Three commands. Zero cost. GPL-3.0.

The endgame is that GitHub builds native lockfile support into Actions,
making pinpoint's gate unnecessary. That's the best possible outcome. If our
tool works so well that GitHub absorbs its functionality into the platform,
we've won. The ecosystem is safer. The tool becomes unnecessary.

Until then: pinpoint.
