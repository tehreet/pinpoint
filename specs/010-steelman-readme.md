# Spec 010: STEELMAN.md Update + Real README

## STEELMAN.md Updates

The current STEELMAN.md was written before the gate existed. Several sections
are now partially or fully wrong. Update these sections:

### Section 7: "It Detects But Doesn't Prevent"

**Current:** Says pinpoint only detects, can't prevent. Suggests a pre-job
verification action as future work.

**Update:** The gate (`pinpoint gate`) now exists. Rewrite to acknowledge
that prevention is implemented, but document the gate's own limitations:
- Gate itself must be SHA-pinned (chicken-and-egg)
- TOCTOU race between runner download and gate verification
- Manifest must be kept fresh (stale manifest = blind gate)
- Fork PR manifest poisoning is mitigated but depends on correct env vars

### Section 2a: API Rate Limits

**Current:** Only discusses REST API costs.

**Update:** Add GraphQL numbers. 50 repos per query, 1 point per batch.
2,000 repos = 40 points. The scale story is dramatically better now.
Keep the REST numbers for context but note GraphQL is the default.

### Section 2b: Annotated Tag Dereferencing

**Current:** Says dereferencing multiplies API calls.

**Update:** GraphQL auto-dereferences via `... on Tag { target { oid } }`.
No second API call needed. This problem is solved for the GraphQL path.
REST fallback still has this issue — note that.

### Add New Section: Gate Limitations

Add a new section between 7 and 8 documenting gate-specific limitations:
- Manifest poisoning via fork PR (mitigated but requires GITHUB_EVENT_NAME)
- Transitive dependency attacks (not covered)
- Dynamic action references (not parseable)
- Self-hosted runner binary verification (future: hash on-disk actions)

### Section 10: "The Meta-Problem"

**Current:** Says pinpoint is "an MVP suitable for monitoring 10-50 critical actions."

**Update:** With the gate, audit, GraphQL poller, and 72 tests, it's more than
an MVP. Revise to say it's suitable for monitoring 200+ actions with the gate
providing active prevention. The enterprise gaps are tiered polling, SQLite,
and multi-token — not fundamental architecture issues.

## README.md Rewrite

Replace the current README with a real one. Structure:

```markdown
# Pinpoint

GitHub Actions tag integrity monitor. Detects and prevents supply chain
attacks that repoint action version tags to malicious commits.

Built in response to the [Trivy supply chain attack](link) of March 2026.

## The Problem

(3-4 sentences: tags are mutable, 95% of ecosystem uses tags not SHAs,
attackers exploit this. Trivy: 75 tags repointed, credential stealer.)

## What Pinpoint Does

(Detection: monitors tag→SHA mappings, alerts on changes)
(Prevention: gate verifies all actions against manifest before execution)

## Quick Start

### Install

    go install github.com/tehreet/pinpoint/cmd/pinpoint@latest

Or download from [releases](link).

### Discover Your Actions

    pinpoint discover --workflows .github/workflows/

### Generate a Manifest

    export GITHUB_TOKEN=ghp_...
    pinpoint audit --org your-org --output manifest > .pinpoint-manifest.json

### Add the Gate to Your Workflow

    steps:
      - uses: tehreet/pinpoint@COMMIT_SHA
        with:
          manifest: .pinpoint-manifest.json
      
      - uses: actions/checkout@v4
      # ... your steps

### Continuous Monitoring

    pinpoint watch --config .pinpoint.yml --interval 5m

## Commands

| Command | Description |
|---------|-------------|
| `pinpoint scan` | One-shot scan, detect tag changes |
| `pinpoint watch` | Continuous monitoring on interval |
| `pinpoint discover` | Find actions in local workflow files |
| `pinpoint audit --org <n>` | Org-wide security posture scan |
| `pinpoint gate` | Pre-execution integrity verification |
| `pinpoint manifest refresh` | Update manifest with current SHAs |
| `pinpoint manifest verify` | Check manifest against live tags |
| `pinpoint manifest init` | Bootstrap manifest + workflows |

## Gate: How It Works

(4-5 sentences: runs as first step, fetches workflow + manifest from API,
resolves tags via GraphQL, compares SHAs, aborts if mismatch. 3 API calls,
<2 seconds.)

## Audit: Org-Wide Visibility

(3-4 sentences: one command, scans all repos, discovers all action deps,
checks immutable releases, reports pinning status. Show the StepSecurity
example output briefly.)

## Risk Scoring

| Signal | Description | Score |
|--------|-------------|-------|
| MASS_REPOINT | >5 tags repointed at once | +100 |
| OFF_BRANCH | New commit not a descendant | +80 |
| SIZE_ANOMALY | Entry point size changed >50% | +60 |
| SEMVER_REPOINT | Exact version tag moved | +50 |
| BACKDATED_COMMIT | Commit date >30 days old | +40 |
| NO_RELEASE | No GitHub Release | +20 |
| SELF_HOSTED | Self-hosted runners affected | +15 |

## Scale

| Metric | Value |
|--------|-------|
| 142 repos, 7,736 tags | 3 GraphQL points, 34 seconds |
| 277 repos (StepSecurity org) | 6 points, <2 minutes |
| Gate per CI run | 2 REST + 1 GraphQL, <2 seconds |

## Configuration

(Show example .pinpoint.yml with actions and allow-list)

## SARIF Integration

(Show workflow snippet for uploading to GitHub Security tab)

## Limitations

See [STEELMAN.md](STEELMAN.md) for an honest assessment of what pinpoint
can and cannot do.

## License

GPL-3.0. Supply chain security monitoring should be free.
```

## Implementation

This spec is different from the others — it's documentation, not code.
Claude Code should:

1. Rewrite `STEELMAN.md` with the updates described above. Keep the
   same brutally honest tone. Don't soften it. Just correct the facts.

2. Rewrite `README.md` following the structure above. Keep it concise.
   Use the real numbers from our testing (142 repos, 7736 tags, etc.).
   Include actual CLI examples that work. Reference the current SHA
   of the repo for the gate example.

3. Update `PRODUCT.md` to mark completed items:
   - v0.1: all done (was already marked)
   - v0.2: mark GraphQL poller, audit command, manifest generation as done
   - v0.3: mark gate, manifest refresh/verify, SARIF output as done
   - Update any items that have been superseded

## Files to Modify

- MODIFY: `STEELMAN.md`
- MODIFY: `README.md`
- MODIFY: `PRODUCT.md`
