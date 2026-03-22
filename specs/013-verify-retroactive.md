# Spec 013: pinpoint verify — Retroactive Integrity Check

## Summary

A command that checks whether your current action dependencies show signs
of tampering, WITHOUT requiring any prior baseline data. Works on day one.
Uses internal consistency signals that an attacker can't retroactively
clean up.

```bash
pinpoint verify --workflows .github/workflows/
```

No config file. No manifest. No prior scan history. One command, immediate
results.

## Why This Matters

The most common criticism of any monitoring tool is: "What about the time
before I installed it?" Pinpoint's scan and gate both require a known-good
baseline. If you're already compromised when you start, you bless the
malicious state as legitimate.

This command addresses that directly. It doesn't need a baseline because
it checks properties that are inherent to the commit and release metadata,
not relative to a prior observation.

## The Four Signals

### Signal 1: Release/Tag SHA Mismatch

When a maintainer creates a GitHub Release, GitHub stores the commit SHA
at the time of creation in the Release object's `tagCommit.oid` field.
This is a historical anchor. The attacker can move the tag, but they
cannot retroactively modify the Release object.

If the current tag SHA differs from the Release's recorded `tagCommit`,
the tag has been repointed since the Release was created.

**Verified API contract (2026-03-21):**

```graphql
repository(owner: "actions", name: "checkout") {
  releases(first: 5, orderBy: {field: CREATED_AT, direction: DESC}) {
    nodes {
      tagName
      tagCommit { oid }
      createdAt
    }
  }
  refs(refPrefix: "refs/tags/", first: 100) {
    nodes {
      name
      target { oid ... on Tag { target { oid } } }
    }
  }
}
```

Both release tagCommit and current tag refs in ONE query, 1 GraphQL point.
Batch 50 repos per query. Verified: actions/checkout v6.0.2 release
tagCommit matches current tag SHA.

**Pushback you'll have:** "This only works for tags that have Releases."
Correct. Major version tags like `v4` typically don't have their own
Release object. So this signal catches attacks on exact version tags
(v1.2.3) but not on major version tags (v4). In the Trivy attack, the
exact version tags (0.0.1 through 0.34.0) all had Releases, so this
signal would have caught 75 of 75 repointed tags retroactively.

**Pushback you'll have:** "The attacker could create a new Release for
the malicious commit." They could, but they can't delete or modify the
existing Release (especially with immutable releases enabled). So you'd
see TWO Releases for the same tag name, which is itself suspicious. And
creating a Release generates email notifications to watchers, audit log
entries, and RSS feed items, all of which increase detection probability.

### Signal 2: GPG Signature Discontinuity

Many action maintainers create releases via the GitHub web UI, which
automatically GPG-signs commits with GitHub's `web-flow` key. If a repo's
recent releases are all signed but the current tag commit is unsigned,
something changed.

**Verified API contract:**

```graphql
tagCommit {
  oid
  signature { isValid signer { login } }
}
```

Verified: actions/checkout, actions/setup-go, docker/build-push-action
all have `signature.isValid: true` on release commits.

**Pushback you'll have:** "Many legitimate actions don't GPG-sign."
True. This signal only fires when there's a DISCONTINUITY: prior releases
were signed, current commit is not. If an action has never signed, this
signal stays silent. It's not "unsigned = bad." It's "was signed, now
isn't = suspicious."

**Pushback you'll have:** "This has false positive risk if a maintainer
switches from web UI releases to CLI releases." Correct, and that's why
this is a WARNING signal, not a CRITICAL. The verify command should report
it but not treat it as definitive proof of compromise.

### Signal 3: Impossible Chronology

Git allows setting arbitrary author and committer dates. The Trivy attacker
used this to backdate commits to July 2024. But they can't fake the parent
commit's date (because the parent already existed). If a commit's authored
date is BEFORE its parent's committed date, someone forged the timestamps.

**Verified API contract:**

```graphql
tagCommit {
  authoredDate
  committedDate
  parents(first: 1) {
    nodes { oid committedDate }
  }
}
```

Verified live: legitimate commits always have authoredDate >= parent's
committedDate. Trivy attack commits had July 2024 dates with March 2026
parents.

**Pushback you'll have:** "An attacker could just use a correct date."
Yes. If the attacker doesn't backdate, this signal doesn't fire. But
backdating is common in attacks because it makes the commit look like it
was part of the original release history. The Trivy attacker did it. The
tj-actions attacker impersonated renovate[bot]'s commit style. Attackers
forge metadata because it works. This signal catches when they do.

**Pushback you'll have:** "Timezone weirdness could cause false positives."
Possible but unlikely. We compare authoredDate < parent committedDate,
and we'd need the dates to be inverted by MORE than timezone offset
(max 26 hours). Adding a tolerance of 48 hours eliminates timezone
false positives while still catching backdating by days/months.

### Signal 4: Known Compromised Versions

The GitHub Advisory Database tracks CVEs for GitHub Actions via the
`/advisories` REST endpoint with `ecosystem=actions`. We can check
whether any action you currently depend on has a known advisory.

**Verified API contract:**

```
GET /advisories?type=reviewed&ecosystem=actions&per_page=100
```

Returns advisories with `vulnerabilities[].package.name` matching
action repos. Verified: CVE-2025-30066 returns with
`package.name: "tj-actions/changed-files"`.

Additionally, we maintain a hardcoded list of known-bad commit SHAs from
major incidents (already exists in `internal/risk/score.go` as
`knownCompromised`). Cross-reference current tag SHAs against this list.

**Pushback you'll have:** "CVEs take days or weeks to be assigned."
True. The advisory database is a trailing indicator, not a leading one.
But it catches the case where you installed pinpoint a month after an
attack and are still running a version that was flagged. It's cleanup
detection, not real-time detection.

**Pushback you'll have:** "The hardcoded list goes stale." Yes. We ship
updates with each release. Not ideal, but it's better than nothing for
known-bad SHAs like `0e58ed8` (tj-actions).

## What This Does NOT Catch

Being honest here because someone will ask:

1. A perfectly crafted attack where the attacker creates a properly
   signed commit with correct chronology, no associated Release exists,
   and no CVE has been filed. This is a sophisticated, targeted attack.
   Nothing short of auditing the actual source code catches this.

2. Tags that have never had a Release object. If the action maintainer
   never creates Releases (just pushes tags), Signal 1 has nothing to
   compare against.

3. Attacks that happened and were REVERTED before you run verify. If
   the attacker moved the tag, stole credentials, and moved it back,
   the current state looks clean.

These limitations are real. The command catches the class of attacks we've
actually seen (Trivy, tj-actions, reviewdog), not theoretical perfect
attacks. That's still enormously valuable for day-one deployment.

## Output Format

```
pinpoint verify: checking 12 action dependencies...

✓ actions/checkout@v4
    Tag v4 → 34e1148... (no release for v4, checking v4.2.2 release)
    Release SHA matches current tag: ✓
    GPG signed (web-flow): ✓
    Chronology: ✓ (authored 2025-11-20, parent 2025-11-19)
    Advisories: none

✓ actions/setup-go@v5
    Release SHA matches: ✓
    GPG signed: ✓
    Chronology: ✓
    Advisories: none

⚠ some-org/custom-action@v2
    No releases found (cannot verify tag/release SHA match)
    Not GPG signed (no prior signed releases to compare)
    Chronology: ✓
    Advisories: none
    Note: limited verification possible without release history

✗ aquasecurity/trivy-action@0.20.0
    Release SHA: abc123... (recorded 2024-03-15)
    Current tag: def456... MISMATCH
    GPG signed: ✗ (prior releases were signed)
    Chronology: ✗ (commit dated 2024-07-09, parent dated 2026-03-19)
    Advisories: CVE-2026-XXXXX (if assigned)
    ⚠ MULTIPLE INTEGRITY SIGNALS FAILED — investigate immediately

Verification complete: 10 clean, 1 limited, 1 FAILED
```

**Exit codes:** 0 = all clean, 1 = error, 2 = integrity signals failed

## Smart Tag Resolution

For major version tags like `v4` that don't have their own Release, the
verify command should find the corresponding exact version Release. Logic:

1. Get the current SHA that `v4` points to
2. Look through releases for one whose `tagCommit.oid` matches that SHA
3. If found (e.g., `v4.2.2` release points to the same commit), use that
   release as the anchor
4. If no matching release found, report "limited verification"

This handles the common case where `v4` and `v4.2.2` point to the same
commit (which they should, if `v4` was advanced legitimately).

## API Cost

For each repo, we need releases + current tags. Both in one query.
Batch 50 repos per query at 1 point each.

For a typical workflow with 10 action dependencies: 1 GraphQL point.
For the advisory check: 1 REST call (paginated, covers all ecosystems).

Total: 2 API calls for a full verify of a standard project.

## Implementation

### CLI Interface

```
pinpoint verify [flags]
```

Flags:
- `--workflows <dir>` — scan workflows to discover actions (default: `.github/workflows/`)
- `--config <path>` — use existing pinpoint config for action list
- `--lockfile <path>` — use lockfile for action list (also compares SHAs)
- `--chronology-tolerance <duration>` — tolerance for date comparison
  (default: 48h, eliminates timezone false positives)
- `--output json|sarif` — machine-readable output

When `--lockfile` is provided, verify does BOTH the retroactive checks
AND the lockfile SHA comparison. This is the "belt and suspenders" mode.

### New file: `internal/verify/verify.go`

```go
package verify

type VerifyResult struct {
    Actions  []ActionVerification
    Clean    int
    Limited  int  // Couldn't fully verify (no releases, no signatures)
    Failed   int
}

type ActionVerification struct {
    Repo              string
    Tag               string
    CurrentSHA        string
    Status            string   // "clean", "limited", "failed"
    ReleaseSHAMatch   *bool    // nil if no release found
    ReleaseSHA        string   // from Release tagCommit
    GPGSigned         *bool    // nil if no prior signatures to compare
    GPGDiscontinuity  bool     // was signed, now isn't
    ChronologyValid   *bool    // nil if no parent
    AuthoredDate      string
    ParentDate        string
    Advisories        []string // CVE IDs
    Notes             []string // human-readable explanations
}

func Verify(ctx context.Context, repos []string, opts VerifyOptions) (*VerifyResult, error)
```

### New file: `internal/verify/verify_test.go`

Tests using mock GraphQL server:

- TestVerify_AllClean: 3 repos, all releases match, all signed, clean chronology
- TestVerify_ReleaseMismatch: tag SHA != release tagCommit SHA. Status: failed.
- TestVerify_GPGDiscontinuity: prior releases signed, current commit unsigned.
- TestVerify_ImpossibleChronology: authored date before parent committed date.
- TestVerify_NoReleases: repo has no releases. Status: limited.
- TestVerify_MajorTagResolution: v4 has no release, but v4.2.2 does and points to
  same SHA. Verify uses v4.2.2 release as anchor.
- TestVerify_KnownBadSHA: current tag matches a known compromised SHA.
- TestVerify_AdvisoryMatch: action has a CVE in the advisory database.
- TestVerify_ChronologyTolerance: date diff within 48h tolerance. Status: clean.
- TestVerify_CombinedSignals: release mismatch AND unsigned AND bad chronology.
  All three signals reported.

### Changes to `cmd/pinpoint/main.go`

Add `verify` as a top-level subcommand:

```go
case "verify":
    cmdVerify()
```

The verify command:
1. Discover actions from `--workflows` dir (reuse discover package)
2. Deduplicate by owner/repo
3. Build batched GraphQL query: releases + current tags per repo
4. Fetch advisories from REST API
5. For each action: run all 4 signal checks
6. Format and output results

### GraphQL Query Builder

```go
func buildVerifyQuery(aliasToRepo map[string]string) string {
    // For each repo, fetch:
    // - releases(first: 10) with tagCommit { oid, signature, authoredDate, parent }
    // - refs(refPrefix: "refs/tags/", first: 100) with target resolution
    // One query, 1 point per 50 repos
}
```

## Files to Create/Modify

- CREATE: `internal/verify/verify.go`
- CREATE: `internal/verify/verify_test.go`
- MODIFY: `cmd/pinpoint/main.go` — add `verify` subcommand

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
./pinpoint verify --help

# Live test
GITHUB_TOKEN=$(gh auth token) ./pinpoint verify --workflows .github/workflows/
```
