# Spec 017: GPG Signature Delta Signal

## Problem

In the March 2026 Trivy attack, all original trivy-action commits were GPG-signed
by GitHub's web-flow key (merged via the GitHub UI). The malicious replacements were
unsigned — the attacker had a valid PAT but couldn't forge GitHub's GPG signature.

Pinpoint currently ignores GPG signature status entirely. A new SIGNATURE_DROPPED
signal would catch this forensic indicator with near-zero false positives when used
as a delta (was signed, now isn't).

## Design

### New field in ScoreContext

```go
type ScoreContext struct {
    // ... existing fields ...
    WasGPGSigned    bool   // Was the commit GPG-signed at lock time?
    IsGPGSigned     bool   // Is the current commit GPG-signed?
    VerifiedSigner  string // e.g. "web-flow" — who signed the original
}
```

### New signal in risk/score.go

```go
// GPG signature was present at lock time but absent now
if ctx.WasGPGSigned && !ctx.IsGPGSigned {
    score += 45
    signals = append(signals, "SIGNATURE_DROPPED: commit was GPG-signed at lock time, replacement is unsigned")
}
```

Score: +45. Rationale: stronger than BACKDATED_COMMIT (+40) because it's harder
to legitimately explain, but weaker than SIZE_ANOMALY (+60) because some repos
legitimately have unsigned commits. Combined with other signals in an actual attack,
this pushes the total well into CRITICAL.

### Lockfile format change

Add `gpg_signed` field to the lockfile v2 entry:

```json
{
  "actions/checkout": {
    "v4": {
      "sha": "34e114876b...",
      "integrity": "sha256-...",
      "disk_integrity": "sha256-...",
      "gpg_signed": true,
      "gpg_signer": "web-flow",
      "type": "node20",
      "dependencies": []
    }
  }
}
```

Fields are optional — missing means "not recorded" (backward compat with existing
lockfiles). Only `gpg_signed: true` → `gpg_signed: false` triggers the signal.
A lockfile without the field never fires the signal.

### GitHub API data source

The commit object from `GET /repos/{owner}/{repo}/git/commits/{sha}` includes:

```json
{
  "verification": {
    "verified": true,
    "reason": "valid",
    "signature": "-----BEGIN PGP SIGNATURE-----...",
    "payload": "tree ..."
  }
}
```

Pinpoint already fetches commit metadata via the REST API in `poller/github.go`.
The `verification` field is included in the standard commit response — no additional
API call needed. Just read `commit.Verification.Verified` and
`commit.Committer.Login` (for signer identity).

### Where this fires

This signal is relevant in three commands:

1. **`pinpoint lock`** — record `gpg_signed` and `gpg_signer` when generating the lockfile.
2. **`pinpoint lock --verify`** — compare live commit's GPG status against recorded status.
   If `gpg_signed` went from true→false, report it.
3. **`pinpoint gate`** — same check as verify, but contributes to the risk score that
   determines pass/fail.
4. **`pinpoint scan`/`pinpoint watch`** — if state store has previous GPG status, compare.

### Implementation changes

**internal/poller/github.go** — ensure FetchTagInfo (or equivalent) returns GPG
verification status. The GitHub REST API commit object already includes this; just
parse it into the existing struct:

```go
type CommitInfo struct {
    SHA           string
    Date          time.Time
    Author        string
    Email         string
    GPGVerified   bool   // NEW
    GPGSigner     string // NEW — committer login when verified
    // ... existing fields
}
```

**internal/manifest/manifest.go** — add `GPGSigned` and `GPGSigner` to the
`TagEntry` struct. Populate during `pinpoint lock`. Read during verify/gate.

```go
type TagEntry struct {
    SHA           string            `json:"sha"`
    Integrity     string            `json:"integrity,omitempty"`
    DiskIntegrity string            `json:"disk_integrity,omitempty"`
    GPGSigned     *bool             `json:"gpg_signed,omitempty"`  // pointer for omitempty
    GPGSigner     string            `json:"gpg_signer,omitempty"`
    RecordedAt    string            `json:"recorded_at,omitempty"`
    Type          string            `json:"type,omitempty"`
    Dependencies  []DependencyEntry `json:"dependencies,omitempty"`
}
```

**internal/risk/score.go** — add the SIGNATURE_DROPPED signal as shown above.

**internal/gate/gate.go** — populate ScoreContext.WasGPGSigned from lockfile,
ScoreContext.IsGPGSigned from live API response.

## Tests

### Unit tests in risk/score_test.go

- TestSignatureDropped — WasGPGSigned=true, IsGPGSigned=false → +45, signal present
- TestSignatureStillSigned — both true → no signal
- TestSignatureNeverSigned — both false → no signal
- TestSignatureLockfileNoData — WasGPGSigned=false (no data in lockfile) → no signal
- TestSignatureDroppedWithMassRepoint — combined score exceeds CRITICAL threshold
- TestSignatureDroppedTriviReplay — replay Trivy attack scenario: 76 tags,
  MASS_REPOINT + OFF_BRANCH + BACKDATED_COMMIT + SIGNATURE_DROPPED + SIZE_ANOMALY
  all fire, total score >300

### Integration tests in tests/harness/

- TestLockRecordsGPGStatus — lock a signed action (e.g. actions/checkout@v4),
  verify lockfile contains `gpg_signed: true`
- TestVerifyDetectsSignatureDrop — lock with signed commit, then verify against
  unsigned commit → SIGNATURE_DROPPED in output

## Backward compatibility

Existing lockfiles without `gpg_signed` field work unchanged. The signal only fires
when `gpg_signed` was explicitly recorded as `true` and the live commit is unsigned.
The pointer type (`*bool`) ensures omitempty works correctly — nil means "not recorded",
false means "recorded as unsigned".

## Files to create/modify

- MODIFY: `internal/poller/github.go` — parse GPG verification from commit response
- MODIFY: `internal/manifest/manifest.go` — add GPGSigned/GPGSigner to TagEntry
- MODIFY: `internal/risk/score.go` — add SIGNATURE_DROPPED signal
- MODIFY: `internal/gate/gate.go` — populate WasGPGSigned/IsGPGSigned in ScoreContext
- MODIFY: `internal/risk/score_test.go` — add signature delta test cases
- MODIFY: `tests/harness/` — add integration test for GPG recording and detection
