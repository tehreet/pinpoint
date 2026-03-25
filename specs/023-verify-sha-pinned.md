# Spec 023: Verify SHA-pinned references against lockfile

## Problem

The gate currently treats any `action@<40-char-hex-SHA>` reference as "inherently
safe" and skips lockfile verification entirely (gate.go lines 274-278). This
creates a bypass: an attacker who opens a PR that references `actions/checkout@<malicious-SHA>`
will pass the gate because the SHA format is trusted unconditionally.

**Attack demonstrated:** In the ultimate attack battery (Attack 4), a PR swapped
`actions/checkout@v4` to `actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`
(a random valid-looking SHA). The gate classified it as "SHA-pinned (inherently safe)"
and passed it through without checking the lockfile.

## Why the current behavior exists

The original assumption was: "If someone already pins to a full SHA, they've done
the hard work of verifying the commit." This is true for honest developers but
fails for adversarial PRs. A malicious contributor can pin to a backdoored commit's
SHA directly.

## Fix

When `--fail-on-missing` is active (which it is by default for new lockfile paths),
SHA-pinned references should be verified against the lockfile:

1. Look up the action (`owner/repo`) in the manifest
2. Check if ANY entry for that action has a `sha` field matching the pinned SHA
3. If match found → pass (verified, not just skipped)
4. If no match → violation ("SHA not in manifest")
5. If the action itself isn't in the manifest → violation ("not in manifest")

When `--fail-on-missing` is NOT active (legacy mode), preserve current behavior:
skip SHA-pinned refs as before for backward compatibility.

## Code changes

### `internal/gate/gate.go`

Replace the current SHA-pinned block (lines 274-278):

```go
if shaRegexp.MatchString(ref) {
    // SHA-pinned: inherently safe
    result.Skipped++
    fmt.Fprintf(messageWriter, "  ● %s@%s... → SHA-pinned (inherently safe)\n", key, ref[:7])
    continue
}
```

With:

```go
if shaRegexp.MatchString(ref) {
    if opts.FailOnMissing {
        // Verify SHA-pinned refs against lockfile when fail-on-missing is active
        shaRefs = append(shaRefs, actionRef{
            Owner: owner, Repo: repo, Ref: ref, Raw: raw,
            IsSHA: true, IsBranch: false,
        })
    } else {
        // Legacy: trust SHA-pinned refs without verification
        result.Skipped++
        fmt.Fprintf(messageWriter, "  ● %s@%s... → SHA-pinned (inherently safe)\n", key, ref[:7])
    }
    continue
}
```

Add a new `shaRefs` slice alongside `tagRefs`. After manifest is loaded, verify
SHA-pinned refs:

```go
// Verify SHA-pinned refs against manifest
for _, sr := range shaRefs {
    key := sr.Owner + "/" + sr.Repo
    actionEntry, exists := manifest.Actions[key]
    if !exists {
        result.Violations = append(result.Violations, Violation{
            Action: key, Ref: sr.Ref, Message: "not in manifest",
        })
        fmt.Fprintf(messageWriter, "  ✗ %s@%s... → not in manifest\n", key, sr.Ref[:7])
        continue
    }

    // Check if any tag entry's SHA matches
    matched := false
    for _, entry := range actionEntry {
        if entry.SHA == sr.Ref {
            matched = true
            result.Verified++
            fmt.Fprintf(messageWriter, "  ✓ %s@%s... → SHA matches manifest\n", key, sr.Ref[:7])
            break
        }
    }
    if !matched {
        result.Violations = append(result.Violations, Violation{
            Action: key, Ref: sr.Ref, Message: "SHA not in manifest",
        })
        fmt.Fprintf(messageWriter, "  ✗ %s@%s... → SHA not in manifest (expected one of: %s)\n",
            key, sr.Ref[:7], manifestSHAsFor(actionEntry))
    }
}
```

### Output examples

Before (current, broken):
```
  ● actions/checkout@b4ffde6... → SHA-pinned (inherently safe)
```

After (with --fail-on-missing):
```
  ✗ actions/checkout@b4ffde6... → SHA not in manifest (expected: 34e1148...)
```

After (matching SHA):
```
  ✓ actions/checkout@34e1148... → SHA matches manifest
```

After (without --fail-on-missing, legacy):
```
  ● actions/checkout@b4ffde6... → SHA-pinned (inherently safe)
```

## Tests

1. **SHA in manifest** — `actions/checkout@<correct-sha>` should pass as verified
2. **SHA not in manifest** — `actions/checkout@<wrong-sha>` should fail
3. **Action not in manifest** — `unknown/action@<any-sha>` should fail
4. **Legacy mode** — without `--fail-on-missing`, SHA-pinned should still be skipped
5. **SHA-pinned actions from reusable workflows** — e.g. `actions/checkout@34e1148...`
   in the shared workflow should pass (it's already in manifest)

## Impact

- Zero API calls added (SHA verification is purely against local manifest data)
- No performance impact
- Backward compatible (only changes behavior when --fail-on-missing is active)
- Closes the last known bypass in the attack battery (Attack 4)

## Files to modify

- `internal/gate/gate.go` — main fix
- `internal/gate/gate_test.go` — new test cases
