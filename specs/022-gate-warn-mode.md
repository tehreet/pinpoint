# Spec 022: Gate Warn Mode

## Problem

pinpoint gate currently exits 0 (pass) or 2 (violation). There is no way to
deploy gate in CI without risking build breakage. Teams need a --warn flag that
logs violations but always exits 0, enabling a weeks-long observation period
before enforcing.

This is the #1 blocker for internal adoption. Without it, deploying gate requires
100% confidence in the allow-list on day one — which is impossible.

## Design

### Flag

```
pinpoint gate --warn
```

Behavior: identical to normal gate (runs all checks, prints all output, reports
all violations) but overrides exit code to 0 regardless of findings. Stderr gets
an extra line: `⚠ Running in warn mode — violations logged but not enforced`

### Environment variable override

```
PINPOINT_GATE_WARN=true
```

This allows orgs to enable warn mode via an org-level Actions variable without
modifying every workflow file. The flag takes precedence over the env var.

### Output changes

When violations are found in warn mode, the summary line changes from:
```
✗ 3 action integrity violations detected (build blocked)
```
to:
```
⚠ 3 action integrity violations detected (warn mode — not blocking)
```

JSON output (--json) includes a new field:
```json
{
  "mode": "warn",
  "violations": [...],
  "exit_code_override": true
}
```

### Exit codes

| Scenario | Normal mode | Warn mode |
|---|---|---|
| All checks pass | 0 | 0 |
| Violations found | 2 | 0 |
| Internal error | 1 | 1 |

Note: exit 1 (internal error) is NOT overridden by warn mode. If gate can't
run at all (no token, API failure, etc.), the build should still fail.

## Implementation

~15 lines in cmd/pinpoint/main.go:

```go
// In gate subcommand flag parsing:
warnMode := flagSet.Bool("warn", false, "Log violations but don't fail the build")

// After flag parsing:
if !*warnMode && os.Getenv("PINPOINT_GATE_WARN") == "true" {
    *warnMode = true
}

// At the end of runGate, before os.Exit:
if *warnMode {
    fmt.Fprintf(os.Stderr, "⚠ Running in warn mode — violations logged but not enforced\n")
    if exitCode == 2 {
        exitCode = 0
    }
}
```

## Workflow example (Phase 2 deployment)

```yaml
- name: Pinpoint gate (warn mode)
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    ./pinpoint gate --warn
  # Always exits 0, violations go to step summary
```

Or via org-level variable (no workflow changes needed):

```yaml
env:
  PINPOINT_GATE_WARN: ${{ vars.PINPOINT_GATE_WARN }}  # set to "true" at org level
```

To switch from warn to enforce: flip the org variable from "true" to "false".
Every repo picks up the change on next run. No PRs, no workflow edits.

## Tests

- TestGateWarnModePassesOnViolation — gate finds violation, --warn set, exits 0
- TestGateWarnModeStillFailsOnError — API error, --warn set, still exits 1
- TestGateWarnModeEnvVar — PINPOINT_GATE_WARN=true, no flag, exits 0
- TestGateWarnModeFlagOverridesEnv — --warn flag works even without env var
- TestGateWarnModeOutput — output contains "warn mode" string

## Files to modify

- MODIFY: cmd/pinpoint/main.go — add --warn flag, env var check, exit code override
