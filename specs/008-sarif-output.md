# Spec 008: SARIF Output for GitHub Security Tab

## Why This Matters

SARIF (Static Analysis Results Interchange Format) is the standard format
GitHub uses to display results in the Security tab → Code Scanning Alerts.
When pinpoint outputs SARIF and uploads it via `codeql/upload-sarif`, every
detected issue appears as a security alert with severity, location, and
remediation guidance — right where security teams already look.

This turns pinpoint from "a CLI tool someone runs" into "a security scanner
integrated with GitHub's native UI."

## New Flag: `--output sarif`

Add SARIF output to both `pinpoint scan` and `pinpoint audit`.

```bash
# Scan with SARIF output
pinpoint scan --config .pinpoint.yml --output sarif > results.sarif

# Audit with SARIF output
pinpoint audit --org coreweave --output sarif > results.sarif
```

## SARIF Format

The SARIF 2.1.0 schema. Minimal valid structure:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "pinpoint",
          "version": "0.3.0",
          "informationUri": "https://github.com/tehreet/pinpoint",
          "rules": [
            {
              "id": "pinpoint/tag-repointed",
              "shortDescription": { "text": "Action tag has been repointed" },
              "fullDescription": { "text": "A GitHub Action version tag now points to a different commit SHA than previously recorded. This could indicate a supply chain attack." },
              "defaultConfiguration": { "level": "error" },
              "helpUri": "https://github.com/tehreet/pinpoint#tag-repointing",
              "properties": { "tags": ["security", "supply-chain"] }
            },
            {
              "id": "pinpoint/tag-unpinned",
              "shortDescription": { "text": "Action is not SHA-pinned" },
              "fullDescription": { "text": "This action reference uses a mutable tag instead of a commit SHA. It is vulnerable to tag repointing attacks." },
              "defaultConfiguration": { "level": "warning" },
              "helpUri": "https://github.com/tehreet/pinpoint#sha-pinning"
            },
            {
              "id": "pinpoint/branch-pinned",
              "shortDescription": { "text": "Action is pinned to a branch" },
              "fullDescription": { "text": "This action uses a branch reference which changes on every commit. This is the least secure form of action pinning." },
              "defaultConfiguration": { "level": "error" },
              "helpUri": "https://github.com/tehreet/pinpoint#branch-pinning"
            },
            {
              "id": "pinpoint/no-immutable-release",
              "shortDescription": { "text": "Action lacks immutable releases" },
              "fullDescription": { "text": "This action's upstream repository does not have immutable releases enabled, making tag repointing easier for attackers." },
              "defaultConfiguration": { "level": "note" },
              "helpUri": "https://github.com/tehreet/pinpoint#immutable-releases"
            },
            {
              "id": "pinpoint/no-gate",
              "shortDescription": { "text": "Workflow has no pinpoint gate" },
              "fullDescription": { "text": "This workflow does not include a pinpoint gate step. Actions used in this workflow are not verified before execution." },
              "defaultConfiguration": { "level": "warning" },
              "helpUri": "https://github.com/tehreet/pinpoint#gate"
            }
          ]
        }
      },
      "results": []
    }
  ]
}
```

### Result Examples

**Tag repointed (from scan):**
```json
{
  "ruleId": "pinpoint/tag-repointed",
  "level": "error",
  "message": {
    "text": "aquasecurity/trivy-action@0.35.0 tag has been repointed from abc123... to def456.... This may indicate a supply chain attack."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": ".github/workflows/ci.yml"
        },
        "region": {
          "startLine": 15
        }
      }
    }
  ],
  "properties": {
    "severity": "CRITICAL",
    "previousSHA": "abc123...",
    "currentSHA": "def456...",
    "signals": ["MASS_REPOINT", "SEMVER_REPOINT", "SIZE_ANOMALY"]
  }
}
```

**Unpinned action (from audit):**
```json
{
  "ruleId": "pinpoint/tag-unpinned",
  "level": "warning",
  "message": {
    "text": "actions/checkout@v4 in 1,823 repos is not SHA-pinned. Pin to 34e114876b0b11c390a56381ad16ebd13914f8d5 for immutability."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": ".github/workflows/ci.yml"
        }
      }
    }
  ],
  "fixes": [
    {
      "description": { "text": "Pin to commit SHA" },
      "artifactChanges": [
        {
          "artifactLocation": { "uri": ".github/workflows/ci.yml" },
          "replacements": [
            {
              "deletedRegion": { "startLine": 15 },
              "insertedContent": { "text": "uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4" }
            }
          ]
        }
      ]
    }
  ]
}
```

## Implementation

### New file: `internal/sarif/sarif.go`

```go
package sarif

// SARIF 2.1.0 types — only what we need

type Log struct {
    Schema  string `json:"$schema"`
    Version string `json:"version"`
    Runs    []Run  `json:"runs"`
}

type Run struct {
    Tool    Tool     `json:"tool"`
    Results []Result `json:"results"`
}

type Tool struct {
    Driver Driver `json:"driver"`
}

type Driver struct {
    Name           string `json:"name"`
    Version        string `json:"version"`
    InformationURI string `json:"informationUri"`
    Rules          []Rule `json:"rules"`
}

type Rule struct { ... }
type Result struct { ... }
type Location struct { ... }

// FormatScanSARIF converts scan alerts to SARIF
func FormatScanSARIF(alerts []risk.Alert, version string) (*Log, error)

// FormatAuditSARIF converts audit results to SARIF
func FormatAuditSARIF(result *audit.AuditResult, version string) (*Log, error)
```

### New file: `internal/sarif/sarif_test.go`

Tests:
- TestFormatScanSARIF — scan with 2 alerts, valid SARIF JSON
- TestFormatAuditSARIF — audit with unpinned + branch-pinned actions
- TestSARIFSchema — validate output matches SARIF 2.1.0 required fields
- TestEmptyResults — no alerts produces valid SARIF with empty results array

### Changes to `cmd/pinpoint/main.go`

In `runScan` and `cmdAudit`, check `--output sarif` and call the formatter.

### Workflow Integration

```yaml
- name: Pinpoint Scan
  run: pinpoint scan --config .pinpoint.yml --output sarif > pinpoint.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pinpoint.sarif
```

## Files to Create/Modify

- CREATE: `internal/sarif/sarif.go`
- CREATE: `internal/sarif/sarif_test.go`
- MODIFY: `cmd/pinpoint/main.go` — add sarif output handling to scan and audit
