# Codebase Cleanup & Refactoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean up dead code, split the 1592-line main.go into a commands/ subpackage, add tests for 4 untested packages, remove hardcoded stats from docs, and update STEELMAN.md.

**Architecture:** Create `internal/util/` for deduplicated helpers, `cmd/pinpoint/commands/` for per-command files. Each command exports `Cmd<Name>(args []string)` called from main(). New test files follow existing patterns (httptest, t.TempDir, table-driven).

**Tech Stack:** Go 1.24, standard library only, `gopkg.in/yaml.v3`

**Spec:** `docs/superpowers/specs/2026-03-28-codebase-cleanup-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/util/strings.go` | Create | `ShortSHA()`, `LeadingSpaces()` |
| `internal/util/strings_test.go` | Create | Tests for util functions |
| `cmd/pinpoint/main.go` | Rewrite | ~150 lines: main(), printUsage(), dispatch |
| `cmd/pinpoint/commands/scan.go` | Create | CmdScan, CmdWatch, runScan, fetchTagsREST |
| `cmd/pinpoint/commands/gate.go` | Create | CmdGate |
| `cmd/pinpoint/commands/lock.go` | Create | CmdLock, CmdManifest* |
| `cmd/pinpoint/commands/audit.go` | Create | CmdAudit |
| `cmd/pinpoint/commands/discover.go` | Create | CmdDiscover |
| `cmd/pinpoint/commands/verify.go` | Create | CmdVerify |
| `cmd/pinpoint/commands/inject.go` | Create | CmdInject, CmdInjectPR |
| `cmd/pinpoint/commands/helpers.go` | Create | getFlag, hasFlag, truncate, computeMeanInterval |
| `internal/config/config.go` | Modify | Remove GitHubIssues field |
| `internal/config/config_test.go` | Create | Config validation tests |
| `internal/alert/alert_test.go` | Create | Emitter tests |
| `internal/discover/discover_test.go` | Create | Workflow discovery tests |
| `internal/store/store_test.go` | Create | State persistence tests |
| `internal/sarif/sarif.go` | Modify | Replace local shortSHA with util.ShortSHA |
| `internal/verify/verify.go` | Modify | Replace local shortSHA with util.ShortSHA |
| `internal/audit/triggers.go` | Modify | Replace local leadingSpaces with util.LeadingSpaces |
| `internal/inject/inject.go` | Modify | Replace local leadingSpaces with util.LeadingSpaces |
| `scripts/parallel-audit.go` | Modify | Add copyright header |
| `.github/workflows/ci.yml` | Modify | Add benchmark step |
| `CLAUDE.md` | Modify | Remove hardcoded stats |
| `PROJECT-CONTEXT.md` | Modify | Remove hardcoded stats |
| `README.md` | Modify | Remove hardcoded stats |
| `STEELMAN.md` | Modify | Add behavioral anomaly limitations |

---

### Task 1: Create internal/util with deduplicated helpers

**Files:**
- Create: `internal/util/strings.go`
- Create: `internal/util/strings_test.go`

- [ ] **Step 1: Create util package with ShortSHA and LeadingSpaces**

Create `internal/util/strings.go`:

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package util

import "strings"

// ShortSHA truncates a SHA to 7 characters with an ellipsis.
func ShortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7] + "..."
	}
	return sha
}

// LeadingSpaces counts the number of leading whitespace characters in a line.
// Tabs count as 2 spaces.
func LeadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2
		} else {
			break
		}
	}
	return count
}
```

- [ ] **Step 2: Write tests**

Create `internal/util/strings_test.go`:

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package util

import "testing"

func TestShortSHA(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sha  string
		want string
	}{
		{"long sha", "abcdef1234567890", "abcdef1..."},
		{"exactly 7", "abcdef1", "abcdef1"},
		{"short sha", "abc", "abc"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ShortSHA(tt.sha); got != tt.want {
				t.Errorf("ShortSHA(%q) = %q, want %q", tt.sha, got, tt.want)
			}
		})
	}
}

func TestLeadingSpaces(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
		want int
	}{
		{"no indent", "hello", 0},
		{"two spaces", "  hello", 2},
		{"tab", "\thello", 2},
		{"mixed", " \t hello", 4},
		{"all spaces", "   ", 3},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := LeadingSpaces(tt.line); got != tt.want {
				t.Errorf("LeadingSpaces(%q) = %d, want %d", tt.line, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/util/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/util/
git commit -m "feat: create internal/util package with ShortSHA and LeadingSpaces

Consolidates shortSHA (3 copies) and leadingSpaces (2 copies) into a
shared utility package."
```

---

### Task 2: Replace all duplicate function call sites

**Files:**
- Modify: `internal/sarif/sarif.go`
- Modify: `internal/verify/verify.go`
- Modify: `internal/audit/triggers.go`
- Modify: `internal/inject/inject.go`
- Modify: `cmd/pinpoint/main.go`

- [ ] **Step 1: Update sarif.go**

In `internal/sarif/sarif.go`:
- Add `"github.com/tehreet/pinpoint/internal/util"` to imports
- Delete the local `shortSHA` function (lines 322-327)
- Replace all calls from `shortSHA(` to `util.ShortSHA(`

- [ ] **Step 2: Update verify.go**

In `internal/verify/verify.go`:
- Add `"github.com/tehreet/pinpoint/internal/util"` to imports
- Delete the local `shortSHA` function (lines 650-655)
- Replace all calls from `shortSHA(` to `util.ShortSHA(`

- [ ] **Step 3: Update audit/triggers.go**

In `internal/audit/triggers.go`:
- Add `"github.com/tehreet/pinpoint/internal/util"` to imports
- Delete the local `leadingSpaces` function (lines 306-318)
- Replace all calls from `leadingSpaces(` to `util.LeadingSpaces(`

- [ ] **Step 4: Update inject/inject.go**

In `internal/inject/inject.go`:
- Add `"github.com/tehreet/pinpoint/internal/util"` to imports
- Delete the local `leadingSpaces` function (lines 30-33)
- Replace all calls from `leadingSpaces(` to `util.LeadingSpaces(`

- [ ] **Step 5: Update cmd/pinpoint/main.go**

In `cmd/pinpoint/main.go`:
- Add `"github.com/tehreet/pinpoint/internal/util"` to imports
- Delete the local `shortSHA` function (lines 1292-1297)
- Replace all calls from `shortSHA(` to `util.ShortSHA(`

- [ ] **Step 6: Build and test**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add internal/sarif/sarif.go internal/verify/verify.go internal/audit/triggers.go internal/inject/inject.go cmd/pinpoint/main.go
git commit -m "refactor: replace duplicate shortSHA/leadingSpaces with util package

Removes 3 copies of shortSHA and 2 copies of leadingSpaces in favor
of the shared internal/util package."
```

---

### Task 3: Cleanup fixes (dead config, typo, copyright)

**Files:**
- Modify: `internal/config/config.go`
- Modify: `cmd/pinpoint/main.go`
- Modify: `scripts/parallel-audit.go`

- [ ] **Step 1: Remove GitHubIssues from config**

In `internal/config/config.go`, remove line 45 (`GitHubIssues  bool   \`yaml:"github_issues"\``). The AlertConfig struct should become:

```go
type AlertConfig struct {
	MinSeverity   string `yaml:"min_severity"`
	SlackWebhook  string `yaml:"slack_webhook"`
	WebhookURL    string `yaml:"webhook_url"`
	Stdout        bool   `yaml:"stdout"`
}
```

- [ ] **Step 2: Fix typo in main.go**

In `cmd/pinpoint/main.go` around line 1482, find:
```go
fmt.Fprintf(os.Stderr, "  Error creating temp dir: %v\n", repo)
```
Change `repo` to `err`:
```go
fmt.Fprintf(os.Stderr, "  Error creating temp dir: %v\n", err)
```

- [ ] **Step 3: Add copyright header to parallel-audit.go**

In `scripts/parallel-audit.go`, prepend before `package main`:
```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

```

- [ ] **Step 4: Build and test**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go cmd/pinpoint/main.go scripts/parallel-audit.go
git commit -m "fix: remove dead GitHubIssues config, fix typo, add copyright header

- Remove unused GitHubIssues field from AlertConfig (we use Jira)
- Fix error message at main.go:1482 printing repo instead of err
- Add CoreWeave copyright header to scripts/parallel-audit.go"
```

---

### Task 4: Split main.go into commands/ subpackage

This is the largest task. The approach: create all command files first, then rewrite main.go to dispatch.

**Files:**
- Create: `cmd/pinpoint/commands/helpers.go`
- Create: `cmd/pinpoint/commands/scan.go`
- Create: `cmd/pinpoint/commands/gate.go`
- Create: `cmd/pinpoint/commands/audit.go`
- Create: `cmd/pinpoint/commands/discover.go`
- Create: `cmd/pinpoint/commands/verify.go`
- Create: `cmd/pinpoint/commands/lock.go`
- Create: `cmd/pinpoint/commands/inject.go`
- Rewrite: `cmd/pinpoint/main.go`

- [ ] **Step 1: Create commands/helpers.go**

Create `cmd/pinpoint/commands/helpers.go` with `package commands`. Move these functions from main.go:
- `getFlag()` (lines 116-126) → export as `GetFlag()`
- `hasFlag()` (lines 128-135) → export as `HasFlag()`
- `truncate()` (lines 1299-1304) → export as `Truncate()`
- `computeMeanInterval()` (lines 1307-1323) → export as `ComputeMeanInterval()`

Add copyright header. Add necessary imports (`os`, `sort`, `time`).

All functions use `os.Args` — change `GetFlag` and `HasFlag` to accept `args []string` parameter instead of reading `os.Args` directly, so they're testable.

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"sort"
	"strings"
	"time"
)

// GetFlag retrieves a flag value from args (e.g., "--config" "path").
func GetFlag(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, name+"=") {
			return a[len(name)+1:]
		}
	}
	return ""
}

// HasFlag checks if a flag exists in args.
func HasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

// Truncate shortens a string to max characters with "..." suffix.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// ComputeMeanInterval calculates the average time between release timestamps.
func ComputeMeanInterval(history []string) time.Duration {
	if len(history) < 2 {
		return 0
	}
	var times []time.Time
	for _, ts := range history {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			times = append(times, t)
		}
	}
	if len(times) < 2 {
		return 0
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	total := times[len(times)-1].Sub(times[0])
	return total / time.Duration(len(times)-1)
}
```

- [ ] **Step 2: Create commands/scan.go**

Create `cmd/pinpoint/commands/scan.go` with `package commands`. Move:
- `cmdScan()` (lines 137-205) → `CmdScan(args []string)`
- `cmdWatch()` (lines 207-284) → `CmdWatch(args []string)`
- `runScan()` (lines 618-917) — keep as unexported `runScan()`
- `fetchTagsREST()` (lines 920-935) — keep as unexported

Update all `getFlag`/`hasFlag` calls to use `GetFlag(args, ...)` / `HasFlag(args, ...)`.
Update all `shortSHA` calls to `util.ShortSHA`.
Add copyright header. Add all necessary imports from main.go's import block that these functions use.

The `version`, `commit`, `date` variables need to be accessible — add exported package-level vars:
```go
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
```
These get set from main.go during init.

- [ ] **Step 3: Create commands/gate.go**

Create `cmd/pinpoint/commands/gate.go`. Move `cmdGate()` (lines 404-536) → `CmdGate(args []string)`. Same pattern: update flag helpers, add imports, copyright header.

- [ ] **Step 4: Create commands/audit.go**

Move `cmdAudit()` (lines 310-402) → `CmdAudit(args []string)`.

- [ ] **Step 5: Create commands/discover.go**

Move `cmdDiscover()` (lines 286-308) → `CmdDiscover(args []string)`.

- [ ] **Step 6: Create commands/verify.go**

Move `cmdVerify()` (lines 538-615) → `CmdVerify(args []string)`.

- [ ] **Step 7: Create commands/lock.go**

Move all manifest/lock commands:
- `cmdManifest()` (lines 937-969) → `CmdManifest(args []string)`
- `cmdManifestRefresh()` (lines 971-1024) → unexported
- `cmdManifestVerify()` (lines 1025-1069) → unexported
- `cmdManifestInit()` (lines 1071-1121) → unexported
- `cmdLock()` (lines 1123-1290) → `CmdLock(args []string)`

- [ ] **Step 8: Create commands/inject.go**

Move:
- `cmdInject()` (lines 1325-1414) → `CmdInject(args []string)`
- `cmdInjectPR()` (lines 1415-1588) → unexported `cmdInjectPR()`

- [ ] **Step 9: Rewrite main.go**

Replace `cmd/pinpoint/main.go` with a thin dispatcher (~150 lines):

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only
//
// Pinpoint detects GitHub Actions tag repointing attacks.
// It monitors the commit SHAs behind action version tags
// and alerts when they change — before malicious code executes.

package main

import (
	"fmt"
	"os"

	"github.com/tehreet/pinpoint/cmd/pinpoint/commands"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Pass build info to commands package
	commands.Version = version
	commands.Commit = commit
	commands.Date = date

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		commands.CmdScan(os.Args[2:])
	case "watch":
		commands.CmdWatch(os.Args[2:])
	case "discover":
		commands.CmdDiscover(os.Args[2:])
	case "audit":
		commands.CmdAudit(os.Args[2:])
	case "gate":
		commands.CmdGate(os.Args[2:])
	case "verify":
		commands.CmdVerify(os.Args[2:])
	case "lock":
		commands.CmdLock(os.Args[2:])
	case "manifest":
		commands.CmdManifest(os.Args[2:])
	case "inject":
		commands.CmdInject(os.Args[2:])
	case "version":
		fmt.Printf("pinpoint %s (commit: %s, built: %s)\n", version, commit, date)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	// Keep the existing printUsage content from current main.go lines 81-115
}
```

- [ ] **Step 10: Build and test**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: ALL PASS

- [ ] **Step 11: Verify binary works**

Run:
```bash
go build -o pinpoint ./cmd/pinpoint/
./pinpoint version
./pinpoint help
./pinpoint discover --workflows .github/workflows
```
Expected: Same output as before the split.

- [ ] **Step 12: Commit**

```bash
git add cmd/pinpoint/
git commit -m "refactor: split main.go into commands/ subpackage

Moves 1592-line main.go into focused command files:
- commands/scan.go: scan, watch, runScan
- commands/gate.go: gate verification
- commands/lock.go: lock, manifest subcommands
- commands/audit.go: org-wide audit
- commands/discover.go: workflow discovery
- commands/verify.go: retroactive verification
- commands/inject.go: workflow injection + PR mode
- commands/helpers.go: flag parsing, truncate, computeMeanInterval

main.go is now ~100 lines: dispatch + usage."
```

---

### Task 5: Add tests for internal/config

**Files:**
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write config tests**

Create `internal/config/config_test.go`:

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"strings"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	t.Parallel()
	yaml := `
actions:
  - repo: actions/checkout
    tags: [v4]
alerts:
  min_severity: critical
  stdout: true
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(cfg.Actions))
	}
	if cfg.Alerts.MinSeverity != "critical" {
		t.Errorf("expected min_severity=critical, got %s", cfg.Alerts.MinSeverity)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	t.Parallel()
	_, err := LoadFromBytes([]byte("not: [valid: yaml"))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestAllowRuleRequiresReason(t *testing.T) {
	t.Parallel()
	yaml := `
actions:
  - repo: actions/checkout
    tags: [v4]
allow:
  - repo: "actions/*"
    condition: major_tag_advance
    suppress: true
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Error("expected error for allow rule without reason")
	}
	if err != nil && !strings.Contains(err.Error(), "reason") {
		t.Errorf("expected error about missing reason, got: %v", err)
	}
}

func TestAllowRuleWithReason(t *testing.T) {
	t.Parallel()
	yaml := `
actions:
  - repo: actions/checkout
    tags: [v4]
allow:
  - repo: "actions/*"
    condition: major_tag_advance
    suppress: true
    reason: "Official GitHub actions are trusted"
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.AllowRules) != 1 {
		t.Errorf("expected 1 allow rule, got %d", len(cfg.AllowRules))
	}
}

func TestWildcardTags(t *testing.T) {
	t.Parallel()
	yaml := `
actions:
  - repo: actions/checkout
    tags: ["*"]
`
	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Actions[0].AllTags {
		t.Error("expected AllTags=true for wildcard tag")
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if cfg.Alerts.MinSeverity != "medium" {
		t.Errorf("expected default min_severity=medium, got %s", cfg.Alerts.MinSeverity)
	}
	if !cfg.Alerts.Stdout {
		t.Error("expected default stdout=true")
	}
}

func TestEmptyConfig(t *testing.T) {
	t.Parallel()
	cfg, err := LoadFromBytes([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty config: %v", err)
	}
	if cfg.Alerts.MinSeverity != "medium" {
		t.Errorf("expected default min_severity for empty config, got %s", cfg.Alerts.MinSeverity)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/config/ -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/config/config_test.go
git commit -m "test: add config package tests

Covers YAML parsing, allow rule validation, wildcard tags, defaults."
```

---

### Task 6: Add tests for internal/alert

**Files:**
- Create: `internal/alert/alert_test.go`

- [ ] **Step 1: Write alert tests**

Create `internal/alert/alert_test.go`:

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package alert

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tehreet/pinpoint/internal/risk"
)

func testAlert() risk.Alert {
	return risk.Alert{
		Severity:   risk.SeverityCritical,
		Type:       "TAG_REPOINTED",
		Action:     "actions/checkout",
		Tag:        "v4",
		PreviousSHA: "aabbccdd",
		CurrentSHA:  "11223344",
		DetectedAt:  time.Now().UTC(),
		Signals:    []string{"OFF_BRANCH: new commit is not a descendant"},
	}
}

func TestEmitStdout(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	e := &Emitter{writer: &buf, stdout: true}
	e.Emit(testAlert())
	output := buf.String()
	if !strings.Contains(output, "actions/checkout") {
		t.Errorf("expected action name in output, got: %s", output)
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Errorf("expected CRITICAL in output, got: %s", output)
	}
}

func TestEmitSlack(t *testing.T) {
	t.Parallel()
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := &Emitter{slackWebhook: srv.URL}
	e.Emit(testAlert())

	if len(received) == 0 {
		t.Fatal("expected Slack webhook to receive POST")
	}
	if !strings.Contains(string(received), "actions/checkout") {
		t.Errorf("expected action name in Slack payload, got: %s", string(received))
	}
}

func TestEmitWebhook(t *testing.T) {
	t.Parallel()
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := &Emitter{webhookURL: srv.URL}
	e.Emit(testAlert())

	if len(received) == 0 {
		t.Fatal("expected webhook to receive POST")
	}
	var a risk.Alert
	if err := json.Unmarshal(received, &a); err != nil {
		t.Fatalf("expected valid JSON alert in webhook, got: %s", string(received))
	}
	if a.Action != "actions/checkout" {
		t.Errorf("expected action=actions/checkout, got %s", a.Action)
	}
}

func TestFormatJSON(t *testing.T) {
	t.Parallel()
	j, err := FormatJSON(testAlert())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(j, "TAG_REPOINTED") {
		t.Errorf("expected TAG_REPOINTED in JSON, got: %s", j)
	}
}

func TestEmitSlackError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	e := &Emitter{slackWebhook: srv.URL}
	// Should not panic on error
	e.Emit(testAlert())
}
```

Note: The Emitter struct fields are unexported. The test is in the same package (`package alert`), so it can access them directly. Check the actual field names in `alert.go` and adjust if needed (the explore agent found: writer, stdout, slackWebhook, webhookURL or similar).

- [ ] **Step 2: Run tests**

Run: `go test ./internal/alert/ -v`
Expected: PASS (may need field name adjustments based on actual struct)

- [ ] **Step 3: Commit**

```bash
git add internal/alert/alert_test.go
git commit -m "test: add alert emitter tests

Covers stdout, Slack webhook, generic webhook, JSON formatting,
and error resilience."
```

---

### Task 7: Add tests for internal/discover

**Files:**
- Create: `internal/discover/discover_test.go`

- [ ] **Step 1: Write discover tests**

Create `internal/discover/discover_test.go`:

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

const testWorkflow = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
`

func TestFromWorkflowDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(testWorkflow), 0644); err != nil {
		t.Fatal(err)
	}
	refs, err := FromWorkflowDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find checkout@v4, setup-go@v5, and checkout@sha (pinned)
	if len(refs) < 2 {
		t.Errorf("expected at least 2 refs, got %d", len(refs))
	}
}

func TestSHAPinnedDetected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(testWorkflow), 0644); err != nil {
		t.Fatal(err)
	}
	refs, err := FromWorkflowDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pinnedCount := 0
	for _, ref := range refs {
		if ref.IsPinned {
			pinnedCount++
		}
	}
	if pinnedCount != 1 {
		t.Errorf("expected 1 SHA-pinned ref, got %d", pinnedCount)
	}
}

func TestNoWorkflows(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	refs, err := FromWorkflowDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 refs for empty dir, got %d", len(refs))
	}
}

func TestMultipleWorkflowFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	wf1 := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	wf2 := `name: Release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
`
	os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(wf1), 0644)
	os.WriteFile(filepath.Join(dir, "release.yml"), []byte(wf2), 0644)

	refs, err := FromWorkflowDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Should find checkout@v4 (twice, different source files) and docker/build-push-action@v5
	if len(refs) < 3 {
		t.Errorf("expected at least 3 refs from 2 files, got %d", len(refs))
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/discover/ -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/discover/discover_test.go
git commit -m "test: add discover package tests

Covers workflow parsing, SHA-pinned detection, empty dirs,
and multi-file discovery."
```

---

### Task 8: Add tests for internal/store

**Files:**
- Create: `internal/store/store_test.go`

- [ ] **Step 1: Write store tests**

Create `internal/store/store_test.go`:

```go
// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package store

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestNewFileStore(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	fs := NewFileStore(path)
	if fs == nil {
		t.Fatal("expected non-nil FileStore")
	}
	if fs.TagCount() != 0 {
		t.Errorf("expected 0 tags, got %d", fs.TagCount())
	}
}

func TestRecordTagNew(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	fs := NewFileStore(path)

	changed, prevSHA := fs.RecordTag("actions/checkout", "v4", "abc123", "")
	if !changed {
		t.Error("expected changed=true for new tag")
	}
	if prevSHA != "" {
		t.Errorf("expected empty previousSHA for new tag, got %s", prevSHA)
	}
}

func TestRecordTagUnchanged(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	fs := NewFileStore(path)

	fs.RecordTag("actions/checkout", "v4", "abc123", "")
	changed, _ := fs.RecordTag("actions/checkout", "v4", "abc123", "")
	if changed {
		t.Error("expected changed=false for same SHA")
	}
}

func TestRecordTagChanged(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	fs := NewFileStore(path)

	fs.RecordTag("actions/checkout", "v4", "abc123", "")
	changed, prevSHA := fs.RecordTag("actions/checkout", "v4", "def456", "")
	if !changed {
		t.Error("expected changed=true for different SHA")
	}
	if prevSHA != "abc123" {
		t.Errorf("expected previousSHA=abc123, got %s", prevSHA)
	}
}

func TestRecordDeletedTag(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	fs := NewFileStore(path)

	fs.RecordTag("actions/checkout", "v4", "abc123", "")
	fs.RecordDeletedTag("actions/checkout", "v4")

	state := fs.GetActionState("actions/checkout")
	if len(state.DeletedTags) == 0 {
		t.Error("expected deleted tag to be recorded")
	}
}

func TestSaveAndLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	fs := NewFileStore(path)

	fs.RecordTag("actions/checkout", "v4", "abc123", "")
	if err := fs.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	fs2 := NewFileStore(path)
	if fs2.TagCount() != 1 {
		t.Errorf("expected 1 tag after reload, got %d", fs2.TagCount())
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	fs := NewFileStore(path)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			repo := "actions/checkout"
			tag := "v4"
			sha := "abc123"
			fs.RecordTag(repo, tag, sha, "")
			fs.GetActionState(repo)
			fs.TagCount()
		}(i)
	}
	wg.Wait()
	// If we get here without panic/race, concurrency is safe
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/store/ -v -race`
Expected: PASS (including race detector)

- [ ] **Step 3: Commit**

```bash
git add internal/store/store_test.go
git commit -m "test: add store package tests

Covers new/changed/unchanged tag recording, deleted tags,
save/load round-trip, and concurrent access with race detector."
```

---

### Task 9: Add t.Parallel() to existing test files

**Files:**
- Modify: All existing `*_test.go` files

- [ ] **Step 1: Add t.Parallel() to all top-level test functions**

For each test file, add `t.Parallel()` as the first line of every top-level `Test*` function. Files to update:

- `internal/risk/score_test.go` — all Test* functions
- `internal/gate/gate_test.go` — all Test* functions
- `internal/gate/gate_docker_test.go` — all Test* functions
- `internal/manifest/manifest_test.go` — all Test* functions
- `internal/manifest/docker_test.go` — all Test* functions
- `internal/manifest/lockpath_test.go` — all Test* functions
- `internal/poller/graphql_test.go` — all Test* functions
- `internal/poller/github_test.go` — all Test* functions
- `internal/sarif/sarif_test.go` — all Test* functions
- `internal/suppress/suppress_test.go` — all Test* functions
- `internal/verify/verify_test.go` — all Test* functions
- `internal/audit/audit_test.go` — all Test* functions
- `internal/inject/inject_test.go` — all Test* functions
- `internal/integrity/integrity_test.go` — all Test* functions (if exists)

Skip any test function that writes to a shared variable or file outside `t.TempDir()`.

- [ ] **Step 2: Run tests with race detector**

Run: `go test ./... -race -count=1`
Expected: ALL PASS. If any race conditions appear, remove `t.Parallel()` from the affected test.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "test: add t.Parallel() to all test functions

Enables parallel test execution for faster CI runs."
```

---

### Task 10: Add CI benchmarks

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add benchmark step to CI**

In `.github/workflows/ci.yml`, add after the "Test" step and before "Verify binary":

```yaml
      - name: Benchmark
        run: go test -bench=. -benchmem -run=^$ ./internal/manifest/ ./internal/integrity/ | tee benchmark-results.txt

      - name: Upload benchmark results
        uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08 # v4
        with:
          name: benchmark-results
          path: benchmark-results.txt
          retention-days: 90
```

Note: The upload-artifact ref needs to be SHA-pinned. Look up the current v4 SHA and use it.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add benchmark step with artifact upload

Runs benchmarks for manifest and integrity packages, stores
results as 90-day artifacts for regression tracking."
```

---

### Task 11: Remove hardcoded stats from docs

**Files:**
- Modify: `CLAUDE.md`
- Modify: `PROJECT-CONTEXT.md`
- Modify: `README.md`

- [ ] **Step 1: Update CLAUDE.md**

Line 32 currently reads:
```
**Current state:** v0.7.0 released. 264 tests, 17,796 lines of Go, 77 commits.
28 repos enforced in test org. 10/10 attack battery. First tool to verify
Docker image digests.
```

Replace with:
```
**Current state:** v0.7.0 released. 28 repos enforced in test org. 10/10
attack battery. First tool to verify Docker image digests.
```

Line 91 currently reads:
```
go test ./...                      # Run all 264 tests
```

Replace with:
```
go test ./...                      # Run all tests
```

Also update the risk/score.go description at line 72 from "Risk scoring (8 signals)" to "Risk scoring (13 signals)".

- [ ] **Step 2: Update PROJECT-CONTEXT.md**

Find and remove the hardcoded "264 tests, 17,796 lines of Go, 77 commits" line. Replace with the version and key features only.

Update the signals table to include all 13 signals.

- [ ] **Step 3: Update README.md**

Find line 259 and remove the "264 tests. 17,796 lines of Go. 77 commits." sentence. Keep "Single binary, one dependency."

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md PROJECT-CONTEXT.md README.md
git commit -m "docs: remove hardcoded stats, update signal count to 13

Test counts, LOC, and commit counts go stale within days.
Removed from CLAUDE.md, PROJECT-CONTEXT.md, and README.md.
Updated risk scoring signal count from 8 to 13."
```

---

### Task 12: Update STEELMAN.md

**Files:**
- Modify: `STEELMAN.md`

- [ ] **Step 1: Add behavioral anomaly limitations section**

Append a new section at the end of STEELMAN.md (after the Docker limitations section):

```markdown

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
```

- [ ] **Step 2: Commit**

```bash
git add STEELMAN.md
git commit -m "docs: add behavioral anomaly signal limitations to STEELMAN.md

Covers compromised maintainer bypass, action.yml false positives,
baseline requirements, and high-cadence exclusion."
```

---

### Task 13: Final validation

- [ ] **Step 1: Run full build and test suite**

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./...
go vet ./...
go test ./... -race -count=1
```

Expected: ALL PASS

- [ ] **Step 2: Verify binary**

```bash
go build -o pinpoint ./cmd/pinpoint/
./pinpoint version
./pinpoint help
./pinpoint discover --workflows .github/workflows
```

Expected: All commands work identically to before.

- [ ] **Step 3: Verify no duplicate functions remain**

```bash
grep -rn "func shortSHA" --include="*.go" | grep -v util/
grep -rn "func leadingSpaces" --include="*.go" | grep -v util/
grep -rn "GitHubIssues" --include="*.go"
```

Expected: No matches (all duplicates removed, dead field gone).
