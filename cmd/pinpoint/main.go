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

// version is set at build time via ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
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
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `pinpoint %s — GitHub Actions tag integrity monitor

USAGE:
  pinpoint scan      --config <path>  [--state <path>]  [--json]  [--output sarif]  [--rest]
  pinpoint watch     --config <path>  [--state <path>]  [--interval 5m]  [--rest]
  pinpoint discover  --workflows <dir>
  pinpoint audit     --org <name>  [--output report|config|manifest|json|sarif]  [--skip-upstream]
  pinpoint gate      [--manifest <path>]  [--fail-on-missing]  [--fail-on-unpinned]  [--integrity]  [--on-disk]  [--actions-dir <path>]  [--skip-transitive]  [--warn]  [--json]
  pinpoint lock      [--lockfile <path>]  [--workflows <dir>]  [--verify]  [--skip-disk-integrity]
  pinpoint verify    [--workflows <dir>]  [--output json]
  pinpoint manifest  <refresh|verify|init>  [options]
  pinpoint inject    [--file <path>]  [--workflows <dir>]  [--dry-run]  [--mode warn|enforce]  [--version <tag>]  [--pr <org>]  [--pr-title <title>]

COMMANDS:
  scan       One-shot: poll all monitored actions and report changes
  watch      Continuous: poll on interval, alert on changes
  discover   Scan workflow files and output actions to monitor
  audit      Scan an entire GitHub org and produce a security posture report
  gate       Pre-execution: verify action tag integrity before CI runs
  lock       Generate or update .github/actions-lock.json
  verify     Retroactive: check current dependencies for signs of tampering
  manifest   Manage the pinpoint manifest (refresh, verify, init)
  inject     Inject pinpoint-action step into workflow files

ENVIRONMENT:
  GITHUB_TOKEN     GitHub personal access token (recommended)
  PINPOINT_CONFIG  Default config path (overridden by --config)

FLAGS:
  --rest  Force REST API mode (default: GraphQL with REST fallback)

`, version)
}
