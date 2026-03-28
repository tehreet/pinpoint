// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/tehreet/pinpoint/internal/audit"
	"github.com/tehreet/pinpoint/internal/poller"
	"github.com/tehreet/pinpoint/internal/sarif"
)

// CmdAudit scans an entire GitHub org and produces a security posture report.
func CmdAudit(args []string) {
	org := GetFlag(args, "org")
	if org == "" {
		fmt.Fprintf(os.Stderr, "Error: --org is required.\n\nUsage: pinpoint audit --org <name> [--output report|config|manifest|json] [--skip-upstream]\n")
		os.Exit(1)
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintf(os.Stderr, `Error: GITHUB_TOKEN is required for org audit.

Set a token with read access to your organization's repositories:
  export GITHUB_TOKEN=ghp_...

Create a token at: https://github.com/settings/tokens
Required scopes: repo (or read:org for public repos only)
Optional scope: admin:org (enables SHA pinning policy check)
`)
		os.Exit(1)
	}

	output := GetFlag(args, "output")
	if output == "" {
		output = "report"
	}
	switch output {
	case "report", "config", "manifest", "json", "sarif":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid --output %q. Must be one of: report, config, manifest, json, sarif\n", output)
		os.Exit(1)
	}

	skipUpstream := HasFlag(args, "skip-upstream")

	ctx := context.Background()
	graphqlClient := poller.NewGraphQLClient(token)
	restClient := poller.NewGitHubClient(token)

	opts := audit.Options{
		Org:          org,
		Output:       output,
		SkipUpstream: skipUpstream,
		ProgressFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	}

	result, err := audit.RunAudit(ctx, opts, graphqlClient, restClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
		os.Exit(1)
	}

	switch output {
	case "report":
		fmt.Fprint(os.Stderr, audit.FormatReport(result))
	case "config":
		fmt.Print(audit.FormatConfig(result))
	case "manifest":
		// For manifest, we need to resolve tags for discovered actions
		repos := make([]string, len(result.UniqueActions))
		for i, a := range result.UniqueActions {
			repos[i] = a.Repo
		}
		fmt.Fprintf(os.Stderr, "\nResolving tags for %d actions...\n", len(repos))
		tagResults, err := graphqlClient.FetchTagsBatch(ctx, repos)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving tags: %v\n", err)
			os.Exit(1)
		}
		manifestStr, err := audit.FormatManifest(result, tagResults)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting manifest: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(manifestStr)
	case "json":
		jsonStr, err := audit.FormatJSON(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(jsonStr)
	case "sarif":
		sarifStr, err := sarif.FormatAuditSARIF(result, Version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting SARIF: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(sarifStr)
	}
}
