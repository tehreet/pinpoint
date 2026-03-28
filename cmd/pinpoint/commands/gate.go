// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tehreet/pinpoint/internal/gate"
	"github.com/tehreet/pinpoint/internal/manifest"
)

// CmdGate performs pre-execution action tag integrity verification.
func CmdGate(args []string) {
	repo := GetFlag(args, "repo")
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if repo == "" {
		fmt.Fprintf(os.Stderr, "Error: --repo is required (or set GITHUB_REPOSITORY).\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned] [--integrity] [--on-disk] [--actions-dir <path>] [--skip-transitive] [--all-workflows]\n")
		os.Exit(1)
	}

	sha := GetFlag(args, "sha")
	if sha == "" {
		sha = os.Getenv("GITHUB_SHA")
	}
	if sha == "" {
		fmt.Fprintf(os.Stderr, "Error: --sha is required (or set GITHUB_SHA).\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned] [--integrity] [--on-disk] [--actions-dir <path>] [--skip-transitive] [--all-workflows]\n")
		os.Exit(1)
	}

	workflowRef := GetFlag(args, "workflow-ref")
	if workflowRef == "" {
		workflowRef = os.Getenv("GITHUB_WORKFLOW_REF")
	}
	allWorkflows := HasFlag(args, "all-workflows")
	if !allWorkflows && os.Getenv("PINPOINT_GATE_ALL_WORKFLOWS") == "true" {
		allWorkflows = true
	}
	if workflowRef == "" && !allWorkflows {
		fmt.Fprintf(os.Stderr, "Error: --workflow-ref is required (or set GITHUB_WORKFLOW_REF), unless --all-workflows is set.\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned] [--integrity] [--on-disk] [--actions-dir <path>] [--skip-transitive] [--all-workflows]\n")
		os.Exit(1)
	}

	manifestPath := GetFlag(args, "manifest")
	failOnMissingExplicit := HasFlag(args, "fail-on-missing")
	if manifestPath == "" {
		// Gate runs in CI and fetches via API, not local disk.
		// Default to new lockfile path; the gate will try legacy as fallback.
		manifestPath = manifest.DefaultLockfilePath
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API requests may fail or be rate-limited.")
	}

	apiURL := os.Getenv("GITHUB_API_URL")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}

	graphqlURL := os.Getenv("GITHUB_GRAPHQL_URL")
	if graphqlURL == "" {
		graphqlURL = "https://api.github.com/graphql"
	}

	warnMode := HasFlag(args, "warn")
	if !warnMode && os.Getenv("PINPOINT_GATE_WARN") == "true" {
		warnMode = true
	}
	jsonOutput := HasFlag(args, "json")

	if warnMode {
		fmt.Fprintf(os.Stderr, "⚠ Running in warn mode — violations logged but not enforced\n")
	}

	eventName := os.Getenv("GITHUB_EVENT_NAME")
	baseRef := os.Getenv("GITHUB_BASE_REF")

	opts := gate.GateOptions{
		Repo:                  repo,
		SHA:                   sha,
		WorkflowRef:           workflowRef,
		ManifestPath:          manifestPath,
		Token:                 token,
		APIURL:                apiURL,
		GraphQLURL:            graphqlURL,
		FailOnMissing:         failOnMissingExplicit,
		FailOnMissingExplicit: failOnMissingExplicit,
		FailOnUnpinned:        HasFlag(args, "fail-on-unpinned"),
		Integrity:             HasFlag(args, "integrity"),
		SkipTransitive:        HasFlag(args, "skip-transitive"),
		OnDisk:                HasFlag(args, "on-disk"),
		ActionsDir:            GetFlag(args, "actions-dir"),
		EventName:             eventName,
		BaseRef:               baseRef,
		AllWorkflows:          allWorkflows,
	}

	ctx := context.Background()
	result, err := gate.RunGate(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Gate error: %v\n", err)
		os.Exit(1)
	}

	if len(result.Violations) > 0 {
		if jsonOutput {
			out := map[string]interface{}{
				"violations": result.Violations,
				"verified":   result.Verified,
				"skipped":    result.Skipped,
			}
			if warnMode {
				out["mode"] = "warn"
				out["exit_code_override"] = true
			}
			json.NewEncoder(os.Stdout).Encode(out)
		}
		if warnMode {
			fmt.Fprintf(os.Stderr, "\n⚠ %d action integrity violations detected (warn mode — not blocking)\n", len(result.Violations))
			return
		}
		fmt.Fprintf(os.Stderr, "\n✗ INTEGRITY VIOLATION: %d action tag(s) do not match manifest\n", len(result.Violations))
		fmt.Fprintf(os.Stderr, "  Job will not continue. Investigate immediately.\n")
		fmt.Fprintf(os.Stderr, "  Dashboard: https://github.com/%s/security\n", repo)
		os.Exit(2)
	}

	if jsonOutput {
		out := map[string]interface{}{
			"violations": []interface{}{},
			"verified":   result.Verified,
			"skipped":    result.Skipped,
		}
		if warnMode {
			out["mode"] = "warn"
		}
		json.NewEncoder(os.Stdout).Encode(out)
	}

	fmt.Fprintf(os.Stderr, "\n✓ All action integrity checks passed (%d verified, %d skipped, 0 violations) in %s\n",
		result.Verified, result.Skipped, result.Duration.Round(time.Millisecond))
}
