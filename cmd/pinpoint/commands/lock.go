// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tehreet/pinpoint/internal/manifest"
	"github.com/tehreet/pinpoint/internal/poller"
	"github.com/tehreet/pinpoint/internal/util"
)

// CmdLock generates or updates the lockfile.
func CmdLock(args []string) {
	lockfile := GetFlag(args, "lockfile")
	isLegacy := false
	if lockfile == "" {
		lockfile, isLegacy = manifest.ResolveLockfilePath(".")
	}

	workflowDir := GetFlag(args, "workflows")
	if workflowDir == "" {
		workflowDir = ".github/workflows"
	}

	if HasFlag(args, "verify") {
		// Delegate to manifest verify logic using the resolved lockfile path
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API rate limits will be very low (60/hour).\nSet GITHUB_TOKEN for authenticated access (5000 requests/hour).")
		}

		client := poller.NewGraphQLClient(token)
		ctx := context.Background()
		fmt.Fprintf(os.Stderr, "Verifying lockfile (%s)...\n", lockfile)

		result, err := manifest.Verify(ctx, lockfile, client)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		total := result.Unchanged + result.Updated + result.Missing
		drifted := result.Updated + result.Missing

		for _, c := range result.Changes {
			switch c.Type {
			case "updated":
				fmt.Fprintf(os.Stderr, "  ✗ %s@%s: DRIFTED\n", c.Action, c.Tag)
				fmt.Fprintf(os.Stderr, "    lockfile: %s\n", util.ShortSHA(c.OldSHA))
				fmt.Fprintf(os.Stderr, "    current:  %s  (resolved just now)\n", util.ShortSHA(c.NewSHA))
			case "missing_tag":
				fmt.Fprintf(os.Stderr, "  ✗ %s@%s: TAG MISSING (was %s)\n", c.Action, c.Tag, util.ShortSHA(c.OldSHA))
			}
		}

		if drifted == 0 {
			fmt.Fprintf(os.Stderr, "\n✓ All %d tags match lockfile.\n", total)
		} else {
			fmt.Fprintf(os.Stderr, "\n✗ Lockfile drift detected: %d of %d tags have changed.\n", drifted, total)
			fmt.Fprintf(os.Stderr, "  Run: pinpoint lock\n")
			os.Exit(3)
		}
		return
	}

	if HasFlag(args, "list") {
		m, err := manifest.LoadManifest(lockfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		manifest.PrintDependencyTree(m, lockfile, os.Stdout)
		return
	}

	// Default: refresh/generate lockfile with discover=true
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API rate limits will be very low (60/hour).\nSet GITHUB_TOKEN for authenticated access (5000 requests/hour).")
	}

	// The lock command always writes to .github/actions-lock.json unless --lockfile overrides.
	outputPath := lockfile
	if GetFlag(args, "lockfile") == "" {
		outputPath = filepath.Join(".", manifest.DefaultLockfilePath)
	}

	// If the resolved path was legacy but output is the new path, read from legacy first
	if isLegacy && outputPath == filepath.Join(".", manifest.DefaultLockfilePath) {
		fmt.Fprintf(os.Stderr, "ℹ Migrating from %s to %s\n", manifest.LegacyManifestPath, manifest.DefaultLockfilePath)
		// Copy legacy manifest content to new location so Refresh reads existing entries
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
			os.Exit(1)
		}
		data, err := os.ReadFile(lockfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading legacy manifest: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing lockfile: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ensure .github/ directory exists
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
			os.Exit(1)
		}
		// If lockfile doesn't exist yet, create an empty one so Refresh can read it
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			m := &manifest.Manifest{
				Version: 1,
				Actions: make(map[string]map[string]manifest.ManifestEntry),
			}
			if err := manifest.SaveManifest(outputPath, m); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating lockfile: %v\n", err)
				os.Exit(1)
			}
		}
	}

	apiURL := os.Getenv("GITHUB_API_URL")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	graphqlURL := os.Getenv("GITHUB_GRAPHQL_URL")
	if graphqlURL == "" {
		graphqlURL = "https://api.github.com/graphql"
	}

	client := poller.NewGraphQLClient(token)
	ctx := context.Background()
	fmt.Fprintf(os.Stderr, "Generating lockfile (%s)...\n", outputPath)

	iOpts := &manifest.IntegrityOptions{
		HTTPClient:        &http.Client{Timeout: 60 * time.Second},
		BaseURL:           apiURL,
		GraphQLURL:        graphqlURL,
		Token:             token,
		SkipDiskIntegrity: HasFlag(args, "skip-disk-integrity"),
		RegistryClient: &manifest.RegistryClient{
			HTTP: &http.Client{Timeout: 30 * time.Second},
		},
	}

	result, err := manifest.Refresh(ctx, outputPath, workflowDir, true, client, iOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print per-change details
	for _, c := range result.Changes {
		switch c.Type {
		case "updated":
			fmt.Fprintf(os.Stderr, "  %s@%s: UPDATED %s → %s\n", c.Action, c.Tag, util.ShortSHA(c.OldSHA), util.ShortSHA(c.NewSHA))
		case "added":
			source := ""
			if c.Source != "" {
				source = fmt.Sprintf(" (from %s)", c.Source)
			}
			fmt.Fprintf(os.Stderr, "  + %s@%s: NEW%s\n", c.Action, c.Tag, source)
		case "missing_tag":
			fmt.Fprintf(os.Stderr, "  ! %s@%s: WARNING tag no longer exists on remote\n", c.Action, c.Tag)
		}
	}

	totalActions := result.Unchanged + result.Updated + result.Added
	fmt.Fprintf(os.Stderr, "\n✓ Lockfile written: %s (%d actions)\n", outputPath, totalActions)

	if isLegacy && outputPath == filepath.Join(".", manifest.DefaultLockfilePath) {
		fmt.Fprintf(os.Stderr, "ℹ You can now remove %s\n", manifest.LegacyManifestPath)
	}

	if result.Updated > 0 || result.Added > 0 {
		os.Exit(3)
	}
}

// CmdManifest handles the manifest subcommands (refresh, verify, init).
func CmdManifest(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage:
  pinpoint manifest refresh  --manifest <path>  --workflows <dir>  [--discover]
  pinpoint manifest verify   --manifest <path>
  pinpoint manifest init

SUBCOMMANDS:
  refresh   Update manifest with current tag SHAs (exit 0=no changes, 3=changes written)
  verify    Check manifest against live tags without modifying (exit 0=match, 3=drift)
  init      Write starter manifest and workflow files to current directory
`)
		os.Exit(1)
	}

	switch args[0] {
	case "refresh":
		cmdManifestRefresh(args[1:])
	case "verify":
		cmdManifestVerify(args[1:])
	case "init":
		cmdManifestInit()
	case "help", "-h", "--help":
		fmt.Fprintf(os.Stderr, `Usage:
  pinpoint manifest refresh  --manifest <path>  --workflows <dir>  [--discover]
  pinpoint manifest verify   --manifest <path>
  pinpoint manifest init
`)
	default:
		fmt.Fprintf(os.Stderr, "Unknown manifest subcommand: %s\n\nRun 'pinpoint manifest' for usage.\n", args[0])
		os.Exit(1)
	}
}

func cmdManifestRefresh(args []string) {
	manifestPath := GetFlag(args, "manifest")
	if manifestPath == "" {
		manifestPath = ".pinpoint-manifest.json"
	}

	workflowDir := GetFlag(args, "workflows")
	if workflowDir == "" {
		workflowDir = ".github/workflows"
	}

	doDiscover := HasFlag(args, "discover")

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API rate limits will be very low (60/hour).\nSet GITHUB_TOKEN for authenticated access (5000 requests/hour).")
	}

	client := poller.NewGraphQLClient(token)

	ctx := context.Background()
	fmt.Fprintf(os.Stderr, "Refreshing manifest (%s)...\n", manifestPath)

	result, err := manifest.Refresh(ctx, manifestPath, workflowDir, doDiscover, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print per-change details
	for _, c := range result.Changes {
		switch c.Type {
		case "updated":
			fmt.Fprintf(os.Stderr, "  %s@%s: UPDATED %s → %s (tag advanced)\n", c.Action, c.Tag, util.ShortSHA(c.OldSHA), util.ShortSHA(c.NewSHA))
		case "added":
			source := ""
			if c.Source != "" {
				source = fmt.Sprintf(" (discovered from %s)", c.Source)
			}
			fmt.Fprintf(os.Stderr, "  + %s@%s: NEW%s\n", c.Action, c.Tag, source)
		case "missing_tag":
			fmt.Fprintf(os.Stderr, "  ! %s@%s: WARNING tag no longer exists on remote (keeping old SHA %s)\n", c.Action, c.Tag, util.ShortSHA(c.OldSHA))
		}
	}

	// Summary
	fmt.Fprintf(os.Stderr, "\nManifest updated: %d changed, %d added, %d unchanged.\n",
		result.Updated, result.Added, result.Unchanged)

	if result.Updated > 0 || result.Added > 0 {
		os.Exit(3)
	}
}

func cmdManifestVerify(args []string) {
	manifestPath := GetFlag(args, "manifest")
	if manifestPath == "" {
		manifestPath = ".pinpoint-manifest.json"
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API rate limits will be very low (60/hour).\nSet GITHUB_TOKEN for authenticated access (5000 requests/hour).")
	}

	client := poller.NewGraphQLClient(token)

	ctx := context.Background()
	fmt.Fprintf(os.Stderr, "Verifying manifest (%s)...\n", manifestPath)

	result, err := manifest.Verify(ctx, manifestPath, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	total := result.Unchanged + result.Updated + result.Missing
	drifted := result.Updated + result.Missing

	for _, c := range result.Changes {
		switch c.Type {
		case "updated":
			fmt.Fprintf(os.Stderr, "  ✗ %s@%s: DRIFTED\n", c.Action, c.Tag)
			fmt.Fprintf(os.Stderr, "    manifest: %s\n", util.ShortSHA(c.OldSHA))
			fmt.Fprintf(os.Stderr, "    current:  %s  (resolved just now)\n", util.ShortSHA(c.NewSHA))
		case "missing_tag":
			fmt.Fprintf(os.Stderr, "  ✗ %s@%s: TAG MISSING (was %s)\n", c.Action, c.Tag, util.ShortSHA(c.OldSHA))
		}
	}

	// Print matches
	if drifted == 0 {
		fmt.Fprintf(os.Stderr, "\n✓ All %d tags match manifest.\n", total)
	} else {
		fmt.Fprintf(os.Stderr, "\n✗ Manifest drift detected: %d of %d tags have changed.\n", drifted, total)
		fmt.Fprintf(os.Stderr, "  Run: pinpoint manifest refresh --manifest %s\n", manifestPath)
		os.Exit(3)
	}
}

func cmdManifestInit() {
	manifestPath := manifest.DefaultLockfilePath
	refreshPath := ".github/workflows/pinpoint-refresh.yml"
	gatePath := ".github/workflows/pinpoint-gate.yml"

	// Check for existing files
	for _, path := range []string{manifestPath, refreshPath, gatePath} {
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(os.Stderr, "File already exists: %s\nRemove it first or use 'pinpoint lock' to update.\n", path)
			os.Exit(1)
		}
	}

	// Ensure .github/workflows/ exists
	if err := os.MkdirAll(".github/workflows", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating workflow directory: %v\n", err)
		os.Exit(1)
	}

	// Write empty manifest
	m := &manifest.Manifest{
		Version: 1,
		Actions: make(map[string]map[string]manifest.ManifestEntry),
	}
	if err := manifest.SaveManifest(manifestPath, m); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing manifest: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  ✓ Created %s\n", manifestPath)

	// Write refresh workflow
	if err := os.WriteFile(refreshPath, []byte(manifest.RefreshWorkflowTemplate), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing workflow: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  ✓ Created %s\n", refreshPath)

	// Write gate workflow
	if err := os.WriteFile(gatePath, []byte(manifest.GateWorkflowTemplate), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing workflow: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  ✓ Created %s\n", gatePath)

	fmt.Fprintf(os.Stderr, `
Next steps:
  1. Populate the lockfile:  pinpoint lock
  2. Commit all three files
  3. The refresh workflow will run weekly to keep the lockfile current
`)
}

