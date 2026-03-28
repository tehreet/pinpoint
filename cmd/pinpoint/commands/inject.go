// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/inject"
)

// CmdInject injects pinpoint gate steps into workflow files.
func CmdInject(args []string) {
	file := GetFlag(args, "file")
	workflows := GetFlag(args, "workflows")
	pr := GetFlag(args, "pr")
	dryRun := HasFlag(args, "dry-run")
	mode := GetFlag(args, "mode")
	if mode == "" {
		mode = "warn"
	}
	ver := GetFlag(args, "version")
	if ver == "" {
		ver = "v1"
	}

	// Validate: need at least one of --file, --workflows, or --pr
	if file == "" && workflows == "" && pr == "" {
		fmt.Fprintf(os.Stderr, `Error: specify --file, --workflows, or --pr.

Usage:
  pinpoint inject --file <path>                    Inject into a single workflow file
  pinpoint inject --workflows <dir>                Inject into all workflows in directory
  pinpoint inject --pr <org>                       Open PRs across all repos in an org

Options:
  --dry-run              Preview changes without writing files
  --mode warn|enforce    Gate mode (default: warn)
  --version <tag>        Pinpoint action version (default: v1)
  --pr-title <title>     Custom PR title
`)
		os.Exit(1)
	}

	opts := inject.InjectOptions{
		Mode:    mode,
		Version: ver,
		DryRun:  dryRun,
	}

	if pr != "" {
		cmdInjectPR(args, pr, opts)
		return
	}

	if file != "" {
		result, err := inject.InjectFile(file, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if dryRun {
			fmt.Print(result.Output)
		}
		if result.Modified {
			fmt.Fprintf(os.Stderr, "✓ %s: injected into %d/%d jobs\n", result.File, result.JobsInjected, result.JobsFound)
		} else {
			fmt.Fprintf(os.Stderr, "✓ %s: no changes needed (%d jobs already have pinpoint-action)\n", result.File, result.JobsSkipped)
		}
		return
	}

	// --workflows mode
	results, err := inject.InjectDir(workflows, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	totalFiles := len(results)
	modifiedFiles := 0
	totalInjected := 0
	totalSkipped := 0
	for _, r := range results {
		if r.Modified {
			modifiedFiles++
		}
		totalInjected += r.JobsInjected
		totalSkipped += r.JobsSkipped
		if dryRun {
			fmt.Print(r.Output)
		}
		if r.Modified {
			fmt.Fprintf(os.Stderr, "  ✓ %s: injected into %d/%d jobs\n", filepath.Base(r.File), r.JobsInjected, r.JobsFound)
		} else if r.JobsSkipped > 0 {
			fmt.Fprintf(os.Stderr, "  · %s: no changes needed\n", filepath.Base(r.File))
		}
	}
	fmt.Fprintf(os.Stderr, "\n✓ Processed %d files: %d modified, %d jobs injected, %d already had pinpoint-action\n",
		totalFiles, modifiedFiles, totalInjected, totalSkipped)
}

func cmdInjectPR(args []string, org string, opts inject.InjectOptions) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintf(os.Stderr, `Error: GITHUB_TOKEN is required for PR mode.

Set a token with repo access:
  export GITHUB_TOKEN=ghp_...

Create a token at: https://github.com/settings/tokens
Required scopes: repo
`)
		os.Exit(1)
	}

	prTitle := GetFlag(args, "pr-title")
	if prTitle == "" {
		prTitle = "ci: add Pinpoint Gate to workflow steps"
	}

	prBody := `## Pinpoint Gate — TOCTOU-safe GitHub Actions monitoring

This PR adds [Pinpoint Gate](https://github.com/tehreet/pinpoint) as the first step
in each workflow job to verify action tag integrity before execution.

Pinpoint detects tag repointing attacks (like the March 2026 Trivy incident) by
checking that action tags still point to the same commit SHA at execution time.

**Mode:** ` + opts.Mode + `
**No action required** — this step runs in seconds and does not affect existing jobs.
`

	// List all repos in the org
	fmt.Fprintf(os.Stderr, "Listing repos in org %q...\n", org)
	listCmd := exec.Command("gh", "api", fmt.Sprintf("/orgs/%s/repos", org), "--paginate", "--jq", ".[].full_name")
	listOut, err := listCmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing repos: %v\n", err)
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			fmt.Fprintf(os.Stderr, "  gh stderr: %s\n", string(exitErr.Stderr))
		}
		fmt.Fprintf(os.Stderr, "\nEnsure 'gh' CLI is installed and authenticated:\n  gh auth login\n")
		os.Exit(1)
	}

	repos := strings.Split(strings.TrimSpace(string(listOut)), "\n")
	if len(repos) == 0 || (len(repos) == 1 && repos[0] == "") {
		fmt.Fprintf(os.Stderr, "No repos found in org %q\n", org)
		return
	}

	branch := fmt.Sprintf("pinpoint-inject-%d", time.Now().Unix())

	opened := 0
	skipped := 0
	failed := 0

	for _, repo := range repos {
		repo = strings.TrimSpace(repo)
		if repo == "" {
			continue
		}

		fmt.Fprintf(os.Stderr, "\n--- %s ---\n", repo)

		// Create temp dir
		tmpdir, err := os.MkdirTemp("", "pinpoint-inject-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error creating temp dir: %v\n", err)
			failed++
			continue
		}

		// Shallow clone
		cloneCmd := exec.Command("gh", "repo", "clone", repo, tmpdir, "--", "--depth", "1")
		if cloneOut, err := cloneCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "  Clone failed: %v\n  %s\n", err, string(cloneOut))
			os.RemoveAll(tmpdir)
			failed++
			continue
		}

		// Check if workflows dir exists
		workflowsDir := filepath.Join(tmpdir, ".github", "workflows")
		if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "  Skipped: no .github/workflows/ directory\n")
			os.RemoveAll(tmpdir)
			skipped++
			continue
		}

		// Inject with DryRun=false
		injectOpts := inject.InjectOptions{
			Mode:    opts.Mode,
			Version: opts.Version,
			DryRun:  false,
		}
		results, err := inject.InjectDir(workflowsDir, injectOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Inject error: %v\n", err)
			os.RemoveAll(tmpdir)
			failed++
			continue
		}

		// Check if any files were modified
		anyModified := false
		for _, r := range results {
			if r.Modified {
				anyModified = true
				break
			}
		}
		if !anyModified {
			fmt.Fprintf(os.Stderr, "  Skipped: no changes needed (all jobs already have pinpoint-action)\n")
			os.RemoveAll(tmpdir)
			skipped++
			continue
		}

		// Create branch
		checkoutCmd := exec.Command("git", "-C", tmpdir, "checkout", "-b", branch)
		if out, err := checkoutCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "  Branch creation failed: %v\n  %s\n", err, string(out))
			os.RemoveAll(tmpdir)
			failed++
			continue
		}

		// Stage changes
		addCmd := exec.Command("git", "-C", tmpdir, "add", ".github/workflows/")
		if out, err := addCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "  Git add failed: %v\n  %s\n", err, string(out))
			os.RemoveAll(tmpdir)
			failed++
			continue
		}

		// Commit
		commitCmd := exec.Command("git", "-C", tmpdir, "commit", "-m", prTitle)
		if out, err := commitCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "  Git commit failed: %v\n  %s\n", err, string(out))
			os.RemoveAll(tmpdir)
			failed++
			continue
		}

		// Push
		pushCmd := exec.Command("git", "-C", tmpdir, "push", "-u", "origin", branch)
		if out, err := pushCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "  Git push failed: %v\n  %s\n", err, string(out))
			os.RemoveAll(tmpdir)
			failed++
			continue
		}

		// Open PR
		prCmd := exec.Command("gh", "pr", "create", "-R", repo, "--title", prTitle, "--body", prBody, "--head", branch)
		prOut, err := prCmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  PR creation failed: %v\n  %s\n", err, string(prOut))
			os.RemoveAll(tmpdir)
			failed++
			continue
		}

		prURL := strings.TrimSpace(string(prOut))
		fmt.Fprintf(os.Stderr, "  ✓ Opened PR: %s\n", prURL)
		opened++

		os.RemoveAll(tmpdir)
	}

	totalRepos := opened + skipped + failed
	fmt.Fprintf(os.Stderr, "\nOpened %d PRs across %d repos (%d skipped)\n", opened, totalRepos, skipped)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "  %d repos failed — see errors above\n", failed)
	}
}
