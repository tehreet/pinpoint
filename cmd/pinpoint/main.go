// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only
//
// Pinpoint detects GitHub Actions tag repointing attacks.
// It monitors the commit SHAs behind action version tags
// and alerts when they change — before malicious code executes.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/alert"
	"github.com/tehreet/pinpoint/internal/audit"
	"github.com/tehreet/pinpoint/internal/config"
	"github.com/tehreet/pinpoint/internal/discover"
	"github.com/tehreet/pinpoint/internal/gate"
	"github.com/tehreet/pinpoint/internal/manifest"
	"github.com/tehreet/pinpoint/internal/poller"
	"github.com/tehreet/pinpoint/internal/risk"
	"github.com/tehreet/pinpoint/internal/store"
)

// version is set at build time via ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan()
	case "watch":
		cmdWatch()
	case "discover":
		cmdDiscover()
	case "audit":
		cmdAudit()
	case "gate":
		cmdGate()
	case "manifest":
		cmdManifest()
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
  pinpoint scan      --config <path>  [--state <path>]  [--json]  [--rest]
  pinpoint watch     --config <path>  [--state <path>]  [--interval 5m]  [--rest]
  pinpoint discover  --workflows <dir>
  pinpoint audit     --org <name>  [--output report|config|manifest|json]  [--skip-upstream]
  pinpoint gate      [--manifest <path>]  [--fail-on-missing]  [--fail-on-unpinned]
  pinpoint manifest  <refresh|verify|init>  [options]

COMMANDS:
  scan       One-shot: poll all monitored actions and report changes
  watch      Continuous: poll on interval, alert on changes
  discover   Scan workflow files and output actions to monitor
  audit      Scan an entire GitHub org and produce a security posture report
  gate       Pre-execution: verify action tag integrity before CI runs
  manifest   Manage the pinpoint manifest (refresh, verify, init)

ENVIRONMENT:
  GITHUB_TOKEN     GitHub personal access token (recommended)
  PINPOINT_CONFIG  Default config path (overridden by --config)

FLAGS:
  --rest  Force REST API mode (default: GraphQL with REST fallback)

`, version)
}

func getFlag(name string) string {
	for i, arg := range os.Args {
		if arg == "--"+name && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if strings.HasPrefix(arg, "--"+name+"=") {
			return strings.TrimPrefix(arg, "--"+name+"=")
		}
	}
	return ""
}

func hasFlag(name string) bool {
	for _, arg := range os.Args {
		if arg == "--"+name {
			return true
		}
	}
	return false
}

func cmdScan() {
	configPath := getFlag("config")
	if configPath == "" {
		configPath = os.Getenv("PINPOINT_CONFIG")
	}
	if configPath == "" {
		configPath = ".pinpoint.yml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	statePath := getFlag("state")
	if statePath == "" {
		statePath = cfg.Store.Path
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API rate limits will be very low (60/hour).")
	}

	jsonOutput := hasFlag("json")
	useREST := hasFlag("rest")

	ctx := context.Background()
	restClient := poller.NewGitHubClient(token)
	var graphqlClient *poller.GraphQLClient
	if !useREST {
		graphqlClient = poller.NewGraphQLClient(token)
	}
	stateStore, err := store.NewFileStore(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
		os.Exit(1)
	}
	emitter := alert.NewEmitter(!jsonOutput, cfg.Alerts.SlackWebhook, cfg.Alerts.WebhookURL)

	alerts, err := runScan(ctx, cfg, restClient, graphqlClient, stateStore, emitter, jsonOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	if err := stateStore.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
		os.Exit(1)
	}

	if len(alerts) > 0 {
		fmt.Fprintf(os.Stderr, "\n⚠ %d alert(s) detected.\n", len(alerts))
		os.Exit(2) // Non-zero exit for CI integration
	} else {
		fmt.Fprintf(os.Stderr, "✓ All %d tracked tags verified. No repointing detected.\n", stateStore.TagCount())
	}
}

func cmdWatch() {
	configPath := getFlag("config")
	if configPath == "" {
		configPath = ".pinpoint.yml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	statePath := getFlag("state")
	if statePath == "" {
		statePath = cfg.Store.Path
	}

	intervalStr := getFlag("interval")
	if intervalStr == "" {
		intervalStr = "5m"
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid interval %q: %v\n", intervalStr, err)
		os.Exit(1)
	}

	token := os.Getenv("GITHUB_TOKEN")
	useREST := hasFlag("rest")
	restClient := poller.NewGitHubClient(token)
	var graphqlClient *poller.GraphQLClient
	if !useREST {
		graphqlClient = poller.NewGraphQLClient(token)
	}
	stateStore, err := store.NewFileStore(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
		os.Exit(1)
	}
	emitter := alert.NewEmitter(true, cfg.Alerts.SlackWebhook, cfg.Alerts.WebhookURL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nShutting down...")
		cancel()
	}()

	mode := "GraphQL"
	if useREST {
		mode = "REST"
	}
	fmt.Fprintf(os.Stderr, "pinpoint watching (interval: %s, actions: %d, mode: %s)\n", interval, len(cfg.Actions), mode)
	fmt.Fprintln(os.Stderr, "Press Ctrl+C to stop.")

	// Initial scan
	runScan(ctx, cfg, restClient, graphqlClient, stateStore, emitter, false)
	stateStore.Save()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			stateStore.Save()
			return
		case <-ticker.C:
			runScan(ctx, cfg, restClient, graphqlClient, stateStore, emitter, false)
			stateStore.Save()
		}
	}
}

func cmdDiscover() {
	dir := getFlag("workflows")
	if dir == "" {
		dir = ".github/workflows"
	}

	refs, err := discover.FromWorkflowDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning workflows: %v\n", err)
		os.Exit(1)
	}

	if len(refs) == 0 {
		fmt.Fprintln(os.Stderr, "No GitHub Action references found.")
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr, discover.Summary(refs))

	if hasFlag("config") {
		fmt.Print(discover.GenerateConfig(refs))
	}
}

func cmdAudit() {
	org := getFlag("org")
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

	output := getFlag("output")
	if output == "" {
		output = "report"
	}
	switch output {
	case "report", "config", "manifest", "json":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid --output %q. Must be one of: report, config, manifest, json\n", output)
		os.Exit(1)
	}

	skipUpstream := hasFlag("skip-upstream")

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
	}
}

func cmdGate() {
	repo := getFlag("repo")
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if repo == "" {
		fmt.Fprintf(os.Stderr, "Error: --repo is required (or set GITHUB_REPOSITORY).\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned]\n")
		os.Exit(1)
	}

	sha := getFlag("sha")
	if sha == "" {
		sha = os.Getenv("GITHUB_SHA")
	}
	if sha == "" {
		fmt.Fprintf(os.Stderr, "Error: --sha is required (or set GITHUB_SHA).\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned]\n")
		os.Exit(1)
	}

	workflowRef := getFlag("workflow-ref")
	if workflowRef == "" {
		workflowRef = os.Getenv("GITHUB_WORKFLOW_REF")
	}
	if workflowRef == "" {
		fmt.Fprintf(os.Stderr, "Error: --workflow-ref is required (or set GITHUB_WORKFLOW_REF).\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned]\n")
		os.Exit(1)
	}

	manifestPath := getFlag("manifest")
	if manifestPath == "" {
		manifestPath = ".pinpoint-manifest.json"
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

	eventName := os.Getenv("GITHUB_EVENT_NAME")
	baseRef := os.Getenv("GITHUB_BASE_REF")

	opts := gate.GateOptions{
		Repo:           repo,
		SHA:            sha,
		WorkflowRef:    workflowRef,
		ManifestPath:   manifestPath,
		Token:          token,
		APIURL:         apiURL,
		GraphQLURL:     graphqlURL,
		FailOnMissing:  hasFlag("fail-on-missing"),
		FailOnUnpinned: hasFlag("fail-on-unpinned"),
		EventName:      eventName,
		BaseRef:        baseRef,
	}

	ctx := context.Background()
	result, err := gate.RunGate(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Gate error: %v\n", err)
		os.Exit(1)
	}

	if len(result.Violations) > 0 {
		fmt.Fprintf(os.Stderr, "\n✗ INTEGRITY VIOLATION: %d action tag(s) do not match manifest\n", len(result.Violations))
		fmt.Fprintf(os.Stderr, "  Job will not continue. Investigate immediately.\n")
		fmt.Fprintf(os.Stderr, "  Dashboard: https://github.com/%s/security\n", repo)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "\n✓ All action integrity checks passed (%d verified, %d skipped, 0 violations) in %s\n",
		result.Verified, result.Skipped, result.Duration.Round(time.Millisecond))
}

// runScan performs a single scan cycle across all configured actions.
func runScan(ctx context.Context, cfg *config.Config, restClient *poller.GitHubClient, graphqlClient *poller.GraphQLClient, stateStore *store.FileStore, emitter *alert.Emitter, jsonOutput bool) ([]risk.Alert, error) {
	var allAlerts []risk.Alert
	batchChanges := make(map[string]int) // repo → count of changes this cycle

	// Collect valid repos for batching
	validActions := make([]config.ActionConfig, 0, len(cfg.Actions))
	for _, actionCfg := range cfg.Actions {
		if actionCfg.Discover || actionCfg.Repo == "" {
			continue
		}
		parts := strings.SplitN(actionCfg.Repo, "/", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Warning: invalid repo %q, skipping\n", actionCfg.Repo)
			continue
		}
		validActions = append(validActions, actionCfg)
	}

	// Fetch tags: GraphQL batch or REST per-repo
	fetchResults := make(map[string]*poller.FetchResult)

	if graphqlClient != nil {
		repos := make([]string, len(validActions))
		for i, a := range validActions {
			repos[i] = a.Repo
		}

		results, err := graphqlClient.FetchTagsBatch(ctx, repos)
		if err != nil {
			// Failover to REST
			fmt.Fprintf(os.Stderr, "⚠ GraphQL unavailable (%v). Falling back to REST.\n", err)
			fetchResults = fetchTagsREST(ctx, restClient, validActions, stateStore)
		} else {
			fetchResults = results
		}
	} else {
		fetchResults = fetchTagsREST(ctx, restClient, validActions, stateStore)
	}

	for _, actionCfg := range validActions {
		result, ok := fetchResults[actionCfg.Repo]
		if !ok || result == nil {
			continue
		}

		if result.NotModified {
			continue // Nothing changed (REST ETag)
		}

		if result.ETag != "" {
			stateStore.SetRepoETag(actionCfg.Repo, result.ETag)
		}

		parts := strings.SplitN(actionCfg.Repo, "/", 2)
		owner, repo := parts[0], parts[1]

		// Build set of current tags for deletion detection
		currentTags := make(map[string]bool)

		for _, tag := range result.Tags {
			// Filter to configured tags unless monitoring all
			if !actionCfg.AllTags {
				found := false
				for _, t := range actionCfg.Tags {
					if t == tag.Name {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			currentTags[tag.Name] = true

			changed, previousSHA := stateStore.RecordTag(actionCfg.Repo, tag.Name, tag.CommitSHA, tag.TagSHA)
			if changed {
				batchChanges[actionCfg.Repo]++

				// Build scoring context
				scoreCtx := risk.ScoreContext{
					TagName:    tag.Name,
					SelfHosted: actionCfg.SelfHostedRunners,
					BatchSize:  1, // Updated after all tags processed
				}

				// Enrichment: check commit ancestry
				isDesc, ahead, behind, err := restClient.CompareCommits(ctx, owner, repo, previousSHA, tag.CommitSHA)
				if err == nil {
					scoreCtx.IsDescendant = isDesc
					scoreCtx.AheadBy = ahead
					scoreCtx.BehindBy = behind
				}

				// Enrichment: commit info
				commitInfo, err := restClient.GetCommitInfo(ctx, owner, repo, tag.CommitSHA)
				if err == nil {
					scoreCtx.CommitAuthor = commitInfo.AuthorName
					scoreCtx.CommitEmail = commitInfo.AuthorEmail
					scoreCtx.CommitDate = commitInfo.CommitDate
				}

				// Enrichment: entry point size (check common paths)
				for _, path := range []string{"entrypoint.sh", "dist/index.js", "action.yml"} {
					oldSize, _ := restClient.GetFileSize(ctx, owner, repo, path, previousSHA)
					newSize, _ := restClient.GetFileSize(ctx, owner, repo, path, tag.CommitSHA)
					if oldSize > 0 && newSize > 0 {
						scoreCtx.EntryPointOld = oldSize
						scoreCtx.EntryPointNew = newSize
						break
					}
				}

				severity, signals := risk.Score(scoreCtx)

				a := risk.Alert{
					Severity:    severity,
					Type:        "TAG_REPOINTED",
					Action:      actionCfg.Repo,
					Tag:         tag.Name,
					PreviousSHA: previousSHA,
					CurrentSHA:  tag.CommitSHA,
					DetectedAt:  time.Now().UTC(),
					Signals:     signals,
					SelfHosted:  actionCfg.SelfHostedRunners,
					Enrichment:  make(map[string]string),
				}

				if commitInfo != nil {
					a.Enrichment["commit_author"] = fmt.Sprintf("%s <%s>", commitInfo.AuthorName, commitInfo.AuthorEmail)
					a.Enrichment["commit_date"] = commitInfo.CommitDate.Format(time.RFC3339)
					a.Enrichment["commit_message"] = truncate(commitInfo.Message, 100)
				}

				allAlerts = append(allAlerts, a)
			}
		}

		// Detect deleted tags
		if !actionCfg.AllTags {
			for _, t := range actionCfg.Tags {
				if !currentTags[t] {
					actionState := stateStore.GetActionState(actionCfg.Repo)
					if _, exists := actionState.Tags[t]; exists {
						stateStore.RecordDeletedTag(actionCfg.Repo, t)
						a := risk.Alert{
							Severity:   risk.SeverityMedium,
							Type:       "TAG_DELETED",
							Action:     actionCfg.Repo,
							Tag:        t,
							DetectedAt: time.Now().UTC(),
							Signals:    []string{"TAG_DELETED: previously tracked tag no longer exists"},
							SelfHosted: actionCfg.SelfHostedRunners,
						}
						allAlerts = append(allAlerts, a)
					}
				}
			}
		}
	}

	// Second pass: update batch sizes and re-score if mass repointing detected
	for repo, count := range batchChanges {
		if count > 5 {
			for i := range allAlerts {
				if allAlerts[i].Action == repo {
					allAlerts[i].Severity = risk.SeverityCritical
					allAlerts[i].Signals = append(allAlerts[i].Signals,
						fmt.Sprintf("MASS_REPOINT: %d tags repointed in same scan cycle", count))
				}
			}
		}
	}

	// Emit all alerts (after mass repoint scoring has been applied)
	var filteredAlerts []risk.Alert
	for _, a := range allAlerts {
		if risk.MeetsThreshold(a.Severity, cfg.Alerts.MinSeverity) {
			filteredAlerts = append(filteredAlerts, a)
			if jsonOutput {
				j, _ := alert.FormatJSON(a)
				fmt.Println(j)
			} else {
				emitter.Emit(a)
			}
		}
	}

	return filteredAlerts, nil
}

// fetchTagsREST fetches tags for each repo individually using the REST API.
func fetchTagsREST(ctx context.Context, client *poller.GitHubClient, actions []config.ActionConfig, stateStore *store.FileStore) map[string]*poller.FetchResult {
	results := make(map[string]*poller.FetchResult)
	for _, actionCfg := range actions {
		parts := strings.SplitN(actionCfg.Repo, "/", 2)
		owner, repo := parts[0], parts[1]
		actionState := stateStore.GetActionState(actionCfg.Repo)

		result, err := client.FetchAllTags(ctx, owner, repo, actionState.RepoETag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching %s: %v\n", actionCfg.Repo, err)
			continue
		}
		results[actionCfg.Repo] = result
	}
	return results
}

func cmdManifest() {
	if len(os.Args) < 3 {
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

	switch os.Args[2] {
	case "refresh":
		cmdManifestRefresh()
	case "verify":
		cmdManifestVerify()
	case "init":
		cmdManifestInit()
	case "help", "-h", "--help":
		fmt.Fprintf(os.Stderr, `Usage:
  pinpoint manifest refresh  --manifest <path>  --workflows <dir>  [--discover]
  pinpoint manifest verify   --manifest <path>
  pinpoint manifest init
`)
	default:
		fmt.Fprintf(os.Stderr, "Unknown manifest subcommand: %s\n\nRun 'pinpoint manifest' for usage.\n", os.Args[2])
		os.Exit(1)
	}
}

func cmdManifestRefresh() {
	manifestPath := getFlag("manifest")
	if manifestPath == "" {
		manifestPath = ".pinpoint-manifest.json"
	}

	workflowDir := getFlag("workflows")
	if workflowDir == "" {
		workflowDir = ".github/workflows"
	}

	doDiscover := hasFlag("discover")

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
			fmt.Fprintf(os.Stderr, "  %s@%s: UPDATED %s → %s (tag advanced)\n", c.Action, c.Tag, shortSHA(c.OldSHA), shortSHA(c.NewSHA))
		case "added":
			source := ""
			if c.Source != "" {
				source = fmt.Sprintf(" (discovered from %s)", c.Source)
			}
			fmt.Fprintf(os.Stderr, "  + %s@%s: NEW%s\n", c.Action, c.Tag, source)
		case "missing_tag":
			fmt.Fprintf(os.Stderr, "  ! %s@%s: WARNING tag no longer exists on remote (keeping old SHA %s)\n", c.Action, c.Tag, shortSHA(c.OldSHA))
		}
	}

	// Summary
	fmt.Fprintf(os.Stderr, "\nManifest updated: %d changed, %d added, %d unchanged.\n",
		result.Updated, result.Added, result.Unchanged)

	if result.Updated > 0 || result.Added > 0 {
		os.Exit(3)
	}
}

func cmdManifestVerify() {
	manifestPath := getFlag("manifest")
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
			fmt.Fprintf(os.Stderr, "    manifest: %s\n", shortSHA(c.OldSHA))
			fmt.Fprintf(os.Stderr, "    current:  %s  (resolved just now)\n", shortSHA(c.NewSHA))
		case "missing_tag":
			fmt.Fprintf(os.Stderr, "  ✗ %s@%s: TAG MISSING (was %s)\n", c.Action, c.Tag, shortSHA(c.OldSHA))
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
	manifestPath := ".pinpoint-manifest.json"
	refreshPath := ".github/workflows/pinpoint-refresh.yml"
	gatePath := ".github/workflows/pinpoint-gate.yml"

	// Check for existing files
	for _, path := range []string{manifestPath, refreshPath, gatePath} {
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(os.Stderr, "File already exists: %s\nRemove it first or use 'pinpoint manifest refresh' to update.\n", path)
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
  1. Populate the manifest:  pinpoint manifest refresh --manifest %s --workflows .github/workflows/ --discover
  2. Commit all three files
  3. The refresh workflow will run weekly to keep the manifest current
`, manifestPath)
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7] + "..."
	}
	return sha
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
