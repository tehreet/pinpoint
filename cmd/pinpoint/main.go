// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only
//
// Pinpoint detects GitHub Actions tag repointing attacks.
// It monitors the commit SHAs behind action version tags
// and alerts when they change — before malicious code executes.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/alert"
	"github.com/tehreet/pinpoint/internal/audit"
	"github.com/tehreet/pinpoint/internal/config"
	"github.com/tehreet/pinpoint/internal/discover"
	"github.com/tehreet/pinpoint/internal/gate"
	"github.com/tehreet/pinpoint/internal/inject"
	"github.com/tehreet/pinpoint/internal/manifest"
	"github.com/tehreet/pinpoint/internal/poller"
	"github.com/tehreet/pinpoint/internal/risk"
	"github.com/tehreet/pinpoint/internal/sarif"
	"github.com/tehreet/pinpoint/internal/store"
	"github.com/tehreet/pinpoint/internal/suppress"
	"github.com/tehreet/pinpoint/internal/verify"
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
	case "lock":
		cmdLock()
	case "verify":
		cmdVerify()
	case "manifest":
		cmdManifest()
	case "inject":
		cmdInject()
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
	sarifOutput := getFlag("output") == "sarif"
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
	emitter := alert.NewEmitter(!jsonOutput && !sarifOutput, cfg.Alerts.SlackWebhook, cfg.Alerts.WebhookURL)

	alerts, err := runScan(ctx, cfg, restClient, graphqlClient, stateStore, emitter, jsonOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	if err := stateStore.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
		os.Exit(1)
	}

	if sarifOutput {
		sarifStr, err := sarif.FormatScanSARIF(alerts, version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting SARIF: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(sarifStr)
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
	case "report", "config", "manifest", "json", "sarif":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid --output %q. Must be one of: report, config, manifest, json, sarif\n", output)
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
	case "sarif":
		sarifStr, err := sarif.FormatAuditSARIF(result, version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting SARIF: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(sarifStr)
	}
}

func cmdGate() {
	repo := getFlag("repo")
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if repo == "" {
		fmt.Fprintf(os.Stderr, "Error: --repo is required (or set GITHUB_REPOSITORY).\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned] [--integrity] [--on-disk] [--actions-dir <path>] [--skip-transitive] [--all-workflows]\n")
		os.Exit(1)
	}

	sha := getFlag("sha")
	if sha == "" {
		sha = os.Getenv("GITHUB_SHA")
	}
	if sha == "" {
		fmt.Fprintf(os.Stderr, "Error: --sha is required (or set GITHUB_SHA).\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned] [--integrity] [--on-disk] [--actions-dir <path>] [--skip-transitive] [--all-workflows]\n")
		os.Exit(1)
	}

	workflowRef := getFlag("workflow-ref")
	if workflowRef == "" {
		workflowRef = os.Getenv("GITHUB_WORKFLOW_REF")
	}
	allWorkflows := hasFlag("all-workflows")
	if !allWorkflows && os.Getenv("PINPOINT_GATE_ALL_WORKFLOWS") == "true" {
		allWorkflows = true
	}
	if workflowRef == "" && !allWorkflows {
		fmt.Fprintf(os.Stderr, "Error: --workflow-ref is required (or set GITHUB_WORKFLOW_REF), unless --all-workflows is set.\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned] [--integrity] [--on-disk] [--actions-dir <path>] [--skip-transitive] [--all-workflows]\n")
		os.Exit(1)
	}

	manifestPath := getFlag("manifest")
	failOnMissingExplicit := hasFlag("fail-on-missing")
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

	warnMode := hasFlag("warn")
	if !warnMode && os.Getenv("PINPOINT_GATE_WARN") == "true" {
		warnMode = true
	}
	jsonOutput := hasFlag("json")

	if warnMode {
		fmt.Fprintf(os.Stderr, "⚠ Running in warn mode — violations logged but not enforced\n")
	}

	eventName := os.Getenv("GITHUB_EVENT_NAME")
	baseRef := os.Getenv("GITHUB_BASE_REF")

	opts := gate.GateOptions{
		Repo:                   repo,
		SHA:                    sha,
		WorkflowRef:            workflowRef,
		ManifestPath:           manifestPath,
		Token:                  token,
		APIURL:                 apiURL,
		GraphQLURL:             graphqlURL,
		FailOnMissing:          failOnMissingExplicit,
		FailOnMissingExplicit:  failOnMissingExplicit,
		FailOnUnpinned:         hasFlag("fail-on-unpinned"),
		Integrity:              hasFlag("integrity"),
		SkipTransitive:         hasFlag("skip-transitive"),
		OnDisk:                 hasFlag("on-disk"),
		ActionsDir:             getFlag("actions-dir"),
		EventName:              eventName,
		BaseRef:                baseRef,
		AllWorkflows:           allWorkflows,
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

func cmdVerify() {
	workflowDir := getFlag("workflows")
	if workflowDir == "" {
		workflowDir = ".github/workflows"
	}

	outputFormat := getFlag("output")
	jsonOutput := outputFormat == "json"

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API rate limits will be very low (60/hour).\nSet GITHUB_TOKEN for authenticated access (5000 requests/hour).")
	}

	// Discover actions from workflow files
	refs, err := discover.FromWorkflowDir(workflowDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning workflows in %s: %v\n\nMake sure the directory exists and contains .yml/.yaml workflow files.\n", workflowDir, err)
		os.Exit(1)
	}

	if len(refs) == 0 {
		fmt.Fprintf(os.Stderr, "No GitHub Action references found in %s.\n\nMake sure your workflow files contain 'uses:' directives.\n", workflowDir)
		os.Exit(0)
	}

	// Build unique action inputs (dedup by repo+tag)
	seen := make(map[string]bool)
	var actions []verify.ActionInput
	for _, ref := range refs {
		key := ref.Full() + "@" + ref.Ref
		if seen[key] {
			continue
		}
		seen[key] = true
		actions = append(actions, verify.ActionInput{
			Repo: ref.Full(),
			Tag:  ref.Ref,
		})
	}

	fmt.Fprintf(os.Stderr, "pinpoint verify: checking %d action dependencies...\n", len(actions))

	graphqlEndpoint := os.Getenv("GITHUB_GRAPHQL_URL")
	if graphqlEndpoint == "" {
		graphqlEndpoint = "https://api.github.com/graphql"
	}
	restEndpoint := os.Getenv("GITHUB_API_URL")
	if restEndpoint == "" {
		restEndpoint = "https://api.github.com"
	}

	ctx := context.Background()
	result, err := verify.Verify(ctx, actions, verify.VerifyOptions{
		Token:           token,
		GraphQLEndpoint: graphqlEndpoint,
		RESTEndpoint:    restEndpoint,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verify error: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		jsonStr, err := verify.FormatJSON(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(jsonStr)
	} else {
		fmt.Fprint(os.Stderr, verify.FormatText(result))
	}

	if result.Failed > 0 {
		os.Exit(2)
	}
}

// runScan performs a single scan cycle across all configured actions.
func runScan(ctx context.Context, cfg *config.Config, restClient *poller.GitHubClient, graphqlClient *poller.GraphQLClient, stateStore *store.FileStore, emitter *alert.Emitter, jsonOutput bool) ([]risk.Alert, error) {
	var allAlerts []risk.Alert
	batchChanges := make(map[string]int)                     // repo → count of changes this cycle
	scoreContexts := make(map[string]risk.ScoreContext) // "repo@tag" → context for suppression

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
					scoreCtx.IsGPGSigned = commitInfo.GPGVerified

					// Conditional parent fetch: only when BACKDATED_COMMIT would fire
					if time.Since(commitInfo.CommitDate) > 30*24*time.Hour && commitInfo.ParentSHA != "" {
						parentInfo, parentErr := restClient.GetCommitInfo(ctx, owner, repo, commitInfo.ParentSHA)
						if parentErr == nil {
							scoreCtx.ParentSHA = commitInfo.ParentSHA
							scoreCtx.ParentDate = parentInfo.CommitDate
						}
					}
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
				scoreContexts[actionCfg.Repo+"@"+tag.Name] = scoreCtx

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

	// Apply allow-list suppression
	if len(cfg.AllowRules) > 0 {
		filterResult := suppress.Filter(allAlerts, cfg.AllowRules, scoreContexts)
		if len(filterResult.Suppressed) > 0 {
			fmt.Fprintf(os.Stderr, "%d alert(s) suppressed by allow-list rules.\n", len(filterResult.Suppressed))
			for _, s := range filterResult.Suppressed {
				fmt.Fprintf(os.Stderr, "  [suppressed] %s@%s repointed (rule: %q)\n", s.Alert.Action, s.Alert.Tag, s.Reason)
			}
		}
		allAlerts = filterResult.Allowed
	}

	// Emit all alerts (after mass repoint scoring and suppression)
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

func cmdLock() {
	lockfile := getFlag("lockfile")
	isLegacy := false
	if lockfile == "" {
		lockfile, isLegacy = manifest.ResolveLockfilePath(".")
	}

	workflowDir := getFlag("workflows")
	if workflowDir == "" {
		workflowDir = ".github/workflows"
	}

	if hasFlag("verify") {
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
				fmt.Fprintf(os.Stderr, "    lockfile: %s\n", shortSHA(c.OldSHA))
				fmt.Fprintf(os.Stderr, "    current:  %s  (resolved just now)\n", shortSHA(c.NewSHA))
			case "missing_tag":
				fmt.Fprintf(os.Stderr, "  ✗ %s@%s: TAG MISSING (was %s)\n", c.Action, c.Tag, shortSHA(c.OldSHA))
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

	if hasFlag("list") {
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
	if getFlag("lockfile") == "" {
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
		SkipDiskIntegrity: hasFlag("skip-disk-integrity"),
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
			fmt.Fprintf(os.Stderr, "  %s@%s: UPDATED %s → %s\n", c.Action, c.Tag, shortSHA(c.OldSHA), shortSHA(c.NewSHA))
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

func cmdInject() {
	file := getFlag("file")
	workflows := getFlag("workflows")
	pr := getFlag("pr")
	dryRun := hasFlag("dry-run")
	mode := getFlag("mode")
	if mode == "" {
		mode = "warn"
	}
	ver := getFlag("version")
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
		cmdInjectPR(pr, opts)
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

func cmdInjectPR(org string, opts inject.InjectOptions) {
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

	prTitle := getFlag("pr-title")
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
			fmt.Fprintf(os.Stderr, "  Error creating temp dir: %v\n", repo)
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
