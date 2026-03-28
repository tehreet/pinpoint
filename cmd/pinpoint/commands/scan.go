// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/alert"
	"github.com/tehreet/pinpoint/internal/config"
	"github.com/tehreet/pinpoint/internal/manifest"
	"github.com/tehreet/pinpoint/internal/poller"
	"github.com/tehreet/pinpoint/internal/risk"
	"github.com/tehreet/pinpoint/internal/sarif"
	"github.com/tehreet/pinpoint/internal/store"
	"github.com/tehreet/pinpoint/internal/suppress"
)

// CmdScan performs a one-shot scan of all configured actions.
func CmdScan(args []string) {
	configPath := GetFlag(args, "config")
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

	statePath := GetFlag(args, "state")
	if statePath == "" {
		statePath = cfg.Store.Path
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Warning: GITHUB_TOKEN not set. API rate limits will be very low (60/hour).")
	}

	jsonOutput := HasFlag(args, "json")
	sarifOutput := GetFlag(args, "output") == "sarif"
	useREST := HasFlag(args, "rest")

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
		sarifStr, err := sarif.FormatScanSARIF(alerts, Version)
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

// CmdWatch runs continuous scanning on an interval.
func CmdWatch(args []string) {
	configPath := GetFlag(args, "config")
	if configPath == "" {
		configPath = ".pinpoint.yml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	statePath := GetFlag(args, "state")
	if statePath == "" {
		statePath = cfg.Store.Path
	}

	intervalStr := GetFlag(args, "interval")
	if intervalStr == "" {
		intervalStr = "5m"
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid interval %q: %v\n", intervalStr, err)
		os.Exit(1)
	}

	token := os.Getenv("GITHUB_TOKEN")
	useREST := HasFlag(args, "rest")
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

// runScan performs a single scan cycle across all configured actions.
func runScan(ctx context.Context, cfg *config.Config, restClient *poller.GitHubClient, graphqlClient *poller.GraphQLClient, stateStore *store.FileStore, emitter *alert.Emitter, jsonOutput bool) ([]risk.Alert, error) {
	var allAlerts []risk.Alert
	batchChanges := make(map[string]int)                 // repo -> count of changes this cycle
	scoreContexts := make(map[string]risk.ScoreContext)  // "repo@tag" -> context for suppression

	// Load lockfile for behavioral baseline data (spec 025)
	lockfilePath, _ := manifest.ResolveLockfilePath(".")
	behavioralManifest, behavioralLoadErr := manifest.LoadManifest(lockfilePath)
	lockfileExists := behavioralLoadErr == nil
	behavioralUpdated := false

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
				var compareResult *poller.CompareResult
				var err error
				compareResult, err = restClient.CompareCommits(ctx, owner, repo, previousSHA, tag.CommitSHA)
				if err == nil {
					scoreCtx.IsDescendant = compareResult.IsDescendant
					scoreCtx.AheadBy = compareResult.AheadBy
					scoreCtx.BehindBy = compareResult.BehindBy

					// Behavioral enrichment: diff anomaly (spec 025)
					scoreCtx.SuspiciousFiles, scoreCtx.DiffOnly = risk.ClassifyDiffFiles(compareResult.Files)

					// Behavioral enrichment from lockfile (spec 025)
					if lockfileExists {
						if tags, ok := behavioralManifest.Actions[actionCfg.Repo]; ok {
							if entry, ok := tags[tag.Name]; ok {
								// Contributor anomaly: three-state semantics for NewContributors:
								//   nil = first lock (no baseline), signal skipped
								//   []string{} = all authors known, signal skipped
								//   non-empty = new contributors found, signal fires (+35)
								if len(entry.KnownContributors) > 0 {
									known := make(map[string]bool)
									for _, c := range entry.KnownContributors {
										known[c] = true
									}
									for _, login := range compareResult.AuthorLogins {
										if !known[login] {
											scoreCtx.NewContributors = append(scoreCtx.NewContributors, login)
										}
									}
									if scoreCtx.NewContributors == nil {
										scoreCtx.NewContributors = []string{} // empty = all known
									}
								}

								// Release cadence anomaly
								if len(entry.ReleaseHistory) >= 3 {
									scoreCtx.ReleaseHistoryLen = len(entry.ReleaseHistory)
									scoreCtx.MeanReleaseInterval = ComputeMeanInterval(entry.ReleaseHistory)
									if last, parseErr := time.Parse(time.RFC3339, entry.ReleaseHistory[len(entry.ReleaseHistory)-1]); parseErr == nil {
										scoreCtx.TimeSinceLastRelease = time.Since(last)
									}
									cutoff := time.Now().Add(-24 * time.Hour)
									for _, ts := range entry.ReleaseHistory {
										if parsed, parseErr := time.Parse(time.RFC3339, ts); parseErr == nil && parsed.After(cutoff) {
											scoreCtx.ReleasesLast24h++
										}
									}
								}
							}
						}
					}
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
					a.Enrichment["commit_message"] = Truncate(commitInfo.Message, 100)
				}

				allAlerts = append(allAlerts, a)

				// Update behavioral baselines in lockfile (spec 025)
				if lockfileExists {
					if tags, ok := behavioralManifest.Actions[actionCfg.Repo]; ok {
						if entry, ok := tags[tag.Name]; ok {
							// Merge new contributors into known set
							if compareResult != nil && len(compareResult.AuthorLogins) > 0 {
								known := make(map[string]bool)
								for _, c := range entry.KnownContributors {
									known[c] = true
								}
								for _, login := range compareResult.AuthorLogins {
									if !known[login] {
										entry.KnownContributors = append(entry.KnownContributors, login)
									}
								}
							}

							// Append release timestamp
							now := time.Now().UTC().Format(time.RFC3339)
							entry.ReleaseHistory = append(entry.ReleaseHistory, now)
							tags[tag.Name] = entry
							behavioralUpdated = true
						}
					}
				}
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

	// Save behavioral baseline updates (spec 025)
	if behavioralUpdated && lockfileExists {
		if err := manifest.SaveManifest(lockfilePath, behavioralManifest); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save behavioral baseline updates to %s: %v\n", lockfilePath, err)
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

