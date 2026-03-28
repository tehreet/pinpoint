// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/tehreet/pinpoint/internal/discover"
	"github.com/tehreet/pinpoint/internal/verify"
)

// CmdVerify performs retroactive integrity checking of action dependencies.
func CmdVerify(args []string) {
	workflowDir := GetFlag(args, "workflows")
	if workflowDir == "" {
		workflowDir = ".github/workflows"
	}

	outputFormat := GetFlag(args, "output")
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
