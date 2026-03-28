// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"fmt"
	"os"

	"github.com/tehreet/pinpoint/internal/discover"
)

// CmdDiscover scans workflow files and outputs action references.
func CmdDiscover(args []string) {
	dir := GetFlag(args, "workflows")
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

	if HasFlag(args, "config") {
		fmt.Print(discover.GenerateConfig(refs))
	}
}
