// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package inject

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// InjectOptions configures how pinpoint-action steps are injected.
type InjectOptions struct {
	Mode    string // "warn" or "enforce"
	Version string // "v1" or specific version
	DryRun  bool
}

// InjectResult reports what happened during injection.
type InjectResult struct {
	File         string
	JobsFound    int
	JobsInjected int
	JobsSkipped  int
	Modified     bool
	Output       string // modified content (for dry-run)
}

// InjectFile inserts a pinpoint-action step as the first step of each job
// in the given workflow YAML file. It uses line-based manipulation to
// preserve comments and formatting.
func InjectFile(path string, opts InjectOptions) (*InjectResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading workflow file %s: %w", path, err)
	}

	if opts.Mode == "" {
		opts.Mode = "warn"
	}
	if opts.Version == "" {
		opts.Version = "v1"
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	result := &InjectResult{
		File: path,
	}

	var output []string
	inJobs := false
	inJob := false
	inSteps := false
	firstStepFound := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Detect top-level `jobs:` key (no leading whitespace)
		if trimmed == "jobs:" && (line == "jobs:" || strings.TrimRight(line, " \t") == "jobs:") {
			inJobs = true
			output = append(output, line)
			continue
		}

		// Inside jobs block, detect job names (exactly 2-space indent, ending with colon)
		if inJobs && !strings.HasPrefix(line, "    ") && strings.HasPrefix(line, "  ") && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			inJob = true
			inSteps = false
			firstStepFound = false
			result.JobsFound++
			output = append(output, line)
			continue
		}

		// Inside a job, detect `steps:` key
		if inJob && trimmed == "steps:" {
			inSteps = true
			firstStepFound = false
			output = append(output, line)
			continue
		}

		// Inside steps, find the first step line to determine indentation
		if inSteps && !firstStepFound && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if strings.HasPrefix(trimmed, "- uses:") || strings.HasPrefix(trimmed, "- name:") {
				firstStepFound = true

				// Detect the indentation of this step's `- `
				indent := line[:len(line)-len(strings.TrimLeft(line, " "))]

				// Build the pinpoint-action block
				block := []string{
					indent + "- name: Pinpoint Gate",
					indent + "  uses: tehreet/pinpoint-action@" + opts.Version,
					indent + "  with:",
					indent + "    mode: " + opts.Mode,
				}
				output = append(output, block...)
				result.JobsInjected++
			}
		}

		output = append(output, line)
	}

	modified := strings.Join(output, "\n")
	result.Modified = modified != content

	if opts.DryRun {
		result.Output = modified
		return result, nil
	}

	// Atomic write: write to tmp, then rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(modified), 0644); err != nil {
		return nil, fmt.Errorf("writing temporary file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, filepath.Clean(path)); err != nil {
		return nil, fmt.Errorf("renaming %s to %s: %w", tmpPath, path, err)
	}

	result.Output = modified
	return result, nil
}
