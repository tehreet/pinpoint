// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package inject

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tehreet/pinpoint/internal/util"
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
	jobsIndent := -1  // indent level of jobs: key
	jobIndent := -1   // indent level of job names (e.g., "  build:")
	detectedJobIndent := -1 // auto-detected job name indent
	inJob := false
	inSteps := false
	firstStepFound := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Detect top-level `jobs:` key
		if trimmed == "jobs:" && util.LeadingSpaces(line) == 0 {
			inJobs = true
			jobsIndent = 0
			detectedJobIndent = -1
			inJob = false
			inSteps = false
			output = append(output, line)
			continue
		}

		// If we're in the jobs block, check for top-level keys that end jobs block
		if inJobs && trimmed != "" && !strings.HasPrefix(trimmed, "#") && util.LeadingSpaces(line) == 0 && trimmed != "jobs:" {
			inJobs = false
			inJob = false
			inSteps = false
		}

		// Inside jobs block, detect job names
		// A job name is the first non-blank, non-comment indented line after jobs:
		// that ends with colon and has no spaces. Auto-detect the indent level from
		// the first job encountered.
		if inJobs && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			indent := util.LeadingSpaces(line)
			// Auto-detect job indent from first job name
			if detectedJobIndent == -1 && indent > jobsIndent && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
				detectedJobIndent = indent
			}
			if indent == detectedJobIndent && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
				inJob = true
				inSteps = false
				firstStepFound = false
				jobIndent = indent
				output = append(output, line)

				// Look ahead: check for reusable workflow (uses: at job-property level)
				// and if: false. Auto-detect property indent from first property line.
				propIndent := -1
				isReusable := false
				isDisabled := false
				for j := i + 1; j < len(lines); j++ {
					nextLine := lines[j]
					nextTrimmed := strings.TrimSpace(nextLine)
					nextIndent := util.LeadingSpaces(nextLine)

					// Skip blank lines and comments
					if nextTrimmed == "" || strings.HasPrefix(nextTrimmed, "#") {
						continue
					}
					// If indent is back to job level or less, stop scanning
					if nextIndent <= jobIndent {
						break
					}
					// Auto-detect property indent from first property
					if propIndent == -1 {
						propIndent = nextIndent
					}
					// Only look at direct job properties
					if nextIndent == propIndent {
						if strings.HasPrefix(nextTrimmed, "uses:") {
							isReusable = true
						}
						if strings.HasPrefix(nextTrimmed, "if:") {
							val := strings.TrimSpace(strings.TrimPrefix(nextTrimmed, "if:"))
							val = strings.Trim(val, "'\"")
							if val == "false" {
								isDisabled = true
							}
						}
					}
				}

				if isReusable {
					result.JobsFound++
					result.JobsSkipped++
					inJob = false // don't process steps for this job
					continue
				}
				if isDisabled {
					result.JobsFound++
					result.JobsSkipped++
					inJob = false
					continue
				}

				result.JobsFound++
				continue
			}
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
			if strings.HasPrefix(trimmed, "- uses:") || strings.HasPrefix(trimmed, "- name:") || strings.HasPrefix(trimmed, "- run:") {
				firstStepFound = true

				// Detect the indentation of this step's `- `
				stepIndent := util.LeadingSpaces(line)
				indent := strings.Repeat(" ", stepIndent)

				// Check if this step is pinpoint-action (idempotency)
				isPinpoint := strings.Contains(line, "pinpoint-action")
				if !isPinpoint && strings.HasPrefix(trimmed, "- name:") {
					for j := i + 1; j < len(lines); j++ {
						nxt := strings.TrimSpace(lines[j])
						if nxt == "" || strings.HasPrefix(nxt, "#") {
							continue
						}
						if strings.Contains(nxt, "pinpoint-action") {
							isPinpoint = true
						}
						break
					}
				}
				if isPinpoint {
					result.JobsSkipped++
					output = append(output, line)
					continue
				}

				// Check for harden-runner as first step
				isHardenRunner := false
				if strings.HasPrefix(trimmed, "- uses:") && strings.Contains(trimmed, "harden-runner") {
					isHardenRunner = true
				} else if strings.HasPrefix(trimmed, "- name:") {
					for j := i + 1; j < len(lines); j++ {
						nxt := strings.TrimSpace(lines[j])
						if nxt == "" || strings.HasPrefix(nxt, "#") {
							continue
						}
						if strings.HasPrefix(nxt, "uses:") && strings.Contains(nxt, "harden-runner") {
							isHardenRunner = true
						}
						break
					}
				}

				if isHardenRunner {
					// Emit the harden-runner step lines, then inject before next step
					output = append(output, line)
					i++
					for i < len(lines) {
						line = lines[i]
						lt := strings.TrimSpace(line)
						// Next step starts with `- ` at the same indent level
						if lt != "" && !strings.HasPrefix(lt, "#") && strings.HasPrefix(lt, "-") && util.LeadingSpaces(line) == stepIndent {
							break
						}
						output = append(output, line)
						i++
					}

					// Insert pinpoint-action block
					block := []string{
						indent + "- name: Pinpoint Gate",
						indent + "  uses: tehreet/pinpoint-action@" + opts.Version,
						indent + "  with:",
						indent + "    mode: " + opts.Mode,
					}
					output = append(output, block...)
					result.JobsInjected++

					// Emit the next step line
					if i < len(lines) {
						output = append(output, lines[i])
					}
					continue
				}

				// Standard case: inject pinpoint-action before this step
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

// InjectDir processes all .yml/.yaml files in a directory.
func InjectDir(dir string, opts InjectOptions) ([]*InjectResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}
	var results []*InjectResult
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		r, err := InjectFile(filepath.Join(dir, name), opts)
		if err != nil {
			return nil, fmt.Errorf("injecting %s: %w", name, err)
		}
		results = append(results, r)
	}
	return results, nil
}
