// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package inject

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInjectFile(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		opts           InjectOptions
		wantJobsFound  int
		wantInjected   int
		wantSkipped    int
		wantModified   bool
		wantContains   []string
	}{
		{
			name: "simple single-job workflow",
			input: `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: go build ./...
`,
			opts: InjectOptions{
				Mode:    "warn",
				Version: "v1",
				DryRun:  true,
			},
			wantJobsFound: 1,
			wantInjected:  1,
			wantSkipped:   0,
			wantModified:  true,
			wantContains: []string{
				"      - name: Pinpoint Gate",
				"        uses: tehreet/pinpoint-action@v1",
				"        with:",
				"          mode: warn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write input to temp file
			dir := t.TempDir()
			path := filepath.Join(dir, "workflow.yml")
			if err := os.WriteFile(path, []byte(tt.input), 0644); err != nil {
				t.Fatalf("writing temp file: %v", err)
			}

			result, err := InjectFile(path, tt.opts)
			if err != nil {
				t.Fatalf("InjectFile returned error: %v", err)
			}

			if result.JobsFound != tt.wantJobsFound {
				t.Errorf("JobsFound = %d, want %d", result.JobsFound, tt.wantJobsFound)
			}
			if result.JobsInjected != tt.wantInjected {
				t.Errorf("JobsInjected = %d, want %d", result.JobsInjected, tt.wantInjected)
			}
			if result.JobsSkipped != tt.wantSkipped {
				t.Errorf("JobsSkipped = %d, want %d", result.JobsSkipped, tt.wantSkipped)
			}
			if result.Modified != tt.wantModified {
				t.Errorf("Modified = %v, want %v", result.Modified, tt.wantModified)
			}

			for _, s := range tt.wantContains {
				if !strings.Contains(result.Output, s) {
					t.Errorf("output missing expected line %q\n\nFull output:\n%s", s, result.Output)
				}
			}

			// Verify pinpoint-action appears before checkout
			pinpointIdx := strings.Index(result.Output, "pinpoint-action")
			checkoutIdx := strings.Index(result.Output, "actions/checkout")
			if pinpointIdx < 0 {
				t.Fatal("pinpoint-action not found in output")
			}
			if checkoutIdx < 0 {
				t.Fatal("actions/checkout not found in output")
			}
			if pinpointIdx >= checkoutIdx {
				t.Error("pinpoint-action should appear before actions/checkout")
			}

			// Verify dry-run did not modify the file
			if tt.opts.DryRun {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("reading temp file: %v", err)
				}
				if string(data) != tt.input {
					t.Error("dry-run should not modify the original file")
				}
			}
		})
	}
}
