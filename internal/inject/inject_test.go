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
		name          string
		input         string
		opts          InjectOptions
		wantJobsFound int
		wantInjected  int
		wantSkipped   int
		wantModified  bool
		wantContains  []string
		wantOutput    string
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
		{
			name: "multi-job workflow",
			input: `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: go build ./...
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test
        run: go test ./...
`,
			opts: InjectOptions{
				Mode:    "warn",
				Version: "v1",
				DryRun:  true,
			},
			wantJobsFound: 2,
			wantInjected:  2,
			wantSkipped:   0,
			wantModified:  true,
			wantContains: []string{
				"      - name: Pinpoint Gate",
				"        uses: tehreet/pinpoint-action@v1",
			},
		},
		{
			name: "already has pinpoint-action (idempotent)",
			input: `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Pinpoint Gate
        uses: tehreet/pinpoint-action@v1
        with:
          mode: warn
      - uses: actions/checkout@v4
`,
			opts: InjectOptions{
				Mode:    "warn",
				Version: "v1",
				DryRun:  true,
			},
			wantJobsFound: 1,
			wantInjected:  0,
			wantSkipped:   1,
			wantModified:  false,
		},
		{
			name: "has harden-runner as step 1",
			input: `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: audit
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
				"step-security/harden-runner@v2",
				"      - name: Pinpoint Gate",
				"        uses: tehreet/pinpoint-action@v1",
			},
		},
		{
			name: "reusable workflow job",
			input: `name: CI
on: push

jobs:
  deploy:
    uses: org/repo/.github/workflows/reusable.yml@main
    with:
      environment: production
`,
			opts: InjectOptions{
				Mode:    "warn",
				Version: "v1",
				DryRun:  true,
			},
			wantJobsFound: 1,
			wantInjected:  0,
			wantSkipped:   1,
			wantModified:  false,
		},
		{
			name: "job with if: false",
			input: `name: CI
on: push

jobs:
  build:
    if: false
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			opts: InjectOptions{
				Mode:    "warn",
				Version: "v1",
				DryRun:  true,
			},
			wantJobsFound: 1,
			wantInjected:  0,
			wantSkipped:   1,
			wantModified:  false,
		},
		{
			name: "preserves comments",
			input: `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # SHA-pinned — practicing what we preach
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
				"# SHA-pinned — practicing what we preach",
				"      - name: Pinpoint Gate",
			},
		},
		{
			name: "preserves 4-space indentation",
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
				"            - name: Pinpoint Gate",
				"              uses: tehreet/pinpoint-action@v1",
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
					t.Errorf("output missing expected string %q\n\nFull output:\n%s", s, result.Output)
				}
			}

			if tt.wantOutput != "" && result.Output != tt.wantOutput {
				t.Errorf("output mismatch\nwant:\n%s\ngot:\n%s", tt.wantOutput, result.Output)
			}

			// For idempotent test: verify output equals input
			if tt.wantInjected == 0 && !tt.wantModified {
				if result.Output != tt.input {
					t.Errorf("expected output to equal input for unmodified workflow\ngot:\n%s", result.Output)
				}
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

			// For harden-runner test: verify ordering
			if tt.name == "has harden-runner as step 1" {
				hardenIdx := strings.Index(result.Output, "harden-runner")
				pinpointIdx := strings.Index(result.Output, "pinpoint-action")
				if hardenIdx >= pinpointIdx {
					t.Error("harden-runner should appear before pinpoint-action")
				}
			}
		})
	}
}

func TestInjectDir(t *testing.T) {
	dir := t.TempDir()

	workflow1 := `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: go build ./...
`
	workflow2 := `name: Test
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test
        run: go test ./...
`
	txtContent := "this is not a workflow file"

	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(workflow1), 0644); err != nil {
		t.Fatalf("writing ci.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(workflow2), 0644); err != nil {
		t.Fatalf("writing test.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(txtContent), 0644); err != nil {
		t.Fatalf("writing notes.txt: %v", err)
	}

	opts := InjectOptions{Mode: "warn", Version: "v1", DryRun: false}
	results, err := InjectDir(dir, opts)
	if err != nil {
		t.Fatalf("InjectDir returned error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results (skipping .txt), got %d", len(results))
	}

	for _, r := range results {
		if !r.Modified {
			t.Errorf("expected file %s to be modified", r.File)
		}
		if r.JobsInjected != 1 {
			t.Errorf("expected 1 injection in %s, got %d", r.File, r.JobsInjected)
		}
		if !strings.Contains(r.Output, "pinpoint-action@v1") {
			t.Errorf("expected pinpoint-action@v1 in output of %s", r.File)
		}
	}
}
