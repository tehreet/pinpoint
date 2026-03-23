// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package audit

import (
	"testing"
)

func TestCritical_CheckoutPRHead(t *testing.T) {
	content := `
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
`
	findings := DetectDangerousTriggers("myorg/api-server", "apidiff.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "critical" {
		t.Errorf("expected critical risk, got %s", findings[0].Risk)
	}
}

func TestCritical_CheckoutHeadRef(t *testing.T) {
	content := `
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - run: npm test
`
	findings := DetectDangerousTriggers("myorg/frontend", "ci.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "critical" {
		t.Errorf("expected critical risk, got %s", findings[0].Risk)
	}
}

func TestHigh_RunWithPRInterpolation(t *testing.T) {
	content := `
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`
	findings := DetectDangerousTriggers("myorg/frontend", "label.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "high" {
		t.Errorf("expected high risk, got %s", findings[0].Risk)
	}
}

func TestHigh_MultiLineRunWithPRInterpolation(t *testing.T) {
	content := `
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Processing PR"
          echo "Title: ${{ github.event.pull_request.title }}"
          echo "Done"
`
	findings := DetectDangerousTriggers("myorg/frontend", "label.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "high" {
		t.Errorf("expected high risk, got %s", findings[0].Risk)
	}
}

func TestHigh_MultiLineRunFoldedStyle(t *testing.T) {
	// Uses > (folded) instead of | (literal)
	content := `
on:
  pull_request_target:
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: >
          curl -X POST https://api.example.com/webhook
          -d '{"title": "${{ github.event.pull_request.title }}"}'
`
	findings := DetectDangerousTriggers("myorg/api", "webhook.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "high" {
		t.Errorf("expected high risk, got %s", findings[0].Risk)
	}
}

func TestMedium_MultiLineRunSafe(t *testing.T) {
	// Multi-line run block with no PR interpolation should NOT be high
	content := `
on:
  pull_request_target:
    types: [opened]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Welcome!"
          echo "Thanks for contributing"
`
	findings := DetectDangerousTriggers("myorg/docs", "greet.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "medium" {
		t.Errorf("expected medium risk (no dangerous interpolation), got %s", findings[0].Risk)
	}
}

func TestMedium_PullRequestTargetOnly(t *testing.T) {
	content := `
on:
  pull_request_target:
    types: [opened]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Welcome!"
`
	findings := DetectDangerousTriggers("myorg/docs", "auto-merge.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "medium" {
		t.Errorf("expected medium risk, got %s", findings[0].Risk)
	}
}

func TestClean_PullRequest(t *testing.T) {
	content := `
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
`
	findings := DetectDangerousTriggers("myorg/safe", "ci.yml", content)
	if len(findings) != 0 {
		t.Errorf("expected no findings for regular pull_request, got %d: %v", len(findings), findings)
	}
}

func TestClean_CommentedOut(t *testing.T) {
	content := `
on:
  push:
    branches: [main]
# on:
#   pull_request_target:
#     types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	findings := DetectDangerousTriggers("myorg/safe", "ci.yml", content)
	if len(findings) != 0 {
		t.Errorf("expected no findings for commented-out trigger, got %d: %v", len(findings), findings)
	}
}

func TestTrivyAPIDiffReplay(t *testing.T) {
	// Exact replica of trivy's apidiff.yaml pattern
	content := `
name: API Diff
on:
  pull_request_target:
    branches:
      - main
    paths:
      - '**.go'

permissions:
  contents: read
  pull-requests: write

jobs:
  api-diff:
    name: API Diff
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go install golang.org/x/exp/cmd/apidiff@latest
      - run: apidiff -m ./...
`
	findings := DetectDangerousTriggers("aquasecurity/trivy", "apidiff.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "critical" {
		t.Errorf("expected critical risk, got %s", findings[0].Risk)
	}
	if findings[0].Repo != "aquasecurity/trivy" {
		t.Errorf("expected repo aquasecurity/trivy, got %s", findings[0].Repo)
	}
}

func TestSpotbugsReplay(t *testing.T) {
	// Replica of spotbugs/sonar-findbugs pattern
	content := `
name: Build PR
on:
  pull_request_target:
    types: [opened, synchronize, reopened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Set up JDK
        uses: actions/setup-java@v4
        with:
          java-version: '17'
      - run: mvn verify
`
	findings := DetectDangerousTriggers("spotbugs/sonar-findbugs", "build-pr.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Risk != "critical" {
		t.Errorf("expected critical risk, got %s", findings[0].Risk)
	}
}
