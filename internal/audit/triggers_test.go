// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package audit

import (
	"testing"
)

func TestCritical_CheckoutPRHead(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
		t.Errorf("expected medium risk, got %s", findings[0].Risk)
	}
}

func TestMedium_PullRequestTargetOnly(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// === NEW: False positive regression tests ===

func TestClean_PullRequestTargetInIfConditionOnly(t *testing.T) {
	t.Parallel()
	// puppet-falcon pattern: trigger is pull_request (NOT target),
	// but pull_request_target appears in an if: condition.
	// This was a false positive before the fix.
	content := `
name: PR Acceptance Test
on:
  push:
  pull_request:
    types: [labeled]
jobs:
  setup:
    if: |
      (github.event_name == 'pull_request_target' &&
      github.event.label.name == 'ok-to-test') ||
      contains(fromJson('["push"]'), github.event_name)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{github.event.pull_request.head.sha}}
`
	findings := DetectDangerousTriggers("crowdstrike/puppet-falcon", "acceptance-tests.yml", content)
	if len(findings) != 0 {
		t.Errorf("expected no findings (pull_request_target only in if: condition, not trigger), got %d: %v", len(findings), findings)
	}
}

func TestClean_AllJobsDisabledWithIfFalse(t *testing.T) {
	t.Parallel()
	// CrowdStrike ansible_collection_falcon pattern: pull_request_target trigger
	// exists but every job has if: false — dead code.
	content := `
name: falcon_configure
on:
  schedule:
    - cron: '0 3 * * *'
  push:
    paths:
      - 'roles/falcon_configure/**'
  pull_request_target:
    types: [labeled]
jobs:
  molecule:
    if: false
    runs-on: ubuntu-latest
    env:
      FALCON_CLIENT_ID: ${{ secrets.FALCON_CLIENT_ID }}
    steps:
      - uses: actions/checkout@v4
        if: github.event_name != 'pull_request_target'
      - uses: actions/checkout@v4
        with:
          ref: ${{github.event.pull_request.head.sha}}
        if: github.event_name == 'pull_request_target'
      - run: molecule test
`
	findings := DetectDangerousTriggers("crowdstrike/ansible_collection_falcon", "falcon_configure.yml", content)
	if len(findings) != 0 {
		t.Errorf("expected no findings (all jobs disabled with if: false), got %d: %v", len(findings), findings)
	}
}

func TestClean_TestGoatRepo(t *testing.T) {
	t.Parallel()
	// StepSecurity github-actions-goat: intentionally vulnerable
	content := `
on:
  pull_request_target:
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make deploy
`
	findings := DetectDangerousTriggers("step-security/github-actions-goat", "toc-tou.yml", content)
	if len(findings) != 0 {
		t.Errorf("expected no findings for goat/test repo, got %d: %v", len(findings), findings)
	}
}

func TestClean_PlaygroundRepo(t *testing.T) {
	t.Parallel()
	content := `
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
	findings := DetectDangerousTriggers("step-security/workflow-playground-2", "test.yml", content)
	if len(findings) != 0 {
		t.Errorf("expected no findings for playground repo, got %d: %v", len(findings), findings)
	}
}

func TestCritical_LiveJobWithDisabledSibling(t *testing.T) {
	t.Parallel()
	// One job is disabled, another is live with the dangerous pattern.
	// Should still flag the live job.
	content := `
on:
  pull_request_target:
    types: [labeled]
jobs:
  disabled-job:
    if: false
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
  live-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
`
	findings := DetectDangerousTriggers("myorg/mixed-jobs", "ci.yml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (live job has dangerous pattern), got %d", len(findings))
	}
	if findings[0].Risk != "critical" {
		t.Errorf("expected critical risk, got %s", findings[0].Risk)
	}
}

// === Existing replay tests ===

func TestTrivyAPIDiffReplay(t *testing.T) {
	t.Parallel()
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
}

func TestSpotbugsReplay(t *testing.T) {
	t.Parallel()
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
