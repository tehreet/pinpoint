// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"fmt"
	"os"
	"testing"
)

var pool *RepoPool

func TestMain(m *testing.M) {
	// Pool is only created when running scenario tests.
	// Existing tests (harness_test.go, replay_test.go) still work —
	// they create/delete their own repos and don't use the pool.
	if os.Getenv("GITHUB_TOKEN") == "" && os.Getenv("PINPOINT_APP_ID") == "" {
		fmt.Println("Skipping integration tests: no auth configured")
		os.Exit(0)
	}

	// Use a temporary testing.T for pool creation since TestMain doesn't have one.
	// We create the pool lazily in TestAllScenarios instead, since NewRepoPool
	// needs a *testing.T for proper error reporting.
	code := m.Run()
	os.Exit(code)
}

func TestAllScenarios(t *testing.T) {
	if pool == nil {
		pool = NewRepoPool(t, 10)
		t.Cleanup(func() { pool.Destroy(t) })
	}

	RunMultiRepoScenarios(t, pool, []Scenario{
		&TrivyMassRepoint{TagCount: 76},
		&TjActionsChain{},
		&GPGSignatureDrop{},
		&ImpossibleTimestamp{},
		&PullRequestTargetAudit{},
		&LegitMajorAdvance{},
		&OnDiskTOCTOU{},
	})
}
