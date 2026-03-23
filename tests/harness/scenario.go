// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"fmt"
	"testing"
)

// Scenario defines a self-contained attack scenario that knows how to
// set up pre-attack state, execute the attack, and verify detection.
type Scenario interface {
	// Name returns a human-readable scenario name for test output.
	Name() string

	// Setup creates the pre-attack state (tags, commits, workflow files).
	// Returns a ScenarioState that the attack and verify phases use.
	Setup(t *testing.T, h *TestHelper, repo, initSHA, initTree string) *ScenarioState

	// Attack performs the malicious operations (repoint tags, etc).
	Attack(t *testing.T, h *TestHelper, repo string, state *ScenarioState)

	// Verify runs pinpoint and asserts the expected behavior.
	Verify(t *testing.T, h *TestHelper, repo string, state *ScenarioState)
}

// ScenarioState carries data between the Setup, Attack, and Verify phases.
type ScenarioState struct {
	TagSHAs      map[string]string // tag → original commit SHA
	EvilSHA      string            // malicious commit SHA
	ConfigPath   string            // path to generated .pinpoint.yml
	StatePath    string            // path to state.json
	ManifestPath string            // path to actions-lock.json (for gate tests)
	Extra        map[string]string // scenario-specific state
}

// RunScenarios executes each scenario against a pool-allocated repo.
// Each scenario runs in its own sub-test with t.Parallel().
func RunScenarios(t *testing.T, pool *RepoPool, scenarios []Scenario) {
	h := NewTestHelper(t)
	for _, s := range scenarios {
		s := s // capture for parallel
		t.Run(s.Name(), func(t *testing.T) {
			t.Parallel()
			repo, initSHA, initTree := pool.Acquire(t)

			state := s.Setup(t, h, repo, initSHA, initTree)

			// Baseline scan to populate state
			if state.ConfigPath != "" {
				RunPinpointScan(t, state.ConfigPath, state.StatePath)
			}

			// Execute attack
			s.Attack(t, h, repo, state)

			// Verify detection
			s.Verify(t, h, repo, state)
		})
	}
}

// MultiRepoScenario is like Scenario but acquires multiple repos.
// Scenarios that need more than one repo implement this instead.
type MultiRepoScenario interface {
	Scenario

	// RepoCount returns how many repos this scenario needs.
	RepoCount() int
}

// RunMultiRepoScenarios is like RunScenarios but supports MultiRepoScenario.
// For regular Scenarios it acquires 1 repo; for MultiRepoScenario it acquires N.
func RunMultiRepoScenarios(t *testing.T, pool *RepoPool, scenarios []Scenario) {
	h := NewTestHelper(t)
	for _, s := range scenarios {
		s := s
		t.Run(s.Name(), func(t *testing.T) {
			t.Parallel()

			if ms, ok := s.(MultiRepoScenario); ok {
				// Multi-repo scenario handles its own setup/attack/verify with pool
				repos, initSHAs, initTrees := pool.AcquireN(t, ms.RepoCount())
				state := ms.Setup(t, h, repos[0], initSHAs[0], initTrees[0])
				// Store extra repos in state
				if state.Extra == nil {
					state.Extra = make(map[string]string)
				}
				for i := 1; i < len(repos); i++ {
					state.Extra[fmt.Sprintf("repo_%d", i)] = repos[i]
					state.Extra[fmt.Sprintf("initSHA_%d", i)] = initSHAs[i]
					state.Extra[fmt.Sprintf("initTree_%d", i)] = initTrees[i]
				}

				ms.Attack(t, h, repos[0], state)
				ms.Verify(t, h, repos[0], state)
			} else {
				repo, initSHA, initTree := pool.Acquire(t)
				state := s.Setup(t, h, repo, initSHA, initTree)
				if state.ConfigPath != "" {
					RunPinpointScan(t, state.ConfigPath, state.StatePath)
				}
				s.Attack(t, h, repo, state)
				s.Verify(t, h, repo, state)
			}
		})
	}
}
