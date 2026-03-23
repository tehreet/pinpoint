// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"fmt"
	"testing"
	"time"
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

			t.Logf("[scenario] %s: setting up on %s...", s.Name(), repoName(repo))
			start := time.Now()
			state := s.Setup(t, h, repo, initSHA, initTree)
			t.Logf("[scenario] %s: setup done (%s)", s.Name(), time.Since(start).Round(time.Millisecond))

			// Baseline scan to populate state
			if state.ConfigPath != "" {
				t.Logf("[scenario] %s: running baseline scan...", s.Name())
				RunPinpointScan(t, state.ConfigPath, state.StatePath)
			}

			t.Logf("[scenario] %s: executing attack...", s.Name())
			attackStart := time.Now()
			s.Attack(t, h, repo, state)
			t.Logf("[scenario] %s: attack done (%s)", s.Name(), time.Since(attackStart).Round(time.Millisecond))

			t.Logf("[scenario] %s: verifying detection...", s.Name())
			s.Verify(t, h, repo, state)
			t.Logf("[scenario] %s: PASSED (%s total)", s.Name(), time.Since(start).Round(time.Millisecond))
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
			start := time.Now()

			if ms, ok := s.(MultiRepoScenario); ok {
				t.Logf("[scenario] %s: acquiring %d repos...", s.Name(), ms.RepoCount())
				repos, initSHAs, initTrees := pool.AcquireN(t, ms.RepoCount())
				t.Logf("[scenario] %s: setting up on %s (+%d more)...", s.Name(), repoName(repos[0]), len(repos)-1)
				state := ms.Setup(t, h, repos[0], initSHAs[0], initTrees[0])
				if state.Extra == nil {
					state.Extra = make(map[string]string)
				}
				for i := 1; i < len(repos); i++ {
					state.Extra[fmt.Sprintf("repo_%d", i)] = repos[i]
					state.Extra[fmt.Sprintf("initSHA_%d", i)] = initSHAs[i]
					state.Extra[fmt.Sprintf("initTree_%d", i)] = initTrees[i]
				}
				t.Logf("[scenario] %s: setup done (%s)", s.Name(), time.Since(start).Round(time.Millisecond))

				t.Logf("[scenario] %s: executing attack...", s.Name())
				ms.Attack(t, h, repos[0], state)

				t.Logf("[scenario] %s: verifying detection...", s.Name())
				ms.Verify(t, h, repos[0], state)
			} else {
				repo, initSHA, initTree := pool.Acquire(t)
				t.Logf("[scenario] %s: setting up on %s...", s.Name(), repoName(repo))
				state := s.Setup(t, h, repo, initSHA, initTree)
				t.Logf("[scenario] %s: setup done (%s)", s.Name(), time.Since(start).Round(time.Millisecond))

				if state.ConfigPath != "" {
					t.Logf("[scenario] %s: running baseline scan...", s.Name())
					RunPinpointScan(t, state.ConfigPath, state.StatePath)
				}

				t.Logf("[scenario] %s: executing attack...", s.Name())
				s.Attack(t, h, repo, state)

				t.Logf("[scenario] %s: verifying detection...", s.Name())
				s.Verify(t, h, repo, state)
			}
			t.Logf("[scenario] %s: PASSED (%s total)", s.Name(), time.Since(start).Round(time.Millisecond))
		})
	}
}
