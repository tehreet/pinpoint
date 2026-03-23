// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// RepoPool manages a set of pre-created fixture repos that tests can
// check out and return. This eliminates the 2-3 second per-repo creation
// cost from individual tests.
type RepoPool struct {
	mu        sync.Mutex
	helper    *TestHelper
	repos     []poolRepo
	available chan int // indices of available repos
}

type poolRepo struct {
	Name     string // e.g. "fixture-00"
	InitSHA  string // SHA of the initial commit (with README)
	InitTree string // Tree SHA of that commit
	InUse    bool
}

// NewRepoPool creates n fixture repos in the test org and returns a pool.
// This is expensive (~2-3s per repo) but only runs once in TestMain.
func NewRepoPool(t *testing.T, n int) *RepoPool {
	t.Helper()

	if envN := os.Getenv("PINPOINT_POOL_SIZE"); envN != "" {
		if parsed, err := strconv.Atoi(envN); err == nil && parsed > 0 {
			n = parsed
		}
	}

	h := NewTestHelper(t)
	p := &RepoPool{
		helper:    h,
		repos:     make([]poolRepo, n),
		available: make(chan int, n),
	}

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("fixture-%02d", i)
		initSHA := h.CreateRepo(t, name)
		initTree := h.GetCommitTree(t, name, initSHA)

		p.repos[i] = poolRepo{
			Name:     name,
			InitSHA:  initSHA,
			InitTree: initTree,
		}
		p.available <- i
	}

	// Let GitHub settle after bulk creation
	time.Sleep(2 * time.Second)

	return p
}

// Acquire claims a repo from the pool. Blocks if all are in use.
// Returns the full repo name (org/repo), init commit SHA, and init tree SHA.
// Registers t.Cleanup to release the repo when the test finishes.
func (p *RepoPool) Acquire(t *testing.T) (fullRepo, initSHA, initTree string) {
	t.Helper()
	idx := <-p.available
	p.mu.Lock()
	p.repos[idx].InUse = true
	p.mu.Unlock()

	r := p.repos[idx]
	t.Cleanup(func() { p.Release(t, idx) })
	return p.helper.org + "/" + r.Name, r.InitSHA, r.InitTree
}

// AcquireN claims n repos from the pool. Returns slices of full repo names,
// init SHAs, and init tree SHAs.
func (p *RepoPool) AcquireN(t *testing.T, n int) (fullRepos, initSHAs, initTrees []string) {
	t.Helper()
	fullRepos = make([]string, n)
	initSHAs = make([]string, n)
	initTrees = make([]string, n)
	for i := 0; i < n; i++ {
		fullRepos[i], initSHAs[i], initTrees[i] = p.Acquire(t)
	}
	return
}

// Release resets a repo to clean state and returns it to the pool.
func (p *RepoPool) Release(t *testing.T, idx int) {
	r := p.repos[idx]

	// Delete all tags
	p.helper.deleteAllTags(t, r.Name)

	// Force-push main back to init commit
	p.helper.UpdateBranch(t, r.Name, "main", r.InitSHA)

	p.mu.Lock()
	p.repos[idx].InUse = false
	p.mu.Unlock()
	p.available <- idx
}

// Destroy deletes all fixture repos. Called in TestMain cleanup.
func (p *RepoPool) Destroy(t *testing.T) {
	for _, r := range p.repos {
		p.helper.DeleteRepo(t, r.Name)
	}
}
