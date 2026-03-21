// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// State holds the complete pinpoint state, persisted as JSON.
type State struct {
	Version  int                      `json:"version"`
	LastPoll time.Time                `json:"last_poll"`
	Actions  map[string]*ActionState  `json:"actions"` // key: "owner/repo"
	mu       sync.RWMutex
}

// ActionState tracks tag→SHA mappings for a single GitHub Action.
type ActionState struct {
	Tags        map[string]*TagState `json:"tags"`
	DeletedTags []DeletedTag         `json:"deleted_tags,omitempty"`
	RepoETag    string               `json:"repo_etag,omitempty"`
}

// TagState tracks a single tag's commit SHA over time.
type TagState struct {
	CommitSHA    string    `json:"commit_sha"`
	TagSHA       string    `json:"tag_sha,omitempty"` // Ref-level SHA (differs for annotated)
	FirstSeen    time.Time `json:"first_seen"`
	LastVerified time.Time `json:"last_verified"`
	ETag         string    `json:"etag,omitempty"`
	History      []Change  `json:"history,omitempty"`
}

// Change records a tag repointing event.
type Change struct {
	PreviousSHA string    `json:"previous_sha"`
	NewSHA      string    `json:"new_sha"`
	DetectedAt  time.Time `json:"detected_at"`
}

// DeletedTag records when a tag disappears.
type DeletedTag struct {
	Name       string    `json:"name"`
	LastSHA    string    `json:"last_sha"`
	DeletedAt  time.Time `json:"deleted_at"`
}

// FileStore persists state to a JSON file.
type FileStore struct {
	path  string
	state *State
}

// NewFileStore loads or creates state from a JSON file.
func NewFileStore(path string) (*FileStore, error) {
	fs := &FileStore{path: path}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fs.state = &State{
			Version: 1,
			Actions: make(map[string]*ActionState),
		}
		return fs, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading state file %s: %w", path, err)
	}

	fs.state = &State{}
	if err := json.Unmarshal(data, fs.state); err != nil {
		return nil, fmt.Errorf("parsing state file %s: %w", path, err)
	}
	if fs.state.Actions == nil {
		fs.state.Actions = make(map[string]*ActionState)
	}

	return fs, nil
}

// GetState returns the current state (read-only snapshot).
func (fs *FileStore) GetState() *State {
	fs.state.mu.RLock()
	defer fs.state.mu.RUnlock()
	return fs.state
}

// GetActionState returns state for a specific action, creating if needed.
func (fs *FileStore) GetActionState(repo string) *ActionState {
	fs.state.mu.Lock()
	defer fs.state.mu.Unlock()

	if _, ok := fs.state.Actions[repo]; !ok {
		fs.state.Actions[repo] = &ActionState{
			Tags: make(map[string]*TagState),
		}
	}
	return fs.state.Actions[repo]
}

// RecordTag records a tag's current SHA. Returns true if this is a change (repoint).
func (fs *FileStore) RecordTag(repo, tagName, commitSHA, tagSHA string) (changed bool, previousSHA string) {
	fs.state.mu.Lock()
	defer fs.state.mu.Unlock()

	if _, ok := fs.state.Actions[repo]; !ok {
		fs.state.Actions[repo] = &ActionState{
			Tags: make(map[string]*TagState),
		}
	}

	action := fs.state.Actions[repo]
	now := time.Now().UTC()

	existing, exists := action.Tags[tagName]
	if !exists {
		// New tag — record it, no alert
		action.Tags[tagName] = &TagState{
			CommitSHA:    commitSHA,
			TagSHA:       tagSHA,
			FirstSeen:    now,
			LastVerified: now,
		}
		return false, ""
	}

	if existing.CommitSHA == commitSHA {
		// No change
		existing.LastVerified = now
		return false, ""
	}

	// TAG REPOINTED — this is what we're here for
	previousSHA = existing.CommitSHA
	existing.History = append(existing.History, Change{
		PreviousSHA: existing.CommitSHA,
		NewSHA:      commitSHA,
		DetectedAt:  now,
	})
	existing.CommitSHA = commitSHA
	existing.TagSHA = tagSHA
	existing.LastVerified = now

	return true, previousSHA
}

// RecordDeletedTag marks a tag that was present but is now gone.
func (fs *FileStore) RecordDeletedTag(repo, tagName string) {
	fs.state.mu.Lock()
	defer fs.state.mu.Unlock()

	action, ok := fs.state.Actions[repo]
	if !ok {
		return
	}

	if tag, exists := action.Tags[tagName]; exists {
		action.DeletedTags = append(action.DeletedTags, DeletedTag{
			Name:      tagName,
			LastSHA:   tag.CommitSHA,
			DeletedAt: time.Now().UTC(),
		})
		delete(action.Tags, tagName)
	}
}

// SetRepoETag updates the cached ETag for a repo's tag listing.
func (fs *FileStore) SetRepoETag(repo, etag string) {
	fs.state.mu.Lock()
	defer fs.state.mu.Unlock()

	if _, ok := fs.state.Actions[repo]; !ok {
		fs.state.Actions[repo] = &ActionState{
			Tags: make(map[string]*TagState),
		}
	}
	fs.state.Actions[repo].RepoETag = etag
}

// Save persists the current state to disk.
func (fs *FileStore) Save() error {
	fs.state.mu.RLock()
	defer fs.state.mu.RUnlock()

	fs.state.LastPoll = time.Now().UTC()

	data, err := json.MarshalIndent(fs.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tmpPath := fs.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, fs.path); err != nil {
		return fmt.Errorf("renaming state file: %w", err)
	}

	return nil
}

// TagCount returns the total number of tracked tags across all actions.
func (fs *FileStore) TagCount() int {
	fs.state.mu.RLock()
	defer fs.state.mu.RUnlock()

	count := 0
	for _, action := range fs.state.Actions {
		count += len(action.Tags)
	}
	return count
}
