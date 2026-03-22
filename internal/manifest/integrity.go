// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// ActionRef identifies an action tarball to download.
type ActionRef struct {
	Owner string
	Repo  string
	SHA   string
}

// HashResult holds the integrity hash or error for a single action.
type HashResult struct {
	Integrity string
	Err       error
}

// maxConcurrentDownloads limits parallel tarball downloads to avoid GitHub abuse detection.
const maxConcurrentDownloads = 10

// DownloadAndHash downloads an action tarball and returns its SHA-256 hash in SRI format.
func DownloadAndHash(ctx context.Context, client *http.Client, baseURL, token, owner, repo, sha string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/tarball/%s", baseURL, owner, repo, sha)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading tarball for %s/%s@%s: %w", owner, repo, sha, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tarball download failed for %s/%s@%s: HTTP %d", owner, repo, sha, resp.StatusCode)
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, resp.Body); err != nil {
		return "", fmt.Errorf("hashing tarball for %s/%s@%s: %w", owner, repo, sha, err)
	}

	return "sha256-" + base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// DownloadAndHashBatch downloads and hashes multiple action tarballs concurrently
// with bounded parallelism. It deduplicates by action+SHA before downloading.
func DownloadAndHashBatch(ctx context.Context, client *http.Client, baseURL, token string, actions []ActionRef) map[string]HashResult {
	// Deduplicate by action+SHA key
	type uniqueKey struct {
		owner, repo, sha string
	}
	seen := make(map[string]bool)
	var unique []ActionRef
	for _, a := range actions {
		key := a.Owner + "/" + a.Repo + "@" + a.SHA
		if !seen[key] {
			seen[key] = true
			unique = append(unique, a)
		}
	}

	results := make(map[string]HashResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentDownloads)

	for _, a := range unique {
		wg.Add(1)
		go func(a ActionRef) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			integrity, err := DownloadAndHash(ctx, client, baseURL, token, a.Owner, a.Repo, a.SHA)

			key := a.Owner + "/" + a.Repo + "@" + a.SHA
			mu.Lock()
			results[key] = HashResult{Integrity: integrity, Err: err}
			mu.Unlock()
		}(a)
	}

	wg.Wait()
	return results
}
