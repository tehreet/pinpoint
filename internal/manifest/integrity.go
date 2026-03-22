// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tehreet/pinpoint/internal/integrity"
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

// DualHashResult holds both tarball and tree hashes for a single action.
type DualHashResult struct {
	Integrity     string
	DiskIntegrity string
	Err           error
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
			sem <- struct{}{}
			defer func() { <-sem }()

			integrityHash, err := DownloadAndHash(ctx, client, baseURL, token, a.Owner, a.Repo, a.SHA)

			key := a.Owner + "/" + a.Repo + "@" + a.SHA
			mu.Lock()
			results[key] = HashResult{Integrity: integrityHash, Err: err}
			mu.Unlock()
		}(a)
	}

	wg.Wait()
	return results
}

// DownloadExtractAndTreeHash downloads a tarball, computes its integrity hash,
// extracts it to a temp directory, and computes the tree hash of the extracted contents.
// Returns both the tarball hash and the disk integrity (tree) hash.
func DownloadExtractAndTreeHash(ctx context.Context, client *http.Client, baseURL, token, owner, repo, sha string) (tarballHash string, treeHash string, err error) {
	url := fmt.Sprintf("%s/repos/%s/%s/tarball/%s", baseURL, owner, repo, sha)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", fmt.Errorf("creating request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("downloading tarball for %s/%s@%s: %w", owner, repo, sha, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("tarball download failed for %s/%s@%s: HTTP %d", owner, repo, sha, resp.StatusCode)
	}

	// Write to temp file while simultaneously computing the tarball hash
	tmpFile, err := os.CreateTemp("", "pinpoint-tarball-*.tar.gz")
	if err != nil {
		return "", "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	defer os.Remove(tmpFilePath)

	hasher := sha256.New()
	teeReader := io.TeeReader(resp.Body, hasher)

	if _, err := io.Copy(tmpFile, teeReader); err != nil {
		tmpFile.Close()
		return "", "", fmt.Errorf("saving tarball: %w", err)
	}
	tmpFile.Close()

	tarballHash = "sha256-" + base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	// Extract the tarball to a temp directory
	extractDir, err := os.MkdirTemp("", "pinpoint-extract-*")
	if err != nil {
		return tarballHash, "", fmt.Errorf("creating extract dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := extractTarball(tmpFilePath, extractDir); err != nil {
		return tarballHash, "", fmt.Errorf("extracting tarball: %w", err)
	}

	// The tarball extracts to a single subdirectory like owner-repo-shortsha/
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return tarballHash, "", fmt.Errorf("reading extract dir: %w", err)
	}

	if len(entries) == 0 {
		return tarballHash, "", fmt.Errorf("tarball extracted to empty directory")
	}

	actionRoot := filepath.Join(extractDir, entries[0].Name())
	treeHash, err = integrity.ComputeTreeHash(actionRoot)
	if err != nil {
		return tarballHash, "", fmt.Errorf("computing tree hash: %w", err)
	}

	return tarballHash, treeHash, nil
}

// DownloadExtractAndTreeHashBatch downloads, extracts, and tree-hashes multiple
// action tarballs concurrently. Returns both integrity and disk_integrity hashes.
func DownloadExtractAndTreeHashBatch(ctx context.Context, client *http.Client, baseURL, token string, actions []ActionRef) map[string]DualHashResult {
	seen := make(map[string]bool)
	var unique []ActionRef
	for _, a := range actions {
		key := a.Owner + "/" + a.Repo + "@" + a.SHA
		if !seen[key] {
			seen[key] = true
			unique = append(unique, a)
		}
	}

	results := make(map[string]DualHashResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentDownloads)

	for _, a := range unique {
		wg.Add(1)
		go func(a ActionRef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			integrityHash, diskHash, err := DownloadExtractAndTreeHash(ctx, client, baseURL, token, a.Owner, a.Repo, a.SHA)

			key := a.Owner + "/" + a.Repo + "@" + a.SHA
			mu.Lock()
			results[key] = DualHashResult{
				Integrity:     integrityHash,
				DiskIntegrity: diskHash,
				Err:           err,
			}
			mu.Unlock()
		}(a)
	}

	wg.Wait()
	return results
}

// extractTarball extracts a .tar.gz file to the given directory.
func extractTarball(tarballPath, destDir string) error {
	f, err := os.Open(tarballPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar reader: %w", err)
		}

		// Security: prevent path traversal
		name := header.Name
		if strings.Contains(name, "..") {
			continue
		}
		if filepath.IsAbs(name) {
			continue
		}

		target := filepath.Join(destDir, name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			outFile, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}

	return nil
}
