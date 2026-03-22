// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package integrity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// ComputeTreeHash walks a directory and computes a deterministic SHA-256
// hash of all file contents, sorted by relative path. The result is returned
// in SRI format: "sha256-<base64>".
//
// Algorithm:
//  1. Walk directory, skip .git/ and non-regular files (symlinks, etc.)
//  2. For each file: compute SHA-256, record "relPath\x00hexHash"
//  3. Sort entries lexicographically
//  4. Feed each entry + "\n" into a final SHA-256 hasher
//  5. Return SRI-format result
func ComputeTreeHash(dir string) (string, error) {
	var entries []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip .git directory
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		// Only hash regular files (skip symlinks, devices, etc.)
		if !d.Type().IsRegular() {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		// Normalize to forward slashes for cross-platform consistency
		relPath = filepath.ToSlash(relPath)

		// Hash file contents
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}

		fileHash := hex.EncodeToString(h.Sum(nil))
		entries = append(entries, relPath+"\x00"+fileHash)
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Strings(entries)

	treeHasher := sha256.New()
	for _, entry := range entries {
		treeHasher.Write([]byte(entry + "\n"))
	}

	return "sha256-" + base64.StdEncoding.EncodeToString(treeHasher.Sum(nil)), nil
}
