// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"os"
	"path/filepath"
)

// DefaultLockfilePath is the new default lockfile location.
const DefaultLockfilePath = ".github/actions-lock.json"

// LegacyManifestPath is the old default manifest location.
const LegacyManifestPath = ".pinpoint-manifest.json"

// ResolveLockfilePath checks for a lockfile in priority order.
// Returns the path and whether it's the legacy format.
func ResolveLockfilePath(dir string) (path string, legacy bool) {
	newPath := filepath.Join(dir, DefaultLockfilePath)
	if _, err := os.Stat(newPath); err == nil {
		return newPath, false
	}
	oldPath := filepath.Join(dir, LegacyManifestPath)
	if _, err := os.Stat(oldPath); err == nil {
		return oldPath, true
	}
	// Neither exists — default to new path (will be created)
	return newPath, false
}
