// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"fmt"
	"strings"
)

// ParseDockerRef extracts registry, repo, and tag from a "docker://..." reference.
// For Docker Hub images without a registry prefix, returns "docker.io" as registry.
// For library images (e.g., "alpine"), prepends "library/" to repo.
func ParseDockerRef(ref string) (registry, repo, tag string, err error) {
	if !strings.HasPrefix(ref, "docker://") {
		return "", "", "", fmt.Errorf("not a docker reference: %q (must start with docker://)", ref)
	}
	ref = strings.TrimPrefix(ref, "docker://")
	if ref == "" {
		return "", "", "", fmt.Errorf("empty docker reference")
	}

	// Split off digest (@sha256:...) or tag (:...)
	tag = "latest"
	if idx := strings.Index(ref, "@"); idx != -1 {
		tag = ref[idx+1:]
		ref = ref[:idx]
	} else if idx := strings.LastIndex(ref, ":"); idx != -1 {
		lastSlash := strings.LastIndex(ref, "/")
		if idx > lastSlash {
			tag = ref[idx+1:]
			ref = ref[:idx]
		}
	}

	// Determine registry vs repo
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 1 {
		return "docker.io", "library/" + parts[0], tag, nil
	}

	firstPart := parts[0]
	if strings.Contains(firstPart, ".") || strings.Contains(firstPart, ":") || firstPart == "localhost" {
		registry = firstPart
		repo = parts[1]
	} else {
		registry = "docker.io"
		repo = ref
	}

	if repo == "" {
		return "", "", "", fmt.Errorf("empty repo in docker reference")
	}

	return registry, repo, tag, nil
}
