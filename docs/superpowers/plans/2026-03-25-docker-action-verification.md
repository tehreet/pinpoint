# Docker Action Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend pinpoint to verify Docker-based GitHub Actions by resolving and recording container image digests in the lockfile, then verifying them at gate time.

**Architecture:** New `internal/manifest/docker.go` handles Docker registry API (token exchange, manifest HEAD for digest). `transitive.go` is extended to extract Docker image references from action.yml when type is "docker". Gate verifies Docker digests in `--integrity` mode. Dockerfile FROM parsing extracts base image references.

**Tech Stack:** Go standard library (`net/http`, `regexp`, `strings`), OCI Distribution Spec v2 API, existing YAML parsing (`gopkg.in/yaml.v3`)

---

### Task 1: Add DockerInfo structs to lockfile

**Files:**
- Modify: `internal/manifest/manifest.go:29-38` (ManifestEntry struct)

- [ ] **Step 1: Write the failing test**

Create a test that serializes a ManifestEntry with Docker info and checks the JSON output.

**Note:** Add `"strings"` to the import block of `manifest_test.go` if not already present.

```go
// internal/manifest/manifest_test.go — add this test

func TestManifestEntryDockerSerialization(t *testing.T) {
	entry := ManifestEntry{
		SHA:       "abc123def456",
		Integrity: "sha256-AAAA",
		Type:      "docker",
		Docker: &DockerInfo{
			Image:  "ghcr.io/aquasecurity/trivy",
			Tag:    "0.58.1",
			Digest: "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00",
			Source: "action.yml",
		},
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ManifestEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Docker == nil {
		t.Fatal("Docker field is nil after round-trip")
	}
	if got.Docker.Image != "ghcr.io/aquasecurity/trivy" {
		t.Errorf("Image = %q, want %q", got.Docker.Image, "ghcr.io/aquasecurity/trivy")
	}
	if got.Docker.Digest != "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00" {
		t.Errorf("Digest = %q", got.Docker.Digest)
	}

	// Verify omitempty: entry without Docker should not have "docker" key
	noDocker := ManifestEntry{SHA: "abc", Type: "node20"}
	data2, _ := json.Marshal(noDocker)
	if strings.Contains(string(data2), `"docker"`) {
		t.Error("docker key present when DockerInfo is nil")
	}
}

func TestManifestEntryDockerfileBaseImages(t *testing.T) {
	entry := ManifestEntry{
		SHA:  "abc123",
		Type: "docker",
		Docker: &DockerInfo{
			Image: "Dockerfile",
			BaseImages: []DockerBaseImage{
				{Image: "alpine", Tag: "3.19", Digest: "sha256:aaa"},
				{Image: "golang", Tag: "1.24", Digest: "sha256:bbb"},
			},
			Source: "Dockerfile",
		},
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ManifestEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Docker.BaseImages) != 2 {
		t.Fatalf("BaseImages len = %d, want 2", len(got.Docker.BaseImages))
	}
	if got.Docker.BaseImages[0].Image != "alpine" {
		t.Errorf("BaseImages[0].Image = %q", got.Docker.BaseImages[0].Image)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/manifest/ -run TestManifestEntryDocker -v`
Expected: FAIL — `DockerInfo` and `DockerBaseImage` types not defined

- [ ] **Step 3: Add the struct definitions**

In `internal/manifest/manifest.go`, add after the `TransitiveDep` struct (after line 48):

```go
// DockerInfo holds Docker image information for Docker-based actions.
type DockerInfo struct {
	Image      string            `json:"image"`                // "ghcr.io/owner/image" or "Dockerfile"
	Tag        string            `json:"tag,omitempty"`        // "0.58.1"
	Digest     string            `json:"digest,omitempty"`     // "sha256:..."
	BaseImages []DockerBaseImage `json:"base_images,omitempty"` // For Dockerfile actions
	Source     string            `json:"source"`               // "action.yml" or "Dockerfile"
}

// DockerBaseImage holds a resolved base image from a Dockerfile FROM instruction.
type DockerBaseImage struct {
	Image  string `json:"image"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}
```

Add the `Docker` field to `ManifestEntry` (after `Type` field, line 36):

```go
	Type          string          `json:"type,omitempty"`
	Docker        *DockerInfo     `json:"docker,omitempty"`         // NEW
	Dependencies  []TransitiveDep `json:"dependencies,omitempty"`
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/manifest/ -run TestManifestEntryDocker -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `go test ./... -v`
Expected: All existing tests still pass

- [ ] **Step 6: Commit**

```bash
git add internal/manifest/manifest.go internal/manifest/manifest_test.go
git commit -m "feat(docker): add DockerInfo structs to lockfile format"
```

---

### Task 2: Docker reference parser

**Files:**
- Create: `internal/manifest/docker.go`
- Create: `internal/manifest/docker_test.go`

- [ ] **Step 1: Write the failing tests for ParseDockerRef**

```go
// internal/manifest/docker_test.go

package manifest

import (
	"testing"
)

func TestParseDockerRef(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		wantReg  string
		wantRepo string
		wantTag  string
		wantErr  bool
	}{
		{
			name:     "ghcr.io with tag",
			ref:      "docker://ghcr.io/aquasecurity/trivy:0.58.1",
			wantReg:  "ghcr.io",
			wantRepo: "aquasecurity/trivy",
			wantTag:  "0.58.1",
		},
		{
			name:     "ghcr.io with latest (no tag)",
			ref:      "docker://ghcr.io/owner/image",
			wantReg:  "ghcr.io",
			wantRepo: "owner/image",
			wantTag:  "latest",
		},
		{
			name:     "docker hub library image",
			ref:      "docker://alpine:3.19",
			wantReg:  "docker.io",
			wantRepo: "library/alpine",
			wantTag:  "3.19",
		},
		{
			name:     "docker hub user image",
			ref:      "docker://myuser/myimage:v1",
			wantReg:  "docker.io",
			wantRepo: "myuser/myimage",
			wantTag:  "v1",
		},
		{
			name:     "quay.io",
			ref:      "docker://quay.io/org/image:latest",
			wantReg:  "quay.io",
			wantRepo: "org/image",
			wantTag:  "latest",
		},
		{
			name:     "docker.io explicit",
			ref:      "docker://docker.io/library/ubuntu:22.04",
			wantReg:  "docker.io",
			wantRepo: "library/ubuntu",
			wantTag:  "22.04",
		},
		{
			name:     "digest reference (already pinned)",
			ref:      "docker://ghcr.io/owner/image@sha256:abc123",
			wantReg:  "ghcr.io",
			wantRepo: "owner/image",
			wantTag:  "sha256:abc123", // Digest goes in tag slot; caller should detect "sha256:" prefix and skip registry resolution (already immutable)
		},
		{
			name:    "missing docker:// prefix",
			ref:     "ghcr.io/owner/image:v1",
			wantErr: true,
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: true,
		},
		{
			name:    "just docker://",
			ref:     "docker://",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, repo, tag, err := ParseDockerRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if reg != tt.wantReg {
				t.Errorf("registry = %q, want %q", reg, tt.wantReg)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
			if tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", tag, tt.wantTag)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/manifest/ -run TestParseDockerRef -v`
Expected: FAIL — `ParseDockerRef` not defined

- [ ] **Step 3: Implement ParseDockerRef**

```go
// internal/manifest/docker.go

// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		// Make sure the colon is after the last slash (not a port)
		lastSlash := strings.LastIndex(ref, "/")
		if idx > lastSlash {
			tag = ref[idx+1:]
			ref = ref[:idx]
		}
	}

	// Determine registry vs repo
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 1 {
		// No slash: Docker Hub library image (e.g., "alpine")
		return "docker.io", "library/" + parts[0], tag, nil
	}

	// Check if first part looks like a registry (has dot or is localhost)
	firstPart := parts[0]
	if strings.Contains(firstPart, ".") || strings.Contains(firstPart, ":") || firstPart == "localhost" {
		registry = firstPart
		repo = parts[1]
	} else {
		// No dots in first part: Docker Hub user image (e.g., "myuser/myimage")
		registry = "docker.io"
		repo = ref
	}

	if repo == "" {
		return "", "", "", fmt.Errorf("empty repo in docker reference")
	}

	return registry, repo, tag, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/manifest/ -run TestParseDockerRef -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/manifest/docker.go internal/manifest/docker_test.go
git commit -m "feat(docker): add ParseDockerRef for docker:// reference parsing"
```

---

### Task 3: Dockerfile FROM parser

**Files:**
- Modify: `internal/manifest/docker.go`
- Modify: `internal/manifest/docker_test.go`

- [ ] **Step 1: Write the failing tests for ParseDockerfile**

```go
// Add to internal/manifest/docker_test.go

func TestParseDockerfile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []DockerBaseImage
	}{
		{
			name:    "simple FROM",
			content: "FROM alpine:3.19\nRUN echo hello\n",
			want:    []DockerBaseImage{{Image: "alpine", Tag: "3.19"}},
		},
		{
			name:    "FROM with AS",
			content: "FROM golang:1.24 AS builder\nRUN go build\nFROM alpine:3.19\nCOPY --from=builder /app /app\n",
			want: []DockerBaseImage{
				{Image: "golang", Tag: "1.24"},
				{Image: "alpine", Tag: "3.19"},
			},
		},
		{
			name:    "FROM with registry",
			content: "FROM ghcr.io/owner/image:v1.2.3\n",
			want:    []DockerBaseImage{{Image: "ghcr.io/owner/image", Tag: "v1.2.3"}},
		},
		{
			name:    "FROM with digest",
			content: "FROM alpine@sha256:abc123\n",
			want:    []DockerBaseImage{{Image: "alpine", Tag: "sha256:abc123"}},
		},
		{
			name:    "FROM latest (no tag)",
			content: "FROM ubuntu\n",
			want:    []DockerBaseImage{{Image: "ubuntu", Tag: "latest"}},
		},
		{
			name:    "ARG before FROM",
			content: "ARG BASE=alpine\nARG VERSION=3.19\nFROM ${BASE}:${VERSION}\n",
			want:    nil, // Cannot resolve ARG-parameterized FROM
		},
		{
			name:    "FROM scratch",
			content: "FROM scratch\nCOPY binary /\n",
			want:    nil, // scratch is not a real image
		},
		{
			name:    "empty",
			content: "",
			want:    nil,
		},
		{
			name:    "comments and whitespace",
			content: "# Comment\n  FROM  alpine:3.19  \n",
			want:    []DockerBaseImage{{Image: "alpine", Tag: "3.19"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDockerfile([]byte(tt.content))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d base images, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i].Image != tt.want[i].Image {
					t.Errorf("[%d] Image = %q, want %q", i, got[i].Image, tt.want[i].Image)
				}
				if got[i].Tag != tt.want[i].Tag {
					t.Errorf("[%d] Tag = %q, want %q", i, got[i].Tag, tt.want[i].Tag)
				}
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/manifest/ -run TestParseDockerfile -v`
Expected: FAIL — `ParseDockerfile` not defined

- [ ] **Step 3: Implement ParseDockerfile**

Add to `internal/manifest/docker.go`:

```go
// ParseDockerfile extracts FROM instructions from a Dockerfile.
// Returns base images with their tags. Skips ARG-parameterized images
// (containing ${ }) and "scratch". Digest is left empty — caller resolves it.
func ParseDockerfile(content []byte) []DockerBaseImage {
	var bases []DockerBaseImage
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			continue
		}

		// Strip "FROM " prefix
		rest := strings.TrimSpace(line[5:])

		// Take first token (ignore "AS name" suffix)
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		imageRef := fields[0]

		// Skip ARG-parameterized and scratch
		if strings.Contains(imageRef, "${") || strings.Contains(imageRef, "$") {
			continue
		}
		if imageRef == "scratch" {
			continue
		}

		image, tag := parseImageTag(imageRef)
		if image == "" {
			continue
		}

		bases = append(bases, DockerBaseImage{Image: image, Tag: tag})
	}
	return bases
}

// parseImageTag splits "image:tag" or "image@digest" into image and tag parts.
func parseImageTag(ref string) (image, tag string) {
	// Check for digest (@sha256:...)
	if idx := strings.Index(ref, "@"); idx != -1 {
		return ref[:idx], ref[idx+1:]
	}

	// Check for tag — find last colon after last slash
	lastSlash := strings.LastIndex(ref, "/")
	if idx := strings.LastIndex(ref, ":"); idx != -1 && idx > lastSlash {
		return ref[:idx], ref[idx+1:]
	}

	return ref, "latest"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/manifest/ -run TestParseDockerfile -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/manifest/docker.go internal/manifest/docker_test.go
git commit -m "feat(docker): add Dockerfile FROM parser"
```

---

### Task 4: Registry client — token exchange and digest resolution

**Files:**
- Modify: `internal/manifest/docker.go`
- Modify: `internal/manifest/docker_test.go`

- [ ] **Step 1: Write the failing tests for RegistryClient.ResolveDigest**

```go
// Add to internal/manifest/docker_test.go

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveDigest(t *testing.T) {
	const wantDigest = "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" || r.URL.Path == "/v2/token":
			// Token endpoint
			fmt.Fprintf(w, `{"token":"test-token"}`)
		case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/manifests/"):
			// Verify auth header
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Verify accept header includes OCI manifest types
			accept := r.Header.Get("Accept")
			if !strings.Contains(accept, "application/vnd.docker.distribution.manifest") &&
				!strings.Contains(accept, "application/vnd.oci.image") {
				t.Error("missing manifest accept header")
			}
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	rc := &RegistryClient{
		HTTP: &http.Client{},
		// Override registry URLs to point at test server
		registryOverride: ts.URL,
	}

	digest, err := rc.ResolveDigest(context.Background(), "ghcr.io", "aquasecurity/trivy", "0.58.1")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if digest != wantDigest {
		t.Errorf("digest = %q, want %q", digest, wantDigest)
	}
}

func TestResolveDigestUnauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" || r.URL.Path == "/v2/token":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"errors":[{"code":"DENIED"}]}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer ts.Close()

	rc := &RegistryClient{
		HTTP:             &http.Client{},
		registryOverride: ts.URL,
	}

	_, err := rc.ResolveDigest(context.Background(), "ghcr.io", "owner/private", "v1")
	if err == nil {
		t.Fatal("expected error for unauthorized registry")
	}
}

func TestResolveDigestDockerHub(t *testing.T) {
	const wantDigest = "sha256:aabbcc"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" || r.URL.Path == "/v2/token":
			fmt.Fprintf(w, `{"token":"hub-token"}`)
		case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/v2/library/alpine/manifests/3.19"):
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	rc := &RegistryClient{
		HTTP:             &http.Client{},
		registryOverride: ts.URL,
	}

	digest, err := rc.ResolveDigest(context.Background(), "docker.io", "library/alpine", "3.19")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if digest != wantDigest {
		t.Errorf("digest = %q, want %q", digest, wantDigest)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/manifest/ -run TestResolveDigest -v`
Expected: FAIL — `RegistryClient` not defined

- [ ] **Step 3: Implement RegistryClient**

Add to `internal/manifest/docker.go`:

```go
// RegistryClient resolves Docker image digests from OCI-compliant registries.
type RegistryClient struct {
	HTTP             *http.Client
	registryOverride string // for testing: override all registry URLs
}

// tokenResponse represents a Docker registry token exchange response.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"` // Some registries use this field
}

// ResolveDigest returns the manifest digest for image:tag from the given registry.
// Uses the OCI Distribution Spec: HEAD /v2/<repo>/manifests/<tag>.
func (c *RegistryClient) ResolveDigest(ctx context.Context, registry, repo, tag string) (string, error) {
	baseURL := c.registryURL(registry)

	// Step 1: Get auth token
	token, err := c.getToken(ctx, baseURL, registry, repo)
	if err != nil {
		return "", fmt.Errorf("registry auth for %s/%s: %w\n\nEnsure the image is public or set appropriate registry credentials.", registry, repo, err)
	}

	// Step 2: HEAD request for manifest digest
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", baseURL, repo, tag)
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("HEAD %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("unauthorized: %s/%s:%s (HTTP %d). Image may be private or credentials invalid.", registry, repo, tag, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("image not found: %s/%s:%s", registry, repo, tag)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned HTTP %d for %s/%s:%s", resp.StatusCode, registry, repo, tag)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header for %s/%s:%s. Registry may not support digest resolution.", registry, repo, tag)
	}

	return digest, nil
}

// getToken performs token exchange for registry authentication.
func (c *RegistryClient) getToken(ctx context.Context, baseURL, registry, repo string) (string, error) {
	// Token endpoint varies by registry
	tokenURL := c.tokenURL(baseURL, registry, repo)

	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}

	token := tr.Token
	if token == "" {
		token = tr.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("empty token from registry")
	}

	return token, nil
}

// registryURL returns the base URL for a registry.
func (c *RegistryClient) registryURL(registry string) string {
	if c.registryOverride != "" {
		return c.registryOverride
	}
	switch registry {
	case "docker.io":
		return "https://registry-1.docker.io"
	default:
		return "https://" + registry
	}
}

// tokenURL returns the token exchange URL for a registry.
func (c *RegistryClient) tokenURL(baseURL, registry, repo string) string {
	if c.registryOverride != "" {
		return baseURL + "/token?scope=repository:" + repo + ":pull"
	}
	switch registry {
	case "ghcr.io":
		return "https://ghcr.io/token?scope=repository:" + repo + ":pull"
	case "docker.io":
		return "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + repo + ":pull"
	case "quay.io":
		return baseURL + "/v2/auth?service=quay.io&scope=repository:" + repo + ":pull"
	default:
		return baseURL + "/v2/token?scope=repository:" + repo + ":pull"
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/manifest/ -run TestResolveDigest -v`
Expected: PASS

- [ ] **Step 5: Run go vet**

Run: `go vet ./internal/manifest/...`
Expected: No issues

- [ ] **Step 6: Commit**

```bash
git add internal/manifest/docker.go internal/manifest/docker_test.go
git commit -m "feat(docker): add RegistryClient for OCI digest resolution"
```

---

### Task 5: Extract Docker image ref from action.yml

**Files:**
- Modify: `internal/manifest/transitive.go`
- Modify: `internal/manifest/docker.go`
- Modify: `internal/manifest/docker_test.go`

- [ ] **Step 1: Write the failing test for ExtractDockerImageRef**

```go
// Add to internal/manifest/docker_test.go

func TestExtractDockerImageRef(t *testing.T) {
	tests := []struct {
		name       string
		actionYAML string
		wantRef    string // empty string means not a docker action or no image ref
		wantIsFile bool   // true if runs.image == "Dockerfile"
	}{
		{
			name: "pre-built image",
			actionYAML: `name: trivy
runs:
  using: docker
  image: docker://ghcr.io/aquasecurity/trivy:0.58.1
`,
			wantRef: "docker://ghcr.io/aquasecurity/trivy:0.58.1",
		},
		{
			name: "Dockerfile action",
			actionYAML: `name: custom
runs:
  using: docker
  image: Dockerfile
`,
			wantRef:    "Dockerfile",
			wantIsFile: true,
		},
		{
			name: "node action (not docker)",
			actionYAML: `name: setup-node
runs:
  using: node20
  main: index.js
`,
			wantRef: "",
		},
		{
			name: "composite action (not docker)",
			actionYAML: `name: composite
runs:
  using: composite
  steps:
    - run: echo hi
`,
			wantRef: "",
		},
		{
			name: "docker with relative path",
			actionYAML: `name: custom
runs:
  using: docker
  image: ./container/Dockerfile
`,
			wantRef:    "./container/Dockerfile",
			wantIsFile: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, isFile := ExtractDockerImageRef([]byte(tt.actionYAML))
			if ref != tt.wantRef {
				t.Errorf("ref = %q, want %q", ref, tt.wantRef)
			}
			if isFile != tt.wantIsFile {
				t.Errorf("isFile = %v, want %v", isFile, tt.wantIsFile)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/manifest/ -run TestExtractDockerImageRef -v`
Expected: FAIL — `ExtractDockerImageRef` not defined

- [ ] **Step 3: Implement ExtractDockerImageRef**

Add to `internal/manifest/docker.go`:

```go
// dockerActionYAML is a minimal struct for parsing Docker action.yml.
type dockerActionYAML struct {
	Runs struct {
		Using string `yaml:"using"`
		Image string `yaml:"image"`
	} `yaml:"runs"`
}

// ExtractDockerImageRef parses an action.yml and extracts the Docker image reference.
// Returns the image reference and whether it's a file-based reference (Dockerfile).
// Returns ("", false) if not a Docker action.
func ExtractDockerImageRef(content []byte) (ref string, isFile bool) {
	var a dockerActionYAML
	if err := yaml.Unmarshal(content, &a); err != nil {
		return "", false
	}

	using := strings.Trim(a.Runs.Using, "'\"")
	if using != "docker" {
		return "", false
	}

	image := strings.TrimSpace(a.Runs.Image)
	if image == "" {
		return "", false
	}

	if strings.HasPrefix(image, "docker://") {
		return image, false
	}

	// Dockerfile or path to Dockerfile
	return image, true
}
```

Note: This requires importing `"gopkg.in/yaml.v3"` — add it to the import block of `docker.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/manifest/ -run TestExtractDockerImageRef -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/manifest/docker.go internal/manifest/docker_test.go
git commit -m "feat(docker): extract Docker image refs from action.yml"
```

---

### Task 6: Wire Docker digest resolution into lock (Refresh)

**Files:**
- Modify: `internal/manifest/transitive.go:96-157` (ResolveTransitiveDeps)
- Modify: `internal/manifest/manifest.go:295-320` (Refresh integrity section)

This task integrates the Docker pieces into the existing lock flow. When Refresh encounters a Docker action, it resolves the Docker image digest and populates `DockerInfo`.

**Design note:** `ResolveTransitiveDeps` already fetches `action.yml` to determine the action type. To avoid double-fetching, we extract `fetchActionFileForRepo` as a shared helper (refactoring the existing try-yml-then-yaml logic out of `ResolveTransitiveDeps`), and cache the action content in Refresh so it can be reused for Docker resolution.

- [ ] **Step 1: Write the failing test**

Add to `internal/manifest/docker_test.go`:

```go
func TestResolveDockerInfo(t *testing.T) {
	const wantDigest = "sha256:abc123def456"

	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/token"):
			fmt.Fprintf(w, `{"token":"test"}`)
		case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer registryServer.Close()

	rc := &RegistryClient{
		HTTP:             &http.Client{},
		registryOverride: registryServer.URL,
	}

	tests := []struct {
		name       string
		actionYAML string
		dockerfile string // empty if no Dockerfile
		wantDocker *DockerInfo
	}{
		{
			name: "pre-built image",
			actionYAML: `name: trivy
runs:
  using: docker
  image: docker://ghcr.io/aquasecurity/trivy:0.58.1
`,
			wantDocker: &DockerInfo{
				Image:  "ghcr.io/aquasecurity/trivy",
				Tag:    "0.58.1",
				Digest: wantDigest,
				Source: "action.yml",
			},
		},
		{
			name: "Dockerfile action",
			actionYAML: `name: custom
runs:
  using: docker
  image: Dockerfile
`,
			dockerfile: "FROM alpine:3.19\nRUN echo hi\n",
			wantDocker: &DockerInfo{
				Image: "Dockerfile",
				BaseImages: []DockerBaseImage{
					{Image: "alpine", Tag: "3.19", Digest: wantDigest},
				},
				Source: "Dockerfile",
			},
		},
		{
			name: "node action (no docker info)",
			actionYAML: `name: setup
runs:
  using: node20
  main: index.js
`,
			wantDocker: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ResolveDockerInfo(context.Background(), rc, []byte(tt.actionYAML), func(filename string) ([]byte, error) {
				if filename == "Dockerfile" && tt.dockerfile != "" {
					return []byte(tt.dockerfile), nil
				}
				return nil, fmt.Errorf("file not found: %s", filename)
			})
			if err != nil {
				t.Fatalf("ResolveDockerInfo: %v", err)
			}

			if tt.wantDocker == nil {
				if info != nil {
					t.Fatalf("expected nil DockerInfo, got %+v", info)
				}
				return
			}

			if info == nil {
				t.Fatal("expected DockerInfo, got nil")
			}
			if info.Image != tt.wantDocker.Image {
				t.Errorf("Image = %q, want %q", info.Image, tt.wantDocker.Image)
			}
			if info.Tag != tt.wantDocker.Tag {
				t.Errorf("Tag = %q, want %q", info.Tag, tt.wantDocker.Tag)
			}
			if info.Digest != tt.wantDocker.Digest {
				t.Errorf("Digest = %q, want %q", info.Digest, tt.wantDocker.Digest)
			}
			if info.Source != tt.wantDocker.Source {
				t.Errorf("Source = %q, want %q", info.Source, tt.wantDocker.Source)
			}
			if len(info.BaseImages) != len(tt.wantDocker.BaseImages) {
				t.Fatalf("BaseImages len = %d, want %d", len(info.BaseImages), len(tt.wantDocker.BaseImages))
			}
			for i, bi := range info.BaseImages {
				if bi.Image != tt.wantDocker.BaseImages[i].Image {
					t.Errorf("BaseImages[%d].Image = %q, want %q", i, bi.Image, tt.wantDocker.BaseImages[i].Image)
				}
				if bi.Digest != tt.wantDocker.BaseImages[i].Digest {
					t.Errorf("BaseImages[%d].Digest = %q, want %q", i, bi.Digest, tt.wantDocker.BaseImages[i].Digest)
				}
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/manifest/ -run TestResolveDockerInfo -v`
Expected: FAIL — `ResolveDockerInfo` not defined

- [ ] **Step 3: Implement ResolveDockerInfo**

Add to `internal/manifest/docker.go`:

```go
// FileReader is a callback to read files from an action's repository.
// Used to fetch Dockerfiles when the action uses `image: Dockerfile`.
type FileReader func(filename string) ([]byte, error)

// ResolveDockerInfo extracts Docker information from an action.yml and resolves
// image digests from the registry. Returns nil if the action is not Docker-based.
func ResolveDockerInfo(ctx context.Context, rc *RegistryClient, actionContent []byte, readFile FileReader) (*DockerInfo, error) {
	ref, isFile := ExtractDockerImageRef(actionContent)
	if ref == "" {
		return nil, nil
	}

	if !isFile {
		// Pre-built image: docker://registry/repo:tag
		registry, repo, tag, err := ParseDockerRef(ref)
		if err != nil {
			return nil, fmt.Errorf("parsing docker ref %q: %w", ref, err)
		}

		// If already pinned by digest (tag starts with "sha256:"), record it directly
		// without registry resolution — it's already immutable
		if strings.HasPrefix(tag, "sha256:") {
			return &DockerInfo{
				Image:  registry + "/" + repo,
				Digest: tag,
				Source: "action.yml",
			}, nil
		}

		digest, err := rc.ResolveDigest(ctx, registry, repo, tag)
		if err != nil {
			// Non-fatal: record what we can without the digest
			return &DockerInfo{
				Image:  registry + "/" + repo,
				Tag:    tag,
				Source: "action.yml",
			}, nil
		}

		return &DockerInfo{
			Image:  registry + "/" + repo,
			Tag:    tag,
			Digest: digest,
			Source: "action.yml",
		}, nil
	}

	// Dockerfile action: parse FROM instructions and resolve base image digests
	info := &DockerInfo{
		Image:  "Dockerfile",
		Source: "Dockerfile",
	}

	if readFile == nil {
		return info, nil
	}

	// Read the Dockerfile (strip "./" prefix for GitHub API compatibility)
	filename := strings.TrimPrefix(ref, "./")
	dfContent, err := readFile(filename)
	if err != nil {
		// Cannot read Dockerfile — return what we have
		return info, nil
	}

	bases := ParseDockerfile(dfContent)
	for i := range bases {
		// Resolve digest for each base image
		baseReg, baseRepo := baseImageRegistry(bases[i].Image)
		digest, err := rc.ResolveDigest(ctx, baseReg, baseRepo, bases[i].Tag)
		if err == nil {
			bases[i].Digest = digest
		}
	}

	info.BaseImages = bases
	return info, nil
}

// baseImageRegistry determines the registry and normalized repo for a FROM image reference.
func baseImageRegistry(image string) (registry, repo string) {
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 1 {
		// Docker Hub library image
		return "docker.io", "library/" + image
	}

	first := parts[0]
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return first, parts[1]
	}

	// Docker Hub user image
	return "docker.io", image
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/manifest/ -run TestResolveDockerInfo -v`
Expected: PASS

- [ ] **Step 5: Refactor fetchActionFile and wire into Refresh**

**Step 5a: Extract `fetchActionFileForRepo` helper in `transitive.go`**

Add this function after `fetchActionFile` (line 197) in `transitive.go`:

```go
// fetchActionFileForRepo fetches action.yml or action.yaml from a repo at a specific SHA.
// This consolidates the try-yml-then-yaml fallback logic used by both
// ResolveTransitiveDeps and Docker info resolution.
func fetchActionFileForRepo(ctx context.Context, client *http.Client, baseURL, token, repo, sha string) ([]byte, error) {
	content, err := fetchActionFile(ctx, client, baseURL, token, repo, sha, "action.yml")
	if err != nil {
		content, err = fetchActionFile(ctx, client, baseURL, token, repo, sha, "action.yaml")
	}
	return content, err
}
```

Then refactor `ResolveTransitiveDeps` (lines 104-112) to use it — replace:

```go
	content, err := fetchActionFile(ctx, client, baseURL, token, action, sha, "action.yml")
	if err != nil {
		content, err = fetchActionFile(ctx, client, baseURL, token, action, sha, "action.yaml")
		if err != nil {
			return nil, "unknown", nil
		}
	}
```

With:

```go
	content, err := fetchActionFileForRepo(ctx, client, baseURL, token, action, sha)
	if err != nil {
		return nil, "unknown", nil
	}
```

**Step 5b: Make `ResolveTransitiveDeps` return the action content**

Change the return signature of `ResolveTransitiveDeps` to also return the action.yml content so Refresh can reuse it for Docker resolution without a second fetch:

```go
// ResolveTransitiveDeps fetches an action's action.yml and discovers
// inner uses: directives for composite actions.
// Returns the list of transitive dependencies, the action type, the raw action.yml content, and any error.
func ResolveTransitiveDeps(ctx context.Context, client *http.Client, baseURL, graphqlURL, token, action, sha string, depth int) ([]TransitiveDep, string, []byte, error) {
```

Update all return statements in `ResolveTransitiveDeps` to include the content:
- `return nil, "unknown", nil, fmt.Errorf(...)` for depth exceeded
- `return nil, "unknown", nil, nil` for fetch failure
- `return nil, actionType, content, nil` for non-composite (including docker)
- `return deps, "composite", content, nil` at the end

**Step 5c: Update callers of `ResolveTransitiveDeps`**

In `manifest.go` Refresh (around line 311), update the call:

```go
			deps, actionType, actionContent, err := ResolveTransitiveDeps(ctx, iOpts.HTTPClient, iOpts.BaseURL, iOpts.GraphQLURL, iOpts.Token, repo, entry.SHA, 0)
			if err == nil {
				entry.Type = actionType
				entry.Dependencies = deps
			}
```

**Step 5d: Add Docker info resolution after transitive deps (in Refresh)**

Add this block immediately after the transitive deps block above (do NOT replace the existing code — add after it):

```go
			// Resolve Docker image info for Docker actions (reuses actionContent from above)
			if actionType == "docker" && iOpts.RegistryClient != nil && actionContent != nil {
				dockerInfo, dockerErr := ResolveDockerInfo(ctx, iOpts.RegistryClient, actionContent, func(filename string) ([]byte, error) {
					// Strip "./" prefix before GitHub API call
					clean := strings.TrimPrefix(filename, "./")
					return fetchActionFile(ctx, iOpts.HTTPClient, iOpts.BaseURL, iOpts.Token, repo, entry.SHA, clean)
				})
				if dockerErr == nil && dockerInfo != nil {
					entry.Docker = dockerInfo
				}
			}
```

**Step 5e: Add `RegistryClient` field to `IntegrityOptions`**

In `manifest.go` (around line 77), add the field:

```go
type IntegrityOptions struct {
	HTTPClient        *http.Client
	BaseURL           string
	GraphQLURL        string
	Token             string
	SkipDiskIntegrity bool
	RegistryClient    *RegistryClient // Docker registry client for digest resolution
}
```

**Step 5f: Update ALL remaining callers of `ResolveTransitiveDeps`**

The signature change adds a `[]byte` return value. Every caller must be updated:

1. **Recursive call in `transitive.go` (~line 145):**
```go
innerDeps, innerType, _, _ := ResolveTransitiveDeps(ctx, client, baseURL, graphqlURL, token, owner+"/"+repo, resolvedSHA, depth+1)
```

2. **`gate.go` (~line 509):**
```go
				deps, _, _, err := manifestpkg.ResolveTransitiveDeps(ctx, client.http, opts.APIURL, opts.GraphQLURL, opts.Token, key, currentSHA, 0)
```

3. **All test calls in `transitive_test.go`** — find every `ResolveTransitiveDeps(` call and add `_` for the new `[]byte` return:
```go
// Example: change this pattern everywhere in the test file:
deps, actionType, err := ResolveTransitiveDeps(...)
// To:
deps, actionType, _, err := ResolveTransitiveDeps(...)
```

Run `go build ./...` to verify no callers are missed.

- [ ] **Step 6: Run full test suite**

Run: `go test ./... -v`
Expected: All tests pass (existing tests don't set `RegistryClient`, so Docker resolution is skipped)

- [ ] **Step 7: Commit**

```bash
git add internal/manifest/docker.go internal/manifest/docker_test.go internal/manifest/manifest.go internal/manifest/transitive.go
git commit -m "feat(docker): wire Docker digest resolution into lock refresh"
```

---

### Task 7: Gate Docker digest verification

**Files:**
- Modify: `internal/gate/gate.go` — add Docker types (after TransitiveDep, ~line 75), add `RegistryURL` to GateOptions (~line 92), add Docker digest check after tarball integrity block (~line 505, inside the `currentSHA == manifestEntry.SHA` else branch)
- Create: `internal/gate/gate_docker_test.go`

**Insertion point:** The Docker verification block goes at ~line 505 (after the tarball integrity `if` block closes and after transitive dep check closes), but still inside the `else` branch of `currentSHA != manifestEntry.SHA` (line 483). This runs only when the SHA matches (no repoint), giving us the deeper Docker digest check. The check is guarded by `opts.Integrity && manifestEntry.Docker != nil && manifestEntry.Docker.Digest != ""`, so it runs even if `manifestEntry.Integrity` is empty (tarball hash absent).

- [ ] **Step 1: Write the failing test**

```go
// internal/gate/gate_docker_test.go

package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGateDockerDigestVerification(t *testing.T) {
	const goodDigest = "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00"
	const badDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name           string
		manifestDigest string // digest recorded in lockfile
		liveDigest     string // digest returned by registry
		wantViolations int
	}{
		{
			name:           "digest matches",
			manifestDigest: goodDigest,
			liveDigest:     goodDigest,
			wantViolations: 0,
		},
		{
			name:           "digest mismatch — image repointed",
			manifestDigest: goodDigest,
			liveDigest:     badDigest,
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			silenceOutput(t)

			// Registry mock
			registryTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/token"):
					fmt.Fprintf(w, `{"token":"test"}`)
				case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/manifests/"):
					w.Header().Set("Docker-Content-Digest", tt.liveDigest)
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer registryTS.Close()

			// Build lockfile with Docker info
			lockfile := Manifest{
				Version: 2,
				Actions: map[string]map[string]ManifestEntry{
					"aquasecurity/trivy-action": {
						"v0.28.0": {
							SHA:       "abc123def456abc123def456abc123def456abc1",
							Integrity: "sha256-AAAA",
							Type:      "docker",
							Docker: &DockerInfo{
								Image:  "ghcr.io/aquasecurity/trivy",
								Tag:    "0.58.1",
								Digest: tt.manifestDigest,
								Source: "action.yml",
							},
						},
					},
				},
			}
			lockJSON, _ := json.Marshal(lockfile)

			workflow := `on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@v0.28.0
`

			// GitHub API + GraphQL mock
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/graphql"):
					resp := buildGraphQLResponse(map[string]map[string]string{
						"aquasecurity/trivy-action": {"v0.28.0": "abc123def456abc123def456abc123def456abc1"},
					})
					fmt.Fprint(w, resp)
				case strings.Contains(r.URL.Path, "ci.yml"):
					fmt.Fprint(w, buildContentResponse(workflow))
				case strings.Contains(r.URL.Path, "actions-lock.json"):
					fmt.Fprint(w, buildContentResponse(string(lockJSON)))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			result, err := RunGate(context.Background(), GateOptions{
				Repo:         "owner/repo",
				SHA:          "abc123",
				WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
				ManifestPath: ".github/actions-lock.json",
				APIURL:       ts.URL,
				GraphQLURL:   ts.URL + "/graphql",
				Integrity:    true,
				RegistryURL:  registryTS.URL,
			})

			if err != nil {
				t.Fatalf("RunGate: %v", err)
			}

			violations := 0
			for _, v := range result.Violations {
				if strings.Contains(v.ExpectedSHA, "sha256:") || strings.Contains(v.ActualSHA, "sha256:") {
					violations++
				}
			}

			if violations != tt.wantViolations {
				t.Errorf("docker violations = %d, want %d. All violations: %+v", violations, tt.wantViolations, result.Violations)
			}
		})
	}
}
```

Note: This test uses a `DockerInfo` struct in the gate package — it will need to use the one from the gate's local `ManifestEntry` copy (which duplicates the manifest package). You'll need to add the `Docker` field to gate's local `ManifestEntry` (line 56-64 in gate.go) and add the `RegistryURL` field to `GateOptions`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/gate/ -run TestGateDockerDigest -v`
Expected: FAIL — `DockerInfo` not defined in gate package, `RegistryURL` not in GateOptions

- [ ] **Step 3: Add Docker types to gate package and implement verification**

First, add types and field to gate.go. After the `TransitiveDep` struct (line 75), add:

```go
// DockerInfo holds Docker image information from the lockfile.
type DockerInfo struct {
	Image      string            `json:"image"`
	Tag        string            `json:"tag,omitempty"`
	Digest     string            `json:"digest,omitempty"`
	BaseImages []DockerBaseImage `json:"base_images,omitempty"`
	Source     string            `json:"source"`
}

// DockerBaseImage holds a resolved base image from a Dockerfile.
type DockerBaseImage struct {
	Image  string `json:"image"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}
```

Add `Docker` field to gate's `ManifestEntry` (after `Type` field, line 63):

```go
	Docker        *DockerInfo     `json:"docker,omitempty"`
```

Add `RegistryURL` to `GateOptions` (after `ActionsDir`, line 92):

```go
	RegistryURL           string // override for Docker registry (testing)
```

Then, in the integrity verification section (around line 488-505, after the tarball integrity check succeeds), add Docker digest verification:

```go
			// Docker digest verification (integrity mode only)
			// Skip when Tag is empty — digest-pinned images (Tag="", Digest="sha256:...")
			// are already immutable and need no re-verification.
			if opts.Integrity && manifestEntry.Docker != nil && manifestEntry.Docker.Digest != "" && manifestEntry.Docker.Tag != "" {
				rc := &manifestpkg.RegistryClient{HTTP: client.http}
				if opts.RegistryURL != "" {
					rc.SetRegistryOverride(opts.RegistryURL)
				}

				registry, repo, tag, err := manifestpkg.ParseDockerRef("docker://" + manifestEntry.Docker.Image + ":" + manifestEntry.Docker.Tag)
				if err == nil {
					liveDigest, err := rc.ResolveDigest(ctx, registry, repo, tag)
					if err != nil {
						fmt.Fprintf(messageWriter, "    ⚠ Docker digest check failed: %v\n", err)
					} else if liveDigest != manifestEntry.Docker.Digest {
						result.Violations = append(result.Violations, Violation{
							Action:      key,
							Tag:         ar.Ref,
							ExpectedSHA: manifestEntry.Docker.Digest,
							ActualSHA:   liveDigest,
						})
						fmt.Fprintf(messageWriter, "    ✗ DOCKER IMAGE REPOINTED: %s:%s\n", manifestEntry.Docker.Image, manifestEntry.Docker.Tag)
						fmt.Fprintf(messageWriter, "      Expected digest: %s\n", manifestEntry.Docker.Digest)
						fmt.Fprintf(messageWriter, "      Current digest:  %s\n", liveDigest)
						fmt.Fprintf(messageWriter, "      The Docker image tag has been repointed to a different image — possible supply chain attack.\n")
					} else {
						fmt.Fprintf(messageWriter, "    ✓ Docker image digest verified (%s:%s)\n", manifestEntry.Docker.Image, manifestEntry.Docker.Tag)
					}
				}

				// Also verify base image digests for Dockerfile actions
				for _, base := range manifestEntry.Docker.BaseImages {
					if base.Digest == "" {
						continue
					}
					baseReg, baseRepo := manifestpkg.BaseImageRegistry(base.Image)
					liveDigest, err := rc.ResolveDigest(ctx, baseReg, baseRepo, base.Tag)
					if err != nil {
						fmt.Fprintf(messageWriter, "    ⚠ Base image digest check failed for %s:%s: %v\n", base.Image, base.Tag, err)
					} else if liveDigest != base.Digest {
						result.Violations = append(result.Violations, Violation{
							Action:      key,
							Tag:         ar.Ref,
							ExpectedSHA: base.Digest,
							ActualSHA:   liveDigest,
						})
						fmt.Fprintf(messageWriter, "    ✗ BASE IMAGE REPOINTED: %s:%s\n", base.Image, base.Tag)
						fmt.Fprintf(messageWriter, "      Expected: %s\n", base.Digest)
						fmt.Fprintf(messageWriter, "      Current:  %s\n", liveDigest)
					} else {
						fmt.Fprintf(messageWriter, "    ✓ Base image digest verified (%s:%s)\n", base.Image, base.Tag)
					}
				}
			}
```

Also add a `SetRegistryOverride` method to `RegistryClient` in `docker.go`:

```go
// SetRegistryOverride sets a URL override for all registry requests (for testing).
func (c *RegistryClient) SetRegistryOverride(url string) {
	c.registryOverride = url
}
```

Export `BaseImageRegistry` (rename from `baseImageRegistry`) in `docker.go` since gate needs it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/gate/ -run TestGateDockerDigest -v`
Expected: PASS

- [ ] **Step 5: Add Scenario C test (action.yml image reference change)**

This tests the spec's Scenario C: attacker repoints the action tag to a commit that changes action.yml to reference a different Docker image. The existing SHA/tarball integrity check catches this (since action.yml changed → tarball hash changed), but we add an explicit test to confirm.

Add to `internal/gate/gate_docker_test.go`:

```go
func TestGateDockerScenarioC_ImageRefChanged(t *testing.T) {
	// Scenario C: attacker repoints tag to commit with different action.yml
	// The tarball integrity hash changes, so this is caught by existing integrity check
	silenceOutput(t)

	lockfile := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"custom-org/scanner": {
				"v1": {
					SHA:       "abc123def456abc123def456abc123def456abc1",
					Integrity: "sha256-OriginalHash",
					Type:      "docker",
					Docker: &DockerInfo{
						Image:  "ghcr.io/safe-image",
						Tag:    "v1",
						Digest: "sha256:safe",
						Source: "action.yml",
					},
				},
			},
		},
	}
	lockJSON, _ := json.Marshal(lockfile)

	workflow := `on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: custom-org/scanner@v1
`
	// Attacker repointed tag to different commit SHA
	attackerSHA := "bad456abc123bad456abc123bad456abc123bad4"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/graphql"):
			// Tag now points to attacker's commit
			resp := buildGraphQLResponse(map[string]map[string]string{
				"custom-org/scanner": {"v1": attackerSHA},
			})
			fmt.Fprint(w, resp)
		case strings.Contains(r.URL.Path, "ci.yml"):
			fmt.Fprint(w, buildContentResponse(workflow))
		case strings.Contains(r.URL.Path, "actions-lock.json"):
			fmt.Fprint(w, buildContentResponse(string(lockJSON)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".github/actions-lock.json",
		APIURL:       ts.URL,
		GraphQLURL:   ts.URL + "/graphql",
		Integrity:    true,
	})

	if err != nil {
		t.Fatalf("RunGate: %v", err)
	}

	// Should catch as SHA mismatch (tag repoint), before we even get to Docker check
	if len(result.Violations) == 0 {
		t.Fatal("expected violation for tag repoint (Scenario C), got none")
	}

	found := false
	for _, v := range result.Violations {
		if v.Action == "custom-org/scanner" && v.ExpectedSHA != v.ActualSHA {
			found = true
		}
	}
	if !found {
		t.Errorf("no SHA mismatch violation for custom-org/scanner; violations: %+v", result.Violations)
	}
}
```

- [ ] **Step 6: Run all gate tests**

Run: `go test ./internal/gate/ -v`
Expected: All tests pass

- [ ] **Step 7: Run full test suite**

Run: `go test ./... -v`
Expected: All tests pass

- [ ] **Step 8: Commit**

```bash
git add internal/gate/gate.go internal/gate/gate_docker_test.go internal/manifest/docker.go
git commit -m "feat(docker): add Docker digest verification to gate --integrity"
```

---

### Task 8: Wire RegistryClient in CLI lock command

**Files:**
- Modify: `cmd/pinpoint/main.go` (cmdLock function)

- [ ] **Step 1: Read the cmdLock function to understand current flow**

Read `cmd/pinpoint/main.go` and find the `cmdLock` function. Locate where `IntegrityOptions` is constructed and passed to `Refresh`.

- [ ] **Step 2: Add RegistryClient to IntegrityOptions in cmdLock**

Where `IntegrityOptions` is constructed in `cmdLock`, add:

```go
RegistryClient: &manifest.RegistryClient{
	HTTP: &http.Client{Timeout: 30 * time.Second},
},
```

This requires no new flags — Docker digest resolution is automatic when `pinpoint lock` runs with integrity (which is the default for v2 lockfiles).

- [ ] **Step 3: Build and verify**

Run: `go build ./cmd/pinpoint/ && go vet ./...`
Expected: Clean build, no vet issues

- [ ] **Step 4: Run full test suite**

Run: `go test ./... -v`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add cmd/pinpoint/main.go
git commit -m "feat(docker): wire RegistryClient into lock command"
```

---

### Task 9: End-to-end lockfile round-trip test

**Files:**
- Modify: `internal/manifest/docker_test.go`

- [ ] **Step 1: Write an end-to-end test**

This test verifies that a Docker action flows through the full lockfile: serialize → save → load → verify Docker info is intact.

```go
// Add to internal/manifest/docker_test.go

func TestDockerLockfileRoundTrip(t *testing.T) {
	m := &Manifest{
		Version:     2,
		GeneratedAt: "2026-03-25T00:00:00Z",
		Actions: map[string]map[string]ManifestEntry{
			"aquasecurity/trivy-action": {
				"v0.28.0": {
					SHA:       "abc123def456abc123def456abc123def456abc1",
					Integrity: "sha256-AAAA",
					Type:      "docker",
					Docker: &DockerInfo{
						Image:  "ghcr.io/aquasecurity/trivy",
						Tag:    "0.58.1",
						Digest: "sha256:9e3a184f",
						Source: "action.yml",
					},
				},
			},
			"custom-org/scanner-action": {
				"v1": {
					SHA:  "def456abc123def456abc123def456abc123def4",
					Type: "docker",
					Docker: &DockerInfo{
						Image: "Dockerfile",
						BaseImages: []DockerBaseImage{
							{Image: "alpine", Tag: "3.19", Digest: "sha256:aaa"},
							{Image: "golang", Tag: "1.24", Digest: "sha256:bbb"},
						},
						Source: "Dockerfile",
					},
				},
			},
			"actions/checkout": {
				"v4": {
					SHA:  "111222333444555666777888999000aaabbbcccd",
					Type: "node20",
				},
			},
		},
	}

	// Write to temp file
	tmpDir := t.TempDir()
	path := tmpDir + "/actions-lock.json"

	if err := SaveManifest(path, m); err != nil {
		t.Fatalf("SaveManifest: %v", err)
	}

	// Load it back
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	// Verify Docker action
	trivy := loaded.Actions["aquasecurity/trivy-action"]["v0.28.0"]
	if trivy.Docker == nil {
		t.Fatal("trivy Docker info is nil after round-trip")
	}
	if trivy.Docker.Digest != "sha256:9e3a184f" {
		t.Errorf("trivy digest = %q", trivy.Docker.Digest)
	}

	// Verify Dockerfile action
	scanner := loaded.Actions["custom-org/scanner-action"]["v1"]
	if scanner.Docker == nil {
		t.Fatal("scanner Docker info is nil after round-trip")
	}
	if len(scanner.Docker.BaseImages) != 2 {
		t.Fatalf("scanner base images = %d", len(scanner.Docker.BaseImages))
	}
	if scanner.Docker.BaseImages[0].Image != "alpine" {
		t.Errorf("base[0].Image = %q", scanner.Docker.BaseImages[0].Image)
	}

	// Verify non-Docker action has no Docker field
	checkout := loaded.Actions["actions/checkout"]["v4"]
	if checkout.Docker != nil {
		t.Error("checkout should not have Docker info")
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/manifest/ -run TestDockerLockfileRoundTrip -v`
Expected: PASS (all pieces are in place from prior tasks)

- [ ] **Step 3: Commit**

```bash
git add internal/manifest/docker_test.go
git commit -m "test(docker): add end-to-end lockfile round-trip test"
```

---

### Task 10: Build, vet, and full test pass

**Files:** None (verification only)

- [ ] **Step 1: Build**

Run: `go build ./cmd/pinpoint/`
Expected: Clean build

- [ ] **Step 2: Vet**

Run: `go vet ./...`
Expected: No issues

- [ ] **Step 3: Full test suite**

Run: `go test ./... -v`
Expected: All tests pass

- [ ] **Step 4: Verify binary works**

Run: `./pinpoint version`
Expected: Version output, no crash

- [ ] **Step 5: Final commit if any fixups needed**

Only if earlier steps required small fixes. Otherwise, no commit needed.

---

### Known Limitations (document in code comments)

- **Multi-arch manifest lists:** When a registry returns a manifest list (multi-platform index) for a HEAD request, the digest is for the index, not a specific platform manifest. This means the digest is stable (index digests don't change unless a new platform is added/removed), but it represents the "manifest list" not a single image. This is acceptable for detecting tag repoints — if the index digest changes, something changed. Future work could resolve platform-specific digests.
- **Private registries:** Only anonymous/public pull tokens are supported. Private registries requiring login credentials are not yet handled. The `RegistryClient` gracefully degrades (records what it can without the digest).
- **ARG-parameterized FROM:** Dockerfiles using `ARG` before `FROM` (e.g., `FROM ${BASE}:${VERSION}`) cannot be statically resolved. These are skipped with no error.
