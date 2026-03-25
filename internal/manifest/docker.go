// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
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

		rest := strings.TrimSpace(line[5:])
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		imageRef := fields[0]

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
	if idx := strings.Index(ref, "@"); idx != -1 {
		return ref[:idx], ref[idx+1:]
	}

	lastSlash := strings.LastIndex(ref, "/")
	if idx := strings.LastIndex(ref, ":"); idx != -1 && idx > lastSlash {
		return ref[:idx], ref[idx+1:]
	}

	return ref, "latest"
}

// RegistryClient resolves Docker image digests from OCI-compliant registries.
type RegistryClient struct {
	HTTP             *http.Client
	registryOverride string // for testing: override all registry URLs
}

// SetRegistryOverride sets a URL override for all registry requests (for testing).
func (c *RegistryClient) SetRegistryOverride(url string) {
	c.registryOverride = url
}

// tokenResponse represents a Docker registry token exchange response.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

// ResolveDigest returns the manifest digest for image:tag from the given registry.
// Uses the OCI Distribution Spec: HEAD /v2/<repo>/manifests/<tag>.
func (c *RegistryClient) ResolveDigest(ctx context.Context, registry, repo, tag string) (string, error) {
	baseURL := c.registryURL(registry)

	token, err := c.getToken(ctx, baseURL, registry, repo)
	if err != nil {
		return "", fmt.Errorf("registry auth for %s/%s: %w\n\nEnsure the image is public or set appropriate registry credentials.", registry, repo, err)
	}

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

func (c *RegistryClient) getToken(ctx context.Context, baseURL, registry, repo string) (string, error) {
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

// dockerActionYAML is a minimal struct for parsing Docker action.yml.
type dockerActionYAML struct {
	Runs struct {
		Using string `yaml:"using"`
		Image string `yaml:"image"`
	} `yaml:"runs"`
}

// FileReader is a callback to read files from an action's repository.
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
		if strings.HasPrefix(tag, "sha256:") {
			return &DockerInfo{
				Image:  registry + "/" + repo,
				Digest: tag,
				Source: "action.yml",
			}, nil
		}

		digest, err := rc.ResolveDigest(ctx, registry, repo, tag)
		if err != nil {
			// Non-fatal: record what we can, but warn the user
			fmt.Fprintf(os.Stderr, "  ⚠ Docker digest resolution failed for %s/%s:%s: %v\n", registry, repo, tag, err)
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

	filename := strings.TrimPrefix(ref, "./")
	dfContent, err := readFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Could not read %s: %v\n", filename, err)
		return info, nil
	}

	bases := ParseDockerfile(dfContent)
	for i := range bases {
		baseReg, baseRepo := BaseImageRegistry(bases[i].Image)
		digest, err := rc.ResolveDigest(ctx, baseReg, baseRepo, bases[i].Tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Base image digest resolution failed for %s:%s: %v\n", bases[i].Image, bases[i].Tag, err)
		} else {
			bases[i].Digest = digest
		}
	}

	info.BaseImages = bases
	return info, nil
}

// BaseImageRegistry determines the registry and normalized repo for a FROM image reference.
func BaseImageRegistry(image string) (registry, repo string) {
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 1 {
		return "docker.io", "library/" + image
	}

	first := parts[0]
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return first, parts[1]
	}

	return "docker.io", image
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

	return image, true
}
