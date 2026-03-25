# Spec 024: Docker Action Verification

## Problem

Pinpoint currently verifies JavaScript/TypeScript (node20) and composite actions
by checking tag SHAs, tarball integrity hashes, and on-disk content. But **Docker-based
actions** (`runs.using: docker`) are completely unverified. No tool in the space does this.

Docker actions come in two forms:
1. **Dockerfile actions** — `runs.image: Dockerfile` (built at workflow runtime from repo source)
2. **Pre-built image actions** — `runs.image: docker://ghcr.io/owner/image:tag` (pulled from registry)

Both are attack vectors:
- **Dockerfile actions**: The Dockerfile is in the repo tarball, so existing tarball integrity
  covers the build instructions. But the base image (`FROM`) can be swapped upstream.
- **Pre-built image actions**: The image tag is mutable (like a Git tag). An attacker can push
  a new image to the same tag. This is the Docker equivalent of the Trivy tag repoint attack.

## Attack Scenarios

### Scenario A: Pre-built image tag repoint
```yaml
steps:
  - uses: aquasecurity/trivy-action@v0.28.0
    # action.yml contains: image: docker://ghcr.io/aquasecurity/trivy:0.58.1
    # Attacker pushes malicious image to ghcr.io/aquasecurity/trivy:0.58.1
```

### Scenario B: Dockerfile base image swap
```yaml
steps:
  - uses: custom-org/scanner-action@v1
    # action.yml: runs.using: docker, image: Dockerfile
    # Dockerfile: FROM alpine:3.19
    # Alpine pushes compromised 3.19 tag (unlikely but possible)
```

### Scenario C: action.yml image reference change
```yaml
# Attacker repoints scanner-action@v1 to a commit that changes action.yml
# from: image: docker://ghcr.io/safe-image:v1
# to:   image: docker://ghcr.io/evil-image:v1
```

## Solution

### Phase 1: Lockfile records Docker image digests (this spec)

Extend the lockfile format to capture Docker image information for Docker-based actions.

#### Lockfile v2 extension

```json
{
  "actions": {
    "aquasecurity/trivy-action": {
      "v0.28.0": {
        "sha": "abc123...",
        "integrity": "sha256-...",
        "disk_integrity": "sha256-...",
        "type": "docker",
        "docker": {
          "image": "ghcr.io/aquasecurity/trivy",
          "tag": "0.58.1",
          "digest": "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00",
          "source": "action.yml"
        },
        "dependencies": []
      }
    }
  }
}
```

For Dockerfile actions:
```json
{
  "type": "docker",
  "docker": {
    "image": "Dockerfile",
    "base_images": [
      {
        "image": "alpine",
        "tag": "3.19",
        "digest": "sha256:a8cbb8c69ee71561f4b69c066bad07f7612b78939b52a8e7d6cdb92fabb9285e"
      }
    ],
    "source": "Dockerfile"
  }
}
```

### Phase 2: Lock command resolves Docker digests

When `pinpoint lock` encounters a Docker action:

1. Parse `action.yml` → check `runs.using == "docker"`
2. If `runs.image` starts with `docker://`:
   - Extract registry, image, tag
   - Query registry API for manifest digest: `GET /v2/<image>/manifests/<tag>` with
     `Accept: application/vnd.docker.distribution.manifest.v2+json`
   - Record the `Docker-Content-Digest` header as the pinned digest
3. If `runs.image == "Dockerfile"`:
   - Parse Dockerfile for `FROM` instructions
   - Resolve each base image's digest from registry
   - Record base image digests

#### Registry API

```
# ghcr.io auth
GET https://ghcr.io/token?scope=repository:owner/image:pull → token

# Get manifest digest
HEAD https://ghcr.io/v2/owner/image/manifests/tag
  Authorization: Bearer <token>
  Accept: application/vnd.docker.distribution.manifest.v2+json,
          application/vnd.oci.image.manifest.v1+json
→ Docker-Content-Digest: sha256:...
```

Supported registries: ghcr.io, docker.io (hub.docker.com), public ECR, quay.io.
Use OCI distribution spec — same API across all compliant registries.

### Phase 3: Gate verifies Docker digests

When `pinpoint gate` encounters a Docker action with a `docker` field in the lockfile:

1. If `--integrity` flag: re-resolve the image digest from the registry and compare
2. If digest mismatch → violation: "Docker image digest changed"
3. If image reference changed (action.yml now points to different image) → violation

The default SHA-only gate already catches action.yml changes (since the tarball hash
changes). Docker digest verification is an `--integrity` level check.

### Phase 4: Scan/watch monitors Docker image changes

`pinpoint scan` and `pinpoint watch` can poll Docker registries for digest changes
on monitored actions, similar to how they poll GitHub for tag changes.

## Implementation Plan

### Files to create/modify

- `internal/manifest/docker.go` — Docker registry client, digest resolution
- `internal/manifest/docker_test.go` — Tests with httptest registry mocks
- `internal/manifest/integrity.go` — Extend `ComputeIntegrityHash` to handle Docker actions
- `internal/manifest/manifest.go` — Extend lockfile struct with `DockerInfo` field
- `internal/gate/gate.go` — Docker digest verification in `--integrity` mode
- `internal/discover/discover.go` — Detect Docker action type from action.yml

### Lockfile struct changes

```go
type ActionEntry struct {
    SHA           string       `json:"sha"`
    Integrity     string       `json:"integrity,omitempty"`
    DiskIntegrity string       `json:"disk_integrity,omitempty"`
    RecordedAt    string       `json:"recorded_at,omitempty"`
    Type          string       `json:"type"`                    // "node20", "composite", "docker"
    Docker        *DockerInfo  `json:"docker,omitempty"`        // NEW
    Dependencies  []DepEntry   `json:"dependencies,omitempty"`
}

type DockerInfo struct {
    Image      string            `json:"image"`                // "ghcr.io/owner/image" or "Dockerfile"
    Tag        string            `json:"tag,omitempty"`         // "0.58.1"
    Digest     string            `json:"digest,omitempty"`      // "sha256:..."
    BaseImages []DockerBaseImage `json:"base_images,omitempty"` // For Dockerfile actions
    Source     string            `json:"source"`                // "action.yml" or "Dockerfile"
}

type DockerBaseImage struct {
    Image  string `json:"image"`
    Tag    string `json:"tag"`
    Digest string `json:"digest"`
}
```

### Registry client

```go
type RegistryClient struct {
    http *http.Client
}

// ResolveDigest returns the manifest digest for image:tag
func (c *RegistryClient) ResolveDigest(ctx context.Context, image, tag string) (string, error)

// ParseDockerRef extracts registry, repo, tag from "docker://ghcr.io/owner/image:tag"
func ParseDockerRef(ref string) (registry, repo, tag string, err error)

// ParseDockerfile extracts FROM instructions
func ParseDockerfile(content []byte) []DockerBaseImage
```

### No new dependencies

- Registry API is standard HTTP — use `net/http`
- Dockerfile parsing is simple line-by-line — no need for a Docker library
- JWT token exchange for ghcr.io is a single HTTP call

## Competitive Impact

No tool in the GitHub Actions security space verifies Docker image digests:
- gh-actions-lockfile: JS/composite only
- ghasum: JS/composite only
- StepSecurity/harden-runner: runtime monitoring, no pre-execution Docker verification

This would make pinpoint the **first tool to close the Docker action attack vector**.

## Performance

- Registry manifest HEAD requests are fast (~100-200ms each)
- Parallel resolution with existing worker pool
- Digest verification is a string comparison (zero cost at gate time for SHA-only mode)
- Full digest re-resolution only with `--integrity` flag

## Risks

- Private registries may require authentication beyond anonymous pulls
- Multi-arch images have manifest lists — need to resolve the correct platform digest
- Docker Hub rate limits (100 pulls/6h anonymous, 200 authenticated)
- Some actions use `image: Dockerfile` with multi-stage builds and build args

## Test Plan

1. Unit tests with httptest registry mocks
2. Integration test: lock a real Docker action (e.g., `aquasecurity/trivy-action`)
3. Attack scenario: repoint Docker image tag, verify gate catches it
4. Dockerfile parsing: multi-FROM, build args, ARG before FROM

## Milestones

1. **M1**: `DockerInfo` struct + lockfile serialization + type detection → 1 day
2. **M2**: Registry client + digest resolution for ghcr.io/dockerhub → 1-2 days
3. **M3**: `pinpoint lock` records Docker digests → 1 day
4. **M4**: `pinpoint gate --integrity` verifies Docker digests → 1 day
5. **M5**: Dockerfile FROM parsing + base image digests → 1 day
6. **M6**: Attack scenario test in harness → 1 day
