# Spec 014: Content Integrity Hashes + Transitive Dependency Resolution

## Summary

Two features that make pinpoint's lockfile as strong as any competing tool,
while staying a single Go binary with one dependency.

1. **Content integrity hashes:** SHA-256 hash of each action's tarball,
   stored alongside the commit SHA. Proves the content hasn't changed,
   not just that the tag hasn't moved.

2. **Transitive dependency resolution:** For composite actions, fetch
   their `action.yml`, discover inner `uses:` directives, and include
   the full dependency tree in the lockfile.

## Why Both Matter

The commit SHA proves "this is the commit the maintainer tagged."
The integrity hash proves "the code at this commit is what I reviewed."
These are different properties. A commit SHA is a hash of the commit
*object* (author, message, tree pointer, parent), not a direct hash of
the code content. In the unlikely event of a SHA-1 collision or a
GitHub infrastructure compromise, the commit SHA could resolve to
different content. The SHA-256 integrity hash of the tarball catches this.

Transitive dependencies matter because the tj-actions attack chain
proved it: compromising `reviewdog/action-setup` (an inner dependency)
compromised `tj-actions/changed-files` (the outer action). Your
workflow only references the outer action. Without transitive resolution,
the inner compromise is invisible.

## Verified API Contracts (2026-03-22)

### Tarball Download

```
GET /repos/{owner}/{repo}/tarball/{sha}
Authorization: Bearer {token}
```

Response: 302 redirect to `codeload.github.com`, then tarball content.
Follow redirects to get the tarball.

**Verified:**
```
URL: https://api.github.com/repos/actions/checkout/tarball/34e114876b0b11c390a56381ad16ebd13914f8d5
Final URL: https://codeload.github.com/actions/checkout/legacy.tar.gz/34e114876b0b11c390a56381ad16ebd13914f8d5
Size: 428,860 bytes
SHA-256: 5251829f363b759378b315371864d0080d182ad7a7fe5c54bca83d7b0afb3016
```

**Determinism verified:** Two consecutive downloads produce identical SHA-256.

### Fetch action.yml at Specific SHA

```
GET /repos/{owner}/{repo}/contents/action.yml?ref={sha}
```

Response: base64-encoded content (same API used by the gate).

**Verified:** `actions/upload-pages-artifact` at SHA `7b1f4a76...` returns:
```yaml
using: composite
steps:
  - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
```

This shows the transitive dependency: `upload-pages-artifact` internally
uses `upload-artifact`.

### Identifying Composite Actions

Parse `action.yml` and check the `runs.using` field:
- `"composite"` → has steps that may reference other actions
- `"node16"`, `"node20"`, `"node24"` → JavaScript action, no action-level transitive deps
- `"docker"` → Docker action, no action-level transitive deps

Only composite actions have transitive action dependencies.

## Updated Lockfile Format

```json
{
  "version": 2,
  "generated_at": "2026-03-22T02:00:00Z",
  "generated_by": "pinpoint lock",
  "actions": {
    "actions/checkout": {
      "v4": {
        "sha": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "integrity": "sha256-UlGCnzY7dZN4sxU3GGTQCAHRgq16p/5cS8qD17Cvswk=",
        "recorded_at": "2026-03-22T02:00:00Z",
        "type": "node24",
        "dependencies": []
      }
    },
    "actions/upload-pages-artifact": {
      "v4": {
        "sha": "7b1f4a764d45c48632c6b24a0339c27f5614fb0b",
        "integrity": "sha256-abc123...",
        "recorded_at": "2026-03-22T02:00:00Z",
        "type": "composite",
        "dependencies": [
          {
            "action": "actions/upload-artifact",
            "ref": "ea165f8d65b6e75b540449e92b4886f43607fa02",
            "integrity": "sha256-def456...",
            "type": "node24",
            "dependencies": []
          }
        ]
      }
    }
  }
}
```

Fields added:
- `integrity`: SRI-format SHA-256 hash of the tarball (base64-encoded)
- `type`: `"composite"`, `"node24"`, `"node20"`, `"docker"`, or `"unknown"`
- `dependencies`: array of transitive deps (recursive), each with
  their own `action`, `ref` (always a SHA for transitive deps),
  `integrity`, `type`, and `dependencies`

**Backwards compatibility:** version 1 lockfiles (without integrity or
dependencies) are still accepted. The gate warns: "Lockfile v1 detected.
Upgrade with: pinpoint lock". Verification falls back to SHA-only mode.

## Implementation

### Content Integrity: Tarball Download + Hash

```go
// DownloadAndHash downloads an action tarball and returns its SHA-256 hash.
func (c *GitHubClient) DownloadAndHash(ctx context.Context, owner, repo, sha string) (string, error) {
    url := fmt.Sprintf("%s/repos/%s/%s/tarball/%s", c.baseURL, owner, repo, sha)
    
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    // Set Authorization header
    // Follow redirects (http.Client does this by default)
    
    resp, err := c.httpClient.Do(req)
    // Read body into a SHA-256 hasher (streaming, don't buffer entire tarball)
    
    hasher := sha256.New()
    _, err = io.Copy(hasher, resp.Body)
    
    // Return base64-encoded hash in SRI format: "sha256-XXXX..."
    return "sha256-" + base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}
```

Key: stream the tarball through the hasher. Don't load 400KB+ into memory
for each action. `io.Copy` to `sha256.New()` handles this efficiently.

### Transitive Resolution: Fetch + Parse action.yml

```go
// ResolveTransitiveDeps fetches an action's action.yml and discovers
// inner uses: directives for composite actions.
func (c *GitHubClient) ResolveTransitiveDeps(ctx context.Context, owner, repo, sha string, depth int) ([]TransitiveDep, string, error) {
    if depth > 5 {
        return nil, "unknown", fmt.Errorf("transitive dependency depth exceeded (max 5)")
    }
    
    // Fetch action.yml (or action.yaml) at the specified SHA
    content, err := c.FetchFileContent(ctx, owner+"/"+repo, "action.yml", sha)
    if err != nil {
        // Try action.yaml
        content, err = c.FetchFileContent(ctx, owner+"/"+repo, "action.yaml", sha)
        if err != nil {
            return nil, "unknown", nil // Not an error — action may use Dockerfile
        }
    }
    
    // Parse YAML to get runs.using
    actionType := parseActionType(content) // "composite", "node24", etc.
    
    if actionType != "composite" {
        return nil, actionType, nil // No transitive deps for non-composite
    }
    
    // Extract uses: directives from steps
    refs := ExtractUsesDirectives(string(content))
    
    var deps []TransitiveDep
    for _, raw := range refs {
        owner, repo, ref, _, err := ParseActionRef(raw)
        if err != nil {
            continue // Skip local/docker refs
        }
        
        // Resolve the ref to a SHA if it's a tag
        resolvedSHA := ref
        if !isSHA(ref) {
            resolvedSHA, err = c.ResolveTagToSHA(ctx, owner, repo, ref)
            if err != nil {
                continue
            }
        }
        
        // Get integrity hash
        integrity, err := c.DownloadAndHash(ctx, owner, repo, resolvedSHA)
        if err != nil {
            integrity = "" // Warn but continue
        }
        
        // Recurse for this dependency's own transitive deps
        innerDeps, innerType, _ := c.ResolveTransitiveDeps(ctx, owner, repo, resolvedSHA, depth+1)
        
        deps = append(deps, TransitiveDep{
            Action:       owner + "/" + repo,
            Ref:          resolvedSHA,
            Integrity:    integrity,
            Type:         innerType,
            Dependencies: innerDeps,
        })
    }
    
    return deps, actionType, nil
}
```

Depth limit of 5 prevents infinite recursion. GitHub's own composite
action nesting limit is 10, but in practice transitive chains rarely
exceed 2-3 levels.

### Updated Lock Command Flow

```
pinpoint lock:
  1. Scan workflows, extract all uses: directives
  2. Resolve each tag to commit SHA (GraphQL, same as before)
  3. For each action:
     a. Download tarball at SHA, compute SHA-256 integrity hash
     b. Fetch action.yml at SHA, determine type
     c. If composite: recursively resolve transitive deps
     d. For each transitive dep: download tarball, hash, recurse
  4. Write lockfile with version 2 format
```

### Updated Gate Verification

During gate verification, for each action in the lockfile:

1. **SHA check (existing):** Current tag SHA matches lockfile SHA
2. **Integrity check (new):** Download tarball at current SHA, compute
   hash, compare to lockfile's `integrity` field
3. **Transitive check (new):** For composite actions, fetch current
   `action.yml`, verify transitive deps match lockfile's `dependencies`

The integrity check adds one HTTP request per action (tarball download).
For 10 actions, that's 10 extra requests. The tarballs are small
(most actions are 100-500KB). Total time increase: ~2-3 seconds.

Flag to skip if too slow: `--skip-integrity` (mirrors gh-actions-lockfile).

### Dependency Tree Display

```
pinpoint lock --list
```

Output:
```
.github/actions-lock.json (12 actions, 3 transitive)

actions/checkout@v4 (34e1148...) [node24]
actions/setup-go@v5 (40f1582...) [node24]
actions/upload-pages-artifact@v4 (7b1f4a7...) [composite]
  └── actions/upload-artifact@v4.6.2 (ea165f8...) [node24]
docker/build-push-action@v5 (ca052bb...) [node24]
aquasecurity/trivy-action@0.35.0 (57a97c7...) [node24]
```

### API Cost

For `pinpoint lock` with 10 actions, 2 of which are composite with
1 transitive dep each:

| Operation | Calls | Notes |
|---|---|---|
| Resolve tags (GraphQL) | 1 | Batch 50 repos per query |
| Download tarballs (REST) | 12 | 10 direct + 2 transitive |
| Fetch action.yml (REST) | 10 | Check type for all 10 |
| **Total** | **23** | |

For gate verification with `--integrity`:

| Operation | Calls | Notes |
|---|---|---|
| Fetch workflow (REST) | 1 | Same as before |
| Fetch lockfile (REST) | 1 | Same as before |
| Resolve tags (GraphQL) | 1 | Same as before |
| Download tarballs (REST) | 12 | Integrity verification |
| Fetch action.yml (REST) | 2 | Only composite actions |
| **Total** | **17** | ~5 seconds |

Without `--integrity`, cost is unchanged from current: 3 calls, <2 seconds.

## Types

```go
// TransitiveDep represents a dependency discovered in a composite action.
type TransitiveDep struct {
    Action       string          `json:"action"`
    Ref          string          `json:"ref"`
    Integrity    string          `json:"integrity,omitempty"`
    Type         string          `json:"type"`
    Dependencies []TransitiveDep `json:"dependencies"`
}
```

Update existing `ManifestEntry` / lockfile entry to include:
```go
type LockEntry struct {
    SHA          string          `json:"sha"`
    Integrity    string          `json:"integrity,omitempty"`
    RecordedAt   string          `json:"recorded_at,omitempty"`
    Type         string          `json:"type,omitempty"`
    Dependencies []TransitiveDep `json:"dependencies,omitempty"`
}
```

## Tests

### Content Integrity Tests

**TestDownloadAndHash_Deterministic**
Download the same tarball twice. Hashes must match.

**TestDownloadAndHash_DifferentSHAs**
Download tarballs for two different SHAs of the same repo. Hashes must differ.

**TestGate_IntegrityMatch**
Lockfile has correct integrity hash. Gate passes.

**TestGate_IntegrityMismatch**
Lockfile has wrong integrity hash (simulated content change). Gate fails.

**TestGate_IntegritySkipped**
With `--skip-integrity`, integrity check is not performed even if
integrity field is present.

**TestLock_IncludesIntegrity**
After running lock, every entry in the lockfile has a non-empty
`integrity` field starting with `sha256-`.

### Transitive Resolution Tests

**TestResolve_CompositeWithDeps**
Mock an action.yml that is composite with 2 `uses:` directives.
Verify both are discovered and included in `dependencies`.

**TestResolve_NodeAction_NoDeps**
Mock an action.yml with `using: node24`. Verify `dependencies` is empty
and `type` is `"node24"`.

**TestResolve_NestedComposite**
Composite action A uses composite action B, which uses action C.
Verify the full tree is resolved to depth 2.

**TestResolve_DepthLimit**
Chain of 6 composite actions. Verify resolution stops at depth 5
with a warning, not an infinite loop.

**TestResolve_LocalActionSkipped**
Composite action uses `./local-action`. Verify it's skipped (can't
resolve local paths from the API).

**TestLock_ListOutput**
After running lock, `--list` prints the dependency tree with correct
indentation and types.

**TestLock_TransitiveDepsInLockfile**
After running lock on a workflow using a composite action, the lockfile
contains the transitive deps with their own SHAs and integrity hashes.

## Files to Create/Modify

- MODIFY: `internal/gate/gate.go` — add integrity verification, transitive checking
- MODIFY: `internal/manifest/manifest.go` — add integrity hashing, transitive resolution
  to Refresh/lock flow
- MODIFY: `internal/poller/github.go` — add `DownloadAndHash`, `FetchActionYAML`,
  `ResolveTransitiveDeps` methods
- CREATE: `internal/manifest/integrity.go` — tarball download + SHA-256 hashing
- CREATE: `internal/manifest/transitive.go` — action.yml parsing, type detection,
  recursive resolution
- CREATE: `internal/manifest/integrity_test.go` — 6 integrity tests
- CREATE: `internal/manifest/transitive_test.go` — 7 transitive resolution tests
- MODIFY: `cmd/pinpoint/main.go` — add `--list` flag to lock, add `--skip-integrity`
  to gate

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
./pinpoint lock --help
./pinpoint lock --list --help
```
