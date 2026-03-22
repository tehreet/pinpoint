# Spec 015: On-Disk Content Verification (TOCTOU Elimination)

## Summary

Verify what the runner ACTUALLY downloaded, not what the API claims.

The gate currently asks the GitHub API "what SHA does `actions/checkout@v4`
resolve to?" and compares that to the lockfile. But there's a time-of-check
to time-of-use (TOCTOU) gap: the runner already downloaded all actions
BEFORE any step executes. What if the tag was repointed between the runner's
download and the gate's API check? Or what if the download was intercepted
(MITM on self-hosted runners, compromised proxy, GitHub CDN issue)?

This spec adds on-disk verification: the gate hashes the actual files
the runner downloaded and compares those hashes against the lockfile's
integrity field (from spec 014). This is the first tool that verifies
the code that's about to execute, not a proxy for it.

## Why This Matters

### The TOCTOU Problem

```
Timeline:
  T0: Runner resolves actions/checkout@v4 → SHA abc123
  T1: Runner downloads abc123 to _actions/actions/checkout/v4/
  T2: Attacker force-pushes v4 → SHA deadbeef
  T3: Gate asks API "what is v4?" → gets deadbeef
  T4: Gate compares deadbeef to lockfile (abc123) → VIOLATION
  T5: Gate fails the build — but the code at T1 was fine!
```

This is a false positive. The runner got the right code, but the API
check ran after the repoint. The inverse is worse:

```
  T0: Runner resolves v4 → SHA deadbeef (attacker already repointed)
  T1: Runner downloads deadbeef to _actions/actions/checkout/v4/
  T2: Attacker reverts v4 → SHA abc123 (covers their tracks)
  T3: Gate asks API "what is v4?" → gets abc123
  T4: Gate compares abc123 to lockfile (abc123) → PASS
  T5: Malicious code executes — gate was bypassed!
```

On-disk verification eliminates both scenarios. It hashes the files at
`_actions/actions/checkout/v4/` and compares to the lockfile's
`integrity` hash. What the API says doesn't matter. What's on disk
is what will execute.

### Self-Hosted Runner Risks

Self-hosted runners are especially vulnerable:
- No ephemeral environment (actions may be cached across runs)
- Network may be interceptable (corporate proxy, DNS hijack)
- Disk may be tampered with by other processes
- `_actions/` directory persists between runs unless manually cleaned

On-disk verification catches all of these because it hashes what's
actually present on the filesystem at the moment the gate runs.

## Verified Facts

### Runner Actions Cache Path

Actions are downloaded to: `{runner_work_dir}/_actions/{owner}/{repo}/{ref}/`

**GitHub-hosted runners:**
```
/home/runner/work/_actions/actions/checkout/v4/
/home/runner/work/_actions/actions/setup-go/v5/
```

**Self-hosted runners:**
```
{runner_root}/_work/_actions/actions/checkout/v4/
```

**Container jobs:**
```
/__w/_actions/actions/checkout/v4/
```

### Deriving the Path

The `RUNNER_WORKSPACE` environment variable gives us the path:
```
RUNNER_WORKSPACE = /home/runner/work/{repo-name}
Actions dir      = $(dirname $RUNNER_WORKSPACE)/_actions
```

Which resolves to:
```
/home/runner/work/_actions/
```

The gate runs as a composite action step. Inside a composite action,
we have access to `$RUNNER_WORKSPACE` as an environment variable.

### What Gets Downloaded

When the runner resolves `actions/checkout@v4`, it:
1. Resolves the ref to a commit SHA via the GitHub API
2. Downloads a tarball of the repo at that SHA
3. Extracts it to `_actions/actions/checkout/v4/`

The extracted directory contains the full repository at that commit:
`action.yml`, `dist/`, `src/`, `node_modules/`, etc.

### Hashing Strategy

We need to hash the on-disk content in a way that's deterministic and
comparable to the tarball integrity hash from spec 014.

**Option A: Re-tar and hash.** Create a tarball from the on-disk files,
hash it, compare to lockfile. Problem: tarball generation isn't
deterministic (ordering, timestamps, compression).

**Option B: Hash file tree.** Walk the directory, hash each file,
combine into a Merkle-like root hash. Deterministic if we sort files
and use consistent hashing. Problem: this is a different hash than the
tarball integrity hash.

**Option C: Content-addressable tree hash.** Compute SHA-256 of each
file's content, sort the `(path, hash)` pairs, hash the concatenation.
This is deterministic and filesystem-independent. Problem: still a
different hash than the tarball.

**Decision: Option C with a separate `disk_integrity` field.**

The tarball hash (`integrity` field) and the on-disk hash
(`disk_integrity` field computed at lock time by extracting the tarball
and hashing the tree) are different hashes that verify different things:

- `integrity`: verifies the tarball hasn't changed (API-level check)
- `disk_integrity`: verifies the on-disk content matches what was in
  the tarball at lock time (runtime check)

During `pinpoint lock`, we:
1. Download the tarball
2. Compute `integrity` = SHA-256 of the tarball bytes
3. Extract the tarball to a temp directory
4. Compute `disk_integrity` = SHA-256 of the sorted file tree
5. Delete the temp directory
6. Store both hashes in the lockfile

During `pinpoint gate --on-disk`:
1. Walk `_actions/{owner}/{repo}/{ref}/`
2. Compute the tree hash using the same algorithm
3. Compare to `disk_integrity` in the lockfile

### Tree Hash Algorithm

```
for each file in directory (sorted by relative path):
    hash = SHA-256(file contents)
    append "{relative_path}\x00{hash}\n" to buffer
tree_hash = SHA-256(buffer)
return "sha256-" + base64(tree_hash)
```

Specifics:
- Paths are relative to the action root (e.g. `action.yml`, `dist/index.js`)
- Forward slashes only (normalize on Windows)
- Sort lexicographically by path
- Null byte separator between path and hash
- Skip `.git/` directory if present
- Skip symlinks (resolve or skip, don't follow)
- Empty directories are not included (only files contribute)

## Updated Lockfile Format (extends spec 014)

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
        "disk_integrity": "sha256-Xn9f8kL2mQ4pR7sT1vW3yZ...",
        "recorded_at": "2026-03-22T02:00:00Z",
        "type": "node24",
        "dependencies": []
      }
    }
  }
}
```

New field:
- `disk_integrity`: SHA-256 tree hash of extracted tarball contents

## Implementation

### Tree Hash Function

```go
// ComputeTreeHash walks a directory and computes a deterministic
// SHA-256 hash of all file contents, sorted by path.
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

        // Only hash regular files
        if !d.Type().IsRegular() {
            return nil
        }

        relPath, err := filepath.Rel(dir, path)
        if err != nil {
            return err
        }

        // Normalize to forward slashes
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
```

### Lock Command: Computing disk_integrity

```go
// During lock, after downloading each tarball:

// 1. Save tarball to temp file
tmpFile, _ := os.CreateTemp("", "pinpoint-tarball-*.tar.gz")
// ... download tarball, compute integrity hash (streaming) ...

// 2. Extract to temp directory
tmpDir, _ := os.MkdirTemp("", "pinpoint-extract-*")
extractTarball(tmpFile.Name(), tmpDir)

// 3. Compute tree hash
// The tarball extracts to a subdirectory like:
//   {tmpDir}/{owner}-{repo}-{shortsha}/
// We need to find this subdirectory and hash its contents.
subdirs, _ := os.ReadDir(tmpDir)
actionRoot := filepath.Join(tmpDir, subdirs[0].Name())
diskIntegrity, _ := ComputeTreeHash(actionRoot)

// 4. Clean up
os.RemoveAll(tmpDir)
os.Remove(tmpFile.Name())
```

The tarball from GitHub's API extracts to a directory named
`{owner}-{repo}-{shortsha}/`. We hash the contents of that directory.

### Gate: On-Disk Verification

```go
func (g *Gate) verifyOnDisk(action, ref string, entry LockEntry) error {
    // Derive actions cache path from RUNNER_WORKSPACE
    runnerWorkspace := os.Getenv("RUNNER_WORKSPACE")
    if runnerWorkspace == "" {
        return fmt.Errorf("RUNNER_WORKSPACE not set; on-disk verification requires a GitHub Actions runner")
    }
    
    actionsDir := filepath.Join(filepath.Dir(runnerWorkspace), "_actions")
    
    // Parse owner/repo from action string
    parts := strings.Split(action, "/")
    if len(parts) < 2 {
        return fmt.Errorf("invalid action: %s", action)
    }
    
    // The runner stores at: _actions/{owner}/{repo}/{ref}/
    actionPath := filepath.Join(actionsDir, parts[0], parts[1], ref)
    
    if _, err := os.Stat(actionPath); os.IsNotExist(err) {
        return fmt.Errorf("action not found on disk: %s (expected at %s)", action, actionPath)
    }
    
    diskHash, err := ComputeTreeHash(actionPath)
    if err != nil {
        return fmt.Errorf("hashing on-disk content: %w", err)
    }
    
    if diskHash != entry.DiskIntegrity {
        return fmt.Errorf(
            "ON-DISK INTEGRITY MISMATCH: %s@%s\n"+
            "  Expected: %s\n"+
            "  Actual:   %s\n"+
            "  Path:     %s\n"+
            "  The code on disk does not match what was recorded in the lockfile.\n"+
            "  This could indicate: tampering, a stale actions cache, or a supply chain compromise.",
            action, ref, entry.DiskIntegrity, diskHash, actionPath)
    }
    
    return nil
}
```

### Updated action.yml

The composite action needs to pass `RUNNER_WORKSPACE` to pinpoint
and enable on-disk verification:

```yaml
    - name: Verify action integrity
      shell: bash
      env:
        GITHUB_TOKEN: ${{ github.token }}
        RUNNER_WORKSPACE: ${{ runner.workspace }}
      run: |
        ARGS="--manifest ${{ inputs.manifest }}"
        if [ "${{ inputs.on-disk }}" = "true" ]; then
          ARGS="$ARGS --on-disk"
        fi
        # ... rest of flags ...
        "${{ runner.temp }}/pinpoint" gate $ARGS
```

New input:
```yaml
  on-disk:
    description: 'Verify action content on disk (eliminates TOCTOU)'
    required: false
    default: 'false'
```

### Gate Flag Hierarchy

The gate now has three levels of verification:

1. **SHA-only (default, existing):** Check that tag→SHA matches lockfile.
   Fast (3 API calls). Catches tag repointing.

2. **Integrity (spec 014, `--integrity`):** Also download tarball and
   verify SHA-256 hash. Medium (3 + N API calls). Catches content
   changes at the API level.

3. **On-disk (this spec, `--on-disk`):** Also hash what the runner
   downloaded and verify against `disk_integrity`. Comprehensive
   (3 + N API calls + filesystem walk). Catches everything including
   TOCTOU, cache poisoning, MITM, and disk tampering.

`--on-disk` implies `--integrity` (both checks run).

When `--on-disk` is specified but `disk_integrity` is missing from the
lockfile, the gate warns: "disk_integrity not found in lockfile. Run
`pinpoint lock` to regenerate." It falls back to integrity-only mode.

When `--on-disk` is specified outside a GitHub Actions runner
(RUNNER_WORKSPACE not set), the gate errors: "On-disk verification
requires a GitHub Actions runner environment."

## CLI Changes

### pinpoint gate

```
pinpoint gate [flags]

New flags:
  --integrity       Verify tarball content hashes (spec 014)
  --on-disk         Verify on-disk content (implies --integrity)
  --skip-transitive Skip transitive dependency verification
  --actions-dir     Override actions cache directory
                    (default: derived from RUNNER_WORKSPACE)
```

The `--actions-dir` override is useful for:
- Self-hosted runners with non-standard paths
- Testing (point to a mock directory)
- Container jobs where the path differs

### pinpoint lock

```
pinpoint lock [flags]

Updated behavior:
  Now computes disk_integrity for every action (spec 015)
  --skip-disk-integrity  Skip computing disk_integrity hashes
```

## API Cost

On-disk verification adds ZERO API calls. It only reads the local
filesystem. The cost is purely I/O: walking the directory tree and
hashing files. For a typical action (actions/checkout has ~200 files),
this takes <100ms.

Combined with spec 014's integrity check, the full gate with all
three levels:

| Operation | Calls | Time |
|---|---|---|
| Fetch workflow (REST) | 1 | |
| Fetch lockfile (REST) | 1 | |
| Resolve tags (GraphQL) | 1 | |
| Download tarballs (REST) | N | |
| Fetch action.yml (REST) | C | Only composite |
| Hash on-disk dirs (local) | N | ~100ms each |
| **Total** | **3 + N + C** | **~5-8 seconds** |

Where N = number of direct + transitive actions, C = number of
composite actions.

## Edge Cases

### Action Not on Disk

The runner downloads actions during job setup, before any step runs.
If an action isn't on disk, it means:
- The lockfile references an action not in the workflow (stale lockfile)
- The runner failed to download the action (the job would have failed anyway)
- The actions cache was cleaned between download and gate execution

Gate behavior: warn and skip that action. Don't fail on missing disk
entries. The SHA and integrity checks still run via API.

### Self-Hosted Runner Action Caching

Self-hosted runners may cache actions between runs. The `_actions/`
directory may contain actions from previous runs that are no longer
referenced. This is fine: we only check actions that are in the
lockfile AND in the current workflow.

However, a stale cached version could be used by the runner instead
of re-downloading. On-disk verification catches this: if the cached
version has different content than what's in the lockfile, the hash
won't match.

### Container Jobs

In container jobs, the actions directory is mounted at `/__w/_actions/`.
The `RUNNER_WORKSPACE` variable inside the container is `/__w/{repo-name}`,
so `dirname(RUNNER_WORKSPACE)/_actions` resolves correctly.

### Windows Runners

Windows runners store actions at:
`D:\a\_actions\{owner}\{repo}\{ref}\`

The `RUNNER_WORKSPACE` is `D:\a\{repo-name}`.
`dirname(RUNNER_WORKSPACE)\_actions` resolves correctly.

Path normalization in the tree hash (forward slashes only) ensures
the hash is cross-platform consistent.

## Tests

### Tree Hash Tests

**TestComputeTreeHash_Deterministic**
Create a directory with 3 files. Hash twice. Results must match.

**TestComputeTreeHash_OrderIndependent**
Create the same files in different order. Hash must be identical
(sort handles this).

**TestComputeTreeHash_ContentSensitive**
Change one byte in one file. Hash must differ.

**TestComputeTreeHash_SkipsGitDir**
Directory has a `.git/` subdirectory. It must be excluded from hash.

**TestComputeTreeHash_SkipsSymlinks**
Directory has a symlink. It must be excluded from hash.

**TestComputeTreeHash_EmptyDir**
Empty directory. Hash must be deterministic (hash of empty buffer).

**TestComputeTreeHash_CrossPlatformPaths**
On any OS, paths in the hash use forward slashes.

### Lock Disk Integrity Tests

**TestLock_IncludesDiskIntegrity**
After running lock, every entry has a non-empty `disk_integrity` field.

**TestLock_DiskIntegrityMatchesExtracted**
Download a tarball, extract it, compute tree hash. It must match
the `disk_integrity` stored in the lockfile.

**TestLock_SkipDiskIntegrity**
With `--skip-disk-integrity`, `disk_integrity` field is empty.

### Gate On-Disk Tests

**TestGate_OnDiskMatch**
Set up a mock actions directory. Lockfile has correct `disk_integrity`.
Gate with `--on-disk` passes.

**TestGate_OnDiskMismatch**
Set up a mock actions directory. Modify one file. Gate with `--on-disk`
fails with INTEGRITY MISMATCH.

**TestGate_OnDiskMissingAction**
Lockfile references an action not present on disk. Gate warns but
doesn't fail. API checks still run.

**TestGate_OnDiskNoRunnerWorkspace**
`RUNNER_WORKSPACE` not set. Gate with `--on-disk` errors with
a clear message.

**TestGate_OnDiskFallback**
Lockfile has no `disk_integrity` fields. Gate with `--on-disk`
warns and falls back to integrity-only.

**TestGate_OnDiskCustomDir**
`--actions-dir /custom/path` overrides the derived path.

## Files to Create/Modify

- CREATE: `internal/integrity/treehash.go` — ComputeTreeHash function
- CREATE: `internal/integrity/treehash_test.go` — 7 tree hash tests
- MODIFY: `internal/manifest/integrity.go` — add disk_integrity computation
  (extract tarball to temp dir, hash, clean up)
- MODIFY: `internal/gate/gate.go` — add verifyOnDisk method, --on-disk flag
- CREATE: `internal/gate/ondisk_test.go` — 6 on-disk gate tests
- MODIFY: `cmd/pinpoint/main.go` — add --on-disk and --actions-dir flags
  to gate, add --skip-disk-integrity to lock
- MODIFY: `action.yml` — add `on-disk` input, pass RUNNER_WORKSPACE env

## Build Verification

```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
./pinpoint lock --help    # should show --skip-disk-integrity
./pinpoint gate --help    # should show --on-disk, --actions-dir
```
