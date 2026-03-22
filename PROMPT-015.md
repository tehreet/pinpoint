Read specs/015-ondisk-verification.md AND specs/016-performance-testing.md before writing any code.

This spec adds on-disk content verification to the gate. Instead of asking the GitHub API what a tag resolves to, it hashes the actual files the runner downloaded and compares to the lockfile.

CRITICAL PERFORMANCE CONTEXT: On-disk verification is FASTER than tarball-based integrity verification (28ms disk I/O vs 1.5s+ per tarball download) AND more secure (verifies what will actually execute). --on-disk does NOT imply --integrity. They are independent checks:
  --on-disk: hashes files on disk, compares to lockfile
  --integrity: re-downloads tarballs from API, compares to lockfile
Users can use both, but --on-disk alone is the recommended fast+secure option.

PHASE 1: Tree hash function

Create internal/integrity/treehash.go (new package: internal/integrity).

func ComputeTreeHash(dir string) (string, error)

Algorithm:
1. Walk the directory with filepath.WalkDir
2. Skip directories named ".git" (filepath.SkipDir)
3. Skip non-regular files (symlinks, devices, etc.) — check d.Type().IsRegular()
4. For each regular file:
   a. Compute relative path from dir root
   b. Normalize to forward slashes: filepath.ToSlash(relPath)
   c. Open file, stream through sha256.New() via io.Copy
   d. Append "relPath\x00hexHash" to a []string slice
5. Sort the slice lexicographically
6. Feed each entry + "\n" into a final sha256.New() hasher
7. Return "sha256-" + base64.StdEncoding.EncodeToString(finalHash.Sum(nil))

The null byte (\x00) separator between path and hash prevents collisions between paths that end in hex characters.

Create internal/integrity/treehash_test.go:

TestComputeTreeHash_Deterministic:
  Create a temp dir with 3 files (a.txt, b.txt, subdir/c.txt). Hash twice. Results must match.

TestComputeTreeHash_ContentSensitive:
  Create a temp dir. Hash it. Change one byte in one file. Hash again. Results must differ.

TestComputeTreeHash_OrderIndependent:
  Create a temp dir. Write files in order (a, b, c). Hash. Create another temp dir. Write same files in order (c, a, b). Hash. Results must match (the sort ensures this).

TestComputeTreeHash_SkipsGitDir:
  Create a temp dir with .git/ subdirectory containing files. Verify .git/ contents don't affect the hash by comparing with and without the .git/ directory.

TestComputeTreeHash_SkipsSymlinks:
  Create a temp dir with a symlink. Verify it doesn't crash and the symlink is excluded from the hash.

TestComputeTreeHash_EmptyDir:
  Create an empty temp dir. Verify it returns a valid hash (hash of empty input) without error.

TestComputeTreeHash_NestedDirectories:
  Create a temp dir with 3 levels of nesting. Verify hash includes all nested files with correct relative paths.

Run go build, go vet, go test ./internal/integrity/ -v.

PHASE 2: Compute disk_integrity during lock

Modify internal/manifest/integrity.go:

Add a new function:
func DownloadExtractAndTreeHash(ctx context.Context, client *http.Client, baseURL, token, owner, repo, sha string) (tarballHash string, treeHash string, err error)

This function:
1. Downloads the tarball (same as DownloadAndHash, but save to a temp file instead of just hashing — use io.TeeReader to hash AND write simultaneously)
2. Computes tarball integrity hash (streaming)
3. Extracts the tarball to a temp directory using archive/tar and compress/gzip:
   - Open the temp file
   - gzip.NewReader wrapping the file
   - tar.NewReader wrapping the gzip reader
   - For each entry: create file at {tmpDir}/{entry.Name}
   - SECURITY: validate entry names (no .. path traversal, no absolute paths)
4. The tarball extracts to a single subdirectory like owner-repo-shortsha/. Find this subdirectory: read tmpDir, take the first (and only) entry
5. Call ComputeTreeHash on that subdirectory
6. Clean up: remove temp file and temp dir
7. Return both hashes

Also create a batch version:
func DownloadExtractAndTreeHashBatch(ctx context.Context, client *http.Client, baseURL, token string, actions []ActionRef) map[string]DualHashResult

Where DualHashResult is:
  type DualHashResult struct {
      Integrity     string
      DiskIntegrity string
      Err           error
  }

Use the same worker pool pattern from spec 014 (maxConcurrentDownloads = 10, semaphore channel). Deduplicate by action+sha before processing.

Modify the Refresh/lock flow in internal/manifest/manifest.go:

Replace the call to DownloadAndHashBatch with DownloadExtractAndTreeHashBatch. Store the tarball hash in entry.Integrity and the tree hash in entry.DiskIntegrity.

Add DiskIntegrity field to ManifestEntry (in both manifest.go AND gate.go):
  DiskIntegrity string `json:"disk_integrity,omitempty"`

Also add DiskIntegrity to TransitiveDep struct.

Add --skip-disk-integrity flag to lock command in cmd/pinpoint/main.go. When set, only compute tarball integrity (call DownloadAndHashBatch instead of DownloadExtractAndTreeHashBatch).

Run go build, go vet, go test ./... -v.

PHASE 3: Gate on-disk verification

Add to GateOptions in internal/gate/gate.go:
  OnDisk     bool
  ActionsDir string   // override for actions cache path

In the main gate verification loop, after existing checks:

If opts.OnDisk:
  Derive actionsDir:
    if opts.ActionsDir != "" -> use it
    else if RUNNER_WORKSPACE env var set -> filepath.Join(filepath.Dir(os.Getenv("RUNNER_WORKSPACE")), "_actions")
    else -> error with clear message:
      "On-disk verification requires a GitHub Actions runner environment.\n"+
      "  Set RUNNER_WORKSPACE or use --actions-dir to specify the actions cache path.\n"+
      "  On GitHub-hosted runners: /home/runner/work/_actions\n"+
      "  On self-hosted runners: {runner_root}/_work/_actions"

  For each action in the lockfile:
    1. Parse action into owner/repo (split on "/")
    2. Construct path: filepath.Join(actionsDir, owner, repo, ref)
    3. If path doesn't exist (os.Stat): add Warning (not Violation): "Action not found on disk: {action}@{ref} (expected at {path})" Continue to next action.
    4. If entry.DiskIntegrity is empty: add Warning: "disk_integrity not recorded for {action}@{ref}. Regenerate lockfile with: pinpoint lock" Continue to next action.
    5. Call ComputeTreeHash(path)
    6. Compare computed hash to entry.DiskIntegrity
    7. If mismatch, add Violation:
       "ON-DISK INTEGRITY MISMATCH: {action}@{ref}\n"+
       "  Expected: {entry.DiskIntegrity}\n"+
       "  Actual:   {computed}\n"+
       "  Path:     {fullPath}\n"+
       "  The code on disk does not match what was recorded in the lockfile.\n"+
       "  This could indicate tampering, a stale cache, or a supply chain compromise."

IMPORTANT: --on-disk does NOT set opts.Integrity to true. They are independent verification layers. On-disk checks the filesystem. Integrity checks the API. On-disk is faster and more useful for the gate.

Update cmd/pinpoint/main.go:
  Add --on-disk flag to gate subcommand (default false)
  Add --actions-dir flag to gate subcommand (string, default "")
  Do NOT make --on-disk imply --integrity

Run go build, go vet, go test ./... -v.

PHASE 4: Gate on-disk tests

Create internal/gate/ondisk_test.go:

TestGateOnDisk_Match:
  Create a temp dir simulating _actions/actions/checkout/v4/ with known files. Compute the tree hash. Create a lockfile entry with that disk_integrity. Run gate verification with OnDisk=true and ActionsDir pointing to the temp dir. Verify no violations.

TestGateOnDisk_Mismatch:
  Same setup but modify one file after computing disk_integrity. Run gate with OnDisk=true. Verify violation contains "ON-DISK INTEGRITY MISMATCH".

TestGateOnDisk_MissingAction:
  Lockfile references actions/checkout@v4 but the actions dir doesn't have it. Verify warning (not violation) is produced.

TestGateOnDisk_MissingDiskIntegrity:
  Lockfile entry has no disk_integrity field. Gate with OnDisk=true should add warning "disk_integrity not recorded" and skip check.

TestGateOnDisk_NoRunnerWorkspace:
  Unset RUNNER_WORKSPACE env var. Don't set ActionsDir. Gate with OnDisk=true should return error about requiring RUNNER_WORKSPACE.

TestGateOnDisk_CustomActionsDir:
  Set ActionsDir="/custom/path". Verify it uses that path instead of deriving from RUNNER_WORKSPACE.

Run go build, go vet, go test ./... -v.

PHASE 5: Update action.yml

Modify action.yml in the repo root:

Add inputs:
  on-disk:
    description: 'Verify on-disk action content against lockfile (eliminates TOCTOU race conditions, recommended for security-sensitive workflows)'
    required: false
    default: 'false'
  integrity:
    description: 'Re-download and verify tarball content hashes (slower, use for periodic audits)'
    required: false
    default: 'false'

In the "Verify action integrity" step:
  Add RUNNER_WORKSPACE to the env block:
    RUNNER_WORKSPACE: ${{ runner.workspace }}
  Add flag handling:
    if [ "${{ inputs.on-disk }}" = "true" ]; then
      ARGS="$ARGS --on-disk"
    fi
    if [ "${{ inputs.integrity }}" = "true" ]; then
      ARGS="$ARGS --integrity"
    fi

Run go build, go vet, go test ./... -v -count=1.

FINAL VERIFICATION:

go build ./cmd/pinpoint/
go vet ./...
go test ./... -v -count=1
./pinpoint gate --help   # should show --on-disk, --actions-dir, --integrity
./pinpoint lock --help   # should show --skip-disk-integrity

Verify the flags are INDEPENDENT:
  --on-disk alone: checks disk, does NOT download tarballs
  --integrity alone: downloads tarballs, does NOT check disk
  --on-disk --integrity: both checks run

Expected new test count: ~13 new tests (7 tree hash + 6 on-disk gate).
