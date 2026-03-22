# Claude Code Prompts for Specs 014, 015, and 016

## IMPORTANT: Run these sequentially. 014 first, then 015, then 016.

Each spec builds on the previous. Do NOT skip ahead.

---

## Prompt 1: Spec 014 — Content Integrity Hashes + Transitive Dependencies

```
Read specs/014-integrity-transitive.md AND specs/016-performance-testing.md
before writing any code. The performance spec changes how you implement
the tarball downloading (concurrency + deduplication).

This spec adds two features to the lockfile:

1. SHA-256 content integrity hashes (tarball download + hash)
2. Transitive dependency resolution (parse action.yml for composite actions)

PHASE 1: Types and lockfile format

Update the ManifestEntry struct (in internal/manifest/manifest.go AND
internal/gate/gate.go — both have copies) to add three fields:
  Integrity    string          `json:"integrity,omitempty"`
  Type         string          `json:"type,omitempty"`
  Dependencies []TransitiveDep `json:"dependencies,omitempty"`

Create the TransitiveDep struct in internal/manifest/manifest.go:
  type TransitiveDep struct {
      Action       string          `json:"action"`
      Ref          string          `json:"ref"`
      Integrity    string          `json:"integrity,omitempty"`
      Type         string          `json:"type,omitempty"`
      Dependencies []TransitiveDep `json:"dependencies"`
  }

Also copy TransitiveDep to internal/gate/gate.go so it has the full
type for JSON unmarshaling.

Update the Manifest struct's Version field default to 2 in the lock/refresh
flow. Keep reading version 1 lockfiles without error (backwards compat).

Run go build and go vet after this change.

PHASE 2: Tarball download and integrity hashing

Create internal/manifest/integrity.go with:

func DownloadAndHash(ctx context.Context, client *http.Client, baseURL, token, owner, repo, sha string) (string, error)

This function:
- Constructs URL: {baseURL}/repos/{owner}/{repo}/tarball/{sha}
- Sets Authorization: Bearer {token} header
- Follows redirects (Go's http.Client does this by default)
- Streams the response body through sha256.New() using io.Copy
  (do NOT buffer the entire tarball in memory — this is critical
  for performance. A 5MB tarball should use ~16MB RSS, not 5MB heap.)
- Returns SRI format: "sha256-" + base64.StdEncoding.EncodeToString(hash.Sum(nil))
- Returns error if HTTP status is not 200 (after redirects)

Also create a batch download function for concurrent tarball hashing:

func DownloadAndHashBatch(ctx context.Context, client *http.Client, baseURL, token string, actions []ActionRef) map[string]HashResult

Where ActionRef is:
  type ActionRef struct {
      Owner string
      Repo  string
      SHA   string
  }

And HashResult is:
  type HashResult struct {
      Integrity string
      Err       error
  }

This batch function MUST use a worker pool with bounded concurrency:
- const maxConcurrentDownloads = 10
- Use a buffered channel as semaphore: sem := make(chan struct{}, 10)
- Launch one goroutine per action
- Each goroutine acquires semaphore, downloads+hashes, releases
- Use sync.Mutex to protect the results map
- Use sync.WaitGroup to wait for all goroutines

Why 10 concurrent: measured 10 parallel downloads at 1.4s total vs
~15s sequential. Higher concurrency risks GitHub abuse detection.

Create internal/manifest/integrity_test.go with these tests using
httptest.NewServer to mock the tarball endpoint:

TestDownloadAndHash_Success: mock returns fixed bytes, verify
  the expected SHA-256 hash.
TestDownloadAndHash_Deterministic: call twice with same mock,
  hashes must be identical.
TestDownloadAndHash_DifferentContent: two mocks with different
  content, hashes must differ.
TestDownloadAndHash_HTTPError: mock returns 404, verify error.
TestDownloadAndHash_SRIFormat: verify result starts with "sha256-"
  and the rest is valid base64.
TestDownloadAndHashBatch_Concurrent: submit 20 actions to batch
  function with mock server, verify all 20 complete with correct hashes.
TestDownloadAndHashBatch_Deduplication: submit 10 actions where 5
  have the same owner/repo/sha. Verify the mock server only receives
  5 requests (one per unique action+sha), not 10.

For the deduplication test: the batch function should deduplicate by
action+sha key before downloading. If actions/checkout@abc123 appears
3 times in the input, download the tarball once and return the same
hash for all 3. This matters at org scale where 1800 repos all use
the same actions/checkout version.

Run go build, go vet, go test ./internal/manifest/ -v after this phase.

PHASE 3: Action type detection and transitive resolution

Create internal/manifest/transitive.go with:

1. func ParseActionType(content []byte) string
   Parse YAML content of an action.yml. Look for the runs.using field.
   Return "composite", "node16", "node20", "node24", "docker", or "unknown".
   Use gopkg.in/yaml.v3 for parsing. Define a minimal struct:
     type actionYAML struct {
         Runs struct {
             Using string `yaml:"using"`
         } `yaml:"runs"`
     }
   Strip surrounding quotes from the Using value (YAML may have
   'node24' with quotes).

2. func ExtractUsesFromComposite(content []byte) []string
   Parse YAML content of a composite action.yml. Extract all
   runs.steps[].uses values. Return as string slice.
   Define struct:
     type compositeYAML struct {
         Runs struct {
             Steps []struct {
                 Uses string `yaml:"uses"`
             } `yaml:"steps"`
         } `yaml:"runs"`
     }
   Filter out empty strings and local references (starting with "./").

3. func ResolveTransitiveDeps(ctx context.Context, client *http.Client, baseURL, graphqlURL, token, action, sha string, depth int) ([]TransitiveDep, string, error)
   - If depth > 5, return nil, "unknown", error("max depth exceeded")
   - Fetch action.yml (or action.yaml) using the GitHub Contents API:
     GET {baseURL}/repos/{action}/contents/action.yml?ref={sha}
     (the action string is "owner/repo")
   - The response JSON has a "content" field (base64-encoded). Decode it.
   - Call ParseActionType to get the type
   - If type != "composite", return nil, type, nil
   - Call ExtractUsesFromComposite to get inner uses
   - For each inner use:
     - Parse it (owner, repo, ref) — reuse the discover package's
       parsing logic or write a helper. Skip local (./) and docker:// refs.
     - If ref is not a 40-char hex SHA, resolve it to SHA using the
       REST API: GET {baseURL}/repos/{owner}/{repo}/git/ref/tags/{ref}
       Parse response for object.sha. If object.type is "tag", dereference
       with GET {baseURL}/repos/{owner}/{repo}/git/tags/{object.sha}
       for the inner object.sha.
     - Call DownloadAndHash to get integrity hash for the resolved SHA
     - Recurse: call ResolveTransitiveDeps with depth+1
     - Build TransitiveDep entry
   - Return deps, "composite", nil

   IMPORTANT: For the Contents API, handle both action.yml and action.yaml
   filenames. Try action.yml first, if 404, try action.yaml. If both 404,
   return nil, "unknown", nil (not an error — some actions may be Docker-only).

Create internal/manifest/transitive_test.go with tests using httptest.NewServer:

TestParseActionType_Composite: YAML with using: composite → "composite"
TestParseActionType_Node24: YAML with using: 'node24' → "node24"
TestParseActionType_Docker: YAML with using: docker → "docker"
TestParseActionType_Unknown: invalid YAML → "unknown"

TestExtractUsesFromComposite_MultipleUses: composite with 3 steps
  having uses, verify all 3 extracted.
TestExtractUsesFromComposite_SkipsLocal: step has uses: ./local,
  verify it's excluded.
TestExtractUsesFromComposite_SkipsEmpty: step has no uses field,
  verify no empty strings.

TestResolveTransitiveDeps_NodeAction: mock returns node24 action.yml,
  verify empty deps and type "node24".
TestResolveTransitiveDeps_CompositeWithDeps: mock composite action.yml
  with 1 uses directive, mock Contents + tarball for the dep. Verify
  1 TransitiveDep returned with correct SHA and integrity.
TestResolveTransitiveDeps_DepthLimit: mock 6-level chain, verify
  error at depth 5.
TestResolveTransitiveDeps_LocalRefSkipped: composite with uses: ./foo,
  verify empty deps (local skipped).

Run go build, go vet, go test ./internal/manifest/ -v.

PHASE 4: Integrate into lock/refresh flow

Modify the manifest Refresh function (internal/manifest/manifest.go):

After resolving each action's tag to a SHA (existing logic):

1. Collect all unique action+SHA pairs that need tarball hashing
2. Call DownloadAndHashBatch with the deduplicated list (concurrent)
3. For each action, look up its hash from the batch results
4. Call ResolveTransitiveDeps to discover type and transitive deps
5. Store integrity, type, and dependencies in the ManifestEntry

IMPORTANT: Deduplication. If 10 workflow files all reference
actions/checkout@v4 at the same SHA, download the tarball ONCE.
Build a map of unique (action+sha) → integrity before populating entries.

The lock command already calls Refresh. After this change, running
`pinpoint lock` will produce a v2 lockfile with integrity hashes and
transitive deps.

Run go build, go vet, go test ./... -v.

PHASE 5: Gate integrity verification

Modify internal/gate/gate.go:

Add an Integrity bool field to GateOptions.
Add a SkipTransitive bool field to GateOptions.

CRITICAL PERFORMANCE NOTE: --integrity is an OPT-IN flag, NOT the
default. The default gate behavior (SHA-only) must remain fast at
3 API calls, <2 seconds. The --integrity flag adds tarball downloads
which cost 1-2 seconds per action. This is intentional — integrity
verification during the gate is for periodic audits or paranoia mode,
not for every CI run. The SHA check alone catches 99.99% of attacks.

In the main gate verification loop, after the existing SHA check:

If opts.Integrity is true AND the manifest entry has an integrity field:
  1. Call DownloadAndHash for the current SHA
  2. Compare to entry.Integrity
  3. If mismatch, add a Violation with a clear message:
     "Content integrity mismatch: tarball hash changed for {action}@{tag}"

If !opts.SkipTransitive AND the manifest entry has dependencies:
  1. Call ResolveTransitiveDeps for the current SHA
  2. Compare discovered deps to entry.Dependencies
     (compare each dep's Ref field — if any changed, flag it)
  3. If a transitive dep SHA changed, add a Violation:
     "Transitive dependency changed: {dep.Action} was {old} now {new}"

When --integrity is used in the gate, use DownloadAndHashBatch for
parallel tarball verification of all actions, not sequential downloads.

Update cmd/pinpoint/main.go:
- Add --integrity flag to gate subcommand (default false)
- Add --skip-transitive flag to gate subcommand (default false)
- Pass them through GateOptions

Run go build, go vet, go test ./... -v.

PHASE 6: Dependency tree display (pinpoint lock --list)

Add a --list flag to the lock subcommand in cmd/pinpoint/main.go.

When --list is set, after generating the lockfile, print the dependency tree:

.github/actions-lock.json (N actions, M transitive)

actions/checkout@v4 (34e1148...) [node24]
actions/upload-pages-artifact@v4 (7b1f4a7...) [composite]
  └── actions/upload-artifact@v4.6.2 (ea165f8...) [node24]

Implementation: write a PrintDependencyTree function in
internal/manifest/manifest.go that takes a Manifest and an io.Writer.
Sort actions alphabetically. For each action+tag, print the line.
If it has dependencies, print each with "  └── " prefix. For nested
deps (depth > 1), increase indentation.

Run go build, go vet, go test ./... -v.

FINAL VERIFICATION:

go build ./cmd/pinpoint/
go vet ./...
go test ./... -v -count=1
./pinpoint lock --help
./pinpoint gate --help

All tests must pass. The binary must compile. --integrity and --list
flags must appear in help output. --integrity must NOT be default.

Expected new test count: ~20 new tests (7 integrity + 11 transitive + 2 integration).
```

---

## Prompt 2: Spec 015 — On-Disk Content Verification

**Prerequisites: Spec 014 must be fully implemented and passing.**

```
Read specs/015-ondisk-verification.md AND specs/016-performance-testing.md
before writing any code.

This spec adds on-disk content verification to the gate. Instead of
asking the GitHub API what a tag resolves to, it hashes the actual
files the runner downloaded and compares to the lockfile.

CRITICAL PERFORMANCE CONTEXT: On-disk verification is FASTER than
tarball-based integrity verification (28ms disk I/O vs 1.5s+ per
tarball download) AND more secure (verifies what will actually execute).
This is the recommended verification mode for CI gates.
--on-disk does NOT imply --integrity. They are independent checks:
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

The null byte (\x00) separator between path and hash prevents
collisions between paths that end in hex characters.

Create internal/integrity/treehash_test.go:

TestComputeTreeHash_Deterministic:
  Create a temp dir with 3 files (a.txt, b.txt, subdir/c.txt).
  Hash twice. Results must match.

TestComputeTreeHash_ContentSensitive:
  Create a temp dir. Hash it. Change one byte in one file. Hash again.
  Results must differ.

TestComputeTreeHash_OrderIndependent:
  Create a temp dir. Write files in order (a, b, c). Hash.
  Create another temp dir. Write same files in order (c, a, b). Hash.
  Results must match (the sort ensures this).

TestComputeTreeHash_SkipsGitDir:
  Create a temp dir with .git/ subdirectory containing files.
  Verify .git/ contents don't affect the hash by comparing with
  and without the .git/ directory.

TestComputeTreeHash_SkipsSymlinks:
  Create a temp dir with a symlink. Verify it doesn't crash and
  the symlink is excluded from the hash.

TestComputeTreeHash_EmptyDir:
  Create an empty temp dir. Verify it returns a valid hash
  (hash of empty input) without error.

TestComputeTreeHash_NestedDirectories:
  Create a temp dir with 3 levels of nesting. Verify hash includes
  all nested files with correct relative paths.

Run go build, go vet, go test ./internal/integrity/ -v.

PHASE 2: Compute disk_integrity during lock

Modify internal/manifest/integrity.go:

Add a new function:
func DownloadExtractAndTreeHash(ctx context.Context, client *http.Client, baseURL, token, owner, repo, sha string) (tarballHash string, treeHash string, err error)

This function:
1. Downloads the tarball (same as DownloadAndHash, but save to a temp file
   instead of just hashing — use io.TeeReader to hash AND write simultaneously)
2. Computes tarball integrity hash (streaming)
3. Extracts the tarball to a temp directory using archive/tar and compress/gzip:
   - Open the temp file
   - gzip.NewReader wrapping the file
   - tar.NewReader wrapping the gzip reader
   - For each entry: create file at {tmpDir}/{entry.Name}
   - SECURITY: validate entry names (no .. path traversal, no absolute paths)
4. The tarball extracts to a single subdirectory like owner-repo-shortsha/
   Find this subdirectory: read tmpDir, take the first (and only) entry
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

Use the same worker pool pattern from spec 014 (maxConcurrentDownloads = 10,
semaphore channel). Deduplicate by action+sha before processing.

Modify the Refresh/lock flow in internal/manifest/manifest.go:

Replace the call to DownloadAndHashBatch with DownloadExtractAndTreeHashBatch.
Store the tarball hash in entry.Integrity and the tree hash in
entry.DiskIntegrity.

Add DiskIntegrity field to ManifestEntry (in both manifest.go AND gate.go):
  DiskIntegrity string `json:"disk_integrity,omitempty"`

Also add DiskIntegrity to TransitiveDep struct.

Add --skip-disk-integrity flag to lock command in cmd/pinpoint/main.go.
When set, only compute tarball integrity (call DownloadAndHashBatch instead
of DownloadExtractAndTreeHashBatch).

Run go build, go vet, go test ./... -v.

PHASE 3: Gate on-disk verification

Add to GateOptions in internal/gate/gate.go:
  OnDisk     bool
  ActionsDir string   // override for actions cache path

In the main gate verification loop, after existing checks:

If opts.OnDisk:
  Derive actionsDir:
    if opts.ActionsDir != "" → use it
    else if RUNNER_WORKSPACE env var set → filepath.Join(filepath.Dir(os.Getenv("RUNNER_WORKSPACE")), "_actions")
    else → error with clear message:
      "On-disk verification requires a GitHub Actions runner environment.\n"+
      "  Set RUNNER_WORKSPACE or use --actions-dir to specify the actions cache path.\n"+
      "  On GitHub-hosted runners: /home/runner/work/_actions\n"+
      "  On self-hosted runners: {runner_root}/_work/_actions"

  For each action in the lockfile:
    1. Parse action into owner/repo (split on "/")
    2. Construct path: filepath.Join(actionsDir, owner, repo, ref)
    3. If path doesn't exist (os.Stat): add Warning (not Violation):
       "Action not found on disk: {action}@{ref} (expected at {path})"
       Continue to next action.
    4. If entry.DiskIntegrity is empty: add Warning:
       "disk_integrity not recorded for {action}@{ref}. Regenerate lockfile with: pinpoint lock"
       Continue to next action.
    5. Call ComputeTreeHash(path)
    6. Compare computed hash to entry.DiskIntegrity
    7. If mismatch, add Violation:
       "ON-DISK INTEGRITY MISMATCH: {action}@{ref}\n"+
       "  Expected: {entry.DiskIntegrity}\n"+
       "  Actual:   {computed}\n"+
       "  Path:     {fullPath}\n"+
       "  The code on disk does not match what was recorded in the lockfile.\n"+
       "  This could indicate tampering, a stale cache, or a supply chain compromise."

IMPORTANT: --on-disk does NOT set opts.Integrity to true. They are
independent verification layers. On-disk checks the filesystem. Integrity
checks the API. On-disk is faster and more useful for the gate.

Update cmd/pinpoint/main.go:
  Add --on-disk flag to gate subcommand (default false)
  Add --actions-dir flag to gate subcommand (string, default "")
  Do NOT make --on-disk imply --integrity

Run go build, go vet, go test ./... -v.

PHASE 4: Gate on-disk tests

Create internal/gate/ondisk_test.go:

TestGateOnDisk_Match:
  Create a temp dir simulating _actions/actions/checkout/v4/ with
  known files. Compute the tree hash. Create a lockfile entry with
  that disk_integrity. Run gate verification with OnDisk=true and
  ActionsDir pointing to the temp dir. Verify no violations.

TestGateOnDisk_Mismatch:
  Same setup but modify one file after computing disk_integrity.
  Run gate with OnDisk=true. Verify violation contains
  "ON-DISK INTEGRITY MISMATCH".

TestGateOnDisk_MissingAction:
  Lockfile references actions/checkout@v4 but the actions dir doesn't
  have it. Verify warning (not violation) is produced.

TestGateOnDisk_MissingDiskIntegrity:
  Lockfile entry has no disk_integrity field. Gate with OnDisk=true
  should add warning "disk_integrity not recorded" and skip check.

TestGateOnDisk_NoRunnerWorkspace:
  Unset RUNNER_WORKSPACE env var. Don't set ActionsDir. Gate with
  OnDisk=true should return error about requiring RUNNER_WORKSPACE.

TestGateOnDisk_CustomActionsDir:
  Set ActionsDir="/custom/path". Verify it uses that path instead
  of deriving from RUNNER_WORKSPACE.

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
```

---

## Prompt 3: Spec 016 — Performance Benchmarks

**Prerequisites: Specs 014 and 015 must be fully implemented and passing.**

```
Read specs/016-performance-testing.md completely before writing any code.

This spec adds Go benchmarks and integration performance tests for
every operation that touches the network or filesystem.

PHASE 1: Tarball download benchmarks

Create internal/manifest/integrity_bench_test.go:

BenchmarkDownloadAndHash_Single:
  Use httptest.NewServer serving a fixed 500KB random payload.
  Benchmark a single DownloadAndHash call.
  Report bytes/sec: b.SetBytes(500 * 1024)

BenchmarkDownloadAndHash_Parallel10:
  Same mock server. Launch 10 goroutines each calling DownloadAndHash.
  Use b.RunParallel for proper Go benchmark parallelism.
  This measures: goroutine overhead, mutex contention, HTTP client reuse.

BenchmarkDownloadAndHashBatch_20Actions:
  Create 20 ActionRef entries (with some duplicates to test dedup).
  Call DownloadAndHashBatch. Measure total time.

BenchmarkDownloadAndHash_LargePayload:
  Mock server serving a 10MB payload.
  Verify: streaming works, no OOM, timing scales linearly with size.

Run: go test -bench=. -benchmem ./internal/manifest/ -v

PHASE 2: Tree hash benchmarks

Create internal/integrity/treehash_bench_test.go:

Each benchmark creates its temp directory in b.StopTimer/b.StartTimer
blocks so setup doesn't count toward timing.

BenchmarkComputeTreeHash_20Files:
  Create temp dir with 20 files, ~50KB total. Benchmark hash.

BenchmarkComputeTreeHash_200Files:
  Create temp dir with 200 files across 5 subdirs, ~800KB total.
  This simulates a typical GitHub Action.

BenchmarkComputeTreeHash_500Files:
  Create temp dir with 500 files across 10 subdirs, ~5MB total.
  This simulates a large action with node_modules.

BenchmarkComputeTreeHash_15Actions:
  Create 15 separate directories (200 files each, ~800KB each).
  Time hashing all 15 sequentially, then in parallel using goroutines.
  Use b.ReportMetric to report "actions/sec".

Helper function for all benchmarks:
  func createFakeActionDir(t testing.TB, numFiles int, avgSizeKB int) string
  Creates a temp directory with the specified number of random files.
  Returns the path. Caller must defer os.RemoveAll.

Run: go test -bench=. -benchmem ./internal/integrity/ -v

PHASE 3: Memory pressure tests

Create tests/perf/memory_test.go (use build tag //go:build integration):

TestMemory_LargeTarballStreaming:
  Create httptest.NewServer serving a 50MB payload (use io.LimitReader
  on a rand.Reader, don't actually allocate 50MB).
  
  Before: runtime.ReadMemStats → record HeapAlloc
  Call: DownloadAndHash
  After: runtime.GC(); runtime.ReadMemStats → record HeapAlloc
  
  Assert: heap growth < 5MB (the 50MB tarball must be streamed,
  never fully buffered. Allow 5MB for buffers, goroutine stacks, etc.)
  
  Log the actual heap growth for visibility.

TestMemory_50ConcurrentSmallDownloads:
  Mock server serving 500KB per request.
  Launch 50 concurrent DownloadAndHash calls (through the batch function).
  
  Assert: peak heap < 100MB
  This verifies the semaphore (maxConcurrentDownloads=10) actually
  limits concurrency — only 10 should be in-flight at once.

TestMemory_TreeHashLargeDirectory:
  Create a temp directory with 1000 files, 10MB total.
  
  Before/after ReadMemStats around ComputeTreeHash.
  Assert: heap growth < 5MB (files are streamed through hasher,
  only the path+hash strings are accumulated).

Run: go test -tags integration -run TestMemory -v ./tests/perf/

PHASE 4: End-to-end scale benchmarks (shell script)

Create tests/perf/benchmark.sh:

#!/usr/bin/env bash
# Pinpoint performance benchmarks
# Requires: go, GITHUB_TOKEN
set -euo pipefail

cd "$(dirname "$0")/../.."
export PATH=$PATH:/usr/local/go/bin

echo "=== PINPOINT PERFORMANCE BENCHMARKS ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Go: $(go version)"
echo ""

# Build
go build -o ./pinpoint-bench ./cmd/pinpoint/

# Benchmark 1: Go microbenchmarks
echo "[1/4] Running Go benchmarks..."
go test -bench=. -benchmem -count=3 ./internal/manifest/ 2>&1 | tee /tmp/bench-manifest.txt
go test -bench=. -benchmem -count=3 ./internal/integrity/ 2>&1 | tee /tmp/bench-integrity.txt

# Benchmark 2: Lock command with real actions
echo ""
echo "[2/4] Lock command benchmarks..."

# Create a test workflow file with N actions
create_test_workflow() {
  local n=$1
  local dir=$(mktemp -d)
  mkdir -p "$dir/.github/workflows"
  local wf="$dir/.github/workflows/test.yml"
  echo "name: bench" > "$wf"
  echo "on: push" >> "$wf"
  echo "jobs:" >> "$wf"
  echo "  bench:" >> "$wf"
  echo "    runs-on: ubuntu-latest" >> "$wf"
  echo "    steps:" >> "$wf"
  
  # Use real public actions
  local actions=(
    "actions/checkout@v4"
    "actions/setup-go@v5"
    "actions/setup-node@v4"
    "actions/setup-python@v5"
    "actions/cache@v4"
    "actions/upload-artifact@v4"
    "actions/download-artifact@v4"
    "actions/github-script@v7"
    "docker/build-push-action@v5"
    "docker/setup-buildx-action@v3"
    "docker/login-action@v3"
    "golangci/golangci-lint-action@v6"
    "hashicorp/setup-terraform@v3"
    "aws-actions/configure-aws-credentials@v4"
    "google-github-actions/auth@v2"
  )
  
  for i in $(seq 0 $((n - 1))); do
    local idx=$((i % ${#actions[@]}))
    echo "    - uses: ${actions[$idx]}" >> "$wf"
  done
  
  echo "$dir"
}

for n in 5 10 15; do
  dir=$(create_test_workflow $n)
  START=$(date +%s%N)
  ./pinpoint-bench lock \
    --workflows "$dir/.github/workflows" \
    --output "$dir/actions-lock.json" 2>/dev/null
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  echo "  Lock ($n actions): ${MS}ms"
  rm -rf "$dir"
done

# Benchmark 3: Gate modes (requires a lockfile)
echo ""
echo "[3/4] Gate verification benchmarks..."
echo "  (requires running in GitHub Actions — skipping if not in CI)"

# Benchmark 4: Rate limit consumption
echo ""
echo "[4/4] Rate limit check..."
gh api /rate_limit --jq '{
  rest_remaining: .resources.core.remaining,
  rest_limit: .resources.core.limit,
  graphql_remaining: .resources.graphql.remaining,
  graphql_limit: .resources.graphql.limit
}'

echo ""
echo "=== BENCHMARKS COMPLETE ==="

rm -f ./pinpoint-bench

Make this script executable: chmod +x tests/perf/benchmark.sh

Run go build, go vet, go test ./... -v -count=1.

FINAL VERIFICATION:

go build ./cmd/pinpoint/
go vet ./...
go test ./... -v -count=1
go test -bench=. -benchmem ./internal/manifest/ -count=1
go test -bench=. -benchmem ./internal/integrity/ -count=1

All benchmarks should run and produce timing data.
The shell benchmark script should be executable and run without errors.
```

---

## Running Order

1. Run Prompt 1 (spec 014). Wait for all tests to pass.
2. Verify: `go test ./... -v -count=1` — all green.
3. Commit: `git add -A && git commit -m "feat: content integrity hashes + transitive dependency resolution (spec 014)"`
4. Run Prompt 2 (spec 015). Wait for all tests to pass.
5. Verify: `go test ./... -v -count=1` — all green.
6. Commit: `git add -A && git commit -m "feat: on-disk content verification, TOCTOU elimination (spec 015)"`
7. Run Prompt 3 (spec 016). Wait for all benchmarks to complete.
8. Verify: `go test -bench=. ./internal/manifest/ ./internal/integrity/` — benchmarks run.
9. Commit: `git add -A && git commit -m "test: performance benchmarks + memory pressure tests (spec 016)"`
