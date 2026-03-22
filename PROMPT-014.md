Read specs/014-integrity-transitive.md AND specs/016-performance-testing.md before writing any code. The performance spec changes how you implement the tarball downloading (concurrency + deduplication).

This spec adds two features to the lockfile:

1. SHA-256 content integrity hashes (tarball download + hash)
2. Transitive dependency resolution (parse action.yml for composite actions)

PHASE 1: Types and lockfile format

Update the ManifestEntry struct (in internal/manifest/manifest.go AND internal/gate/gate.go — both have copies) to add three fields:
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

Also copy TransitiveDep to internal/gate/gate.go so it has the full type for JSON unmarshaling.

Update the Manifest struct's Version field default to 2 in the lock/refresh flow. Keep reading version 1 lockfiles without error (backwards compat).

Run go build and go vet after this change.

PHASE 2: Tarball download and integrity hashing

Create internal/manifest/integrity.go with:

func DownloadAndHash(ctx context.Context, client *http.Client, baseURL, token, owner, repo, sha string) (string, error)

This function:
- Constructs URL: {baseURL}/repos/{owner}/{repo}/tarball/{sha}
- Sets Authorization: Bearer {token} header
- Follows redirects (Go's http.Client does this by default)
- Streams the response body through sha256.New() using io.Copy (do NOT buffer the entire tarball in memory — this is critical for performance. A 5MB tarball should use ~16MB RSS, not 5MB heap.)
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

Why 10 concurrent: measured 10 parallel downloads at 1.4s total vs ~15s sequential. Higher concurrency risks GitHub abuse detection.

The batch function should deduplicate by action+sha key before downloading. If actions/checkout@abc123 appears 3 times in the input, download the tarball once and return the same hash for all 3.

Create internal/manifest/integrity_test.go with these tests using httptest.NewServer to mock the tarball endpoint:

TestDownloadAndHash_Success: mock returns fixed bytes, verify the expected SHA-256 hash.
TestDownloadAndHash_Deterministic: call twice with same mock, hashes must be identical.
TestDownloadAndHash_DifferentContent: two mocks with different content, hashes must differ.
TestDownloadAndHash_HTTPError: mock returns 404, verify error.
TestDownloadAndHash_SRIFormat: verify result starts with "sha256-" and the rest is valid base64.
TestDownloadAndHashBatch_Concurrent: submit 20 actions to batch function with mock server, verify all 20 complete with correct hashes.
TestDownloadAndHashBatch_Deduplication: submit 10 actions where 5 have the same owner/repo/sha. Verify the mock server only receives 5 requests (one per unique action+sha), not 10.

Run go build, go vet, go test ./internal/manifest/ -v after this phase.

PHASE 3: Action type detection and transitive resolution

Create internal/manifest/transitive.go with:

1. func ParseActionType(content []byte) string
   Parse YAML content of an action.yml. Look for the runs.using field. Return "composite", "node16", "node20", "node24", "docker", or "unknown". Use gopkg.in/yaml.v3 for parsing. Define a minimal struct:
     type actionYAML struct {
         Runs struct {
             Using string `yaml:"using"`
         } `yaml:"runs"`
     }
   Strip surrounding quotes from the Using value (YAML may have 'node24' with quotes).

2. func ExtractUsesFromComposite(content []byte) []string
   Parse YAML content of a composite action.yml. Extract all runs.steps[].uses values. Return as string slice. Define struct:
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
   - Fetch action.yml (or action.yaml) using the GitHub Contents API: GET {baseURL}/repos/{action}/contents/action.yml?ref={sha} (the action string is "owner/repo")
   - The response JSON has a "content" field (base64-encoded). Decode it.
   - Call ParseActionType to get the type
   - If type != "composite", return nil, type, nil
   - Call ExtractUsesFromComposite to get inner uses
   - For each inner use:
     - Parse it (owner, repo, ref) — reuse the discover package's parsing logic or write a helper. Skip local (./) and docker:// refs.
     - If ref is not a 40-char hex SHA, resolve it to SHA using the REST API: GET {baseURL}/repos/{owner}/{repo}/git/ref/tags/{ref}. Parse response for object.sha. If object.type is "tag", dereference with GET {baseURL}/repos/{owner}/{repo}/git/tags/{object.sha} for the inner object.sha.
     - Call DownloadAndHash to get integrity hash for the resolved SHA
     - Recurse: call ResolveTransitiveDeps with depth+1
     - Build TransitiveDep entry
   - Return deps, "composite", nil

   IMPORTANT: For the Contents API, handle both action.yml and action.yaml filenames. Try action.yml first, if 404, try action.yaml. If both 404, return nil, "unknown", nil (not an error — some actions may be Docker-only).

Create internal/manifest/transitive_test.go with tests using httptest.NewServer:

TestParseActionType_Composite: YAML with using: composite -> "composite"
TestParseActionType_Node24: YAML with using: 'node24' -> "node24"
TestParseActionType_Docker: YAML with using: docker -> "docker"
TestParseActionType_Unknown: invalid YAML -> "unknown"

TestExtractUsesFromComposite_MultipleUses: composite with 3 steps having uses, verify all 3 extracted.
TestExtractUsesFromComposite_SkipsLocal: step has uses: ./local, verify it's excluded.
TestExtractUsesFromComposite_SkipsEmpty: step has no uses field, verify no empty strings.

TestResolveTransitiveDeps_NodeAction: mock returns node24 action.yml, verify empty deps and type "node24".
TestResolveTransitiveDeps_CompositeWithDeps: mock composite action.yml with 1 uses directive, mock Contents + tarball for the dep. Verify 1 TransitiveDep returned with correct SHA and integrity.
TestResolveTransitiveDeps_DepthLimit: mock 6-level chain, verify error at depth 5.
TestResolveTransitiveDeps_LocalRefSkipped: composite with uses: ./foo, verify empty deps (local skipped).

Run go build, go vet, go test ./internal/manifest/ -v.

PHASE 4: Integrate into lock/refresh flow

Modify the manifest Refresh function (internal/manifest/manifest.go):

After resolving each action's tag to a SHA (existing logic):

1. Collect all unique action+SHA pairs that need tarball hashing
2. Call DownloadAndHashBatch with the deduplicated list (concurrent)
3. For each action, look up its hash from the batch results
4. Call ResolveTransitiveDeps to discover type and transitive deps
5. Store integrity, type, and dependencies in the ManifestEntry

IMPORTANT: Deduplication. If 10 workflow files all reference actions/checkout@v4 at the same SHA, download the tarball ONCE. Build a map of unique (action+sha) -> integrity before populating entries.

The lock command already calls Refresh. After this change, running `pinpoint lock` will produce a v2 lockfile with integrity hashes and transitive deps.

Run go build, go vet, go test ./... -v.

PHASE 5: Gate integrity verification

Modify internal/gate/gate.go:

Add an Integrity bool field to GateOptions.
Add a SkipTransitive bool field to GateOptions.

CRITICAL PERFORMANCE NOTE: --integrity is an OPT-IN flag, NOT the default. The default gate behavior (SHA-only) must remain fast at 3 API calls, <2 seconds. The --integrity flag adds tarball downloads which cost 1-2 seconds per action. This is intentional — integrity verification during the gate is for periodic audits or paranoia mode, not for every CI run. The SHA check alone catches 99.99% of attacks.

In the main gate verification loop, after the existing SHA check:

If opts.Integrity is true AND the manifest entry has an integrity field:
  1. Call DownloadAndHash for the current SHA
  2. Compare to entry.Integrity
  3. If mismatch, add a Violation with a clear message: "Content integrity mismatch: tarball hash changed for {action}@{tag}"

If !opts.SkipTransitive AND the manifest entry has dependencies:
  1. Call ResolveTransitiveDeps for the current SHA
  2. Compare discovered deps to entry.Dependencies (compare each dep's Ref field — if any changed, flag it)
  3. If a transitive dep SHA changed, add a Violation: "Transitive dependency changed: {dep.Action} was {old} now {new}"

When --integrity is used in the gate, use DownloadAndHashBatch for parallel tarball verification of all actions, not sequential downloads.

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

Implementation: write a PrintDependencyTree function in internal/manifest/manifest.go that takes a Manifest and an io.Writer. Sort actions alphabetically. For each action+tag, print the line. If it has dependencies, print each with "  └── " prefix. For nested deps (depth > 1), increase indentation.

Run go build, go vet, go test ./... -v.

FINAL VERIFICATION:

go build ./cmd/pinpoint/
go vet ./...
go test ./... -v -count=1
./pinpoint lock --help
./pinpoint gate --help

All tests must pass. The binary must compile. --integrity and --list flags must appear in help output. --integrity must NOT be default.

Expected new test count: ~20 new tests (7 integrity + 11 transitive + 2 integration).
