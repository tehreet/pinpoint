# Gate --all-workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--all-workflows` flag to `pinpoint gate` so it verifies action references across ALL workflow files in `.github/workflows/`, not just the triggering workflow.

**Architecture:** Add a `listDirectory` method to `httpClient` that calls the GitHub Contents API for a directory listing. When `--all-workflows` is set, fetch all `.yml`/`.yaml` files and concatenate their content before extracting `uses:` directives. Skip `--workflow-ref` validation when `--all-workflows` is set.

**Tech Stack:** Go 1.24, GitHub REST Contents API

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/gate/gate.go` | Modify | Add `AllWorkflows` to `GateOptions`, add `listDirectory` method, branch in `RunGate` |
| `internal/gate/gate_test.go` | Modify | Add tests for `listDirectory` and all-workflows path |
| `cmd/pinpoint/main.go` | Modify | Wire `--all-workflows` flag and env var |
| `scripts/deploy-gate-warn.sh` | Modify | Add `--all-workflows` to the gate invocation |

---

### Task 1: Add `listDirectory` method to `httpClient`

**Files:**
- Modify: `internal/gate/gate.go:581-657` (httpClient section)
- Test: `internal/gate/gate_test.go`

- [ ] **Step 1: Write the failing test for `listDirectory`**

First, add `"time"` to the import block in `gate_test.go` (after `"testing"`). Then add a test that starts an `httptest.NewServer` returning a JSON array of directory entries, then calls `listDirectory` and asserts the returned filenames.

```go
func TestListDirectory(t *testing.T) {
	buf := silenceOutput(t)
	_ = buf

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/contents/.github/workflows" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
				{"name": "ci.yml", "type": "file", "path": ".github/workflows/ci.yml"},
				{"name": "deploy.yaml", "type": "file", "path": ".github/workflows/deploy.yaml"},
				{"name": "README.md", "type": "file", "path": ".github/workflows/README.md"}
			]`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	client := &httpClient{
		token:   "test-token",
		baseURL: srv.URL,
		http:    &http.Client{Timeout: 5 * time.Second}, // requires adding "time" to imports
	}

	ctx := context.Background()
	files, err := client.listDirectory(ctx, "owner/repo", ".github/workflows", "abc123")
	if err != nil {
		t.Fatalf("listDirectory failed: %v", err)
	}

	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(files))
	}
	expected := []string{"ci.yml", "deploy.yaml", "README.md"}
	for i, name := range expected {
		if files[i] != name {
			t.Errorf("file[%d]: expected %q, got %q", i, name, files[i])
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -run TestListDirectory -v`
Expected: FAIL — `client.listDirectory` undefined

- [ ] **Step 3: Implement `listDirectory`**

Add these types and method to `internal/gate/gate.go` after the `contentResponse` struct (line ~592):

```go
// directoryEntry represents a single entry from the GitHub Contents API directory listing.
type directoryEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

// listDirectory lists files in a directory via the GitHub Contents API.
func (c *httpClient) listDirectory(ctx context.Context, repo, path, sha string) ([]string, error) {
	url := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", c.baseURL, repo, path, sha)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &notFoundError{path: path}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d for %s: %s", resp.StatusCode, path, string(body))
	}

	var entries []directoryEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decoding directory listing: %w", err)
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -run TestListDirectory -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/joshf/pinpoint
git add internal/gate/gate.go internal/gate/gate_test.go
git commit -m "feat(gate): add listDirectory method to httpClient for Contents API directory listing"
```

---

### Task 2: Add `AllWorkflows` option and branch in `RunGate`

**Files:**
- Modify: `internal/gate/gate.go:77-95` (GateOptions) and `internal/gate/gate.go:105-127` (RunGate steps 1-2)
- Test: `internal/gate/gate_test.go`

- [ ] **Step 1: Write the failing test for all-workflows mode**

Add a test that sets `AllWorkflows: true`, mocks the directory listing endpoint, mocks two workflow file fetches, and verifies that `uses:` from both are checked. The test should NOT require `WorkflowRef` to be set.

```go
func TestAllWorkflowsMode(t *testing.T) {
	buf := silenceOutput(t)

	// Two workflow files with different actions
	ciYml := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
`
	deployYml := `name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
`

	manifest := `{
		"version": 1,
		"generated_at": "` + time.Now().Format(time.RFC3339) + `",
		"actions": {
			"actions/checkout": {"v4": {"sha": "` + strings.Repeat("a", 40) + `"}},
			"actions/setup-go": {"v5": {"sha": "` + strings.Repeat("b", 40) + `"}},
			"aws-actions/configure-aws-credentials": {"v4": {"sha": "` + strings.Repeat("c", 40) + `"}}
		}
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows" && r.URL.Query().Get("ref") != "":
			fmt.Fprint(w, `[
				{"name": "ci.yml", "type": "file", "path": ".github/workflows/ci.yml"},
				{"name": "deploy.yml", "type": "file", "path": ".github/workflows/deploy.yml"}
			]`)
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows/ci.yml":
			content := base64.StdEncoding.EncodeToString([]byte(ciYml))
			fmt.Fprintf(w, `{"content": %q, "encoding": "base64"}`, content)
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows/deploy.yml":
			content := base64.StdEncoding.EncodeToString([]byte(deployYml))
			fmt.Fprintf(w, `{"content": %q, "encoding": "base64"}`, content)
		case r.URL.Path == "/repos/owner/repo/contents/.github/actions-lock.json":
			content := base64.StdEncoding.EncodeToString([]byte(manifest))
			fmt.Fprintf(w, `{"content": %q, "encoding": "base64"}`, content)
		case r.URL.Path == "/graphql":
			fmt.Fprint(w, buildGraphQLResponse(map[string]map[string]string{
				"actions/checkout":                       {"v4": strings.Repeat("a", 40)},
				"actions/setup-go":                       {"v5": strings.Repeat("b", 40)},
				"aws-actions/configure-aws-credentials":  {"v4": strings.Repeat("c", 40)},
			}))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	opts := GateOptions{
		Repo:         "owner/repo",
		SHA:          strings.Repeat("d", 40),
		AllWorkflows: true,
		// WorkflowRef intentionally omitted
		Token:      "test-token",
		APIURL:     srv.URL,
		GraphQLURL: srv.URL + "/graphql",
	}

	result, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}

	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d: %+v", len(result.Violations), result.Violations)
	}

	// actions/checkout appears in both files but should be deduplicated.
	// Expect 3 unique refs verified: checkout@v4, setup-go@v5, configure-aws-credentials@v4
	if result.Verified != 3 {
		t.Errorf("expected 3 verified (deduplicated), got %d", result.Verified)
	}

	output := buf.String()
	if !strings.Contains(output, "all-workflows") {
		t.Errorf("expected output to mention all-workflows mode, got: %s", output)
	}
}
```

Note: `buildGraphQLResponse` is an existing test helper in `gate_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -run TestAllWorkflowsMode -v`
Expected: FAIL — `AllWorkflows` field not defined

- [ ] **Step 3: Add `AllWorkflows` field to `GateOptions`**

In `internal/gate/gate.go`, add to `GateOptions` struct (after line 94, before the closing brace):

```go
	AllWorkflows  bool   // fetch all workflows from .github/workflows/ instead of single workflow
```

- [ ] **Step 4: Branch RunGate steps 1-2 for all-workflows mode**

Replace Steps 1-2 in `RunGate` (lines 116-126) with a conditional:

```go
	// Step 1-2: Fetch workflow content
	var wfContent []byte
	if opts.AllWorkflows {
		// Fetch all workflow files from .github/workflows/
		fmt.Fprintf(messageWriter, "  ℹ all-workflows mode: scanning all files in .github/workflows/\n")
		files, err := client.listDirectory(ctx, opts.Repo, ".github/workflows", opts.SHA)
		if err != nil {
			return nil, fmt.Errorf("list .github/workflows: %w\n\nEnsure GITHUB_TOKEN has contents:read permission.", err)
		}
		var allContent []byte
		fetched := 0
		for _, f := range files {
			if strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml") {
				content, err := client.fetchFileContent(ctx, opts.Repo, ".github/workflows/"+f, opts.SHA)
				if err != nil {
					fmt.Fprintf(messageWriter, "  ⚠ skipping %s: %v\n", f, err)
					continue
				}
				allContent = append(allContent, '\n')
				allContent = append(allContent, content...)
				fetched++
			}
		}
		if fetched == 0 {
			return nil, fmt.Errorf("no .yml/.yaml files found in .github/workflows/")
		}
		fmt.Fprintf(messageWriter, "  ℹ fetched %d workflow files\n", fetched)
		wfContent = allContent
	} else {
		// Original single-workflow path
		workflowPath, err := parseWorkflowPath(opts.WorkflowRef, opts.Repo)
		if err != nil {
			return nil, fmt.Errorf("parse workflow ref: %w", err)
		}
		wfContent, err = client.fetchFileContent(ctx, opts.Repo, workflowPath, opts.SHA)
		if err != nil {
			return nil, fmt.Errorf("fetch workflow file %q: %w\n\nEnsure GITHUB_TOKEN has contents:read permission and the workflow file exists at the specified commit.", workflowPath, err)
		}
	}
```

Note: The original lines 116-126 (Step 1 + Step 2) are replaced entirely. Steps 3 onward (`manifestRef` logic at line 128+) remain unchanged.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -run TestAllWorkflowsMode -v`
Expected: PASS

- [ ] **Step 6: Run all existing tests to check for regressions**

Run: `cd /home/joshf/pinpoint && go test ./internal/gate/ -v`
Expected: All existing tests still pass

- [ ] **Step 7: Commit**

```bash
cd /home/joshf/pinpoint
git add internal/gate/gate.go internal/gate/gate_test.go
git commit -m "feat(gate): add --all-workflows mode to verify all workflow files"
```

---

### Task 3: Wire `--all-workflows` flag in CLI

**Files:**
- Modify: `cmd/pinpoint/main.go:397-478` (cmdGate function)

- [ ] **Step 1: Add flag parsing and env var, reorder workflow-ref validation**

In `cmd/pinpoint/main.go`, in `cmdGate()`, make these changes in order:

**1a.** Insert `allWorkflows` parsing immediately after `workflowRef` is read from env (line 419, after `workflowRef = os.Getenv("GITHUB_WORKFLOW_REF")`), and BEFORE the `workflowRef == ""` validation:

```go
	allWorkflows := hasFlag("all-workflows")
	if !allWorkflows && os.Getenv("PINPOINT_GATE_ALL_WORKFLOWS") == "true" {
		allWorkflows = true
	}
```

**1b.** Change the existing `workflowRef == ""` validation block (lines 420-423) to guard with `!allWorkflows`:

```go
	if workflowRef == "" && !allWorkflows {
		fmt.Fprintf(os.Stderr, "Error: --workflow-ref is required (or set GITHUB_WORKFLOW_REF), unless --all-workflows is set.\n\nUsage: pinpoint gate [--manifest <path>] [--fail-on-missing] [--fail-on-unpinned] [--integrity] [--on-disk] [--actions-dir <path>] [--skip-transitive] [--all-workflows]\n")
		os.Exit(1)
	}
```

The final order in `cmdGate()` is: repo validation → sha validation → workflowRef read → **allWorkflows parse** → workflowRef validation (guarded) → manifest → token → apiURL → graphqlURL → warnMode → jsonOutput → ...

- [ ] **Step 3: Pass `AllWorkflows` to `GateOptions`**

Add to the `opts` struct literal (around line 478):

```go
		AllWorkflows:           allWorkflows,
```

- [ ] **Step 4: Build and verify**

Run: `cd /home/joshf/pinpoint && go build ./cmd/pinpoint/ && go vet ./...`
Expected: Clean build, no vet warnings

- [ ] **Step 5: Commit**

```bash
cd /home/joshf/pinpoint
git add cmd/pinpoint/main.go
git commit -m "feat(gate): wire --all-workflows flag and PINPOINT_GATE_ALL_WORKFLOWS env var"
```

---

### Task 4: Update deploy script

**Files:**
- Modify: `scripts/deploy-gate-warn.sh:56`

- [ ] **Step 1: Add `--all-workflows` to the gate invocation**

In `scripts/deploy-gate-warn.sh`, change line 56 from:

```bash
          ./pinpoint gate --warn 2>&1 || true
```

to:

```bash
          ./pinpoint gate --warn --all-workflows 2>&1 || true
```

- [ ] **Step 2: Commit**

```bash
cd /home/joshf/pinpoint
git add scripts/deploy-gate-warn.sh
git commit -m "ci: add --all-workflows to gate deploy script"
```

---

### Task 5: Final verification

- [ ] **Step 1: Full test suite**

Run: `cd /home/joshf/pinpoint && go test ./... -v 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 2: Build and smoke test**

```bash
cd /home/joshf/pinpoint && go build ./cmd/pinpoint/ && ./pinpoint gate --help 2>&1 || true
```

Verify the binary builds cleanly. (gate --help will error since no repo is set, but confirms the binary runs.)

- [ ] **Step 3: Verify vet passes**

Run: `cd /home/joshf/pinpoint && go vet ./...`
Expected: Clean
