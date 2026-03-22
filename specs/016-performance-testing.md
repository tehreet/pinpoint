# Spec 016: Performance Test Suite + Concurrency Architecture

## Summary

Performance benchmarks for every operation that touches the network or
the filesystem, with scaling projections from CW-current (1,800 repos)
to CW-future (5,000+). Also specifies the concurrency architecture
for tarball downloads and tree hashing.

## Measured Baselines (2026-03-22, VPS ubuntu-32gb-hil-1)

All measurements against live GitHub API from Hetzner US.

### Tarball Downloads (REST API)

| Scenario | Time | Notes |
|---|---|---|
| Single tarball (400KB, actions/checkout) | 2,011ms | |
| Single tarball (1.6MB, actions/setup-go) | 1,584ms | |
| Single tarball (4.7MB, step-security/harden-runner) | 1,870ms | |
| 10 tarballs parallel (via curl &) | 1,430ms | 10x speedup over sequential |
| Streaming hash memory (5MB tarball) | 16MB RSS | Constant regardless of size |

**Key insight:** Download time is dominated by latency, not bandwidth.
A 400KB and a 4.7MB tarball take roughly the same time (~1.5-2s).
Parallelism amortizes the latency: 10 concurrent downloads complete
in essentially the time of 1.

### Tree Hashing (Filesystem I/O)

| Scenario | Sequential | Parallel | Notes |
|---|---|---|---|
| 1 action dir (181 files, ~800KB) | ~7ms | - | |
| 15 action dirs (2,715 files, 11MB) | 97ms | 28ms | |

**Key insight:** Tree hashing is effectively free. Even at 15 actions,
it's under 100ms. This makes on-disk verification massively cheaper
than tarball-based integrity verification.

### Existing Scan/Watch Benchmarks (from scale-test.sh)

| Scenario | GraphQL Cost | Time | Tags |
|---|---|---|---|
| 142 repos (baseline scan) | 3 points | 34s | 7,736 |
| 142 repos (detection scan) | 3 points | ~30s | 7,736 |
| 277 repos (StepSecurity org) | 6 points | <2min | ~15,000 |

### Rate Limit Budget

| Pool | Limit | Budget per scan cycle |
|---|---|---|
| REST | 5,000/hour | Tarball downloads + enrichment |
| GraphQL | 5,000 points/hour | 1 point per 50-repo batch |

At 1,800 repos: 36 GraphQL points per scan cycle (0.7% of budget).
At 5,000 repos: 100 GraphQL points per scan cycle (2% of budget).
At 10,000 repos: 200 GraphQL points per scan cycle (4% of budget).

REST budget for tarballs: if 200 unique actions across 1,800 repos,
that's 200 REST calls per lock operation. 4% of hourly budget. Fine.

## Architecture Decision: Gate Flag Hierarchy

Based on the measurements above, the gate verification levels are:

### Level 1: SHA-only (default)
- **What:** Tag→SHA matches lockfile
- **Cost:** 2 REST + 1 GraphQL = 3 calls
- **Time:** <2 seconds
- **Catches:** Tag repointing (the actual attack vector)
- **When:** Every CI run

### Level 2: On-disk (--on-disk)
- **What:** Level 1 + hash runner's downloaded files vs lockfile
- **Cost:** 3 API calls + ~30ms disk I/O
- **Time:** <2 seconds (API-bound, disk is negligible)
- **Catches:** TOCTOU race, cache poisoning, MITM, disk tampering
- **When:** Security-sensitive CI runs, self-hosted runners
- **Requires:** lockfile with disk_integrity field, runner environment

### Level 3: Integrity (--integrity)
- **What:** Level 1 + re-download tarballs + verify SHA-256
- **Cost:** 3 + N REST calls (N = action count)
- **Time:** 3-5 seconds with parallelism (N=10-15)
- **Catches:** SHA-1 collision (theoretical), GitHub CDN compromise
- **When:** Periodic audits, not every CI run
- **Note:** --on-disk implies --integrity is redundant (disk check is
  strictly more useful than API re-download)

### Level 4: Full (--integrity --on-disk)
- **What:** All checks
- **Cost:** 3 + N REST calls + disk I/O
- **Time:** 3-5 seconds
- **When:** Paranoia mode, incident response

**IMPORTANT:** The spec 014 prompt must NOT make --integrity the default
for the gate. It should be an opt-in flag. The gate default remains
SHA-only for performance.

## Concurrency Architecture

### Tarball Downloads (lock and integrity verification)

Use a worker pool pattern with bounded concurrency:

```go
const maxConcurrentDownloads = 10

func DownloadAndHashBatch(ctx context.Context, client *http.Client,
    baseURL, token string, actions []ActionRef) (map[string]string, error) {
    
    sem := make(chan struct{}, maxConcurrentDownloads)
    var mu sync.Mutex
    results := make(map[string]string)
    var errs []error
    var wg sync.WaitGroup
    
    for _, action := range actions {
        wg.Add(1)
        go func(a ActionRef) {
            defer wg.Done()
            sem <- struct{}{}        // acquire
            defer func() { <-sem }() // release
            
            hash, err := DownloadAndHash(ctx, client, baseURL, token,
                a.Owner, a.Repo, a.SHA)
            
            mu.Lock()
            defer mu.Unlock()
            if err != nil {
                errs = append(errs, fmt.Errorf("%s/%s: %w", a.Owner, a.Repo, err))
            } else {
                results[a.Owner+"/"+a.Repo+"@"+a.SHA] = hash
            }
        }(action)
    }
    
    wg.Wait()
    // Return results and any errors
}
```

Why 10 concurrent:
- 10 parallel downloads measured at 1.4s total
- Higher concurrency risks GitHub secondary rate limit (abuse detection)
- 10 is enough to amortize latency for any realistic workflow

### Tarball Extract + Tree Hash (lock only)

During lock, after downloading each tarball, we need to extract and
compute the tree hash. This is CPU/IO bound, not network bound.
Use the same semaphore but with a higher limit (CPU cores):

```go
const maxConcurrentExtracts = runtime.NumCPU()
```

On the VPS (8 cores), this means 8 concurrent extractions.
Each extraction: ~100ms for a typical action.

### Tree Hashing (gate on-disk verification)

During gate --on-disk, we hash the runner's _actions/ directories.
This is pure disk I/O. Use goroutines for parallelism:

```go
func VerifyOnDiskBatch(entries []LockEntry, actionsDir string) ([]Violation, error) {
    var wg sync.WaitGroup
    var mu sync.Mutex
    var violations []Violation
    
    for _, entry := range entries {
        wg.Add(1)
        go func(e LockEntry) {
            defer wg.Done()
            v := verifyOnDisk(e, actionsDir)
            if v != nil {
                mu.Lock()
                violations = append(violations, *v)
                mu.Unlock()
            }
        }(entry)
    }
    
    wg.Wait()
    return violations, nil
}
```

No semaphore needed: disk I/O is so fast (<7ms per action) that
goroutine scheduling overhead dominates. Just fire them all.

### Deduplication

During lock for an org audit (many repos, many shared actions):

Many repos use the same actions (actions/checkout, actions/setup-go).
Deduplicate before downloading:

```go
// Collect unique action@SHA pairs across all repos
seen := make(map[string]bool)
var unique []ActionRef
for _, repo := range repos {
    for _, action := range repo.Actions {
        key := action.Owner + "/" + action.Repo + "@" + action.SHA
        if !seen[key] {
            seen[key] = true
            unique = append(unique, action)
        }
    }
}
// Download only unique tarballs
```

At CW scale: 1,800 repos likely use ~100-200 unique action+SHA pairs.
Download 200 tarballs in parallel (10 at a time) = ~30 seconds.

## Performance Test Suite

### Test 1: Tarball Download Throughput (Go benchmark)

```go
// internal/manifest/integrity_bench_test.go

func BenchmarkDownloadAndHash_Single(b *testing.B) {
    // Use httptest.NewServer serving a fixed 500KB payload
    // Measures: hash throughput without network variance
}

func BenchmarkDownloadAndHash_Parallel10(b *testing.B) {
    // 10 concurrent downloads against httptest.NewServer
    // Measures: goroutine overhead, mutex contention
}

func BenchmarkDownloadAndHash_Parallel50(b *testing.B) {
    // 50 concurrent (simulating large org)
    // Measures: semaphore backpressure behavior
}
```

### Test 2: Tree Hash Throughput (Go benchmark)

```go
// internal/integrity/treehash_bench_test.go

func BenchmarkComputeTreeHash_SmallAction(b *testing.B) {
    // 20 files, ~50KB total (small composite action)
}

func BenchmarkComputeTreeHash_MediumAction(b *testing.B) {
    // 200 files, ~800KB total (typical JS action)
}

func BenchmarkComputeTreeHash_LargeAction(b *testing.B) {
    // 500 files, ~5MB total (action with node_modules)
}

func BenchmarkComputeTreeHash_15Actions(b *testing.B) {
    // 15 dirs, 2700+ files, ~11MB (realistic workflow)
    // Measures: total gate on-disk overhead
}
```

### Test 3: Lock Command Scale (integration, build tag)

```go
// tests/perf/lock_scale_test.go
//go:build integration

func TestLock_10Actions(t *testing.T) {
    // 10 real actions, measures: total time, API calls, memory
    // Target: <5 seconds
}

func TestLock_50Actions(t *testing.T) {
    // 50 unique actions (simulate large monorepo)
    // Target: <15 seconds (parallel downloads)
}

func TestLock_Deduplication(t *testing.T) {
    // 20 workflow files all using the same 10 actions
    // Verify: only 10 tarballs downloaded, not 200
}
```

### Test 4: Gate Levels (integration, build tag)

```go
// tests/perf/gate_scale_test.go
//go:build integration

func TestGate_SHAOnly_15Actions(t *testing.T) {
    // Target: <2 seconds (existing behavior, regression check)
}

func TestGate_OnDisk_15Actions(t *testing.T) {
    // Needs mock _actions/ dir with real extracted content
    // Target: <2.1 seconds (disk hash adds <100ms)
}

func TestGate_Integrity_15Actions(t *testing.T) {
    // Downloads 15 tarballs with parallelism
    // Target: <5 seconds
}
```

### Test 5: Org-Scale Synthetic Benchmark

```bash
# tests/perf/org-scale-bench.sh
# Generates synthetic data to simulate large orgs

# Scenario A: CW-current (1,800 repos, ~150 unique actions)
# Scenario B: CW-double (3,600 repos, ~250 unique actions)
# Scenario C: CW-10x (18,000 repos, ~500 unique actions)

# For each scenario, measures:
# - Lock time (all unique actions, parallel downloads)
# - Gate time (SHA-only, on-disk, integrity)
# - Scan time (GraphQL batching)
# - Memory high-water mark
# - Rate limit consumption
```

The synthetic benchmark uses httptest.NewServer for network operations
so it's repeatable and doesn't depend on GitHub API availability.
It generates N mock repos with M mock actions each, with configurable
overlap (deduplication ratio).

### Test 6: Memory Pressure

```go
// tests/perf/memory_test.go
//go:build integration

func TestMemory_LargeTarball(t *testing.T) {
    // Serve a 50MB tarball via httptest.NewServer
    // DownloadAndHash must not exceed 20MB RSS
    // (proves streaming, not buffering)
    
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    before := m.HeapAlloc
    
    DownloadAndHash(ctx, client, server.URL, "", "test", "test", "abc123")
    
    runtime.ReadMemStats(&m)
    after := m.HeapAlloc
    
    if after-before > 20*1024*1024 {
        t.Errorf("Memory spike: %dMB (tarball should be streamed, not buffered)",
            (after-before)/1024/1024)
    }
}

func TestMemory_50ConcurrentDownloads(t *testing.T) {
    // 50 concurrent 1MB downloads
    // Total memory must stay under 100MB
    // (proves semaphore limits actual concurrency)
}
```

### Test 7: Sustained Watch with Integrity (stress test)

```bash
# tests/perf/watch-stress.sh
# Run pinpoint watch for 10 cycles at 30s interval
# with 200 repos, measure:
# - GraphQL points consumed per cycle
# - RSS memory after each cycle (leak detection)
# - Cumulative rate limit usage
# - State file growth
```

## Scaling Projections

Based on measured data:

### GraphQL (scan/watch)

| Repos | Queries/cycle | Points/cycle | Cycles/hour at 5min | Points/hour | Budget % |
|---|---|---|---|---|---|
| 1,800 | 36 | 36 | 12 | 432 | 8.6% |
| 5,000 | 100 | 100 | 12 | 1,200 | 24% |
| 10,000 | 200 | 200 | 12 | 2,400 | 48% |
| 20,000 | 400 | 400 | 12 | 4,800 | 96% |

**Wall: 20,000 repos at 5-minute intervals saturates GraphQL budget.**
Solution: longer intervals, or multiple tokens.

### Tarball Downloads (lock, one-time per repo set)

| Unique Actions | Parallel (10 workers) | Time | REST Budget % |
|---|---|---|---|
| 100 | 10 batches | ~15s | 2% |
| 200 | 20 batches | ~30s | 4% |
| 500 | 50 batches | ~75s | 10% |

**No wall here.** Lock is a one-time operation per repo.
Even 500 unique actions finishes in ~75 seconds.

### Gate (per CI run)

| Mode | 10 actions | 15 actions | 20 actions |
|---|---|---|---|
| SHA-only | <2s | <2s | <2s |
| On-disk | <2.1s | <2.1s | <2.1s |
| Integrity | ~3s | ~4s | ~5s |

**No wall for SHA-only or on-disk.** These are O(1) API calls.
Integrity scales linearly with action count but parallelism caps it.

### State File / Lockfile Size

| Repos | Actions | Lockfile (v2, with deps) |
|---|---|---|
| 1 | 10 | ~5KB |
| 1 | 50 | ~25KB |
| 1,800 (audit) | 200 unique | ~100KB |

Lockfile size is not a concern.

## Files to Create

- CREATE: `internal/manifest/integrity_bench_test.go` — tarball download benchmarks
- CREATE: `internal/integrity/treehash_bench_test.go` — tree hash benchmarks
- CREATE: `tests/perf/lock_scale_test.go` — lock command integration benchmarks
- CREATE: `tests/perf/gate_scale_test.go` — gate level benchmarks
- CREATE: `tests/perf/memory_test.go` — memory pressure tests
- CREATE: `tests/perf/org-scale-bench.sh` — synthetic org-scale benchmark script
- CREATE: `tests/perf/watch-stress.sh` — sustained watch stress test

## Claude Code Prompt

See claude-code-prompt-016.md (separate file, references this spec).
