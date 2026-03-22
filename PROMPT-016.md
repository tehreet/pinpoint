Read specs/016-performance-testing.md before writing any code.

This spec adds Go benchmarks and integration performance tests for every operation that touches the network or filesystem.

PHASE 1: Tarball download benchmarks

Create internal/manifest/integrity_bench_test.go:

BenchmarkDownloadAndHash_Single:
  Use httptest.NewServer serving a fixed 500KB random payload. Benchmark a single DownloadAndHash call. Report bytes/sec: b.SetBytes(500 * 1024)

BenchmarkDownloadAndHash_Parallel10:
  Same mock server. Launch 10 goroutines each calling DownloadAndHash. Use b.RunParallel for proper Go benchmark parallelism. This measures: goroutine overhead, mutex contention, HTTP client reuse.

BenchmarkDownloadAndHashBatch_20Actions:
  Create 20 ActionRef entries (with some duplicates to test dedup). Call DownloadAndHashBatch. Measure total time.

BenchmarkDownloadAndHash_LargePayload:
  Mock server serving a 10MB payload. Verify: streaming works, no OOM, timing scales linearly with size.

Run: go test -bench=. -benchmem ./internal/manifest/ -v

PHASE 2: Tree hash benchmarks

Create internal/integrity/treehash_bench_test.go:

Each benchmark creates its temp directory in b.StopTimer/b.StartTimer blocks so setup doesn't count toward timing.

BenchmarkComputeTreeHash_20Files:
  Create temp dir with 20 files, ~50KB total. Benchmark hash.

BenchmarkComputeTreeHash_200Files:
  Create temp dir with 200 files across 5 subdirs, ~800KB total. This simulates a typical GitHub Action.

BenchmarkComputeTreeHash_500Files:
  Create temp dir with 500 files across 10 subdirs, ~5MB total. This simulates a large action with node_modules.

Helper function for all benchmarks:
  func createFakeActionDir(b *testing.B, numFiles int, avgSizeKB int) string
  Creates a temp directory with the specified number of random files distributed across subdirs. Returns the path. Caller must defer os.RemoveAll.

Run: go test -bench=. -benchmem ./internal/integrity/ -v

PHASE 3: Memory pressure tests

Create tests/perf/memory_test.go (use build tag //go:build integration):

TestMemory_LargeTarballStreaming:
  Create httptest.NewServer serving a 50MB payload (use io.LimitReader on a crypto/rand.Reader to generate random bytes on the fly, don't actually allocate 50MB in the mock).

  Before: runtime.ReadMemStats -> record HeapAlloc
  Call: DownloadAndHash
  After: runtime.GC(); runtime.ReadMemStats -> record HeapAlloc

  Assert: heap growth < 10MB (the 50MB tarball must be streamed, never fully buffered. Allow 10MB for buffers, goroutine stacks, etc.)

  Log the actual heap growth for visibility.

TestMemory_50ConcurrentSmallDownloads:
  Mock server serving 500KB per request. Launch 50 concurrent DownloadAndHash calls (through the batch function with 50 ActionRefs).

  Assert: peak heap < 200MB. This verifies the semaphore (maxConcurrentDownloads=10) actually limits concurrency — only 10 should be in-flight at once.

TestMemory_TreeHashLargeDirectory:
  Create a temp directory with 1000 files, 10MB total.

  Before/after ReadMemStats around ComputeTreeHash.
  Assert: heap growth < 10MB (files are streamed through hasher, only the path+hash strings are accumulated).

Run: go test -tags integration -run TestMemory -v ./tests/perf/

PHASE 4: End-to-end benchmark script

Create tests/perf/benchmark.sh:

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH=$PATH:/usr/local/go/bin

echo "=== PINPOINT PERFORMANCE BENCHMARKS ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Go: $(go version)"
echo "CPUs: $(nproc)"
echo ""

# Build
go build -o ./pinpoint-bench ./cmd/pinpoint/

# Go microbenchmarks
echo "[1/3] Running Go benchmarks..."
go test -bench=. -benchmem -count=3 ./internal/manifest/ 2>&1 | tee /tmp/bench-manifest.txt
go test -bench=. -benchmem -count=3 ./internal/integrity/ 2>&1 | tee /tmp/bench-integrity.txt

# Memory tests
echo ""
echo "[2/3] Running memory tests..."
go test -tags integration -run TestMemory -v -timeout 120s ./tests/perf/ 2>&1 | tee /tmp/bench-memory.txt

# Rate limit check
echo ""
echo "[3/3] Rate limit check..."
if [ -n "${GITHUB_TOKEN:-}" ]; then
  curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/rate_limit | grep -A3 '"core"'
else
  echo "GITHUB_TOKEN not set, skipping"
fi

echo ""
echo "=== BENCHMARKS COMPLETE ==="
rm -f ./pinpoint-bench

Make this script executable: chmod +x tests/perf/benchmark.sh

Ensure the tests/perf/ directory exists: mkdir -p tests/perf

Run go build, go vet, go test ./... -v -count=1.

FINAL VERIFICATION:

go build ./cmd/pinpoint/
go vet ./...
go test ./... -v -count=1
go test -bench=. -benchmem ./internal/manifest/ -count=1
go test -bench=. -benchmem ./internal/integrity/ -count=1

All benchmarks should run and produce timing data.
The shell benchmark script should be executable.
