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
