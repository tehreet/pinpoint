# Spec 016 Addendum: Runner Benchmark Workflow

## Problem

All performance measurements in spec 016 were taken on the VPS
(8-core AMD EPYC-Milan, 30GB RAM, Hetzner US). GitHub Actions runners
are different hardware in a different network position.

### Where VPS numbers are pessimistic (good news)

Network latency from VPS to GitHub API: ~147ms TCP connect, ~300ms
including TLS. From a GitHub-hosted runner (Azure VM), this drops to
single-digit ms. Tarball downloads measured at 1.5-2s from VPS would
be ~300-500ms from a runner. The --integrity gate mode is faster on
real runners than our estimates.

### Where VPS numbers are optimistic (less good news)

CPU: VPS has 8 cores, standard runner has 4 (or 2 for ubuntu-latest
on public repos). Tree hashing at 28ms (8 cores) would be ~50-60ms
(4 cores). Still negligible.

Disk: comparable SSDs. Not a factor.

Memory: VPS has 30GB, runner has 16GB. Not a factor for our use
case (streaming, max 100MB at 50 concurrent downloads).

### Where CW self-hosted runners differ

CoreWeave likely runs self-hosted runners on their own infra
(GPU cloud). Network path to GitHub API goes through the public
internet, similar to our VPS latency. Self-hosted runners are where
on-disk verification matters most (persistent _actions/ cache,
no ephemeral environment).

## Solution: CI Benchmark Workflow

A GitHub Actions workflow that runs on every release (or manually)
to produce authoritative benchmark numbers from real runner hardware.

### Workflow file

```yaml
name: Performance Benchmarks
on:
  workflow_dispatch:
  release:
    types: [published]

jobs:
  bench-standard:
    name: Standard runner (4 vCPU)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Runner hardware info
        run: |
          echo "=== Runner specs ==="
          nproc
          free -h | head -2
          lscpu | grep -E "Model name|CPU MHz"
          echo ""
          echo "=== Disk speed ==="
          dd if=/dev/zero of=/tmp/disktest bs=1M count=64 oflag=direct 2>&1 | tail -1
          rm /tmp/disktest
          echo ""
          echo "=== Network latency to GitHub API ==="
          curl -sSo /dev/null -w "TCP: %{time_connect}s  TLS: %{time_appconnect}s  Total: %{time_total}s\n" \
            -H "Authorization: Bearer ${{ github.token }}" \
            "https://api.github.com/rate_limit"

      - name: Go benchmarks
        run: |
          go test -bench=. -benchmem -count=3 ./internal/manifest/ 2>&1 | tee bench-manifest.txt
          go test -bench=. -benchmem -count=3 ./internal/integrity/ 2>&1 | tee bench-integrity.txt

      - name: Tarball download benchmark (real GitHub API)
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          go build -o ./pinpoint-bench ./cmd/pinpoint/
          echo "=== Single tarball download ==="
          for action in \
            "actions/checkout/11bd71901bbe5b1630ceea73d27597364c9af683" \
            "actions/setup-go/d35c59abb061a4a6fb18e82ac0862c26744d6ab5" \
            "step-security/harden-runner/c6295a65d1254861815972266d5933fd6e532bdf"
          do
            owner=$(echo $action | cut -d/ -f1)
            repo=$(echo $action | cut -d/ -f2)
            sha=$(echo $action | cut -d/ -f3)
            start=$(date +%s%N)
            curl -sSL -H "Authorization: Bearer $GITHUB_TOKEN" \
              "https://api.github.com/repos/${owner}/${repo}/tarball/${sha}" \
              -o /dev/null
            end=$(date +%s%N)
            ms=$(( (end - start) / 1000000 ))
            echo "${owner}/${repo}: ${ms}ms"
          done

          echo ""
          echo "=== 10 parallel tarball downloads ==="
          start=$(date +%s%N)
          for i in $(seq 1 10); do
            curl -sSL -H "Authorization: Bearer $GITHUB_TOKEN" \
              "https://api.github.com/repos/actions/checkout/tarball/11bd71901bbe5b1630ceea73d27597364c9af683" \
              -o /dev/null &
          done
          wait
          end=$(date +%s%N)
          ms=$(( (end - start) / 1000000 ))
          echo "10 parallel: ${ms}ms"

      - name: On-disk tree hash benchmark
        run: |
          echo "=== Actions cache contents ==="
          ls -la $(dirname $RUNNER_WORKSPACE)/_actions/ 2>/dev/null || echo "No _actions dir found"
          find $(dirname $RUNNER_WORKSPACE)/_actions/ -type f 2>/dev/null | wc -l || echo "0 files"

          echo ""
          echo "=== Hashing actions on disk ==="
          ACTIONS_DIR="$(dirname $RUNNER_WORKSPACE)/_actions"
          if [ -d "$ACTIONS_DIR" ]; then
            start=$(date +%s%N)
            for dir in $(find "$ACTIONS_DIR" -mindepth 3 -maxdepth 3 -type d 2>/dev/null); do
              find "$dir" -type f -print0 | xargs -0 sha256sum | sort | sha256sum > /dev/null
            done
            end=$(date +%s%N)
            ms=$(( (end - start) / 1000000 ))
            count=$(find "$ACTIONS_DIR" -mindepth 3 -maxdepth 3 -type d 2>/dev/null | wc -l)
            echo "Hashed $count action dirs in ${ms}ms"
          fi

      - name: Memory benchmark
        run: |
          go test -tags integration -run TestMemory -v -timeout 120s ./tests/perf/ 2>&1 || echo "Memory tests not yet implemented"

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: bench-standard
          path: |
            bench-manifest.txt
            bench-integrity.txt
```

### Key measurements this captures

1. **Runner hardware specs** — CPU model, core count, RAM, disk speed.
   We need this to contextualize everything else.

2. **Network latency from runner to GitHub** — TCP connect + TLS time.
   This is the single biggest variable between our VPS and a real runner.

3. **Go microbenchmarks** — same benchmarks from spec 016, but on
   runner hardware. Direct comparison to VPS numbers.

4. **Real tarball downloads** — single and parallel, from inside
   Azure's network. This will show the true --integrity cost.

5. **On-disk tree hashing of actual runner cache** — the runner has
   already downloaded actions/checkout and actions/setup-go for this
   very workflow. We hash them. This is the most realistic benchmark
   possible for --on-disk mode.

6. **Memory under load** — integration tests from spec 016.

### Expected findings

Based on the network analysis:

| Operation | VPS (measured) | Runner (predicted) | Why |
|---|---|---|---|
| Single tarball | 1.5-2.0s | 0.3-0.5s | 300ms network overhead eliminated |
| 10 parallel tarballs | 1.4s | 0.4-0.6s | Same reason |
| Tree hash (15 dirs) | 28ms | 50-60ms | 4 cores vs 8 |
| Gate SHA-only | <2s | <1s | Faster API round-trips |
| Gate --on-disk | +28ms | +50-60ms | Slower CPU, same conclusion: negligible |
| Gate --integrity | +3-5s | +1-2s | Way faster network |

Net effect: on real runners, everything is FASTER than our estimates
except tree hashing (slightly slower, still negligible). The
architecture decisions remain valid. On-disk is still dramatically
cheaper than --integrity for the gate.
