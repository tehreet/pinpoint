# CLAUDE.md — Instructions for Claude Code

## THE #1 RULE: DEVELOPER EXPERIENCE IS EVERYTHING

Every feature, every interface, every config option, every error message must
be designed for the developer who just wants this to work. If it's not dead
simple to deploy and use, nobody will use it. Period.

**DX principles that override all other considerations:**

- **Zero-config should work.** Running `pinpoint scan` in a repo with
  `.github/workflows/` should auto-discover actions and Just Work.
- **One-liner deployment for every platform.** GitHub Actions: copy-paste a
  workflow. Local: `go install`.
- **Smart defaults, no required config.** The tool should do the right thing
  without a YAML file. Config is for overriding defaults, not for basic operation.
- **Error messages must tell the user what to do.** Never "error: rate limit
  exceeded." Always "Rate limit exceeded (4999/5000). Set GITHUB_TOKEN for
  authenticated access (5000 requests/hour). See: https://..."
- **Progressive disclosure.** `pinpoint gate` is simple. `pinpoint gate --integrity`
  adds Docker digest verification. Complexity is opt-in, never required.
- **No silent failures.** If something goes wrong, say so loudly and clearly.

---

## Project Overview

Pinpoint detects and prevents GitHub Actions supply chain attacks. Single Go
binary, one dependency. Built after the March 2026 Trivy attack (75 tags
force-pushed to malicious commits). CoreWeave was directly affected.

**Current state:** v0.7.0 released. 28 repos enforced in test org. 10/10
attack battery. First tool to verify Docker image digests.

**Read these files for full context before making architectural decisions:**
- `PROJECT-CONTEXT.md` — Full project state, deployment status, attack battery results
- `PRODUCT.md` — Product vision, three-product architecture, scaling strategy
- `STEELMAN.md` — Known limitations, scaling walls, and evasion techniques

## Architecture

```
cmd/pinpoint/main.go              — CLI routing, all subcommands
internal/
  alert/alert.go                  — Stdout/Slack/webhook alerting
  audit/audit.go                  — Org-wide scanner
  config/config.go                — YAML config with AllowRule support
  discover/discover.go            — Workflow file parser, action reference extraction
  gate/gate.go                    — Pre-execution verification:
                                     • Tag SHA verification against lockfile
                                     • SHA-pinned ref verification (spec 023)
                                     • Docker digest verification (spec 024)
                                     • PR poisoning protection (base-branch lockfile)
                                     • --all-workflows, --fail-on-missing, --fail-on-unpinned
  gate/gate_test.go               — Gate tests incl. SHA-pinned + Docker scenarios
  gate/gate_docker_test.go        — Docker-specific gate tests
  inject/inject.go                — Add pinpoint gate steps to workflow files
  integrity/treehash.go           — On-disk tree hashing (ComputeTreeHash)
  manifest/manifest.go            — Lockfile structs (ActionEntry, DockerInfo, DockerBaseImage),
                                     refresh, verify, save, load
  manifest/integrity.go           — Tarball download+hash, batch with worker pool (10 goroutines)
  manifest/transitive.go          — Composite action.yml parsing, transitive dep resolution
  manifest/docker.go              — OCI registry client (ghcr.io, Docker Hub, quay.io),
                                     ParseDockerRef, ParseDockerfile, ResolveDigest
  manifest/docker_test.go         — 30+ Docker test cases
  manifest/lockpath.go            — ResolveLockfilePath (new/legacy path detection)
  manifest/templates.go           — Embedded workflow YAML templates
  poller/github.go                — REST API client
  poller/graphql.go               — GraphQL client (50 repos/query, 1 point)
  poller/graphql_org.go           — FetchOrgWorkflows for audit
  risk/score.go                   — Risk scoring (13 signals)
  sarif/sarif.go                  — SARIF 2.1.0 output
  store/store.go                  — JSON state with atomic writes
  suppress/suppress.go            — Allow-list false positive suppression
  verify/verify.go                — Retroactive integrity check (4 signals)
tests/
  harness/                        — Integration tests (attack scenarios + real-world replays)
  perf/                           — Performance benchmarks + memory pressure tests
scripts/
  attack-battery.sh               — 10+ attack automated regression test
  chaos-test.sh                   — 5 attack scenarios against deployed infra
```

## Build & Test Commands

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./cmd/pinpoint/           # Build binary
go vet ./...                       # Lint
go test ./...                      # Run all tests
go test ./internal/gate/ -v        # Verbose gate tests
go test ./internal/manifest/ -v -run Docker  # Docker-specific tests
./pinpoint version                 # Verify binary
```

Always run `go build` after changes to verify compilation.
Always run `go vet` before committing.
All existing tests must pass before committing.

## Go Conventions for This Project

- **Module path:** `github.com/tehreet/pinpoint`
- **Go version:** 1.24
- **No CGo.** Binary must be fully static.
- **No frameworks.** Standard library for HTTP, JSON, flags. Only external
  dep: `gopkg.in/yaml.v3` (config parsing).
- **Error handling:** Wrap with `fmt.Errorf("context: %w", err)`. Never
  swallow errors silently. ALWAYS include actionable guidance in user-facing
  error messages.
- **Context:** All API calls must accept and propagate `context.Context`.
- **Copyright header:** Every .go file starts with:
  ```
  // Copyright (C) 2026 CoreWeave, Inc.
  // SPDX-License-Identifier: GPL-3.0-only
  ```
- **Tests:** Table-driven. Mock APIs with `httptest.NewServer`. Use `//go:build integration` for live API tests.

## Key Technical Facts

- Tarball downloads are latency-bound, not bandwidth-bound
- Tarball hashes are deterministic (verified)
- Streaming: io.Copy to sha256.New(), never buffer whole tarball
- GitHub API: tarball endpoint redirects from api.github.com to codeload.github.com
- Tree hash algorithm: walk files, SHA-256 each, sort "path\x00hash" entries, hash concatenation
- Composite action detection: parse action.yml `runs.using` field, recurse up to depth 5
- Docker type detection: parse action.yml `runs.using: docker`, extract `runs.image`
- Docker digest resolution: OCI distribution spec, HEAD request for manifest digest
- Gate fork PR protection: fetches manifest from GITHUB_BASE_REF for pull_request events
- SHA-pinned refs: verified against lockfile when --fail-on-missing is active (spec 023)
- Worker pool: 10 goroutines, semaphore pattern, deduplication before downloading

## Lockfile Format (v2)

The lockfile at `.github/actions-lock.json` contains:
- `sha` — Git commit SHA the tag points to
- `integrity` — SHA-256 of the tarball downloaded from GitHub
- `disk_integrity` — Tree hash of the extracted action files
- `type` — "node20", "node24", "composite", "docker", "unknown"
- `docker` — (Docker actions only) image, tag, digest from OCI registry, source
- `dependencies` — Transitive deps for composite actions (recursive)

## Spec Files

All 24 implementation specs live in `specs/`. Key recent ones:
- `specs/023-verify-sha-pinned.md` — SHA-pinned ref verification
- `specs/024-docker-action-verification.md` — Docker digest resolution + verification
Read the relevant spec BEFORE implementing a feature.

## What NOT to Do

- Do not add a web framework (no gin, no echo, no fiber)
- Do not add a CLI framework (no cobra, no urfave/cli)
- Do not add a logging framework — `fmt.Fprintf(os.Stderr, ...)` is fine
- Do not make the user think — if a feature requires reading docs to use, it's not done yet
