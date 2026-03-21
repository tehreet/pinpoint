# CLAUDE.md — Instructions for Claude Code

## THE #1 RULE: DEVELOPER EXPERIENCE IS EVERYTHING

Every feature, every interface, every config option, every error message must
be designed for the developer who just wants this to work. If it's not dead
simple to deploy and use, nobody will use it. Period.

**DX principles that override all other considerations:**

- **Zero-config should work.** Running `pinpoint scan` in a repo with
  `.github/workflows/` should auto-discover actions and Just Work.
- **One-liner deployment for every platform.** GitHub Actions: copy-paste a
  workflow. Kubernetes: `helm install`. Docker: `docker run`. Local: `go install`.
  Azure/AWS/GCP: documented and tested.
- **Smart defaults, no required config.** The tool should do the right thing
  without a YAML file. Config is for overriding defaults, not for basic operation.
- **Error messages must tell the user what to do.** Never "error: rate limit
  exceeded." Always "Rate limit exceeded (4999/5000). Set GITHUB_TOKEN for
  authenticated access (5000 requests/hour). See: https://..."
- **Progressive disclosure.** `pinpoint scan` is simple. `pinpoint scan --json`
  adds machine output. `pinpoint scan --config custom.yml` adds customization.
  Complexity is opt-in, never required.
- **No silent failures.** If something goes wrong, say so loudly and clearly.
  If something is degraded (e.g., REST fallback), say so. The user should
  never wonder "is this thing actually working?"

Apply these principles to EVERY function, EVERY CLI flag, EVERY error path.
If you're writing code and thinking "the user will figure it out" — stop,
and make it obvious instead.

---

## Project Overview

Pinpoint is a GitHub Actions tag integrity monitor that detects tag repointing
attacks. It's a Go CLI tool that polls the GitHub API, tracks tag→SHA mappings,
and alerts when tags are moved to point at different commits.

Built in response to the March 2026 Trivy supply chain attack where 75 GitHub
Action tags were force-pushed to malicious commits.

**Read these files for full context before making architectural decisions:**
- `PRODUCT.md` — Complete product vision, three-product architecture, scaling
  strategy, and feature roadmap
- `STEELMAN.md` — Known limitations, scaling walls, and evasion techniques
- `README.md` — User-facing documentation

## Architecture

```
cmd/pinpoint/main.go        — CLI entrypoint, subcommands (scan, watch, discover)
internal/
  config/config.go           — YAML config parsing
  poller/github.go           — GitHub REST API client (fallback)
  poller/graphql.go          — GitHub GraphQL API client (default, batches 50 repos/query)
  poller/graphql_test.go     — 10 tests covering all GraphQL spec cases
  store/store.go             — State persistence (JSON file with atomic writes)
  risk/score.go              — Risk scoring engine
  alert/alert.go             — Alert emission (stdout, Slack, webhook)
  discover/discover.go       — Workflow file parser, action reference extraction
```

## Build & Test Commands

```bash
export PATH=$PATH:/usr/local/go/bin
go build ./cmd/pinpoint/           # Build binary
go vet ./...                       # Lint
go test ./... -v                   # Run tests
./pinpoint version                 # Verify binary works
```

Always run `go build` after changes to verify compilation.
Always run `go vet` before committing.

## Go Conventions for This Project

- **Module path:** `github.com/tehreet/pinpoint`
- **Go version:** 1.24
- **No CGo.** Binary must be fully static. Use `modernc.org/sqlite` not
  `mattn/go-sqlite3` if adding SQLite.
- **No frameworks.** Standard library for HTTP, JSON, flags. Only external
  deps: `gopkg.in/yaml.v3` (config parsing).
- **Error handling:** Wrap with `fmt.Errorf("context: %w", err)`. Never
  swallow errors silently. ALWAYS include actionable guidance in user-facing
  error messages.
- **Context:** All API calls must accept and propagate `context.Context`
  for cancellation.
- **Copyright header:** Every .go file starts with:
  ```
  // Copyright (C) 2026 CoreWeave, Inc.
  // SPDX-License-Identifier: GPL-3.0-only
  ```

## GitHub API Contract Details

**CRITICAL: Do not guess API response schemas. If you need a field name or
endpoint behavior, ask the user to verify or check the specs/ directory.**

Key endpoints used:
- GraphQL: `POST /graphql` — Batch tag resolution, 50 repos per query, 1 point
  per batch. Field names: `refs.nodes[].name`, `target.__typename`, `target.oid`,
  `... on Tag { target { oid } }` for annotated tag dereferencing.
- REST (fallback): `GET /repos/{owner}/{repo}/git/matching-refs/tags`
- REST (enrichment): `/compare/`, `/commits/`, `/contents/`

**ETag caching:** REST list endpoints support `If-None-Match` header.
304 responses do NOT count against rate limit. GraphQL does NOT support ETags.

**Rate limits:**
- REST: 5,000 requests/hour (authenticated)
- GraphQL: 5,000 points/hour (separate budget, 1 point per 50-repo batch)
- Conditional requests (304): free

## Spec Files

Implementation specs for upcoming features live in `specs/`. Each spec
contains exact API contracts, test cases, and implementation guidance.
Read the relevant spec file BEFORE implementing a feature.

## Testing Strategy

- Unit tests go next to the source file: `foo_test.go`
- Test files should use table-driven tests
- Mock the GitHub API using `httptest.NewServer` — do NOT make real API
  calls in tests
- For integration tests that hit the real API, use build tag `//go:build integration`

## State Management

The state file (`.pinpoint-state.json`) uses atomic writes: write to `.tmp`,
then rename. Never write directly to the state file. The `store.Save()` method
handles this.

## What NOT to Do

- Do not add a web framework (no gin, no echo, no fiber)
- Do not add a CLI framework (no cobra, no urfave/cli) — the current manual
  flag parsing is intentional to keep deps minimal
- Do not add a logging framework — `fmt.Fprintf(os.Stderr, ...)` is fine
- Do not reorganize the package structure without explicit instruction
- Do not modify PRODUCT.md, STEELMAN.md, or README.md — those are maintained
  by humans
- Do not make the user think. If a feature requires reading docs to use,
  it's not done yet.
