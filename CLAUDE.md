# CLAUDE.md — Instructions for Claude Code

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
cmd/pinpoint/main.go    — CLI entrypoint, subcommands (scan, watch, discover)
internal/
  config/config.go      — YAML config parsing
  poller/github.go      — GitHub API client (REST, will add GraphQL in v0.2)
  store/store.go        — State persistence (JSON now, SQLite in v0.2)
  risk/score.go         — Risk scoring engine
  alert/alert.go        — Alert emission (stdout, Slack, webhook)
  discover/discover.go  — Workflow file parser, action reference extraction
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
  swallow errors silently.
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
- `GET /repos/{owner}/{repo}/git/matching-refs/tags` — List all tag refs
  (paginated, supports ETag for conditional requests)
- `GET /repos/{owner}/{repo}/git/tags/{sha}` — Dereference annotated tag
  object to commit
- `GET /repos/{owner}/{repo}/compare/{base}...{head}` — Check commit ancestry
- `GET /repos/{owner}/{repo}/commits/{ref}` — Get commit metadata
- `GET /repos/{owner}/{repo}/contents/{path}?ref={ref}` — Get file size

**Annotated vs lightweight tags:** The matching-refs endpoint returns
`object.type` as either `"commit"` (lightweight) or `"tag"` (annotated).
Annotated tags MUST be dereferenced with a second API call to get the commit.

**ETag caching:** All list endpoints support `If-None-Match` header.
304 responses do NOT count against rate limit. Always cache and send ETags.

**Rate limits:**
- REST: 5,000 requests/hour (authenticated)
- GraphQL: 5,000 points/hour (separate budget)
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
