# Spec 001: GraphQL Poller

## Summary

Replace the REST-based tag poller in `internal/poller/github.go` with a
GraphQL-based poller that batches multiple repositories per API call.

This is the single highest-impact change in the pinpoint roadmap. It reduces
API cost from O(repos) REST calls per poll to O(repos/50) GraphQL calls per
poll, enabling monitoring of 200+ repos for ~4 GraphQL points per cycle.

## Motivation

The current REST poller uses `GET /repos/{owner}/{repo}/git/matching-refs/tags`
which costs 1 REST API call per repo per poll. At 200 repos × 12 polls/hour
= 2,400 REST calls/hour against a 5,000/hr limit. Annotated tags require an
additional REST call each for dereferencing, further multiplying cost.

The GraphQL API allows batching N repos into a single query using aliases.
Annotated tags are auto-dereferenced via inline fragments. A single query
for 10 repos with 609 total tags costs 1 GraphQL point (verified empirically).

## Verified API Contract

### GraphQL Endpoint

```
POST https://api.github.com/graphql
Authorization: Bearer <token>
Content-Type: application/json
```

### Query Structure (single repo)

```graphql
{
  repository(owner: "actions", name: "checkout") {
    refs(refPrefix: "refs/tags/", first: 100) {
      totalCount
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes {
        name
        target {
          __typename
          oid
          ... on Tag {
            target {
              __typename
              oid
            }
          }
        }
      }
    }
  }
}
```

### Response Structure (verified on live API 2026-03-21)

Lightweight tag (target is a Commit):
```json
{
  "name": "1.0.0",
  "target": {
    "__typename": "Commit",
    "oid": "af513c7a016048ae468971c52ed77d9562c7c819"
  }
}
```

Annotated tag (target is a Tag, with nested target pointing to Commit):
```json
{
  "name": "v1",
  "target": {
    "__typename": "Tag",
    "oid": "544eadc6bf3d226fd7a7a9f0dc5b5bf7ca0675b9",
    "target": {
      "__typename": "Commit",
      "oid": "50fbc622fc4ef5163becd7fab6573eac35f8462e"
    }
  }
}
```

### Multi-Repo Batching (the key feature)

GitHub GraphQL supports aliases to query multiple repos in one call:

```graphql
{
  rateLimit { cost remaining }
  repo_actions_checkout: repository(owner: "actions", name: "checkout") {
    refs(refPrefix: "refs/tags/", first: 100) {
      totalCount
      pageInfo { endCursor hasNextPage }
      nodes {
        name
        target {
          __typename
          oid
          ... on Tag { target { __typename oid } }
        }
      }
    }
  }
  repo_actions_setup_go: repository(owner: "actions", name: "setup-go") {
    refs(refPrefix: "refs/tags/", first: 100) {
      totalCount
      pageInfo { endCursor hasNextPage }
      nodes {
        name
        target {
          __typename
          oid
          ... on Tag { target { __typename oid } }
        }
      }
    }
  }
}
```

Alias names MUST be valid GraphQL identifiers: alphanumeric + underscore,
no hyphens, no slashes. Generate alias from owner/repo by replacing
non-alphanumeric chars with underscores: "actions/checkout" -> "actions_checkout",
"aquasecurity/trivy-action" -> "aquasecurity_trivy_action".

### Verified Rate Limit Behavior

Empirical measurement on 2026-03-21:
- 10 repos, 609 total tags, single query: cost = 1 point
- GraphQL budget: 5,000 points/hour (PAT), 10,000/hr (GitHub Enterprise Cloud)
- Secondary rate limit: 2,000 points/minute
- Node limit per query: 500,000

Cost formula from GitHub docs: "Add up the number of requests needed to fulfill
each unique connection in the call. Assume every request will reach the first or
last argument limits. Divide the number by 100 and round the result. Minimum is 1."

For 50 repos: 50 connections × 100 nodes each = 5,000 nodes. Cost = 50/100 = 1 point.
This means 50 repos per query at 1 point. At 5,000 points/hour budget, that's
5,000 queries/hour × 50 repos = 250,000 repo-polls/hour. Effectively unlimited.

### Important: GraphQL Does NOT Support ETags

Unlike REST, GraphQL responses do not include ETag headers and do not support
conditional requests (If-None-Match). Every GraphQL query consumes its point
cost regardless of whether data changed.

At 1 point per 50 repos this is irrelevant — but the code should NOT attempt
to send ETag headers on GraphQL requests.

### Pagination

If a repo has >100 tags, `pageInfo.hasNextPage` will be true and `endCursor`
will contain the cursor string. To get the next page:

```graphql
{
  repository(owner: "actions", name: "checkout") {
    refs(refPrefix: "refs/tags/", first: 100, after: "CURSOR_STRING") {
      ...
    }
  }
}
```

Repos needing pagination must be queried individually in follow-up calls.
This is an edge case — most action repos have <100 tags.

## Implementation Plan

### New File: `internal/poller/graphql.go`

Create a new file alongside `github.go`. Do NOT modify `github.go` — keep the
REST client working as a fallback.

### New Type: GraphQLClient

```go
type GraphQLClient struct {
    httpClient *http.Client
    token      string
    endpoint   string // "https://api.github.com/graphql"
}
```

### Key Method: FetchTagsBatch

```go
// FetchTagsBatch resolves all tags for up to 50 repos in a single GraphQL call.
// repos is a slice of "owner/repo" strings.
// Returns a map of "owner/repo" -> []ResolvedTag (reusing the existing type).
func (c *GraphQLClient) FetchTagsBatch(ctx context.Context, repos []string) (map[string]*FetchResult, error)
```

Implementation steps:
1. Accept up to 50 repos. If more than 50, split into batches.
2. For each repo, generate a GraphQL alias (replace non-alphanum with _).
3. Build the query string by concatenating aliased repository fragments.
4. POST to the GraphQL endpoint.
5. Parse the response: for each alias, iterate `refs.nodes`.
6. For each node:
   - Read `name` (tag name, without "refs/tags/" prefix — already stripped by API)
   - Read `target.__typename`:
     - If `"Commit"`: `commitSHA = target.oid`
     - If `"Tag"`: `commitSHA = target.target.oid`, `tagSHA = target.oid`
   - Create a `ResolvedTag` struct (reuse existing type from github.go)
7. Check `pageInfo.hasNextPage` for each repo. If true, add to a "needs
   pagination" list and handle with individual follow-up queries.
8. Return map of repo -> FetchResult.

### GraphQL Request/Response Types

```go
type graphqlRequest struct {
    Query string `json:"query"`
}

type graphqlResponse struct {
    Data   map[string]json.RawMessage `json:"data"`
    Errors []struct {
        Message string `json:"message"`
    } `json:"errors"`
}

type refsPayload struct {
    Refs struct {
        TotalCount int `json:"totalCount"`
        PageInfo   struct {
            EndCursor   string `json:"endCursor"`
            HasNextPage bool   `json:"hasNextPage"`
        } `json:"pageInfo"`
        Nodes []struct {
            Name   string `json:"name"`
            Target struct {
                TypeName string `json:"__typename"`
                OID      string `json:"oid"`
                Target   *struct {
                    TypeName string `json:"__typename"`
                    OID      string `json:"oid"`
                } `json:"target,omitempty"`
            } `json:"target"`
        } `json:"nodes"`
    } `json:"refs"`
}

type rateLimitPayload struct {
    Cost      int `json:"cost"`
    Remaining int `json:"remaining"`
}
```

### Alias Generation

```go
func repoToAlias(ownerRepo string) string {
    // "aquasecurity/trivy-action" -> "aquasecurity_trivy_action"
    // Must produce valid GraphQL identifier: [a-zA-Z_][a-zA-Z0-9_]*
    alias := strings.Map(func(r rune) rune {
        if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
            return r
        }
        return '_'
    }, ownerRepo)
    // Ensure starts with letter or underscore (not digit)
    if len(alias) > 0 && alias[0] >= '0' && alias[0] <= '9' {
        alias = "_" + alias
    }
    return alias
}
```

### Query Builder

```go
func buildBatchQuery(repos []string) string {
    var b strings.Builder
    b.WriteString("{\n  rateLimit { cost remaining }\n")
    for _, repo := range repos {
        parts := strings.SplitN(repo, "/", 2)
        owner, name := parts[0], parts[1]
        alias := repoToAlias(repo)
        fmt.Fprintf(&b, `  %s: repository(owner: %q, name: %q) {
    refs(refPrefix: "refs/tags/", first: 100) {
      totalCount
      pageInfo { endCursor hasNextPage }
      nodes {
        name
        target {
          __typename
          oid
          ... on Tag { target { __typename oid } }
        }
      }
    }
  }
`, alias, owner, name)
    }
    b.WriteString("}")
    return b.String()
}
```

### Integration With Existing Code

The main scan loop in `cmd/pinpoint/main.go` currently calls
`client.FetchAllTags()` per repo. Update it to:

1. Collect all repos from config into a slice.
2. Call `graphqlClient.FetchTagsBatch(ctx, repos)` in batches of 50.
3. For each result, feed into the existing store/comparison/scoring logic.
4. The REST client remains available as fallback (e.g., if GraphQL fails,
   if user doesn't have a token with GraphQL access).

Add a `--rest` flag to force REST mode for backwards compatibility.

### New Constructor

Add to `cmd/pinpoint/main.go`:

```go
graphqlClient := poller.NewGraphQLClient(token)
```

## Error Handling

### GraphQL Errors

If the `errors` array in the response is non-empty, log each error message.
Common cases:
- `"Could not resolve to a Repository"` — repo doesn't exist or is private
  and token doesn't have access. Log warning, skip this repo, continue batch.
- Rate limit exceeded — check `rateLimit.remaining` in response and back off.

### Partial Failures

GraphQL can return partial data + errors. A query for 50 repos might succeed
for 48 and fail for 2 (e.g., 2 repos are private). The response will have
data for the 48 successful repos and errors for the 2 failures.

Implementation MUST handle this: iterate `data` keys for successful repos,
log errors for failed repos, do NOT abort the entire batch.

### Network Errors

Retry with exponential backoff: 1s, 2s, 4s, max 3 retries. Use context
for cancellation.

## Test Cases

### Test 1: Alias Generation

```
Input:  "aquasecurity/trivy-action"
Output: "aquasecurity_trivy_action"

Input:  "actions/checkout"
Output: "actions_checkout"

Input:  "docker/build-push-action"
Output: "docker_build_push_action"

Input:  "123org/repo"
Output: "_123org_repo"
```

### Test 2: Response Parsing (Lightweight Tag)

Given this JSON node:
```json
{"name": "0.35.0", "target": {"__typename": "Commit", "oid": "abc123"}}
```

Expected ResolvedTag:
```go
ResolvedTag{Name: "0.35.0", CommitSHA: "abc123", TagSHA: "abc123", IsAnnotated: false}
```

### Test 3: Response Parsing (Annotated Tag)

Given this JSON node:
```json
{"name": "v1", "target": {"__typename": "Tag", "oid": "tag111", "target": {"__typename": "Commit", "oid": "commit222"}}}
```

Expected ResolvedTag:
```go
ResolvedTag{Name: "v1", CommitSHA: "commit222", TagSHA: "tag111", IsAnnotated: true}
```

### Test 4: Batch Query Building

Given repos: ["actions/checkout", "docker/build-push-action"]

Query MUST contain:
- `rateLimit { cost remaining }`
- `actions_checkout: repository(owner: "actions", name: "checkout")`
- `docker_build_push_action: repository(owner: "docker", name: "build-push-action")`
- Both with `refs(refPrefix: "refs/tags/", first: 100)` and proper node structure

### Test 5: Batch Splitting

Given 120 repos, FetchTagsBatch MUST:
- Split into 3 batches: 50, 50, 20
- Make 3 GraphQL calls
- Merge results into single map

### Test 6: Partial Failure

Mock a response where repo1 returns data and repo2 returns an error.
FetchTagsBatch MUST:
- Return tags for repo1
- Log a warning for repo2
- NOT return an error (partial success is success)

### Test 7: Pagination Detection

Mock a response where repo1 has hasNextPage: true.
FetchTagsBatch MUST:
- Return the first 100 tags
- Issue a follow-up single-repo query with the endCursor
- Merge the paginated results

## Files to Create/Modify

- CREATE: `internal/poller/graphql.go` — new GraphQL client
- CREATE: `internal/poller/graphql_test.go` — tests using httptest.NewServer
- MODIFY: `cmd/pinpoint/main.go` — use GraphQLClient by default, add --rest flag
- DO NOT MODIFY: `internal/poller/github.go` — keep REST client as fallback

## Build Verification

After implementation, these must pass:
```bash
go build ./cmd/pinpoint/
go vet ./...
go test ./... -v
```

And this integration test (run manually, not in CI):
```bash
GITHUB_TOKEN=$(gh auth token) ./pinpoint scan --config test-config.yml
```
Should produce the same results as the REST poller for the same config.

---

## Addendum: Verified at 50-Repo Scale (2026-03-21)

Empirical test with 50 real GitHub Action repos in a single query:

```
Repos queried:     50
Total tags:        2,629
API cost:          1 point
Remaining budget:  4,990 points
Node count:        5,000
Response time:     6,488ms
```

The 50-repo batch is confirmed working. Node count hits exactly 5,000
(50 repos × first:100 = 5,000 nodes), well under the 500,000 limit.
Response time of ~6.5s is acceptable for a monitoring tool.

## Addendum: Alias Collision Handling

The alias function maps `foo/bar-baz` and `foo/bar_baz` to the same alias
`foo_bar_baz`. In practice this is extremely unlikely — GitHub org/repo names
that differ only in hyphens vs underscores for repos that are BOTH GitHub
Actions is vanishingly rare.

However, to be safe: after generating aliases, check for duplicates. If a
collision occurs, append a numeric suffix: `foo_bar_baz`, `foo_bar_baz_2`.
Maintain a reverse map from alias -> owner/repo for response parsing.

```go
func buildAliasMap(repos []string) map[string]string {
    aliasToRepo := make(map[string]string)
    for _, repo := range repos {
        alias := repoToAlias(repo)
        if _, exists := aliasToRepo[alias]; exists {
            // Collision — append incrementing suffix
            for i := 2; ; i++ {
                candidate := fmt.Sprintf("%s_%d", alias, i)
                if _, exists := aliasToRepo[candidate]; !exists {
                    alias = candidate
                    break
                }
            }
        }
        aliasToRepo[alias] = repo
    }
    return aliasToRepo
}
```

This is a defensive measure. Do not over-engineer it.

## Addendum: Pagination Strategy

If `pageInfo.hasNextPage` is true for a repo, issue individual follow-up
GraphQL queries (NOT batched — pagination cursors are per-repo).

**Max pagination depth: 3 pages (300 tags).** If a repo has >300 tags,
log a warning and stop paginating. Rationale:
- No legitimate GitHub Action has >300 tags
- A repo with >300 tags is either a monorepo or something unusual
- Unbounded pagination could burn API budget on a single repo

```go
const maxPaginationPages = 3  // 300 tags max per repo

func (c *GraphQLClient) paginateRepo(ctx context.Context, owner, repo, cursor string, page int) ([]ResolvedTag, error) {
    if page >= maxPaginationPages {
        fmt.Fprintf(os.Stderr, "Warning: %s/%s has >%d tags, stopping pagination\n",
            owner, repo, maxPaginationPages*100)
        return nil, nil
    }
    // ... single-repo query with after: cursor ...
}
```

Each pagination follow-up costs 1 GraphQL point. For a poll cycle monitoring
200 repos where 5 need pagination: 4 batch queries + 5 pagination queries =
9 points total. Still negligible.

## Addendum: Automated GraphQL→REST Failover

### Behavior

If the GraphQL call fails (network error, 5xx, auth error), pinpoint
automatically falls back to the REST client for that poll cycle. It does NOT
retry GraphQL — it immediately switches to REST for the affected batch.

On the NEXT poll cycle, it tries GraphQL again. If GraphQL succeeds, normal
operation resumes. If it fails again, fall back to REST again.

This is a per-cycle failover, not a permanent switch.

### Risks of Automated Failover

**Risk 1: REST rate limit burn.**
If GraphQL is down for an extended period and pinpoint is monitoring 200 repos,
each REST poll cycle costs 200+ API calls (plus annotated tag dereferencing).
At 5-minute intervals: 200 × 12 = 2,400 REST calls/hour. This is 48% of the
5,000/hr REST budget. If the user has OTHER tools using the same token,
they could hit the REST limit.

**Mitigation:** When in REST failover mode, automatically increase the poll
interval to 15 minutes (4 polls/hr × 200 = 800 calls/hr — safe). Log a
prominent warning:

```
⚠ GraphQL unavailable. Falling back to REST with extended interval (15m).
  REST API budget: 800/hr estimated usage, 5000/hr limit.
```

**Risk 2: Annotated tag dereferencing multiplier.**
The REST client needs a second call per annotated tag. If 50% of 2,000 tags
are annotated: 1,000 extra calls per cycle. At 15-minute intervals: 4 × 1,200
= 4,800 calls/hr. Dangerously close to the limit.

**Mitigation:** The tag-object SHA cache (spec to be written) eliminates this.
In the interim, during REST failover, skip enrichment (no commit ancestry
checks, no file size comparisons). Detection-only mode: compare SHAs, alert
on changes, skip the expensive enrichment calls.

**Risk 3: Silent degradation.**
If failover happens silently and the user doesn't notice, they might not
realize their poll interval has degraded from 5min to 15min. An attacker who
can cause GraphQL failures could exploit this.

**Mitigation:** The Slack/webhook alert channel should emit a
SYSTEM_DEGRADED alert when failover occurs:

```json
{
  "severity": "MEDIUM",
  "type": "SYSTEM_DEGRADED",
  "message": "GraphQL API unavailable. Operating in REST fallback mode with 15m poll interval.",
  "detected_at": "2026-03-21T06:00:00Z"
}
```

And a SYSTEM_RECOVERED alert when GraphQL comes back:

```json
{
  "severity": "LOW",
  "type": "SYSTEM_RECOVERED",
  "message": "GraphQL API available. Resuming normal 5m poll interval.",
  "detected_at": "2026-03-21T06:15:00Z"
}
```

### Implementation

```go
type Poller struct {
    graphql     *GraphQLClient
    rest        *GitHubClient
    forceREST   bool          // --rest flag
    inFailover  bool          // currently in REST fallback
    normalInterval time.Duration
    failoverInterval time.Duration
}

func (p *Poller) Poll(ctx context.Context, repos []string) (map[string]*FetchResult, error) {
    if p.forceREST {
        return p.pollREST(ctx, repos)
    }

    results, err := p.graphql.FetchTagsBatch(ctx, repos)
    if err != nil {
        if !p.inFailover {
            p.inFailover = true
            // Emit SYSTEM_DEGRADED alert
            fmt.Fprintf(os.Stderr, "⚠ GraphQL unavailable (%v). Falling back to REST.\n", err)
        }
        return p.pollREST(ctx, repos)
    }

    if p.inFailover {
        p.inFailover = false
        // Emit SYSTEM_RECOVERED alert
        fmt.Fprintf(os.Stderr, "✓ GraphQL recovered. Resuming normal operation.\n")
    }
    return results, nil
}

func (p *Poller) CurrentInterval() time.Duration {
    if p.inFailover {
        return p.failoverInterval
    }
    return p.normalInterval
}
```

## Addendum: Production Rate Limit Monitoring

Every GraphQL response includes the `rateLimit` object. Use it.

### Adaptive Backoff

After every GraphQL call, read `rateLimit.remaining`. If remaining drops
below a threshold, slow down proactively:

```go
const (
    rateLimitWarning  = 500   // Slow down
    rateLimitCritical = 100   // Emergency: skip enrichment, extend interval
    rateLimitPanic    = 10    // Stop polling, wait for reset
)

func (p *Poller) adaptToRateLimit(remaining int) {
    switch {
    case remaining < rateLimitPanic:
        fmt.Fprintf(os.Stderr, "🛑 Rate limit nearly exhausted (%d remaining). Pausing until reset.\n", remaining)
        // Sleep until rateLimit.resetAt (would need to track this)
    case remaining < rateLimitCritical:
        fmt.Fprintf(os.Stderr, "⚠ Rate limit low (%d remaining). Disabling enrichment, extending interval.\n", remaining)
        p.skipEnrichment = true
        // Double the poll interval temporarily
    case remaining < rateLimitWarning:
        fmt.Fprintf(os.Stderr, "Rate limit advisory: %d points remaining.\n", remaining)
    }
}
```

### Structured Logging for Rate Limits

Every poll cycle should log (to stderr at minimum, to metrics eventually):

```
[poll] repos=200 batches=4 cost=4 remaining=4986 duration=26.2s
```

This gives operators visibility into API budget consumption at a glance.
When we add Prometheus metrics (v0.5), expose:

```
pinpoint_graphql_cost_total            (counter)
pinpoint_graphql_remaining             (gauge)
pinpoint_graphql_request_duration_seconds (histogram)
pinpoint_poll_repos_total              (counter)
pinpoint_failover_active               (gauge, 0 or 1)
```

### Test Case for Failover

**Test 8: GraphQL Failure Triggers REST Fallback**

Mock GraphQL endpoint to return 500. Verify:
- Poller falls back to REST
- SYSTEM_DEGRADED message is emitted
- Poll interval changes to failoverInterval
- Tags are still resolved correctly via REST

**Test 9: GraphQL Recovery**

After Test 8, mock GraphQL endpoint to return 200. Verify:
- Poller switches back to GraphQL
- SYSTEM_RECOVERED message is emitted
- Poll interval returns to normalInterval

**Test 10: Rate Limit Adaptive Backoff**

Mock GraphQL response with rateLimit.remaining = 50. Verify:
- Poller logs a critical warning
- Enrichment is disabled
- No panic, no crash
