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
