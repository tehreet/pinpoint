# Spec 020: GitHub App for pinpoint-testing

## Problem

Three things are broken or fragile because we're using a PAT:

1. **Phase 2 lockfile workflows fail** because the binary download from
   `pinpoint-testing/pinpoint` can't authenticate cross-repo. A GitHub App
   installed on the org can mint tokens scoped to any repo in the org.

2. **Integration tests use Josh's PAT** which has overly broad scopes, expires,
   and can't be shared. A GitHub App has no expiration on the installation and
   mints 1-hour tokens on demand.

3. **Future CI/CD** — when the test suite runs in GitHub Actions, it needs a
   token. A GitHub App + `actions/create-github-app-token@v3` is the standard
   pattern. No secrets rotation ever.

## GitHub App Configuration

### App name: `pinpoint-test-bot`

### Permissions (minimum viable):
- **Repository permissions:**
  - Contents: Read & Write (create/delete tags, push commits, read tarballs)
  - Actions: Read-only (check workflow run status)
  - Metadata: Read-only (required, always on)
- **Organization permissions:**
  - Members: Read-only (for audit org policy checks)

### Events subscribed: None (we poll, not webhook-driven for now)

### Installation: Install on `pinpoint-testing` org, grant access to **all repositories**.

### Where the App ID and private key live:
- App ID: stored as `PINPOINT_APP_ID` org-level Actions secret on `pinpoint-testing`
- Private key (.pem): stored as `PINPOINT_APP_PRIVATE_KEY` org-level Actions secret
- Also saved on VPS at `/home/joshf/.config/pinpoint/app.pem` for local test runs

## Token minting

### In GitHub Actions workflows (Phase 2 lockfile + future gate):

```yaml
- name: Generate token
  id: app-token
  uses: actions/create-github-app-token@5d869da34e18e7287c1daad50e0b8ea0f506ce69 # v1.11.0
  with:
    app-id: ${{ secrets.PINPOINT_APP_ID }}
    private-key: ${{ secrets.PINPOINT_APP_PRIVATE_KEY }}
    owner: pinpoint-testing

- name: Download pinpoint
  env:
    GH_TOKEN: ${{ steps.app-token.outputs.token }}
  run: |
    gh release download v0.5.0 \
      --repo pinpoint-testing/pinpoint \
      --pattern 'pinpoint-linux-amd64' \
      --output pinpoint
    chmod +x pinpoint
```

### In integration tests (local / VPS):

The test harness needs to mint tokens from the App private key. Go has the
`golang-jwt/jwt/v5` library for signing JWTs, but that adds a dependency.
Since pinpoint avoids external deps, the harness should shell out to `gh`:

```go
// In tests/harness/auth.go
func MintAppToken(t *testing.T) string {
    t.Helper()

    // Prefer GITHUB_TOKEN if already set (backwards compat with PAT)
    if token := os.Getenv("GITHUB_TOKEN"); token != "" {
        return token
    }

    // Try GitHub App auth
    appID := os.Getenv("PINPOINT_APP_ID")
    keyPath := os.Getenv("PINPOINT_APP_KEY_PATH")
    if appID == "" || keyPath == "" {
        t.Fatal("Set GITHUB_TOKEN or PINPOINT_APP_ID + PINPOINT_APP_KEY_PATH")
    }

    // Use gh CLI to create installation token
    // gh auth login --with-token uses the JWT, then gh api creates installation token
    // Actually simpler: use the go-github approach with crypto/rsa + net/http
    // Since this is test-only code, we can use crypto/rsa from stdlib
    return mintTokenFromKey(t, appID, keyPath)
}
```

Actually, since this is test-only code (behind `//go:build integration`), we CAN
use additional imports without affecting the main binary. The JWT signing only needs
`crypto/rsa`, `crypto/x509`, `encoding/pem`, `encoding/json`, `time`, `net/http` —
all stdlib. No external deps needed.

```go
// mintTokenFromKey creates a JWT, exchanges it for an installation token.
// Uses only stdlib crypto — no external JWT library needed.
func mintTokenFromKey(t *testing.T, appID, keyPath string) string {
    // 1. Read PEM private key
    // 2. Create JWT: iss=appID, iat=now-60s, exp=now+600s
    // 3. POST /app/installations → get installation_id
    // 4. POST /app/installations/{id}/access_tokens → get token
    // Standard GitHub App flow, ~60 lines of stdlib Go
}
```

### On VPS for manual test runs:

```bash
# ~/.zshrc or test runner script
export PINPOINT_APP_ID="123456"
export PINPOINT_APP_KEY_PATH="/home/joshf/.config/pinpoint/app.pem"

# Or keep using PAT for now — harness falls back to GITHUB_TOKEN
export GITHUB_TOKEN="ghp_..."
```

## Fixing Phase 2 lockfile workflows

The 5 deployed repos (go-api, platform-api, monorepo-services, franken-pipeline,
secure-api) currently fail because they try to download the pinpoint binary from
`pinpoint-testing/pinpoint` releases without authentication.

Updated workflow snippet:

```yaml
name: Pinpoint Lock
on:
  push:
    branches: [main]
    paths: ['.github/workflows/**']

permissions:
  contents: write

jobs:
  lock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Generate token
        id: app-token
        uses: actions/create-github-app-token@5d869da34e18e7287c1daad50e0b8ea0f506ce69
        with:
          app-id: ${{ secrets.PINPOINT_APP_ID }}
          private-key: ${{ secrets.PINPOINT_APP_PRIVATE_KEY }}
          owner: pinpoint-testing

      - name: Download pinpoint
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
        run: |
          gh release download v0.5.0 \
            --repo pinpoint-testing/pinpoint \
            --pattern 'pinpoint-linux-amd64' \
            --output pinpoint
          chmod +x pinpoint

      - name: Generate lockfile
        env:
          GITHUB_TOKEN: ${{ steps.app-token.outputs.token }}
        run: ./pinpoint lock

      - name: Commit lockfile
        run: |
          git config user.name "pinpoint-test-bot[bot]"
          git config user.email "pinpoint-test-bot[bot]@users.noreply.github.com"
          git add .github/actions-lock.json
          git diff --staged --quiet || git commit -m "chore: update actions lockfile"
          git push
```

## Setup steps (manual, one-time)

1. Go to https://github.com/organizations/pinpoint-testing/settings/apps/new
2. App name: `pinpoint-test-bot`
3. Homepage URL: `https://github.com/pinpoint-testing/pinpoint`
4. Uncheck "Active" under Webhook (we don't need webhooks)
5. Set permissions as listed above
6. "Where can this GitHub App be installed?" → Only on this account
7. Create App → note the App ID
8. Generate a private key → download .pem file
9. Install the App on `pinpoint-testing` → All repositories
10. Add `PINPOINT_APP_ID` and `PINPOINT_APP_PRIVATE_KEY` as org secrets
11. Copy .pem to VPS: `scp pinpoint-test-bot.pem joshf@5.78.91.92:~/.config/pinpoint/app.pem`
12. Update workflows on the 5 Phase 2 repos
13. Test: trigger a workflow run on go-api, verify binary downloads successfully

## Files to create/modify

- CREATE: `tests/harness/auth.go` — MintAppToken + mintTokenFromKey (stdlib only)
- MODIFY: `tests/harness/harness.go` — use MintAppToken instead of raw os.Getenv
- UPDATE: Phase 2 workflow files on 5 repos (manual via Chrome extension or gh CLI)
