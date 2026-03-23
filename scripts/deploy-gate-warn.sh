#!/bin/bash
# Deploy pinpoint gate --warn to all repos in pinpoint-testing org
set -euo pipefail

export GITHUB_TOKEN=$(gh auth token)
ORG="pinpoint-testing"
PINPOINT_VERSION="v0.5.0"

# The workflow content
WORKFLOW=$(cat <<'WORKFLOW_EOF'
name: Pinpoint Gate (Warn)
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  gate:
    name: Verify action integrity
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4

      - name: Generate app token
        id: app-token
        uses: actions/create-github-app-token@f8d387b68d61c58ab83c6c016672934102569859 # v3
        with:
          app-id: ${{ secrets.PINPOINT_APP_ID }}
          private-key: ${{ secrets.PINPOINT_APP_PRIVATE_KEY }}
          owner: pinpoint-testing
          repositories: pinpoint

      - name: Download pinpoint
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
        run: |
          ASSET_URL=$(curl -sSL \
            -H "Authorization: Bearer $GH_TOKEN" \
            "https://api.github.com/repos/pinpoint-testing/pinpoint/releases/tags/v0.5.0" \
            | jq -r '.assets[] | select(.name=="pinpoint-linux-amd64") | .url')
          curl -sSL \
            -H "Authorization: Bearer $GH_TOKEN" \
            -H "Accept: application/octet-stream" \
            "$ASSET_URL" -o pinpoint
          chmod +x pinpoint

      - name: Pinpoint gate (warn mode)
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          echo "::group::Pinpoint gate output"
          ./pinpoint gate --warn --all-workflows 2>&1 || true
          echo "::endgroup::"
WORKFLOW_EOF
)

ENCODED=$(echo "$WORKFLOW" | base64 -w 0)

# Get all repos
REPOS=$(gh api "/orgs/$ORG/repos?per_page=100&type=all" --jq '.[].name' | sort)
TOTAL=$(echo "$REPOS" | wc -l)
echo "Deploying gate --warn to $TOTAL repos..."
echo ""

SUCCESS=0
SKIPPED=0
FAILED=0

for repo in $REPOS; do
  # Skip the pinpoint repo itself
  if [ "$repo" = "pinpoint" ]; then
    echo "[SKIP] $repo (pinpoint tool repo)"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  # Check if the file already exists
  EXISTING_SHA=$(gh api "/repos/$ORG/$repo/contents/.github/workflows/pinpoint-gate.yml" --jq '.sha' 2>/dev/null || echo "")

  if [ -n "$EXISTING_SHA" ]; then
    # Update existing file
    RESULT=$(gh api -X PUT "/repos/$ORG/$repo/contents/.github/workflows/pinpoint-gate.yml" \
      -f message="ci: deploy pinpoint gate --warn mode" \
      -f content="$ENCODED" \
      -f sha="$EXISTING_SHA" \
      -f branch="main" \
      --jq '.commit.sha' 2>&1) || true
  else
    # Create new file
    RESULT=$(gh api -X PUT "/repos/$ORG/$repo/contents/.github/workflows/pinpoint-gate.yml" \
      -f message="ci: deploy pinpoint gate --warn mode" \
      -f content="$ENCODED" \
      -f branch="main" \
      --jq '.commit.sha' 2>&1) || true
  fi

  if echo "$RESULT" | grep -qE '^[0-9a-f]{40}$'; then
    echo "[OK]   $repo → ${RESULT:0:12}"
    SUCCESS=$((SUCCESS + 1))
  else
    echo "[FAIL] $repo: $RESULT"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "Done: $SUCCESS deployed, $SKIPPED skipped, $FAILED failed (of $TOTAL repos)"
