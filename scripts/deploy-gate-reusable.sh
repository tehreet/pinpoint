#!/bin/bash
# Deploy thin pinpoint gate caller to all repos (calls reusable workflow)
set -euo pipefail

export GITHUB_TOKEN=$(gh auth token)
ORG="pinpoint-testing"

CALLER=$(cat <<'CALLER_EOF'
name: Pinpoint Gate
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  gate:
    uses: pinpoint-testing/shared-workflows/.github/workflows/pinpoint-gate.yml@main
    with:
      warn: true
    secrets:
      PINPOINT_APP_ID: ${{ secrets.PINPOINT_APP_ID }}
      PINPOINT_APP_PRIVATE_KEY: ${{ secrets.PINPOINT_APP_PRIVATE_KEY }}
CALLER_EOF
)

ENCODED=$(echo "$CALLER" | base64 -w 0)

REPOS=$(gh api "/orgs/$ORG/repos?per_page=100&type=all" --jq '.[].name' | sort)
TOTAL=$(echo "$REPOS" | wc -l)
echo "Deploying reusable gate caller to $TOTAL repos..."
echo ""

SUCCESS=0; SKIPPED=0; FAILED=0

for repo in $REPOS; do
  if [ "$repo" = "pinpoint" ] || [ "$repo" = "shared-workflows" ]; then
    echo "[SKIP] $repo"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  EXISTING_SHA=$(gh api "/repos/$ORG/$repo/contents/.github/workflows/pinpoint-gate.yml" --jq '.sha' 2>/dev/null || echo "")

  if [ -n "$EXISTING_SHA" ]; then
    RESULT=$(gh api -X PUT "/repos/$ORG/$repo/contents/.github/workflows/pinpoint-gate.yml" \
      -f message="ci: switch to reusable pinpoint gate workflow" \
      -f content="$ENCODED" \
      -f sha="$EXISTING_SHA" \
      -f branch="main" \
      --jq '.commit.sha' 2>&1) || true
  else
    RESULT=$(gh api -X PUT "/repos/$ORG/$repo/contents/.github/workflows/pinpoint-gate.yml" \
      -f message="ci: add pinpoint gate via reusable workflow" \
      -f content="$ENCODED" \
      -f branch="main" \
      --jq '.commit.sha' 2>&1) || true
  fi

  if echo "$RESULT" | grep -qE '^[0-9a-f]{40}$'; then
    echo "[OK]   $repo"
    SUCCESS=$((SUCCESS + 1))
  else
    echo "[FAIL] $repo: $RESULT"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "Done: $SUCCESS deployed, $SKIPPED skipped, $FAILED failed"
