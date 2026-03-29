#!/bin/bash
# Copyright (C) 2026 CoreWeave, Inc.
# SPDX-License-Identifier: GPL-3.0-only
#
# Open PRs to inject pinpoint-action into all repos in an org.
# Usage: bash scripts/deploy-inject-prs.sh <org> [mode] [version]

set -euo pipefail

ORG="${1:?Usage: deploy-inject-prs.sh <org> [mode] [version]}"
MODE="${2:-warn}"
VERSION="${3:-v1}"
TITLE="ci: add Pinpoint Gate to workflow steps"

opened=0
skipped=0
failed=0

for repo in $(gh api "/orgs/$ORG/repos" --paginate --jq '.[].full_name'); do
    reponame=$(basename "$repo")
    echo "Processing $repo..."

    # Skip pinpoint itself and shared-workflows
    if [ "$reponame" = "pinpoint" ] || [ "$reponame" = "shared-workflows" ]; then
        echo "  skip (infra repo)"
        ((skipped++)) || true
        continue
    fi

    tmpdir=$(mktemp -d)

    if ! gh repo clone "$repo" "$tmpdir" -- --depth 1 2>/dev/null; then
        echo "  skip (clone failed)"
        rm -rf "$tmpdir"
        ((skipped++)) || true
        continue
    fi

    if [ ! -d "$tmpdir/.github/workflows" ]; then
        echo "  skip (no workflows)"
        rm -rf "$tmpdir"
        ((skipped++)) || true
        continue
    fi

    pinpoint inject --workflows "$tmpdir/.github/workflows/" --mode "$MODE" --version "$VERSION" 2>&1 || true

    cd "$tmpdir"
    if git diff --quiet; then
        echo "  skip (no changes needed)"
        cd - > /dev/null
        rm -rf "$tmpdir"
        ((skipped++)) || true
        continue
    fi

    # Unique branch per repo
    BRANCH="pinpoint/inject-gate-step"

    # Delete remote branch if it exists from a previous run
    git push origin --delete "$BRANCH" 2>/dev/null || true

    git checkout -b "$BRANCH"
    git add -A
    git commit -m "$TITLE"
    git push -u origin "$BRANCH" 2>&1

    if gh pr create \
        --repo "$repo" \
        --title "$TITLE" \
        --head "$BRANCH" \
        --base "main" \
        --body "Injects \`pinpoint-action@$VERSION\` as step 1 in every workflow job to eliminate the TOCTOU vulnerability.

**Mode:** \`$MODE\`

**Why:** Gate as a separate prerequisite job is vulnerable to tag repointing between verification and execution (proven in testing with a 1-second window). Injecting gate as a step within each job means all actions are downloaded at job start, before any steps run. Gate verifies what is already on disk. The TOCTOU window collapses to zero.

See: https://github.com/tehreet/pinpoint" 2>&1; then
        echo "  ✓ PR opened"
        ((opened++)) || true
    else
        echo "  ✗ failed to create PR"
        ((failed++)) || true
    fi

    cd - > /dev/null
    rm -rf "$tmpdir"
done

echo ""
echo "Done: $opened PRs opened, $skipped repos skipped, $failed failures"
