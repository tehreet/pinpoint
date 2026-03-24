#!/bin/bash
# Copyright (C) 2026 CoreWeave, Inc.
# SPDX-License-Identifier: GPL-3.0-only
#
# Open PRs to inject pinpoint-action into all repos in an org.
# Usage: bash scripts/deploy-inject-prs.sh <org> [mode] [version]
#   org:     GitHub org name (required)
#   mode:    warn (default) or enforce
#   version: v1 (default) or specific tag

set -euo pipefail

ORG="${1:?Usage: deploy-inject-prs.sh <org> [mode] [version]}"
MODE="${2:-warn}"
VERSION="${3:-v1}"
BRANCH="pinpoint-inject-$(date +%s)"
TITLE="ci: add Pinpoint Gate to workflow steps"

opened=0
skipped=0
failed=0

for repo in $(gh api "/orgs/$ORG/repos" --paginate --jq '.[].full_name'); do
    echo "Processing $repo..."
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

    if git checkout -b "$BRANCH" && \
       git add -A && \
       git commit -m "$TITLE" && \
       git push -u origin "$BRANCH" && \
       gh pr create --title "$TITLE" --body "Injects \`pinpoint-action@$VERSION\` as step 1 in every workflow job to eliminate TOCTOU vulnerability.

Mode: \`$MODE\`

This ensures gate runs inside the same job as the actions it protects, closing the window where tags could be repointed between verification and execution.

See: https://github.com/tehreet/pinpoint"; then
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
