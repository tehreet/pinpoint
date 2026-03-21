// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

// RefreshWorkflowTemplate is the GitHub Actions workflow for automated manifest refresh.
const RefreshWorkflowTemplate = `# .github/workflows/pinpoint-refresh.yml
name: Pinpoint Manifest Refresh
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday at 6am UTC
  workflow_dispatch:       # Manual trigger

permissions:
  contents: write
  pull-requests: write

jobs:
  refresh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4

      - name: Install pinpoint
        run: |
          curl -sSL "https://github.com/tehreet/pinpoint/releases/download/v0.3.0/pinpoint-linux-amd64" \
            -o /usr/local/bin/pinpoint
          chmod +x /usr/local/bin/pinpoint

      - name: Refresh manifest
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          pinpoint manifest refresh \
            --manifest .pinpoint-manifest.json \
            --workflows .github/workflows/ \
            --discover

      - name: Create PR if changed
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          if git diff --quiet .pinpoint-manifest.json; then
            echo "No changes detected."
            exit 0
          fi
          BRANCH="pinpoint/manifest-refresh-$(date +%Y%m%d)"
          git checkout -b "$BRANCH"
          git add .pinpoint-manifest.json
          git commit -m "chore: refresh pinpoint manifest

          Updated by pinpoint manifest refresh.
          Review tag changes before merging."
          git push origin "$BRANCH"
          gh pr create \
            --title "chore: refresh pinpoint manifest" \
            --body "Automated manifest refresh by pinpoint. Review the tag SHA changes below before merging." \
            --base main
`

// GateWorkflowTemplate is the reusable workflow for org-wide gate enforcement.
const GateWorkflowTemplate = `# .github/workflows/pinpoint-gate.yml
name: Security Gate
on:
  workflow_call:
    inputs:
      manifest:
        type: string
        default: '.pinpoint-manifest.json'
      fail-on-missing:
        type: boolean
        default: false

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Pinpoint Gate
        uses: tehreet/pinpoint@SHA_HERE
        with:
          manifest: ${{ inputs.manifest }}
          fail-on-missing: ${{ inputs.fail-on-missing }}
`
