#!/usr/bin/env bash
# Creates a realistic test org with 30 repos of varying complexity.
# Run once to set up, then use pinpoint to scan/audit/lock/verify against it.
set -euo pipefail

export GITHUB_TOKEN=${GITHUB_TOKEN:-$(gh auth token)}
ORG="pinpoint-testing"
API="https://api.github.com"

gh_api() {
  local method=$1 path=$2
  shift 2
  curl -sSL -X "$method" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    "$API$path" "$@"
}

create_repo() {
  local name=$1 desc=$2
  echo "  Creating $name..."
  # Delete if exists
  gh_api DELETE "/repos/$ORG/$name" 2>/dev/null || true
  sleep 1
  gh_api POST "/orgs/$ORG/repos" -d "{
    \"name\": \"$name\",
    \"description\": \"$desc\",
    \"auto_init\": true,
    \"visibility\": \"public\"
  }" > /dev/null
  sleep 2
}

add_workflow() {
  local repo=$1 filename=$2 content=$3
  local encoded=$(echo "$content" | base64 -w0)
  gh_api PUT "/repos/$ORG/$repo/contents/.github/workflows/$filename" -d "{
    \"message\": \"Add $filename\",
    \"content\": \"$encoded\"
  }" > /dev/null 2>&1
}

echo "╔══════════════════════════════════════════════╗"
echo "║  PINPOINT TEST ORG SETUP                     ║"
echo "║  Org: $ORG                                   ║"
echo "║  Creating 30 repos with realistic workflows  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ============================================================
# CATEGORY 1: Simple CI (tag-pinned, typical developer setup)
# ============================================================
echo "[1/6] Simple CI repos (tag-pinned, common patterns)..."

create_repo "go-api" "Go REST API service"
add_workflow "go-api" "ci.yml" 'name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"
      - run: go test ./...
      - run: go vet ./...
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - uses: golangci/golangci-lint-action@v6
'

create_repo "node-webapp" "Next.js web application"
add_workflow "node-webapp" "ci.yml" 'name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm test
      - run: npm run build
'

create_repo "python-ml" "Python ML pipeline"
add_workflow "python-ml" "ci.yml" 'name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: pip-${{ hashFiles("requirements.txt") }}
      - run: pip install -r requirements.txt
      - run: pytest
'

create_repo "rust-cli" "Rust CLI tool"
add_workflow "rust-cli" "ci.yml" 'name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test
      - run: cargo clippy -- -D warnings
'

create_repo "java-service" "Java Spring Boot service"
add_workflow "java-service" "ci.yml" 'name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 21
      - uses: actions/cache@v4
        with:
          path: ~/.gradle/caches
          key: gradle-${{ hashFiles("**/*.gradle*") }}
      - run: ./gradlew build
'

# ============================================================
# CATEGORY 2: Complex CI/CD (multi-job, deploy, Docker)
# ============================================================
echo ""
echo "[2/6] Complex CI/CD repos (Docker, multi-job, deploy)..."

create_repo "platform-api" "Platform API with Docker + deploy"
add_workflow "platform-api" "ci.yml" 'name: CI/CD
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test ./...
  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: ${{ github.ref == '"'"'refs/heads/main'"'"' }}
          tags: ghcr.io/${{ github.repository }}:latest
  deploy:
    needs: build
    if: github.ref == '"'"'refs/heads/main'"'"'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::role/deploy
          aws-region: us-east-1
      - run: echo "Deploying..."
'

create_repo "infra-terraform" "Infrastructure as Code"
add_workflow "infra-terraform" "plan.yml" 'name: Terraform Plan
on: pull_request
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::role/terraform
          aws-region: us-east-1
      - run: terraform init
      - run: terraform plan
'
add_workflow "infra-terraform" "apply.yml" 'name: Terraform Apply
on:
  push:
    branches: [main]
jobs:
  apply:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::role/terraform
          aws-region: us-east-1
      - run: terraform init
      - run: terraform apply -auto-approve
      - uses: slackapi/slack-github-action@v2
        with:
          payload: '"'"'{"text": "Terraform applied"}'"'"'
'

create_repo "monorepo-services" "Multi-service monorepo"
add_workflow "monorepo-services" "ci.yml" 'name: CI
on: [push, pull_request]
jobs:
  detect-changes:
    runs-on: ubuntu-latest
    outputs:
      api: ${{ steps.filter.outputs.api }}
      web: ${{ steps.filter.outputs.web }}
    steps:
      - uses: actions/checkout@v4
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            api: services/api/**
            web: services/web/**
  api:
    needs: detect-changes
    if: needs.detect-changes.outputs.api == '"'"'true'"'"'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: cd services/api && go test ./...
  web:
    needs: detect-changes
    if: needs.detect-changes.outputs.web == '"'"'true'"'"'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: cd services/web && npm ci && npm test
'

create_repo "multi-arch-build" "Multi-architecture Docker build"
add_workflow "multi-arch-build" "build.yml" 'name: Multi-arch Build
on:
  push:
    tags: ["v*"]
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        platform: [linux/amd64, linux/arm64]
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          platforms: ${{ matrix.platform }}
          push: true
'

# ============================================================
# CATEGORY 3: Security-conscious (SHA-pinned, hardened)
# ============================================================
echo ""
echo "[3/6] Security-conscious repos (SHA-pinned, hardened)..."

create_repo "secure-api" "SHA-pinned, security-hardened API"
add_workflow "secure-api" "ci.yml" 'name: Secure CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5
        with:
          go-version: "1.24"
      - run: go test ./...
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: aquasecurity/trivy-action@915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2 # v0.28.0
        with:
          scan-type: fs
'

create_repo "crypto-wallet" "Cryptocurrency wallet (high-value target)"
add_workflow "crypto-wallet" "ci.yml" 'name: CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm audit --audit-level=high
      - run: npm test
'

# ============================================================
# CATEGORY 4: Bad practices (branch-pinned, dangerous patterns)
# ============================================================
echo ""
echo "[4/6] Bad practice repos (branch-pinned, dangerous patterns)..."

create_repo "yolo-deploy" "Branch-pinned, no permissions, self-hosted"
add_workflow "yolo-deploy" "deploy.yml" 'name: YOLO Deploy
on: push
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@main
      - uses: ad-m/github-push-action@master
      - uses: EndBug/add-and-commit@main
      - run: ./deploy.sh
'

create_repo "intern-project" "Typical intern project with outdated actions"
add_workflow "intern-project" "ci.yml" 'name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: 16
      - uses: actions/cache@v3
      - run: npm test
'

create_repo "franken-pipeline" "Cobbled together from Stack Overflow"
add_workflow "franken-pipeline" "ci.yml" 'name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - uses: actions/setup-python@v5
      - uses: actions/setup-go@v5
      - uses: actions/setup-java@v4
      - uses: actions/cache@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v5
      - uses: softprops/action-gh-release@v2
        if: startsWith(github.ref, '"'"'refs/tags/'"'"')
      - uses: peter-evans/create-pull-request@v6
      - uses: EndBug/add-and-commit@v9
      - uses: JamesIves/github-pages-deploy-action@v4
      - uses: peaceiris/actions-gh-pages@v4
'

# ============================================================
# CATEGORY 5: Release & publishing workflows
# ============================================================
echo ""
echo "[5/6] Release & publishing repos..."

create_repo "oss-library" "Open source Go library with releases"
add_workflow "oss-library" "release.yml" 'name: Release
on:
  push:
    tags: ["v*"]
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
      - run: go build ./...
      - uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
'
add_workflow "oss-library" "ci.yml" 'name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test ./...
      - uses: golangci/golangci-lint-action@v6
'

create_repo "npm-package" "Published npm package"
add_workflow "npm-package" "publish.yml" 'name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://registry.npmjs.org
      - run: npm ci
      - run: npm publish --provenance --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
'

create_repo "helm-charts" "Helm chart repository"
add_workflow "helm-charts" "release.yml" 'name: Release Charts
on:
  push:
    branches: [main]
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: azure/setup-helm@v4
      - uses: actions/configure-pages@v4
      - uses: actions/upload-pages-artifact@v4
        with:
          path: charts/
      - uses: actions/deploy-pages@v4
'

create_repo "container-images" "Container image builds"
add_workflow "container-images" "build.yml" 'name: Build Images
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        image: [base, runtime, dev]
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          context: images/${{ matrix.image }}
          push: true
          tags: ghcr.io/${{ github.repository }}/${{ matrix.image }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
'

# ============================================================
# CATEGORY 6: GCP/cloud-specific, composite actions, misc
# ============================================================
echo ""
echo "[6/6] Cloud-specific & miscellaneous repos..."

create_repo "gcp-functions" "Google Cloud Functions"
add_workflow "gcp-functions" "deploy.yml" 'name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/pool/providers/provider
          service_account: deploy@project.iam.gserviceaccount.com
      - uses: google-github-actions/setup-gcloud@v2
      - run: gcloud functions deploy my-function
'

create_repo "docs-site" "Documentation site with GitHub Pages"
add_workflow "docs-site" "deploy.yml" 'name: Deploy Docs
on:
  push:
    branches: [main]
permissions:
  contents: read
  pages: write
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci && npm run build
      - uses: actions/upload-pages-artifact@v4
        with:
          path: build/
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
    steps:
      - uses: actions/deploy-pages@v4
'

create_repo "cron-jobs" "Scheduled automation"
add_workflow "cron-jobs" "daily.yml" 'name: Daily Tasks
on:
  schedule:
    - cron: "0 8 * * *"
  workflow_dispatch:
jobs:
  cleanup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("Running daily cleanup")
      - uses: dessant/lock-threads@v5
        with:
          issue-inactive-days: 30
'

create_repo "pr-automation" "PR automation and checks"
add_workflow "pr-automation" "pr.yml" 'name: PR Checks
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/labeler@v5
      - uses: marocchino/sticky-pull-request-comment@v2
        with:
          message: "Thanks for your PR!"
      - uses: reviewdog/action-golangci-lint@v2
'

create_repo "notification-hub" "Notification and alerting"
add_workflow "notification-hub" "notify.yml" 'name: Notify
on:
  release:
    types: [published]
  workflow_dispatch:
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: slackapi/slack-github-action@v2
        with:
          payload: '"'"'{"text": "New release!"}'"'"'
'

create_repo "security-scanning" "Security scanning pipeline"
add_workflow "security-scanning" "scan.yml" 'name: Security Scan
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 0 * * 0"
jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aquasecurity/trivy-action@0.35.0
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
  codeql:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3
'

create_repo "shared-workflows" "Reusable workflow templates"
add_workflow "shared-workflows" "reusable-go.yml" 'name: Reusable Go CI
on:
  workflow_call:
    inputs:
      go-version:
        type: string
        default: "1.24"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ inputs.go-version }}
      - run: go test ./...
      - uses: golangci/golangci-lint-action@v6
'

# Two repos that call the shared workflow
create_repo "svc-auth" "Auth service using shared workflow"
add_workflow "svc-auth" "ci.yml" "name: CI
on: [push, pull_request]
jobs:
  test:
    uses: $ORG/shared-workflows/.github/workflows/reusable-go.yml@main
    with:
      go-version: '1.24'
"

create_repo "svc-billing" "Billing service using shared workflow"
add_workflow "svc-billing" "ci.yml" "name: CI
on: [push, pull_request]
jobs:
  test:
    uses: $ORG/shared-workflows/.github/workflows/reusable-go.yml@main
    with:
      go-version: '1.24'
"

# One more — a repo with a composite action that has transitive deps
create_repo "custom-action" "Custom composite action with deps"
add_workflow "custom-action" "test.yml" 'name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-pages-artifact@v4
        with:
          path: dist/
      - uses: actions/deploy-pages@v4
'

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  SETUP COMPLETE                               ║"
echo "║  Created repos in $ORG                        ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Now run:"
echo "  pinpoint audit --org $ORG"
echo "  pinpoint audit --org $ORG --output report"
echo "  pinpoint audit --org $ORG --output config > test-org.yml"
echo "  pinpoint scan --config test-org.yml"
