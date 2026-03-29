#!/bin/bash
# Full 300-org audit (verified org names only)
set -uo pipefail

PINPOINT="/tmp/pp"
OUTPUT_DIR="/home/joshf/pinpoint/audits"
export GITHUB_TOKEN=$(gh auth token)

mkdir -p "$OUTPUT_DIR"

# Verified org list — ~270 orgs across 16 categories
ORGS=(
  # Cloud & Infrastructure (24)
  aws azure googlecloudplatform hashicorp pulumi digitalocean cloudflare
  fastly vercel netlify supabase fly-apps nhost upstash coreweave
  hetznercloud scaleway equinix

  # Security (28)
  crowdstrike paloaltonetworks snyk aquasecurity bridgecrewio tenable
  rapid7 sonatype anchore chainguard-dev sigstore trufflesecurity
  returntocorp step-security falcosecurity ossf wiz-sec deepfence
  mondoohq endorlabs phylum-dev stackrox

  # DevOps & CI/CD (22)
  actions docker kubernetes helm argoproj fluxcd tektoncd goreleaser
  github dagger buildkite coder woodpecker-ci harness jenkinsci
  circleci nektos reviewdog gitpod-io

  # CNCF & Foundations (22)
  cncf kubernetes-sigs envoyproxy istio prometheus grafana open-telemetry
  containerd etcd-io nats-io grpc cert-manager dapr knative crossplane
  linkerd thanos-io cortexproject

  # Languages & Runtimes (18)
  golang rust-lang python nodejs dotnet openjdk ruby elixir-lang
  ziglang denoland crystal-lang astral-sh python-poetry oven-sh

  # Databases (18)
  cockroachdb pingcap influxdata clickhouse redis prisma hasura
  apache mongodb questdb timescale neondatabase tursodatabase surrealdb
  duckdb edgedb dragonflydb

  # AI/ML (20)
  openai huggingface langchain-ai ollama pytorch tensorflow meta-llama
  vllm-project run-llama Lightning-AI wandb mlflow ray-project
  keras-team scikit-learn numpy pandas-dev modal-labs replicate
  stability-ai mistralai

  # Web Frameworks (20)
  facebook vuejs sveltejs angular withastro remix-run solidjs nuxt
  tailwindlabs trpc honojs expressjs fastify nestjs django pallets
  laravel rails phoenixframework calcom

  # Enterprise SaaS (20)
  microsoft stripe shopify datadog elastic getsentry posthog
  appwrite medusajs mattermost zulip twilio atlassian slackhq
  pagerduty

  # Crypto & Web3 (14)
  ethereum solana-labs OpenZeppelin Uniswap paradigmxyz smartcontractkit
  aave celestiaorg cosmos near aptos-labs sui-foundation starkware-libs

  # Networking (10)
  traefik caddyserver tailscale firezone cilium projectcalico

  # Observability (8)
  VictoriaMetrics signoz

  # Package Managers (6)
  homebrew nixos conda-forge

  # Gaming & Media (4)
  godotengine obsproject blender audacity

  # Compliance (8)
  open-policy-agent kyverno slsa-framework in-toto

  # Misc High-Profile (4)
  bitwarden matrix-org
)

TOTAL=${#ORGS[@]}
echo "============================================"
echo "  PINPOINT 300-ORG SECURITY AUDIT"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Orgs: $TOTAL"
echo "============================================"
echo ""

SUCCESS=0
FAIL=0
SKIP=0

for i in "${!ORGS[@]}"; do
  org="${ORGS[$i]}"
  idx=$((i + 1))
  outfile="$OUTPUT_DIR/${org}.json"

  # Skip if already audited and file is >1KB (valid result)
  if [ -f "$outfile" ] && [ $(stat -c %s "$outfile" 2>/dev/null || echo 0) -gt 1000 ]; then
    echo "[$idx/$TOTAL] $org: CACHED ($(stat -c %s "$outfile") bytes)"
    SUCCESS=$((SUCCESS + 1))
    SKIP=$((SKIP + 1))
    continue
  fi

  echo -n "[$idx/$TOTAL] $org: "
  if $PINPOINT audit --org "$org" --output json > "$outfile" 2>"$OUTPUT_DIR/${org}.log"; then
    SIZE=$(stat -c %s "$outfile" 2>/dev/null || echo 0)
    echo "OK (${SIZE} bytes)"
    SUCCESS=$((SUCCESS + 1))
  else
    echo "FAIL (see ${org}.log)"
    FAIL=$((FAIL + 1))
  fi

  # Rate limit check every 10 orgs
  if [ $((idx % 10)) -eq 0 ]; then
    REMAINING=$(gh api /rate_limit --jq '.resources.graphql.remaining' 2>/dev/null || echo "?")
    echo "  [rate limit: $REMAINING GraphQL points remaining]"
  fi
done

echo ""
echo "============================================"
echo "  AUDIT COMPLETE"
echo "  $SUCCESS succeeded ($SKIP cached), $FAIL failed"
echo "============================================"
