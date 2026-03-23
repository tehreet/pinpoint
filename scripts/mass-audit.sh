#!/bin/bash
# Scan security vendors + major orgs in parallel, dump results
export PATH=$PATH:/usr/local/go/bin
export GITHUB_TOKEN=$(gh auth token)
cd /home/joshf/pinpoint

OUTDIR=/tmp/pinpoint-audits
mkdir -p $OUTDIR

# Security vendors who wrote about the Trivy attack
ORGS=(
  aquasecurity
  step-security
  crowdstrike
  snyk
  SocketDev
  wiz-sec
  # Other security companies
  paloaltonetworks
  endorlabs
  chainguard-dev
  sigstore
  slsa-framework
  # Big cloud/infra orgs
  hashicorp
  vercel
  supabase
  grafana
  datadog
  elastic
  mongodb
  docker
  github
  actions
  googleapis
  azure
  aws
  # CNCF / popular OSS
  kubernetes
  helm
  prometheus
  argoproj
  fluxcd
  crossplane
  istio
  linkerd
  # Dev tools
  nodejs
  denoland
  oven-sh
  astral-sh
  tailwindlabs
  vitejs
  vuejs
  facebook
  vercel
  # The compromised orgs
  tj-actions
  reviewdog
)

echo "Starting ${#ORGS[@]} org audits at $(date)"

for org in "${ORGS[@]}"; do
  (
    echo "[START] $org"
    timeout 120 ./pinpoint audit --org "$org" --output json --skip-upstream 2>/dev/null > "$OUTDIR/$org.json"
    if [ -s "$OUTDIR/$org.json" ]; then
      echo "[DONE] $org"
    else
      echo "[FAIL] $org (empty or timeout)"
      rm -f "$OUTDIR/$org.json"
    fi
  ) &
done

wait
echo "All done at $(date)"
echo "Results in $OUTDIR"
ls -la $OUTDIR/*.json 2>/dev/null | wc -l
echo " orgs completed"
