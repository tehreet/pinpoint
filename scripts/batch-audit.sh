#!/bin/bash
# Batch audit runner — runs pinpoint audit against multiple orgs in parallel
set -uo pipefail

PINPOINT="${PINPOINT:-/tmp/pp}"
OUTPUT_DIR="${OUTPUT_DIR:-/home/joshf/pinpoint/audits}"
PARALLEL="${PARALLEL:-5}"
export GITHUB_TOKEN=$(gh auth token)

mkdir -p "$OUTPUT_DIR"

if [ $# -eq 0 ]; then
  echo "Usage: $0 org1 org2 org3 ..."
  echo "  Or pipe orgs: echo 'org1 org2' | xargs $0"
  exit 1
fi

ORGS=("$@")
TOTAL=${#ORGS[@]}
DONE=0
FAIL=0
SUCCESS=0

echo "============================================"
echo "  PINPOINT BATCH AUDIT"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Orgs: $TOTAL (parallelism: $PARALLEL)"
echo "============================================"
echo ""

run_audit() {
  local org=$1
  local outfile="$OUTPUT_DIR/${org}.json"
  local logfile="$OUTPUT_DIR/${org}.log"

  echo "[START] $org"
  if $PINPOINT audit --org "$org" --output json > "$outfile" 2>"$logfile"; then
    local repos=$(python3 -c "import json; d=json.load(open('$outfile')); print(d.get('total_repos', d.get('repos_scanned', '?')))" 2>/dev/null || echo "?")
    local actions=$(python3 -c "import json; d=json.load(open('$outfile')); print(d.get('total_action_refs', d.get('total_actions', '?')))" 2>/dev/null || echo "?")
    echo "[DONE]  $org — $repos repos, $actions action refs"
    return 0
  else
    echo "[FAIL]  $org — see $logfile"
    return 1
  fi
}

export -f run_audit
export PINPOINT OUTPUT_DIR

# Run in parallel using xargs
printf '%s\n' "${ORGS[@]}" | xargs -P "$PARALLEL" -I {} bash -c 'run_audit "$@"' _ {}

echo ""
echo "============================================"
echo "  AUDIT COMPLETE"
echo "  Results in: $OUTPUT_DIR/"
echo "============================================"

# Summary
echo ""
echo "=== SUMMARY ==="
for org in "${ORGS[@]}"; do
  if [ -f "$OUTPUT_DIR/${org}.json" ] && [ -s "$OUTPUT_DIR/${org}.json" ]; then
    echo -n "  $org: "
    python3 -c "
import json, sys
try:
    d = json.load(open('$OUTPUT_DIR/${org}.json'))
    repos = d.get('total_repos', d.get('repos_scanned', '?'))
    refs = d.get('total_action_refs', d.get('total_actions', '?'))
    print(f'{repos} repos, {refs} refs')
except:
    print('parse error')
" 2>/dev/null || echo "error"
  else
    echo "  $org: FAILED"
  fi
done
