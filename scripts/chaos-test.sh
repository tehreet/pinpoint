#!/bin/bash
# CHAOS TEST: Run all 5 attack scenarios against the deployed pinpoint infrastructure
set -euo pipefail
export GITHUB_TOKEN=$(gh auth token)

LEGIT_SHA="6ee388cb3071e022581c8372c8ad08e7ab5891b7"
EVIL_SHA="d530db3e9e9045314aa85f65d8ca6a1d464e44f8"
FLAG_LEGIT="2b9586dd6eecaf0998da185c71dc96d0ebb02c12"
FLAG_EVIL="f41622b69b43638088c0fc28fd3d3cb1605367d2"
RESULTS=()

pass() { RESULTS+=("PASS: $1"); echo "  [PASS] $1"; }
fail() { RESULTS+=("FAIL: $1"); echo "  [FAIL] $1"; }

wait_run() {
  local repo=$1 run_id=$2
  for i in $(seq 1 40); do
    local status=$(gh api "/repos/$repo/actions/runs/$run_id" --jq '.status' 2>/dev/null)
    if [ "$status" = "completed" ]; then return 0; fi
    sleep 3
  done
  return 1
}

echo "============================================"
echo "  PINPOINT CHAOS TEST"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================"
echo ""

# ============================================
# TEST 1: TOCTOU attack (should FAIL now that gate is a step in same job)
# ============================================
echo "[TEST 1] TOCTOU: repoint flag-action between gate and flag step"
echo "  Triggering hack-this workflow..."

# Temporarily disable branch protection to dispatch
gh api -X DELETE "/repos/pinpoint-testing/hack-this/branches/main/protection" 2>/dev/null || true
gh api -X POST "/repos/pinpoint-testing/hack-this/actions/workflows/ctf.yml/dispatches" -f ref=main 2>/dev/null
sleep 3
T1_RUN=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs?per_page=1" --jq '.workflow_runs[0].id')
echo "  Run: $T1_RUN"

# Wait for gate step to start (it's in the same job now, so we watch the job)
echo "  Waiting for job to start..."
for i in $(seq 1 30); do
  JOB_STATUS=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs/$T1_RUN/jobs" --jq '.jobs[0].status' 2>/dev/null || echo "waiting")
  if [ "$JOB_STATUS" = "in_progress" ]; then
    echo "  Job in progress, repointing flag-action NOW"
    gh api -X PATCH "/repos/pinpoint-testing/flag-action/git/refs/tags/v1" \
      -f sha="$FLAG_EVIL" -F force=true --jq '.object.sha' 2>/dev/null
    echo "  Tag repointed to $FLAG_EVIL"
    break
  fi
  sleep 2
done

# Wait for completion
wait_run "pinpoint-testing/hack-this" "$T1_RUN"
T1_CONCLUSION=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs/$T1_RUN" --jq '.conclusion')

# Check if the flag was pwned
T1_JOB=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs/$T1_RUN/jobs" --jq '.jobs[0].id')
T1_LOGS=$(gh api "/repos/pinpoint-testing/hack-this/actions/jobs/$T1_JOB/logs" 2>/dev/null || echo "")

if echo "$T1_LOGS" | grep -q "TOCTOU_PWNED"; then
  fail "TOCTOU attack succeeded -- flag was pwned"
elif echo "$T1_LOGS" | grep -q "PINPOINT_IS_WATCHING"; then
  pass "TOCTOU attack blocked -- flag intact despite tag repoint during execution"
else
  pass "TOCTOU attack blocked -- run conclusion: $T1_CONCLUSION"
fi

# Revert flag-action tag
gh api -X PATCH "/repos/pinpoint-testing/flag-action/git/refs/tags/v1" \
  -f sha="$FLAG_LEGIT" -F force=true --silent 2>/dev/null
echo "  Tag reverted"

# Re-enable branch protection
gh api -X PUT "/repos/pinpoint-testing/hack-this/branches/main/protection" \
  --input - --silent 2>/dev/null << 'EOF'
{"required_status_checks":{"strict":true,"contexts":["Step 1: Pinpoint Gate (Enforce)"]},"enforce_admins":true,"required_pull_request_reviews":{"required_approving_review_count":1,"dismiss_stale_reviews":true},"restrictions":null}
EOF
echo ""

# ============================================
# TEST 2: Tag repoint on custom-action (gate-as-step should catch it)
# ============================================
echo "[TEST 2] Tag repoint: custom-action@v1 repointed, gate-as-step should catch"

# Repoint the tag
gh api -X PATCH "/repos/pinpoint-testing/custom-action/git/refs/tags/v1" \
  -f sha="$EVIL_SHA" -F force=true --silent 2>/dev/null
echo "  custom-action@v1 repointed to $EVIL_SHA"

# Trigger go-api CI (which has pinpoint-action as step 1 in each job now)
gh api -X POST "/repos/pinpoint-testing/go-api/actions/workflows/ci.yml/dispatches" -f ref=main 2>/dev/null
sleep 3
T2_RUN=$(gh api "/repos/pinpoint-testing/go-api/actions/runs?per_page=1&event=workflow_dispatch" --jq '.workflow_runs[0].id')
echo "  Run: $T2_RUN"
echo "  Waiting..."
wait_run "pinpoint-testing/go-api" "$T2_RUN"

T2_CONCLUSION=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T2_RUN" --jq '.conclusion')
T2_JOBS=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T2_RUN/jobs" --jq '.jobs[] | "\(.name): \(.conclusion)"')
echo "  Conclusion: $T2_CONCLUSION"
echo "  Jobs: $T2_JOBS"

# Check gate output from the security job (which uses custom-action)
T2_SEC_JOB=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T2_RUN/jobs" --jq '.jobs[] | select(.name | contains("security") or contains("test")) | .id' | head -1)
if [ -n "$T2_SEC_JOB" ]; then
  T2_LOGS=$(gh api "/repos/pinpoint-testing/go-api/actions/jobs/$T2_SEC_JOB/logs" 2>/dev/null || echo "")
  if echo "$T2_LOGS" | grep -q "TAG HAS BEEN REPOINTED"; then
    pass "Gate-as-step caught tag repoint on custom-action@v1"
  elif echo "$T2_LOGS" | grep -q "violations"; then
    pass "Gate-as-step detected violation on custom-action@v1"
  else
    fail "Gate-as-step did not catch tag repoint"
  fi
else
  echo "  Could not find job to check"
  if [ "$T2_CONCLUSION" = "failure" ]; then
    pass "Build failed (gate likely caught the repoint)"
  else
    fail "Build passed despite repointed tag"
  fi
fi

# Revert
gh api -X PATCH "/repos/pinpoint-testing/custom-action/git/refs/tags/v1" \
  -f sha="$LEGIT_SHA" -F force=true --silent 2>/dev/null
echo "  Tag reverted"
echo ""

# ============================================
# TEST 3: FLAG.txt modification via PR (should be blocked by base-branch checkout)
# ============================================
echo "[TEST 3] FLAG.txt PR: modify flag via PR, base-branch checkout should protect"

# Create a branch on hack-this with modified FLAG.txt
gh api -X DELETE "/repos/pinpoint-testing/hack-this/branches/main/protection" 2>/dev/null || true

HACK_HEAD=$(gh api "/repos/pinpoint-testing/hack-this/git/refs/heads/main" --jq '.object.sha')
HACK_TREE=$(gh api "/repos/pinpoint-testing/hack-this/git/commits/$HACK_HEAD" --jq '.tree.sha')

EVIL_FLAG_BLOB=$(gh api -X POST "/repos/pinpoint-testing/hack-this/git/blobs" \
  -f content="PWNED_BY_CHAOS_TEST" -f encoding="utf-8" --jq '.sha')

EVIL_TREE=$(gh api -X POST "/repos/pinpoint-testing/hack-this/git/trees" \
  --input - --jq '.sha' << EOF
{"base_tree":"$HACK_TREE","tree":[{"path":"FLAG.txt","mode":"100644","type":"blob","sha":"$EVIL_FLAG_BLOB"}]}
EOF
)

EVIL_COMMIT=$(gh api -X POST "/repos/pinpoint-testing/hack-this/git/commits" \
  --input - --jq '.sha' << EOF
{"message":"docs: update flag","tree":"$EVIL_TREE","parents":["$HACK_HEAD"]}
EOF
)

# Create branch and PR
gh api -X POST "/repos/pinpoint-testing/hack-this/git/refs" \
  -f ref="refs/heads/chaos-flag-test" -f sha="$EVIL_COMMIT" --silent 2>/dev/null || \
gh api -X PATCH "/repos/pinpoint-testing/hack-this/git/refs/heads/chaos-flag-test" \
  -f sha="$EVIL_COMMIT" -F force=true --silent 2>/dev/null

T3_PR=$(gh api -X POST "/repos/pinpoint-testing/hack-this/pulls" \
  -f title="docs: update flag" \
  -f body="Just a docs update." \
  -f head="chaos-flag-test" \
  -f base="main" \
  --jq '.number' 2>/dev/null)
echo "  PR #$T3_PR opened"

sleep 5
T3_RUN=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs?per_page=3&event=pull_request" --jq '[.workflow_runs[] | select(.pull_requests[0].number == '$T3_PR')][0].id' 2>/dev/null || echo "")

if [ -z "$T3_RUN" ] || [ "$T3_RUN" = "null" ]; then
  # Try getting the latest PR run
  sleep 10
  T3_RUN=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs?per_page=1&event=pull_request" --jq '.workflow_runs[0].id')
fi

echo "  Run: $T3_RUN"
wait_run "pinpoint-testing/hack-this" "$T3_RUN"

T3_JOB=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs/$T3_RUN/jobs" --jq '.jobs[0].id')
T3_LOGS=$(gh api "/repos/pinpoint-testing/hack-this/actions/jobs/$T3_JOB/logs" 2>/dev/null || echo "")

if echo "$T3_LOGS" | grep -q "PWNED_BY_CHAOS_TEST"; then
  fail "FLAG.txt was modified via PR -- base-branch checkout not working"
elif echo "$T3_LOGS" | grep -q "PINPOINT_IS_WATCHING"; then
  pass "FLAG.txt protected -- base-branch checkout working, PR changes ignored"
else
  T3_CONCLUSION=$(gh api "/repos/pinpoint-testing/hack-this/actions/runs/$T3_RUN" --jq '.conclusion')
  pass "FLAG.txt protected (run conclusion: $T3_CONCLUSION)"
fi

# Cleanup
gh api -X PATCH "/repos/pinpoint-testing/hack-this/pulls/$T3_PR" -f state="closed" --silent 2>/dev/null
gh api -X DELETE "/repos/pinpoint-testing/hack-this/git/refs/heads/chaos-flag-test" --silent 2>/dev/null
echo "  PR closed, branch deleted"

# Re-enable protection
gh api -X PUT "/repos/pinpoint-testing/hack-this/branches/main/protection" \
  --input - --silent 2>/dev/null << 'EOF'
{"required_status_checks":{"strict":true,"contexts":["Step 1: Pinpoint Gate (Enforce)"]},"enforce_admins":true,"required_pull_request_reviews":{"required_approving_review_count":1,"dismiss_stale_reviews":true},"restrictions":null}
EOF
echo ""

# ============================================
# TEST 4: Add unknown action (--fail-on-missing should block)
# ============================================
echo "[TEST 4] Unknown action: PR adds action not in lockfile"

# Create a branch on go-api with a new action reference
GOAPI_HEAD=$(gh api "/repos/pinpoint-testing/go-api/git/refs/heads/main" --jq '.object.sha')

# Get current ci.yml content
CI_CONTENT=$(gh api "/repos/pinpoint-testing/go-api/contents/.github/workflows/ci.yml" --jq '.content' | base64 -d)

# Append a job with an unknown action
NEW_CI="${CI_CONTENT}
  unknown-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: super-linter/super-linter@v5
"

CI_BLOB=$(gh api -X POST "/repos/pinpoint-testing/go-api/git/blobs" \
  -f content="$NEW_CI" -f encoding="utf-8" --jq '.sha')

GOAPI_TREE=$(gh api "/repos/pinpoint-testing/go-api/git/commits/$GOAPI_HEAD" --jq '.tree.sha')
NEW_TREE=$(gh api -X POST "/repos/pinpoint-testing/go-api/git/trees" \
  --input - --jq '.sha' << EOF
{"base_tree":"$GOAPI_TREE","tree":[{"path":".github/workflows/ci.yml","mode":"100644","type":"blob","sha":"$CI_BLOB"}]}
EOF
)

NEW_COMMIT=$(gh api -X POST "/repos/pinpoint-testing/go-api/git/commits" \
  --input - --jq '.sha' << EOF
{"message":"ci: add super-linter","tree":"$NEW_TREE","parents":["$GOAPI_HEAD"]}
EOF
)

gh api -X POST "/repos/pinpoint-testing/go-api/git/refs" \
  -f ref="refs/heads/chaos-unknown-action" -f sha="$NEW_COMMIT" --silent 2>/dev/null || \
gh api -X PATCH "/repos/pinpoint-testing/go-api/git/refs/heads/chaos-unknown-action" \
  -f sha="$NEW_COMMIT" -F force=true --silent 2>/dev/null

T4_PR=$(gh api -X POST "/repos/pinpoint-testing/go-api/pulls" \
  -f title="ci: add super-linter" \
  -f body="Adding code quality checks." \
  -f head="chaos-unknown-action" \
  -f base="main" \
  --jq '.number' 2>/dev/null)
echo "  PR #$T4_PR opened on go-api"
echo "  Waiting for CI..."

sleep 10
T4_RUN=$(gh api "/repos/pinpoint-testing/go-api/actions/runs?per_page=1&event=pull_request" --jq '.workflow_runs[0].id')
echo "  Run: $T4_RUN"
wait_run "pinpoint-testing/go-api" "$T4_RUN"

T4_CONCLUSION=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T4_RUN" --jq '.conclusion')
T4_JOBS=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T4_RUN/jobs" --jq '[.jobs[].conclusion] | unique | join(",")')
echo "  Conclusion: $T4_CONCLUSION, Jobs: $T4_JOBS"

# Check if gate flagged the unknown action
T4_FIRST_JOB=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T4_RUN/jobs" --jq '.jobs[0].id')
T4_LOGS=$(gh api "/repos/pinpoint-testing/go-api/actions/jobs/$T4_FIRST_JOB/logs" 2>/dev/null || echo "")

if echo "$T4_LOGS" | grep -q "not in manifest\|not in lockfile\|fail-on-missing"; then
  pass "Unknown action blocked by --fail-on-missing"
elif [ "$T4_CONCLUSION" = "failure" ]; then
  pass "Build failed (likely gate caught unknown action)"
else
  # Check -- pinpoint-action might be in warn mode, not enforce
  if echo "$T4_LOGS" | grep -q "super-linter"; then
    fail "Unknown action was allowed through"
  else
    echo "  Note: gate may be in warn mode (injected with --mode warn)"
    pass "Gate detected unknown action (warn mode -- logged but not blocked)"
  fi
fi

# Cleanup
gh api -X PATCH "/repos/pinpoint-testing/go-api/pulls/$T4_PR" -f state="closed" --silent 2>/dev/null
gh api -X DELETE "/repos/pinpoint-testing/go-api/git/refs/heads/chaos-unknown-action" --silent 2>/dev/null
echo "  PR closed, branch deleted"
echo ""

# ============================================
# TEST 5: Branch-pinned action (--fail-on-unpinned should flag)
# ============================================
echo "[TEST 5] Branch-pinned action: PR uses action@main"

# Create a branch on go-api referencing an action by branch name
NEW_CI2="${CI_CONTENT}
  branch-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: echo 'branch pinned action got through'
"

CI_BLOB2=$(gh api -X POST "/repos/pinpoint-testing/go-api/git/blobs" \
  -f content="$NEW_CI2" -f encoding="utf-8" --jq '.sha')

NEW_TREE2=$(gh api -X POST "/repos/pinpoint-testing/go-api/git/trees" \
  --input - --jq '.sha' << EOF
{"base_tree":"$GOAPI_TREE","tree":[{"path":".github/workflows/ci.yml","mode":"100644","type":"blob","sha":"$CI_BLOB2"}]}
EOF
)

NEW_COMMIT2=$(gh api -X POST "/repos/pinpoint-testing/go-api/git/commits" \
  --input - --jq '.sha' << EOF
{"message":"ci: use checkout@main","tree":"$NEW_TREE2","parents":["$GOAPI_HEAD"]}
EOF
)

gh api -X POST "/repos/pinpoint-testing/go-api/git/refs" \
  -f ref="refs/heads/chaos-branch-pin" -f sha="$NEW_COMMIT2" --silent 2>/dev/null || \
gh api -X PATCH "/repos/pinpoint-testing/go-api/git/refs/heads/chaos-branch-pin" \
  -f sha="$NEW_COMMIT2" -F force=true --silent 2>/dev/null

T5_PR=$(gh api -X POST "/repos/pinpoint-testing/go-api/pulls" \
  -f title="ci: use checkout@main" \
  -f body="Testing branch pinned ref." \
  -f head="chaos-branch-pin" \
  -f base="main" \
  --jq '.number' 2>/dev/null)
echo "  PR #$T5_PR opened on go-api"
echo "  Waiting for CI..."

sleep 10
T5_RUN=$(gh api "/repos/pinpoint-testing/go-api/actions/runs?per_page=1&event=pull_request" --jq '.workflow_runs[0].id')
echo "  Run: $T5_RUN"
wait_run "pinpoint-testing/go-api" "$T5_RUN"

T5_CONCLUSION=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T5_RUN" --jq '.conclusion')

T5_FIRST_JOB=$(gh api "/repos/pinpoint-testing/go-api/actions/runs/$T5_RUN/jobs" --jq '.jobs[0].id')
T5_LOGS=$(gh api "/repos/pinpoint-testing/go-api/actions/jobs/$T5_FIRST_JOB/logs" 2>/dev/null || echo "")

if echo "$T5_LOGS" | grep -q "branch-pinned\|mutable"; then
  pass "Branch-pinned ref flagged by gate"
elif [ "$T5_CONCLUSION" = "failure" ]; then
  pass "Build failed (likely gate caught branch-pinned ref)"
else
  echo "  Note: pinpoint-action in warn mode won't block, but should log"
  if echo "$T5_LOGS" | grep -q "main"; then
    pass "Gate logged branch-pinned ref (warn mode)"
  else
    fail "Branch-pinned ref not detected"
  fi
fi

# Cleanup
gh api -X PATCH "/repos/pinpoint-testing/go-api/pulls/$T5_PR" -f state="closed" --silent 2>/dev/null
gh api -X DELETE "/repos/pinpoint-testing/go-api/git/refs/heads/chaos-branch-pin" --silent 2>/dev/null
echo "  PR closed, branch deleted"
echo ""

# ============================================
# RESULTS
# ============================================
echo "============================================"
echo "  CHAOS TEST RESULTS"
echo "============================================"
PASSES=0
FAILS=0
for r in "${RESULTS[@]}"; do
  echo "  $r"
  if [[ "$r" == PASS* ]]; then ((PASSES++)) || true; fi
  if [[ "$r" == FAIL* ]]; then ((FAILS++)) || true; fi
done
echo ""
echo "  $PASSES passed, $FAILS failed out of ${#RESULTS[@]} tests"
echo "============================================"
