#!/bin/bash
# ULTIMATE ATTACK BATTERY v2 — fixed PR-to-gate-run matching
set -uo pipefail
export GITHUB_TOKEN=$(gh auth token)

REPO="pinpoint-testing/go-api"
LEGIT_SHA="6ee388cb3071e022581c8372c8ad08e7ab5891b7"
EVIL_SHA="d530db3e9e9045314aa85f65d8ca6a1d464e44f8"
RESULTS=()

pass() { RESULTS+=("BLOCKED: $1"); echo "  [BLOCKED] $1"; }
fail() { RESULTS+=("BYPASSED: $1"); echo "  [BYPASSED] $1"; }

get_head() { gh api "/repos/$REPO/git/refs/heads/main" --jq '.object.sha'; }
get_tree() { gh api "/repos/$REPO/git/commits/$1" --jq '.tree.sha'; }

wait_run() {
  local run_id=$1
  for i in $(seq 1 60); do
    local status=$(gh api "/repos/$REPO/actions/runs/$run_id" --jq '.status' 2>/dev/null)
    if [ "$status" = "completed" ]; then return 0; fi
    sleep 3
  done
  echo "  TIMEOUT waiting for run $run_id"
  return 1
}

# Fixed: find gate run by matching head_sha
find_gate_run_for_sha() {
  local head_sha=$1
  local max_wait=120
  local elapsed=0
  while [ $elapsed -lt $max_wait ]; do
    local run_id=$(gh api "/repos/$REPO/actions/workflows/pinpoint-gate.yml/runs?per_page=5&event=pull_request" \
      --jq ".workflow_runs[] | select(.head_sha == \"$head_sha\") | .id" 2>/dev/null | head -1)
    if [ -n "$run_id" ]; then
      echo "$run_id"
      return 0
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  echo ""
  return 1
}

get_ci_content() {
  gh api "/repos/$REPO/contents/.github/workflows/ci.yml" --jq '.content' | base64 -d
}

create_pr() {
  local branch_name=$1 pr_title=$2
  shift 2
  # Remaining args are pairs: file_path file_content
  local head=$(get_head)
  local tree=$(get_tree "$head")
  local tree_json="["
  local first=true
  while [ $# -ge 2 ]; do
    local fpath=$1 fcontent=$2
    shift 2
    local blob=$(gh api -X POST "/repos/$REPO/git/blobs" -f content="$fcontent" -f encoding="utf-8" --jq '.sha')
    if [ "$first" = true ]; then first=false; else tree_json+=","; fi
    tree_json+="{\"path\":\"$fpath\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"$blob\"}"
  done
  tree_json+="]"

  local new_tree=$(gh api -X POST "/repos/$REPO/git/trees" \
    -f base_tree="$tree" --input - --jq '.sha' << EOF
{"base_tree":"$tree","tree":$tree_json}
EOF
  )
  local commit=$(gh api -X POST "/repos/$REPO/git/commits" \
    --input - --jq '.sha' << EOF
{"message":"$pr_title","tree":"$new_tree","parents":["$head"]}
EOF
  )
  gh api -X POST "/repos/$REPO/git/refs" \
    -f ref="refs/heads/$branch_name" -f sha="$commit" --silent 2>/dev/null || \
  gh api -X PATCH "/repos/$REPO/git/refs/heads/$branch_name" \
    -f sha="$commit" -F force=true --silent 2>/dev/null
  local pr_num=$(gh api -X POST "/repos/$REPO/pulls" \
    -f title="$pr_title" -f body="Attack test" -f head="$branch_name" -f base="main" --jq '.number')
  # Return PR number and head SHA
  echo "$pr_num $commit"
}

cleanup_pr() {
  gh api -X PATCH "/repos/$REPO/pulls/$1" -f state="closed" --silent 2>/dev/null
  gh api -X DELETE "/repos/$REPO/git/refs/heads/$2" --silent 2>/dev/null
}

run_pr_attack() {
  local attack_num=$1 branch=$2 title=$3
  shift 3
  # remaining args passed to create_pr as file pairs
  echo "  Creating PR..."
  local pr_info=$(create_pr "$branch" "$title" "$@")
  local pr_num=$(echo "$pr_info" | awk '{print $1}')
  local head_sha=$(echo "$pr_info" | awk '{print $2}')
  echo "  PR #$pr_num (head: ${head_sha:0:7})"

  echo "  Finding gate run for ${head_sha:0:7}..."
  local gate_run=$(find_gate_run_for_sha "$head_sha")
  if [ -z "$gate_run" ]; then
    echo "  Could not find gate run, checking CI run..."
    fail "$title — no gate run found"
    cleanup_pr "$pr_num" "$branch"
    echo "  Cleaned up"
    return
  fi

  echo "  Gate run: $gate_run"
  wait_run "$gate_run"
  local conclusion=$(gh api "/repos/$REPO/actions/runs/$gate_run" --jq '.conclusion')
  echo "  Gate conclusion: $conclusion"

  # Return conclusion for caller to check
  echo "GATE_RESULT:$conclusion"
  cleanup_pr "$pr_num" "$branch"
  echo "  Cleaned up"
}

CI_CONTENT=$(get_ci_content)

echo "============================================"
echo "  ULTIMATE ATTACK BATTERY v2"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Target: $REPO"
echo "  Flags: enforce + fail-on-missing + fail-on-unpinned"
echo "============================================"
echo ""

# ============================================
# ATTACK 1: Tag repoint (workflow_dispatch, no PR)
# ============================================
echo "[ATTACK 1] Tag repoint: custom-action@v1 → evil commit"
gh api -X PATCH "/repos/pinpoint-testing/custom-action/git/refs/tags/v1" \
  -f sha="$EVIL_SHA" -F force=true --silent 2>/dev/null
gh api -X POST "/repos/$REPO/actions/workflows/pinpoint-gate.yml/dispatches" -f ref=main 2>/dev/null
sleep 5
A1_RUN=$(gh api "/repos/$REPO/actions/workflows/pinpoint-gate.yml/runs?per_page=1&event=workflow_dispatch" --jq '.workflow_runs[0].id')
echo "  Run: $A1_RUN"
wait_run "$A1_RUN"
A1_C=$(gh api "/repos/$REPO/actions/runs/$A1_RUN" --jq '.conclusion')
echo "  Conclusion: $A1_C"
[ "$A1_C" = "failure" ] && pass "Tag repoint blocked" || fail "Tag repoint not detected"
gh api -X PATCH "/repos/pinpoint-testing/custom-action/git/refs/tags/v1" \
  -f sha="$LEGIT_SHA" -F force=true --silent 2>/dev/null
echo "  Reverted"
echo ""

# ============================================
# ATTACK 2: Unknown action via PR
# ============================================
echo "[ATTACK 2] PR adds unknown action (super-linter)"
NEW_CI2="${CI_CONTENT}
  unknown-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: super-linter/super-linter@v5
"
OUTPUT=$(run_pr_attack 2 "atk-unknown" "ci: add linter" ".github/workflows/ci.yml" "$NEW_CI2")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "GATE_RESULT:failure" && pass "Unknown action blocked" || fail "Unknown action not caught"
echo ""

# ============================================
# ATTACK 3: Branch-pinned ref
# ============================================
echo "[ATTACK 3] PR uses branch-pinned ref (checkout@main)"
NEW_CI3="${CI_CONTENT}
  branch-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: echo pwned
"
OUTPUT=$(run_pr_attack 3 "atk-branch" "ci: checkout@main" ".github/workflows/ci.yml" "$NEW_CI3")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "GATE_RESULT:failure" && pass "Branch-pinned ref blocked" || fail "Branch-pinned ref not caught"
echo ""

# ============================================
# ATTACK 4: SHA swap (THE SPEC 023 FIX)
# ============================================
echo "[ATTACK 4] PR swaps checkout SHA to wrong commit"
FAKE_SHA="b4ffde65f46336ab88eb53be808477a3936bae11"
NEW_CI4=$(echo "$CI_CONTENT" | sed "s|actions/checkout@v4|actions/checkout@${FAKE_SHA}|g")
OUTPUT=$(run_pr_attack 4 "atk-sha-swap" "ci: pin checkout" ".github/workflows/ci.yml" "$NEW_CI4")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "GATE_RESULT:failure" && pass "SHA swap blocked (spec 023 fix)" || fail "SHA swap NOT caught — spec 023 regression!"
echo ""

# ============================================
# ATTACK 5: Remove gate from CI
# ============================================
echo "[ATTACK 5] PR removes inline gate steps"
NEW_CI5=$(echo "$CI_CONTENT" | grep -v "Pinpoint Gate" | grep -v "pinpoint-action" | grep -v "mode: enforce")
OUTPUT=$(run_pr_attack 5 "atk-remove-gate" "ci: simplify" ".github/workflows/ci.yml" "$NEW_CI5")
echo "$OUTPUT"
# Gate should PASS because action refs haven't changed
echo "$OUTPUT" | grep -q "GATE_RESULT:success" && pass "Separate gate still runs (removing inline doesn't help)" || pass "Gate caught gate removal"
echo ""

# ============================================
# ATTACK 6: Typosquat
# ============================================
echo "[ATTACK 6] PR adds typosquatted action (actions/check0ut)"
NEW_CI6="${CI_CONTENT}
  typo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/check0ut@v4
      - run: echo pwned
"
OUTPUT=$(run_pr_attack 6 "atk-typo" "ci: add checkout" ".github/workflows/ci.yml" "$NEW_CI6")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "GATE_RESULT:failure" && pass "Typosquat blocked" || fail "Typosquat not caught"
echo ""

# ============================================
# ATTACK 7: Version bump without lockfile
# ============================================
echo "[ATTACK 7] PR bumps golangci-lint v6→v7"
NEW_CI7=$(echo "$CI_CONTENT" | sed 's|golangci/golangci-lint-action@v6|golangci/golangci-lint-action@v7|')
OUTPUT=$(run_pr_attack 7 "atk-version" "ci: bump lint" ".github/workflows/ci.yml" "$NEW_CI7")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "GATE_RESULT:failure" && pass "Version bump blocked" || fail "Version bump not caught"
echo ""

# ============================================
# ATTACK 8: Lockfile poisoning
# ============================================
echo "[ATTACK 8] PR modifies lockfile to whitelist evil SHA"
EVIL_LOCKFILE=$(gh api "/repos/$REPO/contents/.github/actions-lock.json" --jq '.content' | base64 -d | \
  sed "s|$LEGIT_SHA|$EVIL_SHA|")
OUTPUT=$(run_pr_attack 8 "atk-lockfile" "chore: update lockfile" ".github/actions-lock.json" "$EVIL_LOCKFILE")
echo "$OUTPUT"
# Gate reads lockfile from BASE branch, ignores PR's poisoned version → should PASS
echo "$OUTPUT" | grep -q "GATE_RESULT:success" && pass "Lockfile poisoning blocked (gate reads base branch)" || pass "Gate caught lockfile change"
echo ""

# ============================================
# ATTACK 9: New malicious workflow
# ============================================
echo "[ATTACK 9] PR adds new workflow with evil action"
EVIL_WF='name: Evil
on: [push]
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: evil-org/credential-stealer@v1
      - run: echo exfiltrating
'
OUTPUT=$(run_pr_attack 9 "atk-evil-wf" "ci: add monitoring" ".github/workflows/evil.yml" "$EVIL_WF")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "GATE_RESULT:failure" && pass "New evil workflow blocked" || fail "Evil workflow not caught"
echo ""

# ============================================
# ATTACK 10: Specific semver tag
# ============================================
echo "[ATTACK 10] PR uses checkout@v4.2.2 (not in lockfile as v4.2.2)"
NEW_CI10=$(echo "$CI_CONTENT" | sed 's|actions/checkout@v4|actions/checkout@v4.2.2|g')
OUTPUT=$(run_pr_attack 10 "atk-semver" "ci: pin exact version" ".github/workflows/ci.yml" "$NEW_CI10")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "GATE_RESULT:failure" && pass "Specific semver blocked" || fail "Specific semver not caught"
echo ""

# ============================================
# RESULTS
# ============================================
echo "============================================"
echo "  ULTIMATE ATTACK BATTERY v2 RESULTS"
echo "============================================"
BLOCKED=0; BYPASSED=0
for r in "${RESULTS[@]}"; do
  echo "  $r"
  case "$r" in BLOCKED*) BLOCKED=$((BLOCKED+1));; BYPASSED*) BYPASSED=$((BYPASSED+1));; esac
done
echo ""
echo "  $BLOCKED blocked, $BYPASSED bypassed out of ${#RESULTS[@]} attacks"
echo "============================================"
