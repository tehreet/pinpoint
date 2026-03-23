#!/bin/bash
# pinpoint org-status: single-pane view of pinpoint deployment across an org
set -uo pipefail

ORG="${1:-pinpoint-testing}"

printf "%-25s %-10s %-12s %-12s\n" "REPO" "LOCKFILE" "LOCK-WF" "GATE-WF"
printf "%-25s %-10s %-12s %-12s\n" "-------------------------" "----------" "------------" "------------"

for REPO in $(gh repo list "$ORG" --limit 100 --json name --jq '.[].name'); do
  [ "$REPO" = "pinpoint" ] && continue
  LOCKFILE=$(gh api "repos/$ORG/$REPO/contents/.github/actions-lock.json" --jq '.name' 2>/dev/null && echo "present" || echo "missing")
  [ "$LOCKFILE" != "missing" ] && LOCKFILE="✓"
  LOCK_WF=$(gh run list --repo "$ORG/$REPO" --workflow="Pinpoint Lockfile" --limit 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "none")
  [ -z "$LOCK_WF" ] && LOCK_WF="none"
  GATE_WF=$(gh run list --repo "$ORG/$REPO" --workflow="Pinpoint Gate" --limit 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "none")
  [ -z "$GATE_WF" ] && GATE_WF="none"
  printf "%-25s %-10s %-12s %-12s\n" "$REPO" "$LOCKFILE" "$LOCK_WF" "$GATE_WF"
done
