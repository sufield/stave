#!/usr/bin/env bash
# Stave quickstart — from "I use these AWS services" to findings.
#
#   scripts/quickstart.sh [services] [observations-dir]
#
#   services          comma-separated AWS services (default: iam,s3,ec2,lambda,cloudtrail)
#   observations-dir  a directory of obs.v0.1 OBSERVATIONS (raw snapshots already
#                     converted by your extractor). If given AND non-empty, the
#                     script evaluates it per service group; otherwise it stops
#                     after printing the collection manifest.
#
# Stave never collects data or touches AWS. It reads obs.v0.1 observations. This
# script prints the read-only API calls (your snapshots); you collect and CONVERT
# them to observations with your own tools, then re-run with the observations dir.
set -euo pipefail

SERVICES="${1:-iam,s3,ec2,lambda,cloudtrail}"
OBSERVATIONS="${2:-}"
STAVE="${STAVE:-stave}"
command -v "$STAVE" >/dev/null 2>&1 || STAVE="./stave"

echo "== 1. Discover — what Stave needs for: $SERVICES =="
"$STAVE" discover --services "$SERVICES"

echo
echo "== 2. Plan — what Stave will check =="
"$STAVE" plan --services "$SERVICES"

if [ -z "$OBSERVATIONS" ] || [ ! -d "$OBSERVATIONS" ] || [ -z "$(ls -A "$OBSERVATIONS" 2>/dev/null)" ]; then
  echo
  echo "== Next =="
  echo "1. Collect: run the read-only API calls above with your own tool (-> raw snapshots)."
  echo "2. Convert: transform the snapshots into obs.v0.1 observations with your extractor"
  echo "   (e.g. scripts/aws-snapshot.sh ./observations) -- this step is NOT Stave."
  echo "3. Re-run:  scripts/quickstart.sh $SERVICES ./observations"
  exit 0
fi

echo
echo "== 3. Evaluate per service group: $OBSERVATIONS =="
rc=0
IFS=',' read -ra SVCS <<< "$SERVICES"
for svc in "${SVCS[@]}"; do
  svc="$(echo "$svc" | tr -d '[:space:]')"
  # Exit 3 = violations found = success; capture to a file so pipefail doesn't
  # treat it as an error.
  "$STAVE" apply --services "$svc" -o "$OBSERVATIONS" --format json > "${TMPDIR:-/tmp}/qs-$svc.json" 2>/dev/null || true
  n=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("findings",[])))' \
        < "${TMPDIR:-/tmp}/qs-$svc.json" 2>/dev/null || echo "?")
  echo "  [$svc] $n finding(s)"
done

echo
echo "== Full evaluation (all collected services + compound controls) =="
"$STAVE" apply -o "$OBSERVATIONS" || rc=$?
echo
echo "Exit 3 = violations found (a successful evaluation, not an error)."
echo "After fixing, re-collecting and re-converting: stave check --before $OBSERVATIONS --after ./observations-fixed"
exit 0
