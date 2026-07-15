#!/bin/bash
# Scheduled Stave scan — run via cron or CI schedule.
# Captures a snapshot, evaluates it, and diffs against the previous run.
#
# Usage:
#   STAVE_SNAPSHOT_DIR=./snapshots CONFIG_BUCKET=my-config-bucket \
#     bash examples/ci-gate/scheduled-scan.sh
#
# Requires: stave on PATH, aws CLI with read-only credentials.
set -euo pipefail

SNAPSHOT_DIR="${STAVE_SNAPSHOT_DIR:-./snapshots}"
CURRENT="$SNAPSHOT_DIR/$(date +%Y-%m-%d)"
PREVIOUS=$(ls -d "$SNAPSHOT_DIR"/*/ 2>/dev/null | sort | tail -1 || true)

mkdir -p "$CURRENT"

echo "==> Importing snapshot to $CURRENT"
aws s3 sync "s3://${CONFIG_BUCKET}/AWSLogs/" "$CURRENT/"

echo "==> Evaluating"
stave apply --observations "$CURRENT/" --format json > "$CURRENT/findings.json" || {
    exit_code=$?
    if [ "$exit_code" -eq 3 ]; then
        echo "Violations found (exit 3) — see $CURRENT/findings.json"
    else
        echo "Error (exit $exit_code)" >&2
        exit "$exit_code"
    fi
}

if [ -n "$PREVIOUS" ] && [ -f "$PREVIOUS/findings.json" ]; then
    echo "==> Comparing against $PREVIOUS"
    stave compare \
        --before "$PREVIOUS/" \
        --after "$CURRENT/" \
        --format text || true
fi

echo ""
echo "Findings: $CURRENT/findings.json"
