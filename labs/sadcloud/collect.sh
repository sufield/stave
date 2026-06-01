#!/usr/bin/env bash
# Capture SadCloud observations using the minimal collector.
# Runs after deploy.sh in the fixture-refresh CI job.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OBS_DIR="$SCRIPT_DIR/observations"

# Clear previous observations
rm -f "$OBS_DIR"/*.json

# Run the sample collector
python3 "$REPO_ROOT/examples/collectors/aws_minimal_collector.py" \
    --region us-east-1 \
    --out "$OBS_DIR"

# Validate the output
"$REPO_ROOT/stave" validate --observations "$OBS_DIR" 2>&1 || true

echo "Observations written to $OBS_DIR"
ls -la "$OBS_DIR"/*.json
