#!/usr/bin/env bash
# Stave Atlantis post-plan hook — evaluate Terraform plan for safety violations.
#
# Install: Add to atlantis.yaml as a post-plan workflow step.
# See docs/integrations/atlantis.md for full setup.
#
# What it does:
#   1. Checks if stave is available
#   2. Converts terraform plan JSON to obs.v0.1 (via extractor)
#   3. Runs stave apply against the observations
#   4. Posts findings as a PR comment (via Atlantis output)
#   5. Fails the plan if violations are found
#
# Prerequisites:
#   - stave binary on Atlantis server PATH
#   - jq on Atlantis server PATH
#   - Extractor script or Steampipe for plan-to-obs conversion
#
# Environment:
#   PLANFILE          — path to terraform plan JSON (set by Atlantis)
#   STAVE_CONTROLS    — controls directory (default: controls/)
#   STAVE_PROFILE     — compliance profile (optional, must be alphanumeric/hyphen)
#   STAVE_MAX_UNSAFE  — max unsafe duration (default: 0s for plan checks)
#
set -euo pipefail

# ── Check prerequisites ─────────────────────────────────

if ! command -v stave &>/dev/null; then
    echo "stave: not found — skipping post-plan check"
    echo "Install: brew tap sufield/tap && brew install stave"
    exit 0
fi

if ! command -v jq &>/dev/null; then
    echo "jq: not found — skipping post-plan check"
    exit 0
fi

PLANFILE="${PLANFILE:-${SHOWFILE:-}}"
if [ -z "$PLANFILE" ] || [ ! -f "$PLANFILE" ]; then
    echo "stave: no plan file found — skipping"
    exit 0
fi

CONTROLS="${STAVE_CONTROLS:-controls}"
MAX_UNSAFE="${STAVE_MAX_UNSAFE:-0s}"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Sanitize STAVE_PROFILE — allow only alphanumeric, hyphen, underscore.
PROFILE="${STAVE_PROFILE:-}"
if [ -n "$PROFILE" ] && ! echo "$PROFILE" | grep -qE '^[a-zA-Z0-9_-]+$'; then
    echo "stave: invalid STAVE_PROFILE value — skipping"
    exit 0
fi

# ── Convert plan to observations ─────────────────────────

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
mkdir -p "$WORKDIR/observations"

# Generate plan JSON if not already JSON.
if file "$PLANFILE" | grep -q "text"; then
    PLAN_JSON="$PLANFILE"
else
    terraform show -json "$PLANFILE" > "$WORKDIR/plan.json"
    PLAN_JSON="$WORKDIR/plan.json"
fi

# Extract planned resource configurations to obs.v0.1.
# Recursively walks root_module and all child_modules to catch
# resources in nested Terraform modules.
OBS_FILE="$WORKDIR/observations/$NOW.json"
jq '{
  schema_version: "obs.v0.1",
  captured_at: "'"$NOW"'",
  assets: [
    [.. | .resources? // empty] | flatten | .[] | {
      id: .address,
      type: .type,
      vendor: (if .type | startswith("aws_") then "aws"
               elif .type | startswith("google_") then "gcp"
               elif .type | startswith("azurerm_") then "azure"
               else "unknown" end),
      properties: .values
    }
  ]
}' "$PLAN_JSON" > "$OBS_FILE" 2>/dev/null || {
    echo "stave: failed to parse plan JSON — skipping"
    exit 0
}

# For plan checks, use --max-unsafe 0s (any unsafe state = fail).
# No need for a second snapshot — 0s threshold means even a single
# point-in-time violation triggers a finding. The dual-snapshot
# pattern is only needed for duration-based controls (e.g., "unsafe
# for >168h"). Plan checks are instantaneous safety gates.

# ── Run evaluation ───────────────────────────────────────

echo "## Stave Security Check"
echo ""

RC=0
if [ -n "$PROFILE" ]; then
    stave apply \
        --profile "$PROFILE" \
        --input "$OBS_FILE" \
        --now "$NOW" \
        --format text \
        2>/dev/null || RC=$?
else
    # Single-snapshot mode: copy to create the minimum two snapshots
    # required by the observations directory loader.
    SECOND_TS=$(date -u +%Y-%m-%dT%H%M%SZ)
    jq ".captured_at = \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"" "$OBS_FILE" \
        > "$WORKDIR/observations/${SECOND_TS}.json"

    stave apply \
        --controls "$CONTROLS" \
        --observations "$WORKDIR/observations" \
        --max-unsafe "$MAX_UNSAFE" \
        --now "$NOW" \
        --format text \
        2>/dev/null || RC=$?
fi

echo ""

case $RC in
    0)
        echo "**No violations found.**"
        ;;
    3)
        echo ""
        echo "**Violations detected — plan should not be applied.**"
        echo ""
        echo "Fix the violations above before running \`atlantis apply\`."
        exit 1
        ;;
    *)
        echo "stave: exit code $RC (non-blocking)"
        ;;
esac

exit 0
