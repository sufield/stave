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
#   STAVE_PROFILE     — compliance profile (optional)
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

PLANFILE="${PLANFILE:-$SHOWFILE}"
if [ ! -f "$PLANFILE" ]; then
    echo "stave: no plan file found at $PLANFILE — skipping"
    exit 0
fi

CONTROLS="${STAVE_CONTROLS:-controls}"
MAX_UNSAFE="${STAVE_MAX_UNSAFE:-0s}"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ── Convert plan to observations ─────────────────────────

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# Generate plan JSON if not already JSON.
if file "$PLANFILE" | grep -q "text"; then
    PLAN_JSON="$PLANFILE"
else
    terraform show -json "$PLANFILE" > "$WORKDIR/plan.json"
    PLAN_JSON="$WORKDIR/plan.json"
fi

# Extract planned resource configurations to obs.v0.1.
# This is a minimal extractor — production use should use a full
# Terraform-to-obs extractor (Steampipe, CloudQuery, or custom).
jq '{
  schema_version: "obs.v0.1",
  captured_at: "'"$NOW"'",
  assets: [
    .planned_values.root_module.resources[]? | {
      id: .address,
      type: .type,
      vendor: (if .type | startswith("aws_") then "aws"
               elif .type | startswith("google_") then "gcp"
               elif .type | startswith("azurerm_") then "azure"
               else "unknown" end),
      properties: .values
    }
  ]
}' "$PLAN_JSON" > "$WORKDIR/observations/$NOW.json" 2>/dev/null || {
    echo "stave: failed to parse plan JSON — skipping"
    exit 0
}

# Create a second snapshot (required for duration-based controls).
cp "$WORKDIR/observations/$NOW.json" "$WORKDIR/observations/$(date -u -d '+1 hour' +%Y-%m-%dT%H%M%SZ 2>/dev/null || date -u -v+1H +%Y-%m-%dT%H%M%SZ).json"

# ── Run evaluation ───────────────────────────────────────

echo "## Stave Security Check"
echo ""

CMD="stave apply --controls $CONTROLS --observations $WORKDIR/observations --max-unsafe $MAX_UNSAFE --now $NOW --allow-unknown-input --format text"

if [ -n "${STAVE_PROFILE:-}" ]; then
    CMD="stave apply --profile $STAVE_PROFILE --input $WORKDIR/observations/$NOW.json --now $NOW --format text"
fi

RC=0
eval "$CMD" 2>/dev/null || RC=$?

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
