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
#   STAVE_CONTROLS    — controls directory (default: unset = built-in catalog)
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

# Default to the built-in catalog: leave CONTROLS empty unless the user
# points STAVE_CONTROLS at a directory. Passing --controls to a path that
# doesn't exist (an Atlantis repo has no controls/ dir) errors exit 4 and
# the gate silently passes; omitting --controls uses the embedded catalog.
CONTROLS="${STAVE_CONTROLS:-}"
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

# Use the plan file directly if it is already JSON; otherwise render it
# with terraform show. jq is already a required dependency, so probe with
# it rather than `file` (whose output strings are not portable and which
# is not checked as a prerequisite).
if jq -e . "$PLANFILE" >/dev/null 2>&1; then
    PLAN_JSON="$PLANFILE"
else
    terraform show -json "$PLANFILE" > "$WORKDIR/plan.json"
    PLAN_JSON="$WORKDIR/plan.json"
fi

# Extract planned resource configurations to obs.v0.1.
# Recursively walks root_module and all child_modules to catch
# resources in nested Terraform modules.
# Colons are legal in POSIX filenames but trip up many tools; keep the
# colon-bearing RFC3339 stamp in captured_at only, not the filename.
OBS_FILE="$WORKDIR/observations/snapshot.json"
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

# A plan is a single point in time, so one snapshot is enough — the
# observations directory loader accepts a single snapshot. Point-in-time
# controls (unsafe_state) fire on it regardless of --max-unsafe;
# duration-based controls (e.g. "unsafe for >168h") need two snapshots
# with a real time gap, which a plan cannot provide, so they stay quiet.
# Note: --max-unsafe 0s is treated as "unset" and falls back to the
# default threshold — it does NOT mean "any unsafe state fails".

# ── Run evaluation ───────────────────────────────────────

echo "## Stave Security Check"
echo ""

RC=0
if [ -n "$PROFILE" ]; then
    # --profile reads --input as an observation *bundle*
    # ({"schema_version":"obs.v0.1","snapshots":[...]}), not a single
    # per-timestamp snapshot — wrap the snapshot in a bundle first.
    BUNDLE="$WORKDIR/bundle.json"
    jq '{schema_version: "obs.v0.1", snapshots: [.]}' "$OBS_FILE" > "$BUNDLE"

    stave apply \
        --profile "$PROFILE" \
        --input "$BUNDLE" \
        --now "$NOW" \
        --format text \
        2>/dev/null || RC=$?
else
    # Only pass --controls when STAVE_CONTROLS is set; otherwise Stave
    # evaluates against the built-in catalog. The guarded expansion keeps
    # an empty array safe under `set -u` on bash 3.2.
    CONTROLS_ARGS=()
    [ -n "$CONTROLS" ] && CONTROLS_ARGS=(--controls "$CONTROLS")

    stave apply \
        ${CONTROLS_ARGS[@]+"${CONTROLS_ARGS[@]}"} \
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
