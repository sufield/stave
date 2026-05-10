#!/usr/bin/env bash
# Linear-trend posture-score forecast across 8 daily out.v0.1 assessments.
#
# Pipeline:
#   stave apply --format json   (one per day, captured offline) →
#   forecast.py <dir> [--horizon N] [--sla-profile FILE]        →
#   posture trajectory + per-severity SLA status
#
# Pure-stdlib Python; no NumPy / no statsmodels required. The
# arithmetic is closed-form least-squares on the daily score series.
#
# This example replaces `internal/app/forecast/` per the
# core-audit thin-core contract — the same projection runs as
# external code over Stave's published JSON output.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
runner="$script_dir/forecast.py"
fixtures="$script_dir/fixtures/assessments"

# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"

fmt_section "Forecast — 30-day projection (table)"
python3 "$runner" "$fixtures" --horizon 30 || {
    echo "forecast.py failed" >&2
    exit 1
}

fmt_section "Forecast — 30-day projection (JSON)"
python3 "$runner" "$fixtures" --horizon 30 --format json

fmt_section "Interpretation"
cat <<'EOF'
The 8-day fixture series shows a declining trajectory: each day
adds another finding or two, weighted by severity (critical = 20,
high = 10, medium = 5, low = 2 deducted from a 100 baseline).

The least-squares slope across 8 days drops the score sharply,
flagging the trend as DECLINING. A real deployment with a
0.6 points/day slope and a 90-day horizon would project a
~54-point posture loss — actionable signal for the team.

The MTTR projection runs the same fit per severity. With the
default 24h critical SLA and 24h current MTTR, the projector
flags critical as AT_RISK: even small additional latency would
push MTTR past the deadline.

Per the core-audit migration plan, this Python script is the
external replacement for internal/app/forecast/. Rerun stave
apply daily, capture the JSON output, point this script at the
directory — same projection, no Stave Go internals needed.
EOF
