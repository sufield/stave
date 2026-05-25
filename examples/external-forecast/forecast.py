#!/usr/bin/env python3
"""External port of internal/app/forecast.Compute.

Reads the same JSON shape, runs ordinary least-squares linear
regression in stdlib (no numpy / scipy needed), applies the
same clamps + status thresholds the core uses, and emits JSON
in the shape of `forecast.Result`. The output should match
`verify_against_core.go`'s output (which calls the core Go
function) byte-for-byte after canonical jq sort.

Stdlib-only keeps the example's runtime requirement to
"python3" — no `pip install` step before run.sh works.

Usage:
    python3 forecast.py input.json output.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def linear_fit(ys: list[float]) -> tuple[float, float]:
    """Least-squares fit y = intercept + slope*t.

    Mirrors internal/app/forecast.linearFit exactly: same
    edge cases for n<=1, same sum accumulation pattern. Pure
    Python — no numpy dependency.
    """
    n = len(ys)
    if n <= 1:
        return (0.0, float(ys[0]) if ys else 0.0)
    sum_x = 0.0
    sum_y = 0.0
    sum_xy = 0.0
    sum_x2 = 0.0
    for i, y in enumerate(ys):
        x = float(i)
        yv = float(y)
        sum_x += x
        sum_y += yv
        sum_xy += x * yv
        sum_x2 += x * x
    nf = float(n)
    denom = nf * sum_x2 - sum_x * sum_x
    if denom == 0:
        return (0.0, sum_y / nf)
    slope = (nf * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / nf
    return (slope, intercept)


def compute(input_data: dict) -> dict:
    """Mirrors internal/app/forecast.Compute."""
    score_history = input_data["score_history"]
    horizon_days = int(input_data["horizon_days"])
    sla_deadlines = input_data.get("sla_deadlines_hours", {})
    mttr_history = input_data.get("mttr_history_hours", {})

    if len(score_history) < 7:
        raise ValueError(
            f"insufficient history: {len(score_history)} days (minimum 7 required)"
        )

    n = len(score_history)
    slope, intercept = linear_fit(score_history)
    current_score = float(score_history[-1])
    projected_score = intercept + slope * (n + horizon_days - 1)

    # Clamp to [0, 100] — matches Go core.
    projected_score = max(0.0, min(100.0, projected_score))

    result: dict = {
        "current": {
            "posture_score": current_score,
            "open_findings": 0,
            "mttr_critical_hours": 0,
            "mttr_high_hours": 0,
        },
        "projected": {
            "horizon_days": horizon_days,
            "posture_score": projected_score,
            "score_slope_per_day": slope,
        },
        "model_note": (
            f"Linear projection from {n} days of history. "
            "Accuracy decreases beyond 30-day horizon. "
            "Rerun weekly for updated projections."
        ),
    }

    # SLA projections per severity, in the same fixed order
    # the Go core iterates: critical, high, medium, low.
    sla_projections = []
    for sev in ("critical", "high", "medium", "low"):
        history = mttr_history.get(sev, [])
        deadline = float(sla_deadlines.get(sev, 0.0))
        if len(history) < 3 or deadline <= 0:
            continue

        mttr_slope, mttr_intercept = linear_fit(history)
        current_mttr = float(history[-1])
        projected_mttr = mttr_intercept + mttr_slope * (
            len(history) + horizon_days - 1
        )
        # Clamp MTTR to >= 0 — matches Go core.
        if projected_mttr < 0:
            projected_mttr = 0.0

        # Status thresholds match Go core exactly:
        # > deadline → BREACHING; > deadline*0.8 → AT_RISK;
        # else ON_TRACK.
        if projected_mttr > deadline:
            status = "BREACHING"
        elif projected_mttr > deadline * 0.8:
            status = "AT_RISK"
        else:
            status = "ON_TRACK"

        sla_projections.append({
            "severity": sev,
            "current_mttr_hours": current_mttr,
            "projected_mttr_hours": projected_mttr,
            "sla_deadline_hours": deadline,
            "status": status,
        })

    if sla_projections:
        result["sla_projections"] = sla_projections

    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            f"usage: {argv[0]} <input.json> <output.json>",
            file=sys.stderr,
        )
        return 2
    in_path = Path(argv[1])
    out_path = Path(argv[2])
    with in_path.open() as f:
        input_data = json.load(f)
    result = compute(input_data)
    with out_path.open("w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
