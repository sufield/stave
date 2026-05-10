#!/usr/bin/env python3
"""Linear-trend posture-score forecast over Stave out.v0.1 assessments.

Replicates the role of `internal/app/forecast/` and the `stave trend
forecast` subcommand without depending on Stave Go internals — reads
the same `out.v0.1` assessment JSON files Stave emits and projects a
posture trajectory N days forward.

Pipeline:
    stave apply --format json   →  out.v0.1 assessments (one per day)
    forecast.py <dir> [--horizon N] [--sla-profile FILE]
                                 →  current/projected score + per-severity
                                    SLA status with the same vocabulary
                                    Stave uses (ON_TRACK / AT_RISK /
                                    BREACHING)

Pure stdlib by design (matches `prism-risk-prioritization/risk_model.py`
and `game-theory-cost/cost_model.py`). The arithmetic is closed-form
least-squares on the score series and per-severity MTTR series — no
ML library, no statsmodels, no NumPy required.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# Severity weights for the simple posture score.
# Stave's internal app/score uses richer weighting (chain bonuses,
# duration factors). The external version is intentionally simpler
# and explainable — change the constants to recalibrate.
SEVERITY_WEIGHT = {
    "critical": 20.0,
    "high": 10.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5,
}

# Default SLA deadlines (hours) when no profile is provided.
DEFAULT_SLA = {
    "critical": 24.0,
    "high": 72.0,
    "medium": 168.0,
    "low": 720.0,
}

STATUS_ON_TRACK = "ON_TRACK"
STATUS_AT_RISK = "AT_RISK"
STATUS_BREACHING = "BREACHING"

# AT_RISK fires when projected MTTR is within this fraction of the
# deadline. Mirrors the 0.8 threshold in
# internal/app/forecast/forecast.go.
AT_RISK_RATIO = 0.8


def linear_fit(ys: list[float]) -> tuple[float, float]:
    """Least-squares slope, intercept for y = a + b*t (t = index)."""
    n = len(ys)
    if n == 0:
        return 0.0, 0.0
    if n == 1:
        return 0.0, ys[0]
    sum_x = sum_y = sum_xy = sum_x2 = 0.0
    for i, y in enumerate(ys):
        sum_x += i
        sum_y += y
        sum_xy += i * y
        sum_x2 += i * i
    denom = n * sum_x2 - sum_x * sum_x
    if denom == 0:
        return 0.0, sum_y / n
    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n
    return slope, intercept


def parse_run_now(assessment: dict[str, Any]) -> datetime:
    """Pull the run.now timestamp; required for sorting."""
    raw = assessment.get("run", {}).get("now")
    if not raw:
        raise ValueError("assessment missing run.now")
    # out.v0.1 emits RFC3339 with trailing Z; replace for fromisoformat.
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def severity_of(finding: dict[str, Any]) -> str:
    """Best-effort severity extraction across out.v0.1 shapes."""
    for path in (
        ("control_severity",),
        ("severity",),
        ("evidence", "severity"),
    ):
        cur: Any = finding
        for k in path:
            if not isinstance(cur, dict) or k not in cur:
                cur = None
                break
            cur = cur[k]
        if isinstance(cur, str):
            return cur.lower()
    return "medium"


def compute_score(assessment: dict[str, Any]) -> float:
    """Severity-weighted posture score in [0, 100].

    Lighter than internal/app/score (no chain bonus, no duration
    factor). For trend purposes the absolute value matters less
    than that the same formula is applied to every assessment in
    the series — slope is what drives the projection.
    """
    findings = assessment.get("findings", []) or []
    if not findings:
        return 100.0
    deduction = sum(
        SEVERITY_WEIGHT.get(severity_of(f), SEVERITY_WEIGHT["medium"])
        for f in findings
    )
    score = 100.0 - deduction
    return max(0.0, min(100.0, score))


def build_mttr_history(
    assessments: list[dict[str, Any]],
) -> dict[str, list[float]]:
    """Approximate per-severity MTTR from finding open/close events.

    Mirrors cmd/trend/forecast.go::buildMTTRHistory: tracks
    (control_id, asset_id) pairs across snapshots; when a key
    disappears it counts the elapsed hours by that finding's
    severity.
    """
    history: dict[str, list[float]] = {sev: [] for sev in SEVERITY_WEIGHT}
    open_keys: dict[tuple[str, str], dict[str, Any]] = {}

    for a in assessments:
        now = parse_run_now(a)
        seen: set[tuple[str, str]] = set()
        for f in a.get("findings", []) or []:
            key = (str(f.get("control_id", "")), str(f.get("asset_id", "")))
            seen.add(key)
            if key not in open_keys:
                open_keys[key] = {"sev": severity_of(f), "open": now}

        # Anything previously open but not seen now closed.
        closed = [k for k in open_keys if k not in seen]
        for key in closed:
            window = open_keys.pop(key)
            hours = (now - window["open"]).total_seconds() / 3600.0
            sev = window["sev"]
            history.setdefault(sev, []).append(hours)
    return history


def project_sla(
    mttr_history: dict[str, list[float]],
    sla: dict[str, float],
    horizon_days: int,
) -> list[dict[str, Any]]:
    """Per-severity MTTR projection + ON_TRACK / AT_RISK / BREACHING."""
    out: list[dict[str, Any]] = []
    for sev in ("critical", "high", "medium", "low"):
        history = mttr_history.get(sev, [])
        deadline = sla.get(sev, 0.0)
        if len(history) < 3 or deadline <= 0:
            continue
        slope, intercept = linear_fit(history)
        current = history[-1]
        projected = max(
            0.0, intercept + slope * (len(history) + horizon_days - 1)
        )
        if projected > deadline:
            status = STATUS_BREACHING
        elif projected > deadline * AT_RISK_RATIO:
            status = STATUS_AT_RISK
        else:
            status = STATUS_ON_TRACK
        out.append(
            {
                "severity": sev,
                "current_mttr_hours": round(current, 2),
                "projected_mttr_hours": round(projected, 2),
                "sla_deadline_hours": deadline,
                "status": status,
            }
        )
    return out


def load_assessments(path: Path) -> list[dict[str, Any]]:
    """Read every *.json under path as an assessment, sort by run.now."""
    if not path.is_dir():
        raise FileNotFoundError(f"history directory not found: {path}")
    assessments: list[dict[str, Any]] = []
    for f in sorted(path.glob("*.json")):
        with f.open() as fh:
            assessments.append(json.load(fh))
    assessments.sort(key=parse_run_now)
    return assessments


def load_sla(path: Path | None) -> dict[str, float]:
    """Read an SLA-deadlines JSON file, or fall back to defaults."""
    if path is None:
        return dict(DEFAULT_SLA)
    with path.open() as fh:
        raw = json.load(fh)
    return {sev: float(raw.get(sev, DEFAULT_SLA.get(sev, 0))) for sev in DEFAULT_SLA}


def slope_label(slope: float) -> str:
    if slope > 0.01:
        return "improving"
    if slope < -0.01:
        return "declining"
    return "stable"


def render_table(result: dict[str, Any], horizon: int) -> str:
    lines = [
        "POSTURE SCORE FORECAST",
        f"Horizon: {horizon} days",
        "─" * 55,
        "",
        "SCORE TRAJECTORY",
        f"  Current score:      {result['current']['posture_score']:.1f}",
        f"  Score slope:        {result['projected']['score_slope_per_day']:+.2f} points/day  "
        f"({slope_label(result['projected']['score_slope_per_day'])})",
        f"  Projected ({horizon}d):    {result['projected']['posture_score']:.1f}",
        "",
    ]
    sla = result.get("sla_projections") or []
    if sla:
        lines.append("SLA STATUS")
        lines.append(
            f"  {'Severity':<10}  {'MTTR (current)':<14}  {'SLA target':<10}  Status"
        )
        lines.append(
            f"  {'─' * 10}  {'─' * 14}  {'─' * 10}  {'─' * 10}"
        )
        marker = {STATUS_ON_TRACK: "✓", STATUS_AT_RISK: "⚠", STATUS_BREACHING: "✗"}
        for s in sla:
            lines.append(
                f"  {s['severity']:<10}  "
                f"{s['current_mttr_hours']:>8.1f}h       "
                f"{s['sla_deadline_hours']:>8.0f}h     "
                f"{s['status']} {marker.get(s['status'], '')}"
            )
        lines.append("")
    lines.append(result.get("model_note", ""))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Linear-trend posture-score forecast over out.v0.1 assessments.",
    )
    parser.add_argument(
        "history",
        type=Path,
        help="directory of stave apply --format json output files",
    )
    parser.add_argument(
        "--horizon", type=int, default=90, help="forecast horizon in days"
    )
    parser.add_argument(
        "--sla-profile",
        type=Path,
        default=None,
        help="JSON file mapping severity → deadline hours",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format",
    )
    args = parser.parse_args(argv)

    assessments = load_assessments(args.history)
    if len(assessments) < 7:
        sys.stderr.write(
            f"forecast requires at least 7 assessment files (found {len(assessments)})\n"
        )
        return 2

    score_history = [compute_score(a) for a in assessments]
    slope, intercept = linear_fit(score_history)
    n = len(score_history)
    current = score_history[-1]
    projected = max(0.0, min(100.0, intercept + slope * (n + args.horizon - 1)))

    sla = load_sla(args.sla_profile)
    mttr_history = build_mttr_history(assessments)
    sla_proj = project_sla(mttr_history, sla, args.horizon)

    result = {
        "current": {"posture_score": round(current, 2)},
        "projected": {
            "horizon_days": args.horizon,
            "posture_score": round(projected, 2),
            "score_slope_per_day": round(slope, 4),
        },
        "sla_projections": sla_proj,
        "model_note": (
            f"Linear projection from {n} days of history. "
            "Accuracy decreases beyond 30-day horizon. "
            "Rerun weekly for updated projections."
        ),
    }

    if args.format == "json":
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_table(result, args.horizon))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
