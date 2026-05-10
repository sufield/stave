#!/usr/bin/env python3
"""Counterfactual remediation simulator over a Stave assessment.

Replicates the role of `internal/app/simulate/` and the `stave
simulate` subcommand without depending on Stave Go internals — reads
a stave apply --format json output, takes a list of control IDs to
"fix", and reports:

  • Findings eliminated (count)
  • Compound chains that would deactivate (members below threshold)
  • Posture-score delta (current vs simulated)

The chain-deactivation calculation needs the chain definition's
`escalation_threshold` and member set. Either read both from
`compound_findings[].definition` if your stave version emits them,
or supply them via --chains-file (a small JSON or YAML map).

Pure stdlib by design (matches `forecast/forecast.py` and
`prism-risk-prioritization/risk_model.py`). Counterfactual logic
is set arithmetic — no SAT/SMT needed for the "what if I removed
THESE finding rows?" question; the chain composition rule is a
threshold check.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Severity weights for the posture score. Same constants as
# forecast/forecast.py — keeping them in lockstep so
# the score the simulator prints matches what the trend
# reporter would have shown for the same assessment.
SEVERITY_WEIGHT = {
    "critical": 20.0,
    "high": 10.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5,
}

# Improvement attribution factor for finding removal. Mirrors the
# 0.6 in internal/app/simulate/simulate.go — fixing every finding
# does not get you to a perfect 100 because some posture loss
# (configuration debt, audit gaps) is structural.
IMPROVEMENT_FACTOR = 0.6

# Posture bonus per chain that deactivates. Mirrors the +2.0 in
# internal/app/simulate/simulate.go.
CHAIN_BONUS = 2.0

STATUS_DEACTIVATED = "DEACTIVATED"


def severity_of(finding: dict[str, Any]) -> str:
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


def compute_score(findings: list[dict[str, Any]]) -> float:
    if not findings:
        return 100.0
    deduction = sum(
        SEVERITY_WEIGHT.get(severity_of(f), SEVERITY_WEIGHT["medium"])
        for f in findings
    )
    return max(0.0, min(100.0, 100.0 - deduction))


def load_chains(path: Path | None) -> dict[str, dict[str, Any]]:
    """Read a chain-definitions file. None → empty dict."""
    if path is None:
        return {}
    with path.open() as fh:
        if path.suffix in (".yaml", ".yml"):
            return load_yaml_chains(fh)
        return json.load(fh)


def load_yaml_chains(stream: Any) -> dict[str, dict[str, Any]]:
    """Tiny YAML subset reader for chain definitions.

    Recognises:
        chains:
          - id: cognito_weakauth
            escalation_threshold: 2
            members:
              - CTL.COGNITO.PASSWORD.001
              - CTL.COGNITO.MFA.001
            severity: critical

    Sufficient for the example fixtures shipped here. Operators
    with richer YAML can pre-convert to JSON.
    """
    out: dict[str, dict[str, Any]] = {}
    cur: dict[str, Any] | None = None
    in_members = False
    for raw in stream:
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if indent == 0 and stripped == "chains:":
            continue
        if stripped.startswith("- id:") and indent <= 2:
            cur = {"members": []}
            cur["id"] = stripped.split(":", 1)[1].strip()
            out[cur["id"]] = cur
            in_members = False
            continue
        if cur is None:
            continue
        if stripped.startswith("escalation_threshold:"):
            cur["escalation_threshold"] = int(
                stripped.split(":", 1)[1].strip()
            )
            in_members = False
        elif stripped.startswith("severity:"):
            cur["severity"] = stripped.split(":", 1)[1].strip()
            in_members = False
        elif stripped.startswith("members:"):
            in_members = True
        elif in_members and stripped.startswith("- "):
            cur["members"].append(stripped[2:].strip())
        else:
            in_members = False
    return out


def derive_chains_from_assessment(
    assessment: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Fallback when no --chains-file is given: read whatever chain
    structure the assessment carries (out.v0.1 emits at least the
    failing-control list per chain finding)."""
    chains: dict[str, dict[str, Any]] = {}
    for cf in assessment.get("compound_findings", []) or []:
        cid = cf.get("chain_id") or cf.get("ChainID")
        if not cid:
            continue
        members = (
            cf.get("controls_failing")
            or cf.get("ControlsFailing")
            or []
        )
        # Without an explicit threshold we conservatively assume the
        # chain fired with all-members-failing, so any single fix
        # would deactivate it. This matches the simulator's spirit
        # (operators get a generous estimate; rerun stave apply for
        # the authoritative answer).
        chains[cid] = {
            "id": cid,
            "members": list(members),
            "escalation_threshold": max(1, len(members)),
            "severity": cf.get("severity") or cf.get("Severity") or "high",
        }
    return chains


def simulate(
    assessment: dict[str, Any],
    fix_controls: list[str],
    chains: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    findings = assessment.get("findings", []) or []
    fix_set = set(fix_controls)
    current_score = compute_score(findings)

    # Findings that would be removed.
    remaining: list[dict[str, Any]] = []
    removed = 0
    for f in findings:
        if str(f.get("control_id", "")) in fix_set:
            removed += 1
        else:
            remaining.append(f)

    # Compound chains that would deactivate.
    deactivated: list[dict[str, Any]] = []
    for cid, ch in chains.items():
        members = list(ch.get("members", []))
        threshold = int(ch.get("escalation_threshold", 1))
        if not members:
            continue
        # The chain currently fires only if at least `threshold`
        # members were failing — count those in the assessment.
        currently_failing = sum(
            1 for f in findings
            if str(f.get("control_id", "")) in members
        )
        if currently_failing < threshold:
            # Already not firing; the simulation can't deactivate it.
            continue
        remaining_failing = sum(
            1 for m in members if m not in fix_set
            and any(
                str(f.get("control_id", "")) == m and m not in fix_set
                for f in findings
            )
        )
        if remaining_failing < threshold:
            deactivated.append(
                {
                    "chain_id": cid,
                    "severity": ch.get("severity", "high"),
                    "status": STATUS_DEACTIVATED,
                }
            )

    # Posture score delta — same shape as
    # internal/app/simulate/simulate.go: proportional to findings
    # removed plus a fixed bonus per deactivated chain.
    sim_score = current_score
    if findings:
        improvement_ratio = removed / len(findings)
        max_improvement = 100.0 - current_score
        sim_score += max_improvement * improvement_ratio * IMPROVEMENT_FACTOR
    sim_score += len(deactivated) * CHAIN_BONUS
    sim_score = max(0.0, min(100.0, sim_score))

    return {
        "controls_fixed": fix_controls,
        "score_current": round(current_score, 2),
        "score_simulated": round(sim_score, 2),
        "score_delta": round(sim_score - current_score, 2),
        "findings_removed": removed,
        "findings_remaining": len(remaining),
        "chains_deactivated": deactivated,
        "model_note": (
            "Counterfactual simulation: findings removed = exact, "
            "chain deactivation = exact (threshold check on remaining "
            "members), score delta = approximate proportional model. "
            "Rerun `stave apply` after the fix lands for the "
            "authoritative posture."
        ),
    }


def render_table(result: dict[str, Any]) -> str:
    fix_list = ", ".join(result["controls_fixed"]) or "(none)"
    lines = [
        "REMEDIATION SIMULATION",
        f"Fixing: {fix_list}",
        "",
        "POSTURE SCORE",
        f"  Current:    {result['score_current']:.1f}",
        f"  Simulated:  {result['score_simulated']:.1f}  ({result['score_delta']:+.1f})",
        "",
    ]
    chains = result["chains_deactivated"]
    if chains:
        lines.append("CHAINS DEACTIVATED")
        for c in chains:
            lines.append(
                f"  {c['chain_id']:<40} {c['severity'].upper()} → {c['status']}"
            )
        lines.append("")
    lines.append(f"FINDINGS ELIMINATED: {result['findings_removed']}")
    lines.append(f"FINDINGS REMAINING:  {result['findings_remaining']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Counterfactual remediation simulator over a Stave assessment.",
    )
    parser.add_argument(
        "--assessment",
        type=Path,
        required=True,
        help="stave apply --format json output",
    )
    parser.add_argument(
        "--fix",
        action="append",
        default=[],
        help="control ID to simulate fixing (repeatable)",
    )
    parser.add_argument(
        "--chains-file",
        type=Path,
        default=None,
        help=(
            "JSON or YAML file with chain definitions "
            "(falls back to deriving from assessment)"
        ),
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
    )
    args = parser.parse_args(argv)

    if not args.fix:
        sys.stderr.write("error: at least one --fix CONTROL_ID is required\n")
        return 2

    with args.assessment.open() as fh:
        assessment = json.load(fh)

    chains = load_chains(args.chains_file) or derive_chains_from_assessment(
        assessment
    )
    result = simulate(assessment, args.fix, chains)

    if args.format == "json":
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_table(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
