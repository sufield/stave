#!/usr/bin/env python3
"""Reasoning trace linker — unify findings + facts + engine summaries.

Reads what the demo produced and emits one JSON document that links each
CEL finding to its contributing SIR facts (with provenance + freshness)
and surfaces every engine's verdict against the same fact base. The
narrative scripts read this single file instead of doing bespoke
parsing across five.

Implementation note — file shapes are read, not assumed.
The summary files the demo emits today have shapes that differ from
the iteration-4 spec sketch (e.g. prove-summary.json's `queries` is an
array of {name,z3,cvc5,yices} objects, not a dict; clingo reports
`clingo_atoms` not `violations`; quantify-summary lacks tlaplus /
pysat / prolog blocks because those engines aren't part of the
nodes-2026 demo). This linker reads what's actually present and skips
engines whose summaries are missing — it does NOT force the demo into
the spec's shape. Adding a new engine summary later is a localised
edit to the relevant adapter function below.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any


# =====================================================
# Loaders. Tolerant — missing files come back empty.
# =====================================================

def load_json(path: Path | None) -> dict:
    if not path or not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        sys.stderr.write(f"warning: {path} is not valid JSON ({e}); skipping\n")
        return {}


def load_jsonl(path: Path) -> list[dict]:
    facts = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            facts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return facts


# =====================================================
# Engine adapters — one function per summary file. Each
# returns a dict that lands under the trace's
# `engine_verdicts` block, or None when the engine
# didn't produce parseable output.
# =====================================================

def adapt_cel(findings: list[dict]) -> dict:
    """CEL is the source of findings; presence == verdict."""
    return {
        "verdict": "non_compliant" if findings else "compliant",
        "findings_count": len(findings),
    }


def adapt_prove(prove: dict) -> dict | None:
    """prove-summary.json has a queries array; one entry per Z3 query."""
    queries = prove.get("queries")
    if not queries:
        return None
    out = {"queries": []}
    for q in queries:
        out["queries"].append({
            "name": q.get("name"),
            "z3": q.get("z3"),
            "cvc5": q.get("cvc5"),
            "yices": q.get("yices"),
        })
    # Roll-up verdict: any sat = unsafe, all unsat = safe.
    z3_verdicts = {q.get("z3") for q in queries}
    if "sat" in z3_verdicts:
        out["verdict"] = "sat"
    elif z3_verdicts and z3_verdicts <= {"unsat", "(skipped)"}:
        out["verdict"] = "unsat"
    else:
        out["verdict"] = "mixed"
    return out


def adapt_souffle(enumerate_data: dict) -> dict | None:
    counts = enumerate_data.get("souffle_counts")
    if not counts:
        return None
    total = sum(v for v in counts.values() if isinstance(v, int))
    return {
        "verdict": f"{total} reachable rows",
        "counts": counts,
    }


def adapt_clingo(enumerate_data: dict) -> dict | None:
    if enumerate_data.get("clingo_skipped"):
        return None
    atoms = enumerate_data.get("clingo_atoms")
    if atoms is None:
        return None
    return {
        "verdict": f"{len(atoms)} violation(s)" if atoms else "no violations",
        "atoms": atoms,
    }


def adapt_risk(quantify: dict) -> dict | None:
    if "risk_percent" not in quantify:
        return None
    pct = quantify["risk_percent"]
    return {
        "verdict": f"P={pct}%",
        "probability": round(pct / 100.0, 4),
    }


def adapt_game_theory(quantify: dict) -> dict | None:
    cheap = quantify.get("cheapest_path")
    if not cheap:
        return None
    out = {
        "verdict": f"${cheap.get('cost')} attack",
        "cheapest_path": cheap,
    }
    if "next_cheapest_path" in quantify:
        out["next_cheapest_path"] = quantify["next_cheapest_path"]
    if "top_remediation" in quantify:
        out["top_remediation"] = quantify["top_remediation"]
    return out


def adapt_contrast(contrast: dict) -> dict | None:
    """contrast-summary.json carries the before/after deltas the demo
    renders in step 10 — preserved verbatim so consumers don't
    re-parse the same data."""
    if not contrast:
        return None
    rows = contrast.get("rows")
    if rows is None:
        return None
    return {
        "rows": rows,
        "config_changes": contrast.get("config_changes", []),
        "total_defender_cost": contrast.get("total_defender_cost"),
    }


# =====================================================
# Per-finding linking.
# =====================================================

def resolve_contributing_facts(finding: dict, fact_index: dict) -> list[dict]:
    """For each fact_id on the finding, project the matching JSONL
    record into the trace shape (predicate, object, provenance,
    freshness). Unknown ids — possible if facts.jsonl was generated
    against different controls — drop silently."""
    out = []
    for fid in finding.get("contributing_fact_ids", []) or []:
        fact = fact_index.get(fid)
        if not fact:
            continue
        out.append({
            "fact_id": fid,
            "predicate": fact.get("predicate"),
            "object": fact.get("object"),
            "provenance": fact.get("provenance"),
            "freshness": fact.get("freshness"),
        })
    return out


# =====================================================
# Attack chain — predicate-driven, no inference.
# =====================================================

# Order matters: each predicate marks one structural step in the
# Cognito → IAM → resource chain. When a fact carrying the predicate
# exists in the JSONL, it becomes a step. When it doesn't, the step
# is absent — the chain reflects what the fixture actually contains,
# not what the demo's narrative claims.
CHAIN_PREDICATES = [
    ("allows_unauthenticated", "Identity pool allows unauthenticated access"),
    ("self_registration_unrestricted", "User pool allows self-registration"),
    ("maps_unauth_to", "Pool maps unauthenticated users to IAM role"),
    ("maps_auth_to", "Pool maps authenticated users to IAM role"),
    ("trusts_service", "Role trusts compute service"),
    ("has_action", "Role has action grant"),
    ("has_resource", "Role can access resource"),
    ("resource_policy_principal", "Resource policy grants access to principal"),
    ("resource_policy_action", "Resource policy allows action"),
]


def build_attack_chain(facts: list[dict]) -> dict | None:
    by_pred: dict[str, list[dict]] = {}
    for f in facts:
        by_pred.setdefault(f.get("predicate"), []).append(f)
    steps = []
    step_num = 1
    for pred, description in CHAIN_PREDICATES:
        for fact in by_pred.get(pred, []):
            prov = fact.get("provenance") or {}
            steps.append({
                "step": step_num,
                "description": description,
                "fact_id": fact.get("fact_id"),
                "predicate": pred,
                "object": fact.get("object"),
                "subject": fact.get("subject"),
                "property_path": prov.get("property_path"),
            })
            step_num += 1
    if not steps:
        return None
    return {"steps": steps}


# =====================================================
# Top-level builder.
# =====================================================

def build_trace(
    findings_data: dict,
    facts: list[dict],
    prove: dict,
    enumerate_data: dict,
    quantify: dict,
    contrast: dict,
    *,
    fixture: str = "",
    now: str | None = None,
) -> dict:
    fact_index = {f["fact_id"]: f for f in facts if f.get("fact_id")}
    findings = findings_data.get("findings", []) or []

    engine_verdicts: dict[str, Any] = {"cel": adapt_cel(findings)}
    for name, value in [
        ("z3", adapt_prove(prove)),
        ("souffle", adapt_souffle(enumerate_data)),
        ("clingo", adapt_clingo(enumerate_data)),
        ("risk", adapt_risk(quantify)),
        ("game_theory", adapt_game_theory(quantify)),
        ("contrast", adapt_contrast(contrast)),
    ]:
        if value is not None:
            engine_verdicts[name] = value

    consensus = derive_consensus(engine_verdicts)

    annotated_findings = []
    for f in findings:
        annotated_findings.append({
            "control_id": f.get("control_id"),
            "control_name": f.get("control_name"),
            "asset_id": f.get("asset_id"),
            "control_severity": f.get("control_severity"),
            "classification": f.get("classification"),
            "contributing_facts": resolve_contributing_facts(f, fact_index),
        })

    # Quantification — one block, derived from the same summaries.
    q: dict[str, Any] = {}
    if "risk_percent" in quantify:
        q["exploitation_probability"] = round(quantify["risk_percent"] / 100.0, 4)
    if "cheapest_path" in quantify:
        q["attacker_cost"] = quantify["cheapest_path"].get("cost")
    if "top_remediation" in quantify:
        tr = quantify["top_remediation"]
        q["remediation_cost"] = tr.get("defender_cost")
        q["remediation_roi"] = tr.get("roi")
    sf = enumerate_data.get("souffle_counts") or {}
    if "anonymous_reachable" in sf:
        q["anonymous_reachable"] = sf["anonymous_reachable"]
    if "reachable" in sf:
        q["total_reachable"] = sf["reachable"]

    trace = {
        "generated_at": now or datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "fixture": fixture or prove.get("fixture") or contrast.get("fixture") or "",
        "consensus": consensus,
        "engines_reporting": len(engine_verdicts),
        "engine_verdicts": engine_verdicts,
        "findings": annotated_findings,
    }
    chain = build_attack_chain(facts)
    if chain:
        trace["attack_chain"] = chain
    if q:
        trace["quantification"] = q
    return trace


def derive_consensus(engine_verdicts: dict) -> str:
    """Coarse roll-up: any engine reporting unsafe puts the trace in
    UNSAFE; all engines reporting safe = SAFE; nothing reporting =
    NO_DATA. Mid-points (some safe, some unsafe) report DISAGREEMENT
    so a reader knows to investigate."""
    unsafe = safe = 0
    for name, v in engine_verdicts.items():
        verdict = (v or {}).get("verdict") or ""
        s = str(verdict).lower()
        # Heuristics tuned to the actual verdict strings each adapter
        # emits. Update here when adding a new adapter.
        if name == "cel":
            (unsafe := unsafe + 1) if v.get("findings_count") else (safe := safe + 1)
        elif name == "z3":
            (unsafe := unsafe + 1) if "sat" in s and "unsat" not in s else (safe := safe + 1) if "unsat" in s else None
        elif name == "souffle":
            counts = v.get("counts", {})
            anon = counts.get("anonymous_reachable", 0) or counts.get("self_register_reachable", 0)
            (unsafe := unsafe + 1) if anon else (safe := safe + 1)
        elif name == "clingo":
            (unsafe := unsafe + 1) if v.get("atoms") else (safe := safe + 1)
        elif name == "risk":
            (unsafe := unsafe + 1) if (v.get("probability") or 0) > 0 else (safe := safe + 1)
        elif name == "game_theory":
            (unsafe := unsafe + 1) if v.get("cheapest_path") else (safe := safe + 1)
    if unsafe and not safe:
        return "UNSAFE"
    if safe and not unsafe:
        return "SAFE"
    if unsafe and safe:
        return "DISAGREEMENT"
    return "NO_DATA"


# =====================================================
# CLI.
# =====================================================

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--facts", required=True, type=Path)
    parser.add_argument("--prove", type=Path, default=None)
    parser.add_argument("--enumerate", type=Path, default=None,
                        dest="enumerate_path",
                        help="path to enumerate-summary.json")
    parser.add_argument("--quantify", type=Path, default=None)
    parser.add_argument("--contrast", type=Path, default=None,
                        help="optional contrast-summary.json from demo step 10")
    parser.add_argument("--fixture", default="",
                        help="fixture label for the trace (e.g. capital-one/writeup-config)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--now", default=None,
                        help="RFC3339 UTC timestamp pinning generated_at "
                             "(e.g. 2026-01-09T00:00:00Z); without it, wall-clock is used")
    args = parser.parse_args()

    findings_data = load_json(args.findings)
    facts = load_jsonl(args.facts)
    trace = build_trace(
        findings_data=findings_data,
        facts=facts,
        prove=load_json(args.prove),
        enumerate_data=load_json(args.enumerate_path),
        quantify=load_json(args.quantify),
        contrast=load_json(args.contrast),
        fixture=args.fixture,
        now=args.now,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(trace, indent=2, default=str) + "\n")

    print(f"reasoning trace: {args.output}")
    print(f"  fixture:           {trace['fixture'] or '(unspecified)'}")
    print(f"  findings:          {len(trace['findings'])}")
    print(f"  engines reporting: {trace['engines_reporting']}")
    print(f"  consensus:         {trace['consensus']}")
    if "attack_chain" in trace:
        print(f"  chain steps:       {len(trace['attack_chain']['steps'])}")
    q = trace.get("quantification", {})
    if "exploitation_probability" in q:
        print(f"  P(exploitation):   {q['exploitation_probability']}")
    if "attacker_cost" in q:
        print(f"  attacker cost:     ${q['attacker_cost']}")
    if "remediation_cost" in q:
        print(f"  remediation cost:  ${q['remediation_cost']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
