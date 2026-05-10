#!/usr/bin/env python3
"""
Run forbidden_state queries against a before / after observation
pair and report which queries flipped verdicts.

The verdict comparison uses the auto-generated forbidden_state
queries from `examples/z3-forbidden-state/compile.py` together
with per-fixture fact bindings from
`examples/z3-forbidden-state/obs_to_facts.py`. Each per-fixture
fact file binds only the property variables a query references,
so Z3 runs in milliseconds — orders of magnitude faster than
running queries against the full SIR with closed-world axioms.

Verdict semantics:
    UNSAT → SAT     REGRESSION  — perturbation introduced a new reachable unsafe state
    SAT   → UNSAT   IMPROVEMENT — perturbation closed a previously reachable unsafe state
    UNSAT → UNSAT   NO_CHANGE   — safe before, safe after
    SAT   → SAT     NO_CHANGE   — reachable before, reachable after (the change didn't move this invariant)

For each verdict flip the report ties the cause to the fact-set
delta (read from delta.json produced by diff.py): which added or
removed facts plausibly drove the flip.

Usage:
    impact.py <before-obs-dir> <after-obs-dir> <invariants.json> \
              <delta.json> <output.json>
"""

import json
import os
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FORBIDDEN_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "z3-forbidden-state"))
COMPILE_PY = os.path.join(FORBIDDEN_DIR, "compile.py")
OBS_TO_FACTS_PY = os.path.join(FORBIDDEN_DIR, "obs_to_facts.py")


def run_z3(facts_path: str, query_path: str) -> str:
    """Concatenate query + facts + (check-sat), invoke z3, return first verdict line."""
    with open(query_path) as f:
        query = f.read()
    with open(facts_path) as f:
        facts = f.read()
    payload = query + "\n" + facts + "\n(check-sat)\n"
    result = subprocess.run(
        ["z3", "-in", "-T:30"],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout or result.stderr).strip().splitlines()
    if not output:
        return "error: empty output"
    return output[0].strip()


def severity_for_flip(before: str, after: str) -> str:
    if before == "unsat" and after == "sat":
        return "REGRESSION"
    if before == "sat" and after == "unsat":
        return "IMPROVEMENT"
    return "NO_CHANGE"


def render_facts(invariants: str, obs_dir: str, out_path: str) -> None:
    subprocess.run(
        ["python3", OBS_TO_FACTS_PY, invariants, obs_dir, out_path],
        check=True,
        capture_output=True,
    )


def compile_queries(invariants: str, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    subprocess.run(
        ["python3", COMPILE_PY, invariants, out_dir],
        check=True,
        capture_output=True,
    )
    return sorted(
        os.path.join(out_dir, q) for q in os.listdir(out_dir) if q.endswith(".smt2")
    )


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: impact.py <before-obs-dir> <after-obs-dir> "
            "<invariants.json> <delta.json> <output.json>",
            file=sys.stderr,
        )
        return 2

    before_obs = sys.argv[1]
    after_obs = sys.argv[2]
    invariants = sys.argv[3]
    delta_path = sys.argv[4]
    out_path = sys.argv[5]

    with open(delta_path) as f:
        delta = json.load(f)
    added_ids = [f["fact_id"] for f in delta.get("added_facts", [])]
    removed_ids = [f["fact_id"] for f in delta.get("removed_facts", [])]

    with tempfile.TemporaryDirectory() as tmp:
        before_facts = os.path.join(tmp, "before.facts.smt2")
        after_facts = os.path.join(tmp, "after.facts.smt2")
        queries_dir = os.path.join(tmp, "queries")

        render_facts(invariants, before_obs, before_facts)
        render_facts(invariants, after_obs, after_facts)
        queries = compile_queries(invariants, queries_dir)

        new_unsafe: list = []
        resolved: list = []
        unchanged: list = []
        for q in queries:
            name = os.path.basename(q)
            before_v = run_z3(before_facts, q)
            after_v = run_z3(after_facts, q)
            flip = severity_for_flip(before_v, after_v)
            if flip == "REGRESSION":
                new_unsafe.append({
                    "query": name,
                    "before": before_v,
                    "after": after_v,
                    "added_fact_ids": added_ids,
                    "interpretation": "perturbation introduced facts that make the forbidden state reachable",
                })
            elif flip == "IMPROVEMENT":
                resolved.append({
                    "query": name,
                    "before": before_v,
                    "after": after_v,
                    "removed_fact_ids": removed_ids,
                    "interpretation": "perturbation removed facts that previously made the forbidden state reachable",
                })
            else:
                unchanged.append({"query": name, "verdict": before_v})

    report = {
        "new_unsafe_states": new_unsafe,
        "resolved_unsafe_states": resolved,
        "unchanged_states": unchanged,
        "summary": {
            "queries_evaluated": len(new_unsafe) + len(resolved) + len(unchanged),
            "regressions": len(new_unsafe),
            "improvements": len(resolved),
            "no_change": len(unchanged),
        },
    }
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(
        f"  {report['summary']['queries_evaluated']} queries: "
        f"{report['summary']['regressions']} regressions, "
        f"{report['summary']['improvements']} improvements, "
        f"{report['summary']['no_change']} unchanged",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
