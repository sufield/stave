#!/usr/bin/env python3
"""
Run a directory of SMT-LIB queries against a before / after SMT
fact export pair. For each query, capture the verdict on each
side and report verdict flips.

Verdict flip semantics:
    UNSAT → SAT : the perturbation introduced a new reachable
                  unsafe state (was provably impossible, now SAT)
    SAT → UNSAT : the perturbation closed a previously reachable
                  unsafe state (was reachable, now provably
                  impossible)
    UNSAT → UNSAT : safe before, safe after — no flip
    SAT → SAT     : reachable before, reachable after — no flip
                  (the change didn't fix or break this invariant)

The driver appends `(check-sat)` after concatenating facts +
query so query files don't need to carry the call themselves
(matches the convention z3-forbidden-state already uses).

For each verdict flip the report includes the fact-set delta
(read from delta.json produced by diff.py) so the cause can be
attributed to specific added or removed facts.

Usage:
    impact.py <before-facts.smt2> <after-facts.smt2> \
              <queries-dir> <delta.json> <output.json>
"""

import json
import os
import subprocess
import sys


def run_z3(facts_path: str, query_path: str) -> str:
    """Concatenate facts + query, append (check-sat), invoke z3, return first line of stdout."""
    with open(facts_path) as f:
        facts = f.read()
    with open(query_path) as f:
        query = f.read()
    payload = facts + "\n" + query + "\n(check-sat)\n"
    result = subprocess.run(
        ["z3", "-in"],
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
    """Map a verdict-pair to a severity label for the report."""
    if before == "unsat" and after == "sat":
        return "REGRESSION"
    if before == "sat" and after == "unsat":
        return "IMPROVEMENT"
    return "NO_CHANGE"


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: impact.py <before.smt2> <after.smt2> "
            "<queries-dir> <delta.json> <output.json>",
            file=sys.stderr,
        )
        return 2

    before_smt = sys.argv[1]
    after_smt = sys.argv[2]
    queries_dir = sys.argv[3]
    delta_path = sys.argv[4]
    out_path = sys.argv[5]

    with open(delta_path) as f:
        delta = json.load(f)
    added_ids = [f["fact_id"] for f in delta.get("added_facts", [])]
    removed_ids = [f["fact_id"] for f in delta.get("removed_facts", [])]

    queries = sorted(
        os.path.join(queries_dir, q)
        for q in os.listdir(queries_dir)
        if q.endswith(".smt2") or q.endswith(".query.smt2")
    )

    new_unsafe: list = []
    resolved: list = []
    unchanged: list = []

    for q in queries:
        name = os.path.basename(q)
        before_verdict = run_z3(before_smt, q)
        after_verdict = run_z3(after_smt, q)
        flip = severity_for_flip(before_verdict, after_verdict)

        if flip == "REGRESSION":
            new_unsafe.append({
                "query": name,
                "before": before_verdict,
                "after": after_verdict,
                "added_fact_ids": added_ids,
                "interpretation": (
                    "perturbation introduced facts that make the forbidden state reachable"
                ),
            })
        elif flip == "IMPROVEMENT":
            resolved.append({
                "query": name,
                "before": before_verdict,
                "after": after_verdict,
                "removed_fact_ids": removed_ids,
                "interpretation": (
                    "perturbation removed facts that previously made the forbidden state reachable"
                ),
            })
        else:
            unchanged.append({
                "query": name,
                "verdict": before_verdict,
            })

    report = {
        "new_unsafe_states": new_unsafe,
        "resolved_unsafe_states": resolved,
        "unchanged_states": unchanged,
        "summary": {
            "queries_evaluated": len(queries),
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
