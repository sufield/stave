#!/usr/bin/env python3
"""PySAT: compound-chain satisfiability check.

Given a JSONL fact export from `stave export-sir --format jsonl`,
encodes each chain member control as a boolean variable and asks:
"can all member controls of a compound chain fail simultaneously?"

  SAT   → yes, every member can be in its violating state at the
          same time. The chain is genuinely triggerable.
  UNSAT → no, at least one member must be in its compliant state.
          A direct contradiction in the predicate set (e.g.,
          mutually exclusive observed values) makes the chain
          unreachable as encoded.

This is a starter template. A production implementation would
encode the chain's escalation threshold as a cardinality
constraint, model per-asset rather than catalog-wide
satisfiability, and chain-walk role assumptions instead of
treating each predicate independently. The aim here is to show
the pattern, not the production encoding.

Usage:
    pip install python-sat
    python3 compound_sat.py facts.jsonl [predicate1,predicate2,...]
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict


def load_facts(path: str) -> dict[str, list[tuple[str, str]]]:
    """Load JSONL triples grouped by predicate."""
    by_predicate: dict[str, list[tuple[str, str]]] = defaultdict(list)
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            triple = json.loads(line)
            pred = triple.get("predicate")
            subj = triple.get("subject")
            obj = triple.get("object")
            if pred and subj is not None:
                by_predicate[pred].append((str(subj), str(obj)))
    return by_predicate


def check_compound(by_predicate: dict[str, list[tuple[str, str]]], predicates: list[str]) -> str:
    """Check whether all given predicates can be satisfied simultaneously.

    Each predicate becomes a boolean variable. A predicate is
    "satisfiable" if at least one fact carries it. The CNF
    asserts that every named predicate is true; the solver
    decides whether the combination is consistent.
    """
    try:
        from pysat.solvers import Glucose3
        from pysat.formula import CNF
    except ImportError:
        print("Install python-sat first: pip install python-sat", file=sys.stderr)
        sys.exit(127)

    cnf = CNF()
    var_map: dict[str, int] = {}
    counter = 1

    for pred in predicates:
        if pred not in var_map:
            var_map[pred] = counter
            counter += 1
        # The predicate must hold (positive unit clause).
        cnf.append([var_map[pred]])
        # If the predicate has no supporting facts in the export,
        # also assert its negation — the conjunction becomes UNSAT.
        if pred not in by_predicate or not by_predicate[pred]:
            cnf.append([-var_map[pred]])

    solver = Glucose3()
    solver.append_formula(cnf)
    try:
        return "SAT" if solver.solve() else "UNSAT"
    finally:
        solver.delete()


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 compound_sat.py <facts.jsonl> [predicate1,predicate2,...]", file=sys.stderr)
        return 2

    facts = load_facts(sys.argv[1])
    total_triples = sum(len(v) for v in facts.values())
    print(f"Loaded {total_triples} triples across {len(facts)} distinct predicates.")

    if len(sys.argv) > 2:
        predicates = [p.strip() for p in sys.argv[2].split(",") if p.strip()]
    else:
        # Default: pick a small handful of well-known "violating
        # state" predicates. Adjust to your compound of interest.
        predicates = [
            "has_agent_lambda_scope_broad",
            "has_agent_guardrail",
            "has_agent_invocation_logging",
        ]
    print(f"Checking joint satisfiability of {len(predicates)} predicate(s):")
    for p in predicates:
        n = len(facts.get(p, []))
        print(f"  - {p}: {n} fact(s)")

    result = check_compound(facts, predicates)
    print()
    if result == "SAT":
        print("RESULT: SAT — every named predicate has at least one supporting fact.")
        print("The compound chain's member conditions can hold simultaneously.")
    else:
        print("RESULT: UNSAT — at least one predicate has no supporting facts.")
        print("The compound chain is not triggerable from this snapshot.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
