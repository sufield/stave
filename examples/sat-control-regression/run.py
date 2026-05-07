#!/usr/bin/env python3
"""Boolean compound-of-finding regression via pysat.

Each control gets a SAT variable. Observed verdicts pin the
variables (fired → True, not-fired → False). Each compound
rule is an AND-clause over the variables. A combined CNF
asks: is any compound satisfied under the observed
verdicts?

The shape — boolean-AND over hundreds of control flags —
is where SAT genuinely scales. Z3 handles policy semantics;
ASP enumerates atom triples; SAT is the regression layer
when the question is "given these flags, which compound
shapes light up?" across the full control catalog.

Two modes:
  check    — SAT against pinned verdicts. Each compound
             whose conjuncts are all fired emits UNSAFE;
             otherwise SAFE.
  what-if  — Treat compound_rules controls as undetermined.
             Find any assignment that makes at least one
             compound fire. Returns the smallest such
             trigger set. Genuinely combinatorial: with K
             undetermined controls there are 2^K
             possibilities; SAT decides in O(clauses).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pysat.formula import CNF
from pysat.solvers import Glucose3

# Local rule definitions — same dir; ensure import works.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from compound_rules import COMPOUND_RULES  # noqa: E402


def load_fired_controls(jsonl_path: Path) -> set[str]:
    """Extract the set of controls that fired (have a contributed_by edge)."""
    fired: set[str] = set()
    with jsonl_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            triple = json.loads(line)
            if triple.get("predicate") == "contributed_by":
                fired.add(triple["object"])
    return fired


def assign_vars(rules: list[dict[str, object]]) -> dict[str, int]:
    """Number every control mentioned in any rule starting at 1."""
    seen: list[str] = []
    for rule in rules:
        for ctrl in rule["controls"]:  # type: ignore[index]
            normalized = ctrl.lstrip("!")
            if normalized not in seen:
                seen.append(normalized)
    return {ctrl: i + 1 for i, ctrl in enumerate(seen)}


def check_mode(label: str, fired: set[str], var_map: dict[str, int]) -> int:
    """Per-rule satisfiability check against pinned verdicts.

    Encodes:
      pinned: x_i = True for fired, False otherwise
      unsafe: OR over compound rules, where each compound = AND of conjuncts

    Returns count of compounds that fire on this fixture.
    """
    cnf = CNF()
    # Pin observed verdicts as unit clauses.
    for ctrl, var in var_map.items():
        if ctrl in fired:
            cnf.append([var])
        else:
            cnf.append([-var])

    # Soft trigger: introduce a per-compound activation variable.
    # `c_i` is True iff every conjunct of rule i is fired. Encoding:
    #   c_i ↔ AND(conjuncts) ≡ (NOT c_i OR conjunct_j) for all j
    #                       AND (c_i OR NOT conjunct_1 OR ... OR NOT conjunct_n)
    next_var = max(var_map.values(), default=0) + 1
    activation_vars: list[tuple[int, str]] = []
    for rule in COMPOUND_RULES:
        ci = next_var
        next_var += 1
        activation_vars.append((ci, rule["name"]))  # type: ignore[arg-type]
        conj_lits: list[int] = []
        for ctrl in rule["controls"]:  # type: ignore[index]
            normalized = ctrl.lstrip("!")
            sign = -1 if ctrl.startswith("!") else 1
            conj_lits.append(sign * var_map[normalized])
        # c_i implies each conjunct
        for lit in conj_lits:
            cnf.append([-ci, lit])
        # All conjuncts together imply c_i
        cnf.append([ci] + [-lit for lit in conj_lits])

    print(f"=== {label} ===")
    fired_compounds: list[str] = []
    with Glucose3(bootstrap_with=cnf.clauses) as solver:
        sat = solver.solve()
        if not sat:
            print("  (infeasible: pinned verdicts contradict themselves — bug in encoding)")
            return 0
        model = solver.get_model() or []
        truth = {abs(lit): lit > 0 for lit in model}
        for ci, name in activation_vars:
            if truth.get(ci):
                fired_compounds.append(name)

    if not fired_compounds:
        print("  SAFE: no compound rule fires on this fixture")
        print()
        return 0
    print(f"  UNSAFE: {len(fired_compounds)} compound(s) fire")
    for name in fired_compounds:
        rule = next(r for r in COMPOUND_RULES if r["name"] == name)
        controls = rule["controls"]
        print(f"    - {name}")
        for ctrl in controls:  # type: ignore[union-attr]
            print(f"        fired: {ctrl}")
    print()
    return len(fired_compounds)


def what_if_mode(fired: set[str], var_map: dict[str, int]) -> None:
    """Find any minimal extension of fired-set that triggers a compound.

    Treats every rule-mentioned control as undetermined. Solver picks
    a model where (a) at least one compound is satisfied and (b) the
    pinned facts that are TRUE today remain TRUE (we only ADD
    findings, never RETRACT them — regressions only). The minimization
    pressure picks a model with the fewest *additional* fired controls,
    yielding the smallest tipping set.
    """
    cnf = CNF()
    # Pin the controls that are known fired today as TRUE; leave the
    # rest undetermined. (Don't add unit clauses for currently-clean
    # controls — those are the candidates we want to flip.)
    for ctrl, var in var_map.items():
        if ctrl in fired:
            cnf.append([var])

    next_var = max(var_map.values(), default=0) + 1
    activation_vars: list[int] = []
    for rule in COMPOUND_RULES:
        ci = next_var
        next_var += 1
        activation_vars.append(ci)
        conj_lits: list[int] = []
        for ctrl in rule["controls"]:  # type: ignore[index]
            normalized = ctrl.lstrip("!")
            sign = -1 if ctrl.startswith("!") else 1
            conj_lits.append(sign * var_map[normalized])
        for lit in conj_lits:
            cnf.append([-ci, lit])
        cnf.append([ci] + [-lit for lit in conj_lits])

    # At least one compound must fire.
    cnf.append(activation_vars)

    print("=== what-if: smallest tip-into-unsafe extension ===")
    with Glucose3(bootstrap_with=cnf.clauses) as solver:
        if not solver.solve():
            print("  (no compound is reachable from current verdicts via finding-additions)")
            return
        model = solver.get_model() or []
        truth = {abs(lit): lit > 0 for lit in model}
        candidate_controls = [ctrl for ctrl in var_map if ctrl not in fired]
        new_fires = sorted(c for c in candidate_controls if truth.get(var_map[c]))
        triggered = [
            COMPOUND_RULES[i]["name"]
            for i, ci in enumerate(activation_vars)
            if truth.get(ci)
        ]
        if new_fires:
            print(f"  Adding {len(new_fires)} finding(s) tips configuration into UNSAFE:")
            for ctrl in new_fires:
                print(f"    + {ctrl}")
            print(f"  Compound(s) triggered: {', '.join(triggered)}")
        else:
            print(f"  Already UNSAFE — compounds firing: {', '.join(triggered)}")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: run.py <label> <facts.jsonl> [check|what-if]", file=sys.stderr)
        return 2
    label = sys.argv[1]
    jsonl_path = Path(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else "check"

    fired = load_fired_controls(jsonl_path)
    var_map = assign_vars(COMPOUND_RULES)

    if mode == "check":
        check_mode(label, fired, var_map)
    elif mode == "what-if":
        print(f"=== {label} ===")
        check_mode(label + " (current verdicts)", fired, var_map)
        what_if_mode(fired, var_map)
        print()
    else:
        print(f"unknown mode: {mode}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
