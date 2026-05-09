#!/usr/bin/env python3
"""
Compile forbidden_state predicate trees from InvariantExport into
SMT-LIB satisfiability queries.

Input  : InvariantExport JSON (stave export-invariants --format json)
Output : one query.smt2 per control whose forbidden_state is non-empty

The forbidden_state predicate carries the same vocabulary as
unsafe_predicate (any/all + leaf comparisons). Each leaf becomes
an SMT-LIB assertion over a property variable; combiners fold
into (and ...) / (or ...). The query asks Z3 whether the asset
state can simultaneously satisfy the observed facts AND the
forbidden predicate — SAT means the forbidden state is reachable
(VIOLATION), UNSAT means it is impossible (SAFE).

Operator vocabulary mirrors the Go invariant compiler at
experiments/z3-solver/compiler/invariant.go: eq, ne, present,
absent, contains, in. Operators outside this set are over-
approximated as (true) so the query stays sound — the auditor
sees "no constraint" rather than a silent false positive.

Property paths (e.g. "properties.storage.kind") become SMT
variable names by replacing non-identifier characters with "_".
The same sanitiser runs in obs_to_facts.py so the variable names
line up across the facts and query files.
"""

import json
import os
import re
import sys

ABSENT_SENTINEL = "__absent__"


def sanitize_var(path: str) -> str:
    """Map a property path to an SMT-LIB-safe identifier."""
    return re.sub(r"[^A-Za-z0-9_]", "_", path)


def smt_string_lit(value: object) -> str:
    """Render a Python value as an SMT-LIB string literal."""
    if value is None:
        return f'"{ABSENT_SENTINEL}"'
    if isinstance(value, bool):
        return '"true"' if value else '"false"'
    s = str(value).replace('\\', '\\\\').replace('"', '""')
    return f'"{s}"'


def collect_properties(node: dict, into: dict) -> None:
    """Walk the predicate tree, recording (path → SMT var) pairs."""
    if not node:
        return
    combine = node.get("combine", "")
    if combine:
        for child in node.get("children", []) or []:
            collect_properties(child, into)
        return
    prop = node.get("property")
    if prop:
        into[prop] = sanitize_var(prop)


def compile_leaf(node: dict) -> str:
    """Compile a leaf comparison to an SMT-LIB boolean expression."""
    prop = node.get("property", "")
    op = node.get("operator", "")
    expected = node.get("expected")
    var = sanitize_var(prop)

    if not prop:
        return "true"

    if op == "eq":
        return f"(= {var} {smt_string_lit(expected)})"
    if op == "ne":
        return f"(not (= {var} {smt_string_lit(expected)}))"
    if op == "present":
        return f'(not (= {var} "{ABSENT_SENTINEL}"))'
    if op == "absent":
        return f'(= {var} "{ABSENT_SENTINEL}")'
    if op in ("contains", "in"):
        values = expected if isinstance(expected, list) else []
        if not values:
            return "true"
        terms = " ".join(f"(= {var} {smt_string_lit(v)})" for v in values)
        return f"(or {terms})"
    # Unknown operator — over-approximate to keep the query sound.
    return f";; unmodeled operator: {op}\n  true"


def compile_node(node: dict) -> str:
    """Compile a predicate tree node to an SMT-LIB boolean expression."""
    if not node:
        return "true"
    combine = node.get("combine", "")
    if not combine:
        return compile_leaf(node)
    children = node.get("children", []) or []
    if not children:
        return "true"
    parts = [compile_node(c) for c in children]
    op = "and" if combine == "all" else "or"
    return f"({op} " + " ".join(parts) + ")"


def compile_forbidden_state(control_id: str, forbidden_state: dict) -> str:
    """Render a complete query.smt2 from one forbidden_state block."""
    props: dict[str, str] = {}
    collect_properties(forbidden_state, props)

    lines: list[str] = []
    lines.append(f";; Auto-generated from {control_id}.forbidden_state")
    lines.append(";;")
    lines.append(";; SAT   = forbidden state is reachable → VIOLATION")
    lines.append(";; UNSAT = forbidden state is impossible → SAFE")
    lines.append("")

    for path, var in sorted(props.items(), key=lambda kv: kv[1]):
        lines.append(f";; property: {path}")
        lines.append(f"(declare-const {var} String)")
    lines.append("")

    expr = compile_node(forbidden_state)
    lines.append(f"(assert {expr})")
    lines.append("")
    lines.append(";; (check-sat) is intentionally omitted — the driver appends")
    lines.append(";; it after the observation facts are loaded so the same")
    lines.append(";; query.smt2 file works for any fixture.")
    return "\n".join(lines) + "\n"


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: compile.py <invariants.json> <output_dir>", file=sys.stderr)
        return 2

    invariants_path = sys.argv[1]
    output_dir = sys.argv[2]
    os.makedirs(output_dir, exist_ok=True)

    with open(invariants_path) as f:
        export = json.load(f)

    invariants = export.get("invariants", []) if isinstance(export, dict) else export

    compiled = 0
    for inv in invariants:
        fs = inv.get("forbidden_state") or {}
        if not fs.get("combine") and not fs.get("property"):
            continue
        control_id = inv.get("id", "unknown")
        query = compile_forbidden_state(control_id, fs)
        out_path = os.path.join(output_dir, f"{control_id}.query.smt2")
        with open(out_path, "w") as f:
            f.write(query)
        print(f"  compiled: {control_id} → {os.path.basename(out_path)}", file=sys.stderr)
        compiled += 1

    print(f"\n{compiled} forbidden_state block(s) compiled to {output_dir}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
