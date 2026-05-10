#!/usr/bin/env python3
"""
Translate Z3's unsat-core s-expression back into a human-
readable conflict report by joining each named id against the
requirement / premise definitions in the source
requirements.yaml.

Reads:
    requirements.yaml    — definitions (name, source, description)
    z3-output            — z3's stdout for the compiled query
                           (first line: sat | unsat | unknown;
                            second line: (id1 id2 ...) on unsat)

Writes:
    a multi-line report on stdout suitable for a CI failure
    annotation or developer review.

Usage:
    translate_core.py <requirements.yaml> <z3-output>
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Reuse the YAML parser from the sibling compiler so the schema
# stays in lockstep.
sys.path.insert(0, str(Path(__file__).parent))
from compile_requirements import parse_yaml  # noqa: E402


def parse_z3_output(text: str) -> tuple[str, list[str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "error", []
    verdict = lines[0]
    core: list[str] = []
    if verdict == "unsat" and len(lines) > 1:
        core_line = lines[1]
        if core_line.startswith("(") and core_line.endswith(")"):
            core = [tok for tok in core_line[1:-1].split() if tok]
    return verdict, core


def lookup(spec: dict[str, Any], cid: str) -> dict[str, Any] | None:
    for r in spec.get("requirements", []) or []:
        if r.get("id") == cid:
            return {**r, "_kind": "requirement"}
    for p in spec.get("premises", []) or []:
        if p.get("id") == cid:
            return {**p, "_kind": "premise"}
    return None


def render(spec: dict[str, Any], verdict: str, core: list[str]) -> str:
    name = spec.get("name", "<unnamed>")
    if verdict == "sat":
        return (
            f"COMPATIBLE — {name}\n"
            "  All requirements hold simultaneously in at least one model.\n"
            "  Z3 produced a satisfying assignment; the requirements\n"
            "  describe a configuration the system can in principle reach.\n"
        )
    if verdict != "unsat":
        return f"INCONCLUSIVE — z3 returned: {verdict}\n"

    out: list[str] = []
    out.append(f"CONTRADICTORY — {name}")
    out.append("")
    requirements_in_core = [c for c in core if (lookup(spec, c) or {}).get("_kind") == "requirement"]
    premises_in_core = [c for c in core if (lookup(spec, c) or {}).get("_kind") == "premise"]
    if requirements_in_core:
        out.append(
            f"  {len(requirements_in_core)} requirement"
            + ("s" if len(requirements_in_core) != 1 else "")
            + " cannot all be satisfied"
            + (" under the listed premises:" if premises_in_core else ":")
        )
        out.append("")
        for cid in requirements_in_core:
            entry = lookup(spec, cid) or {}
            source = entry.get("source", "")
            tag = f" ({source})" if source else ""
            out.append(f"  • {cid}{tag}")
            desc = (entry.get("description") or "").strip()
            for d in desc.splitlines():
                out.append(f"      {d.strip()}")
        out.append("")
    if premises_in_core:
        out.append("  Scenario premises that activated the contradiction:")
        for cid in premises_in_core:
            entry = lookup(spec, cid) or {}
            out.append(f"  • {cid}: {entry.get('smt', '').strip()}")
        out.append("")
    out.append(
        "  Resolution requires dropping or weakening at least one of the\n"
        "  requirements above. Common patterns: scope a requirement to a\n"
        "  subset (different accounts / different bucket classes), serve\n"
        "  the public-read need through a different mechanism (CloudFront\n"
        "  origin-access identity), or relax the symmetry constraint."
    )
    return "\n".join(out) + "\n"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: translate_core.py <requirements.yaml> <z3-output>", file=sys.stderr)
        return 2
    spec = parse_yaml(sys.argv[1])
    z3_text = Path(sys.argv[2]).read_text()
    verdict, core = parse_z3_output(z3_text)
    print(render(spec, verdict, core))
    return 0


if __name__ == "__main__":
    sys.exit(main())
