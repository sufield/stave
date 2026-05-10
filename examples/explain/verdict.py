#!/usr/bin/env python3
"""
Render a solver verdict into cloud-security domain language.

Reads a JSON input describing a single solver result plus the
invariant it was checking and the facts that contributed.
Produces a UNSAFE / SAFE / INCONCLUSIVE report a security
engineer can read without knowing what "sat" means.

Input schema (JSON):
    {
      "verdict": "sat" | "unsat" | "unknown" | "timeout",
      "query": "<query name or file>",
      "invariant": {
        "id":             "<control ID>",
        "name":           "<one-line title from YAML>",
        "description":    "<forbidden_state description from YAML>",
        "remediation":    "<remediation.action from YAML>",
        "remediation_cost":   "<optional, e.g. '$0'>",
        "remediation_time":   "<optional, e.g. '30 seconds'>",
        "remediation_effect": "<optional, e.g. 'Breaks the chain at step 1'>"
      },
      "contributing_facts": [
        {
          "predicate":   "<predicate name>",
          "object":      "<value>",
          "subject":     "<asset ID>",
          "evidence":    "<asset[i].path>",
          "provenance":  {"property_path": "..."}
        },
        ...
      ]
    }

Output is a multi-line report suitable for CI logs, terminal,
or a finding annotation. Words "sat" and "unsat" never appear.

Usage:
    verdict.py <input.json>
or
    verdict.py < input.json
"""

from __future__ import annotations

import json
import os
import sys
from typing import Iterable

# Reuse the cloud-domain dictionaries from the encoding report
# so the same predicate / value vocabulary appears on both
# sides of the solver. Keeps the encoding and decoding
# boundaries linguistically consistent.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from format_facts import PREDICATE_LABELS, VALUE_LABELS  # noqa: E402


# ---- TTY-aware color helpers ----

def _color_enabled() -> bool:
    if os.environ.get("FORCE_COLOR") == "1":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


_COLOR = _color_enabled()
_BOLD = "\x1b[1m" if _COLOR else ""
_DIM = "\x1b[2m" if _COLOR else ""
_RED = "\x1b[31m" if _COLOR else ""
_GREEN = "\x1b[32m" if _COLOR else ""
_YELLOW = "\x1b[33m" if _COLOR else ""
_RESET = "\x1b[0m" if _COLOR else ""


# ---- Verdict vocabulary ----

VERDICT_LABELS: dict[str, tuple[str, str]] = {
    "sat":     ("UNSAFE",       "the forbidden state is reachable in this configuration"),
    "unsat":   ("SAFE",         "the forbidden state is impossible in this configuration"),
    "unknown": ("INCONCLUSIVE", "the solver could not decide — likely an encoding issue or timeout"),
    "timeout": ("INCONCLUSIVE", "the solver timed out — query may be too complex for the focused fact binding"),
}


def _verdict_color(verdict: str) -> str:
    if not _COLOR:
        return ""
    if verdict == "sat":
        return _RED
    if verdict == "unsat":
        return _GREEN
    return _YELLOW


def _label_predicate(predicate: str) -> str:
    return PREDICATE_LABELS.get(predicate, predicate)


def _label_value(predicate: str, value: str) -> str:
    return VALUE_LABELS.get(value, value)


def _format_fact_step(idx: int, fact: dict) -> list[str]:
    """One numbered chain-step block: label + source citation."""
    predicate = fact.get("predicate", "")
    label = _label_predicate(predicate)
    value = _label_value(predicate, fact.get("object", ""))
    subject = fact.get("subject", "")
    prov = fact.get("provenance") or {}
    path = prov.get("property_path") or fact.get("evidence", "?")
    out = [f"  {idx}. {_BOLD}{label}:{_RESET} {value}"]
    if subject:
        out.append(f"     {_DIM}on {subject}{_RESET}")
    out.append(f"     {_DIM}({path}){_RESET}")
    return out


# ---- Renderers ----

def render_sat(spec: dict) -> str:
    inv = spec.get("invariant") or {}
    facts: Iterable[dict] = spec.get("contributing_facts") or []
    label, _ = VERDICT_LABELS["sat"]

    lines: list[str] = []
    description = (inv.get("description") or "").strip()
    name = (inv.get("name") or "").strip()
    headline = description or name or inv.get("id", "<unknown invariant>")
    lines.append(f"{_BOLD}{_RED}{label}:{_RESET} {headline}")
    if name and description and name != description:
        lines.append(f"  {_DIM}{name}{_RESET}")
    lines.append("")
    lines.append(f"{_BOLD}The forbidden state is reachable because:{_RESET}")
    facts = list(facts)
    if not facts:
        lines.append("  (no contributing facts attached to this verdict)")
    for i, fact in enumerate(facts, 1):
        lines.extend(_format_fact_step(i, fact))
    lines.append("")

    remediation = (inv.get("remediation") or "").strip()
    if remediation:
        lines.append(f"{_BOLD}Fix:{_RESET} {remediation}")
        cost = inv.get("remediation_cost", "")
        time = inv.get("remediation_time", "")
        effect = inv.get("remediation_effect", "")
        if cost or time:
            parts: list[str] = []
            if cost:
                parts.append(f"Cost: {cost}")
            if time:
                parts.append(f"Time: {time}")
            lines.append(f"     {_DIM}{'  '.join(parts)}{_RESET}")
        if effect:
            lines.append(f"     {_DIM}Effect: {effect}{_RESET}")
    return "\n".join(lines) + "\n"


def render_unsat(spec: dict) -> str:
    inv = spec.get("invariant") or {}
    label, _ = VERDICT_LABELS["unsat"]
    description = (inv.get("description") or "").strip()
    name = (inv.get("name") or "").strip()
    headline = description or name or inv.get("id", "<unknown invariant>")

    lines: list[str] = []
    lines.append(f"{_BOLD}{_GREEN}{label}:{_RESET} {headline}")
    if name and description and name != description:
        lines.append(f"  {_DIM}{name}{_RESET}")
    lines.append("")
    lines.append(
        f"{_BOLD}This forbidden state is impossible in the current configuration.{_RESET}"
    )
    lines.append(
        f"  {_DIM}Z3 verified that no observation property combination admits the "
        f"forbidden_state predicate. Subsequent perturbations are needed to introduce it.{_RESET}"
    )
    return "\n".join(lines) + "\n"


def render_inconclusive(spec: dict, verdict: str) -> str:
    inv = spec.get("invariant") or {}
    label, gloss = VERDICT_LABELS.get(verdict, VERDICT_LABELS["unknown"])
    headline = (inv.get("description") or inv.get("name") or inv.get("id", "<unknown>")).strip()

    lines: list[str] = []
    lines.append(f"{_BOLD}{_YELLOW}{label}:{_RESET} {headline}")
    lines.append(f"  {gloss}")
    lines.append("")
    lines.append(f"{_BOLD}Possible causes:{_RESET}")
    lines.append("  • Encoding bug — the SMT-LIB the formatter sends to the solver does not")
    lines.append("    correctly express the forbidden_state predicate.")
    lines.append("  • Solver timeout — the focused fact binding may have too many free variables.")
    lines.append("  • Vendor extension — the query uses a logic this solver does not handle.")
    lines.append("")
    lines.append(
        f"  {_DIM}Run the encoding report (examples/explain/format_facts.py) "
        f"to verify the encoding before re-running the solver.{_RESET}"
    )
    return "\n".join(lines) + "\n"


def render(spec: dict) -> str:
    verdict = (spec.get("verdict") or "").lower()
    if verdict == "sat":
        return render_sat(spec)
    if verdict == "unsat":
        return render_unsat(spec)
    return render_inconclusive(spec, verdict or "unknown")


def main() -> int:
    if len(sys.argv) > 2:
        print("usage: verdict.py [<input.json>]", file=sys.stderr)
        return 2
    if len(sys.argv) == 2:
        with open(sys.argv[1]) as f:
            spec = json.load(f)
    else:
        spec = json.load(sys.stdin)
    sys.stdout.write(render(spec))
    return 0


if __name__ == "__main__":
    sys.exit(main())
