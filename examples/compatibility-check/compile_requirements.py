#!/usr/bin/env python3
"""
Compile a requirements.yaml into one combined SMT-LIB query
that asks: "Can all of these requirements hold simultaneously?"

The compiler emits each requirement as a `(! ... :named req_id)`
assertion so Z3's `(get-unsat-core)` returns the minimal set
of requirement names that conflict.

Verdict semantics:
    sat   — the requirements are compatible. The model exhibits
            a configuration that satisfies all of them.
    unsat — at least one subset of requirements contradicts.
            The unsat core names the conflicting subset.

Usage:
    compile_requirements.py <requirements.yaml> <output.smt2>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any


def parse_yaml(path: str) -> dict[str, Any]:
    """Minimal YAML parser sufficient for the requirements schema.

    Supports: top-level scalars (`name`, `description`),
    list-of-strings (`declarations`), list-of-objects with `id`,
    `description`, `source`, `smt` fields (`premises`,
    `requirements`). Block scalars (|) are concatenated. Quoted
    scalars trim outer quotes. No flow-style, no anchors.
    """
    text = Path(path).read_text()
    return _parse_block(text.splitlines())


def _strip_quote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_block(lines: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if not re.match(r"^[A-Za-z_]", line):
            i += 1
            continue
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.rstrip()
        if rest.lstrip() == "|":
            i += 1
            block, i = _parse_block_scalar(lines, i)
            out[key] = block
            continue
        rest_value = rest.strip()
        if rest_value:
            out[key] = _strip_quote(rest_value)
            i += 1
            continue
        # Nested block: list or sub-mapping
        i += 1
        body, i = _parse_nested(lines, i)
        out[key] = body
    return out


def _parse_block_scalar(lines: list[str], i: int) -> tuple[str, int]:
    indent = None
    chunks: list[str] = []
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            chunks.append("")
            i += 1
            continue
        leading = len(line) - len(line.lstrip())
        if indent is None:
            indent = leading
        if leading < indent and line.strip():
            break
        chunks.append(line[indent:] if leading >= indent else line.lstrip())
        i += 1
    return "\n".join(chunks).rstrip(), i


def _parse_nested(lines: list[str], i: int) -> tuple[Any, int]:
    items: list[Any] = []
    sub: dict[str, Any] = {}
    base_indent = None
    while i < len(lines):
        raw = lines[i]
        if not raw.strip():
            i += 1
            continue
        if raw.lstrip().startswith("#"):
            i += 1
            continue
        leading = len(raw) - len(raw.lstrip())
        if base_indent is None:
            base_indent = leading
        if leading < base_indent:
            break
        line = raw[base_indent:]
        if line.startswith("- "):
            item_raw = line[2:]
            if ":" in item_raw and not item_raw.startswith("("):
                # List of objects
                obj: dict[str, Any] = {}
                key, _, rest = item_raw.partition(":")
                key = key.strip()
                rest = rest.rstrip()
                if rest.lstrip() == "|":
                    i += 1
                    block, i = _parse_block_scalar(lines, i)
                    obj[key] = block
                else:
                    obj[key] = _strip_quote(rest.strip()) if rest.strip() else ""
                    i += 1
                # Continue collecting fields at deeper indent
                while i < len(lines):
                    raw2 = lines[i]
                    if not raw2.strip() or raw2.lstrip().startswith("#"):
                        i += 1
                        continue
                    leading2 = len(raw2) - len(raw2.lstrip())
                    if leading2 <= base_indent:
                        break
                    sub_line = raw2[base_indent + 2:]
                    if not sub_line.strip():
                        i += 1
                        continue
                    if not re.match(r"^[A-Za-z_]", sub_line):
                        break
                    key2, _, rest2 = sub_line.partition(":")
                    key2 = key2.strip()
                    rest2 = rest2.rstrip()
                    if rest2.lstrip() == "|":
                        i += 1
                        block, i = _parse_block_scalar(lines, i)
                        obj[key2] = block
                    else:
                        obj[key2] = _strip_quote(rest2.strip()) if rest2.strip() else ""
                        i += 1
                items.append(obj)
            else:
                # List of scalars
                items.append(_strip_quote(item_raw))
                i += 1
        else:
            key, _, rest = line.partition(":")
            sub[key.strip()] = _strip_quote(rest.strip())
            i += 1
    if items:
        return items, i
    return sub, i


def compile_query(spec: dict[str, Any]) -> str:
    """Render the combined SMT-LIB query."""
    lines: list[str] = []
    lines.append(f";; Compatibility check: {spec.get('name', 'unnamed')}")
    description = spec.get("description", "").strip()
    if description:
        for d in description.splitlines():
            lines.append(f";; {d}")
    lines.append("")
    lines.append("(set-option :produce-unsat-cores true)")
    lines.append("(set-logic ALL)")
    lines.append("")

    decls = spec.get("declarations", []) or []
    if decls:
        lines.append(";; --- Declarations ---")
        lines.extend(decls)
        lines.append("")

    premises = spec.get("premises", []) or []
    if premises:
        lines.append(";; --- Scenario premises ---")
        for p in premises:
            pid = p.get("id", "premise")
            smt = (p.get("smt") or "").strip()
            wrapped = _wrap_named(smt, pid)
            lines.append(f";; premise: {pid}")
            lines.append(wrapped)
        lines.append("")

    requirements = spec.get("requirements", []) or []
    lines.append(";; --- Requirements ---")
    for r in requirements:
        rid = r.get("id", "requirement")
        source = r.get("source", "")
        desc = (r.get("description") or "").strip()
        smt = (r.get("smt") or "").strip()
        if source:
            lines.append(f";; requirement: {rid}  ({source})")
        else:
            lines.append(f";; requirement: {rid}")
        if desc:
            for d in desc.splitlines():
                lines.append(f";;   {d}")
        wrapped = _wrap_named(smt, rid)
        lines.append(wrapped)
        lines.append("")

    lines.append("(check-sat)")
    lines.append("(get-unsat-core)")
    return "\n".join(lines) + "\n"


_ASSERT_RE = re.compile(r"^\s*\(assert\s+(.*)\)\s*$", re.DOTALL)


def _wrap_named(smt: str, name: str) -> str:
    """Wrap an `(assert <expr>)` form as `(assert (! <expr> :named id))`.

    Block-scalar SMT may have multiple lines and trailing
    whitespace. The named annotation is what unsat-core
    extraction matches against.
    """
    smt = smt.strip()
    m = _ASSERT_RE.match(smt)
    if not m:
        return f";; warning: could not :named-wrap {name}\n{smt}"
    inner = m.group(1).rstrip()
    return f"(assert (! {inner} :named {name}))"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: compile_requirements.py <requirements.yaml> <output.smt2>", file=sys.stderr)
        return 2
    spec = parse_yaml(sys.argv[1])
    query = compile_query(spec)
    Path(sys.argv[2]).write_text(query)
    n_decls = len(spec.get("declarations", []) or [])
    n_prem = len(spec.get("premises", []) or [])
    n_req = len(spec.get("requirements", []) or [])
    print(
        f"  compiled: {spec.get('name', '?')} "
        f"({n_decls} decls, {n_prem} premises, {n_req} requirements)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
