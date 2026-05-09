#!/usr/bin/env python3
"""
Bind observation property values to the SMT-LIB variables the
compiled forbidden_state queries reference.

Input:
  invariants.json  — output of `stave export-invariants`
  observations/    — directory of obs.v0.1 JSON snapshots
  output facts file path

Output:
  facts.smt2 — declarations + value-binding assertions for every
  property path any forbidden_state references, drawn from the
  first asset in the observation that has the path set. Paths
  with no observation match are bound to "__absent__".

The variable-name encoding mirrors compile.py's sanitize_var so
the facts and query SMT files line up by name.
"""

import json
import os
import re
import sys

ABSENT_SENTINEL = "__absent__"


def sanitize_var(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", path)


def smt_string_lit(value: object) -> str:
    if value is None:
        return f'"{ABSENT_SENTINEL}"'
    if isinstance(value, bool):
        return '"true"' if value else '"false"'
    if isinstance(value, list):
        if not value:
            return f'"{ABSENT_SENTINEL}"'
        return f'"{",".join(str(v) for v in value)}"'
    s = str(value).replace('\\', '\\\\').replace('"', '""')
    return f'"{s}"'


def collect_paths(node: dict, into: set) -> None:
    if not node:
        return
    if node.get("combine"):
        for child in node.get("children", []) or []:
            collect_paths(child, into)
        return
    prop = node.get("property")
    if prop:
        into.add(prop)


def lookup(asset: dict, path: str) -> object:
    """
    Resolve a dotted property path against an asset.

    "properties.storage.kind" reads asset["properties"]["storage"]["kind"].
    Hyphenated path segments like "data-classification" are
    preserved literally — the catalog uses them verbatim as map
    keys, so the lookup mirrors that.
    """
    cursor = asset
    for segment in path.split("."):
        if isinstance(cursor, dict) and segment in cursor:
            cursor = cursor[segment]
        else:
            return None
    return cursor


def load_observations(obs_dir: str) -> list:
    """Read every *.obs.json under obs_dir, return the asset list flattened."""
    assets = []
    for entry in sorted(os.listdir(obs_dir)):
        if not entry.endswith(".obs.json") and not entry.endswith(".json"):
            continue
        with open(os.path.join(obs_dir, entry)) as f:
            doc = json.load(f)
        for asset in doc.get("assets", []) or []:
            assets.append(asset)
    return assets


def first_value(assets: list, path: str) -> object:
    """Return the first non-None value for path across the asset list."""
    for asset in assets:
        v = lookup(asset, path)
        if v is not None:
            return v
    return None


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: obs_to_facts.py <invariants.json> <observations-dir> <output.smt2>", file=sys.stderr)
        return 2

    invariants_path = sys.argv[1]
    obs_dir = sys.argv[2]
    out_path = sys.argv[3]

    with open(invariants_path) as f:
        export = json.load(f)
    invariants = export.get("invariants", []) if isinstance(export, dict) else export

    paths: set = set()
    for inv in invariants:
        collect_paths(inv.get("forbidden_state") or {}, paths)

    assets = load_observations(obs_dir)

    lines: list[str] = []
    lines.append(";; Observation-derived facts. One assertion per property path")
    lines.append(";; any forbidden_state references — paths missing from the")
    lines.append(f';; observation are bound to "{ABSENT_SENTINEL}".')
    lines.append("")
    for path in sorted(paths):
        var = sanitize_var(path)
        value = first_value(assets, path)
        lit = smt_string_lit(value)
        lines.append(f";; {path}")
        lines.append(f"(assert (= {var} {lit}))")
    lines.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"  wrote {len(paths)} fact assertions to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
