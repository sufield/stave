#!/usr/bin/env python3
"""
Diff two SIR fact exports (JSONL) by fact_id.

Each line of `stave export-sir --format jsonl` is a fact carrying a
deterministic 12-char fact_id derived from sha256(subject|predicate|
object). Identical (subject, predicate, object) tuples produce
identical fact_ids, so the diff is an exact set operation — no
fuzzy matching, no ordering dependence.

Output: delta.json describing added / removed / unchanged facts.
The added and removed lists carry full fact records (subject,
predicate, object, evidence, provenance) so downstream tools can
attribute each change to its source observation property.

Usage:
    diff.py <before.jsonl> <after.jsonl> <delta.json>
"""

import json
import sys
from collections import OrderedDict


def load_facts(path: str) -> "OrderedDict[str, dict]":
    """Read a JSONL file and index by fact_id, preserving order."""
    facts: "OrderedDict[str, dict]" = OrderedDict()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            fid = row.get("fact_id")
            if fid is None:
                continue
            facts[fid] = row
    return facts


def diff_facts(before: "OrderedDict[str, dict]", after: "OrderedDict[str, dict]") -> dict:
    before_ids = set(before)
    after_ids = set(after)
    added_ids = sorted(after_ids - before_ids)
    removed_ids = sorted(before_ids - after_ids)
    unchanged_ids = before_ids & after_ids
    return {
        "added_facts": [after[i] for i in added_ids],
        "removed_facts": [before[i] for i in removed_ids],
        "unchanged_facts": len(unchanged_ids),
        "total_before": len(before),
        "total_after": len(after),
    }


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: diff.py <before.jsonl> <after.jsonl> <output.json>", file=sys.stderr)
        return 2
    before = load_facts(sys.argv[1])
    after = load_facts(sys.argv[2])
    delta = diff_facts(before, after)
    with open(sys.argv[3], "w") as f:
        json.dump(delta, f, indent=2)
    print(
        f"  {delta['total_before']} → {delta['total_after']} facts "
        f"(+{len(delta['added_facts'])}/-{len(delta['removed_facts'])}, "
        f"{delta['unchanged_facts']} unchanged)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
