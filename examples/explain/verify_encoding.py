#!/usr/bin/env python3
"""
Verify the encoding boundary: each emitted SIR fact should
faithfully reflect the observation property the projector
claims to read.

The verifier loads the observation JSON files in a directory,
indexes every asset by ID, then for each fact with a
verifiable source (asset / tag / policy) walks its
provenance.property_path against the asset's actual JSON and
compares the value to fact.object. Mismatches surface the
encoding bug — wrong path, wrong value, type coercion drift —
independent of solver behaviour.

Verifiable fact sources:
    asset    direct asset attributes (type, vendor, ...)
    tag      asset-tag key=value records
    policy   IAM / resource policy projection records

NOT verified (synthetic — computed by the SIR builder, not
read from observation properties):
    lifecycle    first_seen / last_seen
    exposure     temporal.windows[i] / contributing_controls
    invariant    forbidden_state metadata
    control      catalog records

Usage:
    verify_encoding.py [--strict] <facts.jsonl> <observations-dir>

The exit code is 1 whenever any verifiable fact mismatches its
observation, regardless of the --strict flag. --strict is a no-op
on the matching path; it exists as the documented "CI-gate" flag
so a Makefile reader sees the gate semantics at the call site
rather than relying on documentation. Without --strict the report
prints to stdout and the script still exits 1 on mismatches —
either form is suitable for fail-fast pipelines, but call sites
in CI should prefer the explicit form.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

VERIFIABLE_SOURCES = {"asset", "tag", "policy"}


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


# ---- Loading ----

def load_facts(path: str) -> list[dict]:
    out: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def load_observations(obs_dir: str) -> dict[str, tuple[str, dict]]:
    """Return asset_id -> (source_file, asset_dict).

    On duplicate asset IDs across files the LAST file wins —
    matches Stave's loader, which dedupes by asset.ID.
    """
    index: dict[str, tuple[str, dict]] = {}
    for entry in sorted(os.listdir(obs_dir)):
        if not entry.endswith(".obs.json") and not entry.endswith(".json"):
            continue
        full = os.path.join(obs_dir, entry)
        with open(full) as f:
            doc = json.load(f)
        for asset in doc.get("assets") or []:
            aid = asset.get("id")
            if not aid:
                continue
            index[aid] = (entry, asset)
    return index


# ---- Path navigation ----

_INDEX_RE = re.compile(r"^(.+)\[(\d+)\]$")


def navigate_path(root: Any, path: str) -> tuple[Any, bool]:
    """Walk a dotted path through nested dicts / lists.

    Returns (value, found). path may include numeric subscripts
    (e.g. "policies[0].Action") and hyphenated keys
    (e.g. "tags.data-classification"). Any missing segment short-
    circuits to (None, False) so the caller can flag a wrong-
    path bug distinct from a value mismatch.
    """
    cur = root
    for seg in path.split("."):
        if seg == "":
            continue
        m = _INDEX_RE.match(seg)
        if m:
            key, idx = m.group(1), int(m.group(2))
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None, False
            if not isinstance(cur, list) or idx >= len(cur):
                return None, False
            cur = cur[idx]
            continue
        if isinstance(cur, dict):
            if seg not in cur:
                return None, False
            cur = cur[seg]
        else:
            return None, False
    return cur, True


# ---- Comparison ----

def normalise_scalar(value: Any) -> str:
    """Coerce a scalar (bool / int / float / string) into the wire string Stave emits."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def compare_tag(fact_object: str, observed_tags: Any) -> tuple[bool, str]:
    """Tag facts encode 'key=value'; the observation has a tag map."""
    if not isinstance(observed_tags, dict):
        return False, "(tags map not a dict)"
    if "=" not in fact_object:
        return False, "(fact object missing '=')"
    key, _, value = fact_object.partition("=")
    if key not in observed_tags:
        return False, f"(tag key {key!r} absent from observation tag map)"
    actual = normalise_scalar(observed_tags[key])
    if actual.lower() == value.lower():
        return True, actual
    return False, actual


# ---- Verification ----

def verify(facts: list[dict], obs_index: dict[str, tuple[str, dict]]) -> tuple[int, list[dict]]:
    verified = 0
    mismatches: list[dict] = []
    for fact in facts:
        if fact.get("source") not in VERIFIABLE_SOURCES:
            continue
        subject = fact.get("subject", "")
        if subject not in obs_index:
            mismatches.append({
                "fact_id": fact.get("fact_id", ""),
                "predicate": fact.get("predicate", ""),
                "expected": fact.get("object", ""),
                "actual": "(asset not found in observations)",
                "path": (fact.get("provenance") or {}).get("property_path", ""),
                "file": "?",
                "projector": (fact.get("provenance") or {}).get("projector", "?"),
                "category": "asset_missing",
            })
            continue
        source_file, asset = obs_index[subject]
        prov = fact.get("provenance") or {}
        path = prov.get("property_path", "")
        # Tag projector is a special case: its provenance path
        # lands at the per-tag value, not at the tag map. We
        # walk to the parent tag map and split fact.object as
        # key=value.
        if fact.get("source") == "tag":
            # Tag facts encode "key=value"; provenance.property_path
            # points at the per-tag value, so the LAST path segment
            # must match the fact's key. A mismatch here is a
            # wrong-path bug (the projector wrote a path that doesn't
            # name the tag the fact claims).
            tag_key_in_path = path.rsplit(".", 1)[-1]
            map_path = path.rsplit(".", 1)[0]
            fact_object = fact.get("object", "")
            fact_key, _, fact_value = fact_object.partition("=")
            if fact_key and fact_key != tag_key_in_path:
                mismatches.append({
                    "fact_id": fact.get("fact_id", ""),
                    "predicate": fact.get("predicate", ""),
                    "expected": fact_object,
                    "actual": f"(provenance path names tag {tag_key_in_path!r}, fact names {fact_key!r})",
                    "path": path,
                    "file": source_file,
                    "projector": prov.get("projector", "?"),
                    "category": "wrong_path",
                })
                continue
            tag_map, found = navigate_path(asset, map_path)
            if not found:
                mismatches.append({
                    "fact_id": fact.get("fact_id", ""),
                    "predicate": fact.get("predicate", ""),
                    "expected": fact_object,
                    "actual": "(tag map path absent)",
                    "path": map_path,
                    "file": source_file,
                    "projector": prov.get("projector", "?"),
                    "category": "wrong_path",
                })
                continue
            ok, actual = compare_tag(fact_object, tag_map)
            if ok:
                verified += 1
            else:
                mismatches.append({
                    "fact_id": fact.get("fact_id", ""),
                    "predicate": fact.get("predicate", ""),
                    "expected": fact_object,
                    "actual": actual,
                    "path": path,
                    "file": source_file,
                    "projector": prov.get("projector", "?"),
                    "category": "value_mismatch",
                })
            continue

        observed, found = navigate_path(asset, path)
        if not found:
            mismatches.append({
                "fact_id": fact.get("fact_id", ""),
                "predicate": fact.get("predicate", ""),
                "expected": fact.get("object", ""),
                "actual": "(path absent from observation)",
                "path": path,
                "file": source_file,
                "projector": prov.get("projector", "?"),
                "category": "wrong_path",
            })
            continue
        actual = normalise_scalar(observed)
        expected = fact.get("object", "")
        if actual.lower() == str(expected).lower():
            verified += 1
        else:
            mismatches.append({
                "fact_id": fact.get("fact_id", ""),
                "predicate": fact.get("predicate", ""),
                "expected": expected,
                "actual": actual,
                "path": path,
                "file": source_file,
                "projector": prov.get("projector", "?"),
                "category": "value_mismatch",
            })
    return verified, mismatches


# ---- Reporting ----

def render_report(verified: int, mismatches: list[dict]) -> str:
    total = verified + len(mismatches)
    lines: list[str] = []
    if not mismatches:
        lines.append(
            f"{_BOLD}{_GREEN}Encoding verified:{_RESET} {verified}/{total} verifiable facts match observations ✓"
        )
        return "\n".join(lines) + "\n"

    lines.append(
        f"{_BOLD}{_RED}Encoding mismatch:{_RESET} {len(mismatches)} of {total} verifiable fact(s) "
        f"{_BOLD}do NOT match{_RESET} the observations they claim to come from"
    )
    lines.append("")
    by_category: dict[str, list[dict]] = {}
    for m in mismatches:
        by_category.setdefault(m["category"], []).append(m)
    category_labels = {
        "wrong_path": "Property path absent from observation",
        "value_mismatch": "Value at the path differs from the fact object",
        "asset_missing": "Asset id has no matching observation entry",
    }
    likely_causes = {
        "wrong_path": "Stale projector — the property moved or the path was hand-edited.",
        "value_mismatch": "Type coercion bug, case-folding drift, or a stale denormalisation.",
        "asset_missing": "Fact references a subject that's not in the loaded observation set.",
    }
    for category, items in by_category.items():
        lines.append(
            f"  {_BOLD}{_RED}{category_labels.get(category, category)}{_RESET}  "
            f"{_DIM}({len(items)} fact(s)){_RESET}"
        )
        lines.append(f"    {_DIM}likely cause: {likely_causes.get(category, '?')}{_RESET}")
        for m in items:
            lines.append(
                f"    {_RED}•{_RESET} {_BOLD}{m['predicate']}{_RESET}  "
                f"{_DIM}fact_id: {m['fact_id'][:12]}{_RESET}"
            )
            lines.append(f"        Expected (from fact): {m['expected']}")
            lines.append(f"        Actual (from observation): {m['actual']}")
            lines.append(f"        Path: {m['path']}")
            lines.append(f"        File: {m['file']}")
            lines.append(f"        Projector: {m['projector']}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--strict"]
    # --strict is documentation: the script always exits 1 on
    # mismatches. Pulling the flag out of argv leaves the
    # positional arguments unchanged for the rest of the parser.
    if len(args) != 2:
        print(
            "usage: verify_encoding.py [--strict] <facts.jsonl> <observations-dir>",
            file=sys.stderr,
        )
        return 2
    facts = load_facts(args[0])
    obs_index = load_observations(args[1])
    verified, mismatches = verify(facts, obs_index)
    sys.stdout.write(render_report(verified, mismatches))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
