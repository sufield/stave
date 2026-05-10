#!/usr/bin/env python3
"""
Generate mutations from a safe observation directory.

Reads every *.obs.json under <safe-obs-dir>, runs each
mutation operator (currently: flip_boolean) over the loaded
observations, and writes one mutated observation directory
per mutation under <output-dir>/<index>-<operator>-<sanitised-path>/.

The output layout mirrors what `stave apply --observations`
expects, so verify.py can hand each subdirectory to Stave
without further preparation.

Usage:
    mutate.py <safe-obs-dir> <output-dir>
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# Make `mutations` importable when this script is invoked from
# any working directory.
sys.path.insert(0, str(Path(__file__).parent))
from mutations import flip_boolean  # noqa: E402


OPERATORS = [flip_boolean]


def load_obs_dir(path: str) -> list[tuple[str, dict]]:
    """Load every *.obs.json file in path as (filename, content)."""
    out: list[tuple[str, dict]] = []
    for name in sorted(os.listdir(path)):
        if not name.endswith(".obs.json") and not name.endswith(".json"):
            continue
        full = os.path.join(path, name)
        with open(full) as f:
            out.append((name, json.load(f)))
    return out


def sanitise(token: str) -> str:
    """Make a path token filesystem-safe."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", token)[:80]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: mutate.py <safe-obs-dir> <output-dir>", file=sys.stderr)
        return 2

    safe_dir = sys.argv[1]
    out_dir = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    snapshots = load_obs_dir(safe_dir)
    if not snapshots:
        print(f"no observations under {safe_dir}", file=sys.stderr)
        return 2

    manifest: list[dict] = []
    counter = 0
    for op in OPERATORS:
        for filename, observation in snapshots:
            for mutation in op.mutations(observation):
                counter += 1
                slug = f"{counter:04d}-{op.__name__.split('.')[-1]}-{sanitise(mutation['path'])}"
                mut_dir = os.path.join(out_dir, slug, "observations")
                os.makedirs(mut_dir, exist_ok=True)
                target = os.path.join(mut_dir, filename)
                with open(target, "w") as f:
                    json.dump(mutation["observation"], f, indent=2)
                # Also write the other (unmutated) snapshots so the asset
                # set is identical to the safe baseline.
                for sib_name, sib_obs in snapshots:
                    if sib_name == filename:
                        continue
                    with open(os.path.join(mut_dir, sib_name), "w") as f:
                        json.dump(sib_obs, f, indent=2)
                manifest.append({
                    "id": slug,
                    "operator": mutation["operator"],
                    "source_file": filename,
                    "path": mutation["path"],
                    "before": mutation["before"],
                    "after": mutation["after"],
                    "obs_dir": os.path.join(out_dir, slug, "observations"),
                })

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"  generated {len(manifest)} mutations → {out_dir}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
