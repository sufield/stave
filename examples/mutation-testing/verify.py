#!/usr/bin/env python3
"""
Run Stave against each mutation and classify it KILLED or
SURVIVED.

Workflow:
    1. Run `stave apply` on the safe baseline → baseline finding count.
    2. For each mutation in <mutations-dir>/manifest.json,
       run `stave apply` on the mutated observation directory.
    3. KILLED if finding count > baseline (Stave detected the
       mutation). SURVIVED otherwise.

The mutation score is killed / total. Survivors are flagged
with their property path so coverage gaps surface concretely:
"these properties were mutated but no control fired on them."

Usage:
    verify.py <stave-bin> <safe-obs-dir> <mutations-dir> <out-report.json>
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile


def stave_apply(stave_bin: str, obs_dir: str) -> int:
    """Run stave apply and return the finding count.

    --now is fixed for determinism. --allow-unknown-input keeps
    schema validation lenient on the synthetic mutations the
    operator may emit. JSON output is parsed for the findings
    array length.
    """
    result = subprocess.run(
        [
            stave_bin,
            "apply",
            "--observations", obs_dir,
            "--now", "2026-05-09T12:00:00Z",
            "--allow-unknown-input",
            "--format", "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # stave apply returns exit code 3 when violations exist —
    # that's expected and not an error for this tool. Ignore the
    # exit code; parse stdout.
    if not result.stdout.strip():
        return -1
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return -1
    return len(report.get("findings", []))


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: verify.py <stave-bin> <safe-obs-dir> "
            "<mutations-dir> <out-report.json>",
            file=sys.stderr,
        )
        return 2

    stave_bin = sys.argv[1]
    safe_dir = sys.argv[2]
    mutations_dir = sys.argv[3]
    out_path = sys.argv[4]

    manifest_path = os.path.join(mutations_dir, "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)

    baseline = stave_apply(stave_bin, safe_dir)
    if baseline < 0:
        print("baseline run failed", file=sys.stderr)
        return 4
    print(f"  baseline: {baseline} findings", file=sys.stderr)

    killed: list = []
    survived: list = []
    for mutation in manifest:
        count = stave_apply(stave_bin, mutation["obs_dir"])
        if count < 0:
            mutation["error"] = "stave apply failed"
            survived.append(mutation)
            continue
        mutation["finding_count"] = count
        delta = count - baseline
        mutation["delta"] = delta
        if delta > 0:
            killed.append(mutation)
        else:
            survived.append(mutation)

    score = len(killed) / len(manifest) if manifest else 0.0
    report = {
        "baseline_findings": baseline,
        "total_mutations": len(manifest),
        "killed": len(killed),
        "survived": len(survived),
        "mutation_score": round(score, 4),
        "survivors": [
            {
                "id": m["id"],
                "operator": m["operator"],
                "source_file": m["source_file"],
                "path": m["path"],
                "before": m["before"],
                "after": m["after"],
                "finding_count": m.get("finding_count"),
            }
            for m in survived
        ],
        "killed_summary": [
            {
                "id": m["id"],
                "path": m["path"],
                "before": m["before"],
                "after": m["after"],
                "delta": m["delta"],
            }
            for m in killed
        ],
    }
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(
        f"  {len(manifest)} mutations: {len(killed)} killed, "
        f"{len(survived)} survived, score {score:.2f}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
