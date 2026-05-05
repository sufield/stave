"""Stave Z3 Solver entry point.

Reads SIR JSON from stdin, dispatches each
(ResourceFactGroup, ControlFact) pair targeting the S3
public-exposure question to S3SafetyModel, and emits a JSON
array of Stave Findings to stdout. Exits 0 on success (zero
or more findings); exits 2 on parse error with an error JSON
object on stderr.

Iter L6 wires the S3 composition model. Other services /
controls still produce no findings; future iterations add
per-service modules under ``stave_solver/models/``.
"""
from __future__ import annotations

import json
import sys

from stave_solver import findings, sir
from stave_solver.models import s3


def main() -> int:
    try:
        payload = sys.stdin.read()
        if not payload.strip():
            json.dump([], sys.stdout)
            return 0
        document = sir.Document.from_json(payload)
    except (json.JSONDecodeError, ValueError) as err:
        json.dump({"error": f"sir parse: {err}"}, sys.stderr)
        return 2

    out: list[findings.Finding] = []
    for group in document.resource_groups:
        if group.vendor != "aws" or group.service_area != "s3":
            continue
        model = s3.S3SafetyModel(group)
        for control in document.controls:
            if not _control_targets_s3_public(control):
                continue
            out.extend(model.evaluate(control))

    json.dump([f.to_dict() for f in out], sys.stdout)
    return 0


def _control_targets_s3_public(control: sir.ControlFact) -> bool:
    """Cheap heuristic for "is this an S3 public-exposure
    control?". The control catalog uses ``CTL.S3.*PUBLIC*``
    naming for the family; matching on the ID prefix avoids a
    registry that would only carry one entry today.

    A future control taxonomy in the SIR replaces this prefix
    match — when it does, this function is the single edit
    site.
    """
    cid = control.id.upper()
    return cid.startswith("CTL.S3.") and "PUBLIC" in cid


if __name__ == "__main__":
    sys.exit(main())
