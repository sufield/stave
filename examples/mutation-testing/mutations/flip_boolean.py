"""Flip every boolean property in a safe observation.

Each True flips to False and each False flips to True; one
mutation is emitted per boolean leaf. The operator does not
distinguish "security-relevant" booleans from "operational"
booleans — the verify step decides whether the mutation was
killed (Stave fired a finding) or survived (no finding).
Survivors flag either a coverage gap or a property that was
genuinely not security-relevant.
"""

from __future__ import annotations

import copy
from typing import Iterator


Mutation = dict


def _walk(obj, path):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, path + [k])
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, path + [str(i)])
    else:
        yield path, obj


def _set_at(obj, path, value):
    cur = obj
    for seg in path[:-1]:
        if isinstance(cur, list):
            cur = cur[int(seg)]
        else:
            cur = cur[seg]
    last = path[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def mutations(observation: dict) -> Iterator[Mutation]:
    """Yield one mutation per boolean leaf in the observation tree."""
    for asset_idx, asset in enumerate(observation.get("assets", [])):
        for path, value in _walk(asset, ["assets", str(asset_idx)]):
            if not isinstance(value, bool):
                continue
            mutated = copy.deepcopy(observation)
            _set_at(mutated, path, not value)
            dotted = ".".join(path)
            yield {
                "operator": "flip-boolean",
                "name": f"flip:{dotted}",
                "path": dotted,
                "before": value,
                "after": not value,
                "observation": mutated,
            }
