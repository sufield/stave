"""Generic skill surface for GSD / Superpowers and any tool registry (Iteration 0.5).

Frameworks that consume a plain callable + a JSON spec (GSD Observation producers,
Superpowers tool classes) use this directly — no framework dependency.
"""
from stave_verify_core import verify, verify_text

SKILL_SPEC = {
    "name": "stave-verify",
    "title": "Deterministic Cloud-Config Verification",
    "description": (
        "Evaluate a cloud configuration snapshot against Stave's control catalog. Returns "
        "proven (deterministic) violations with control IDs and evidence — reachability, "
        "privilege escalation, misconfiguration. Not LLM judgment; reproducible."),
    "input": {
        "snapshot_path": "directory of obs.v0.1 snapshot JSON files (required)",
        "pack": "optional pack to scope evaluation (quick, entropy)",
        "now": "optional RFC3339 time override",
    },
    "output": "structured findings: {status, finding_count, findings:[{control_id, resource, severity, ...}]}",
    "deterministic": True,
}


def run(snapshot_path: str, **kw) -> dict:
    """GSD-style: returns structured observations a planner can reason over."""
    return verify(snapshot_path, **kw)


def run_text(snapshot_path: str, **kw) -> str:
    """Superpowers-style: returns a compact text result for an LLM tool call."""
    return verify_text(snapshot_path, **kw)
