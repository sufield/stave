"""Stave verification — framework-agnostic core (Iteration 0.5, skill registry).

The single engine every agent-framework wrapper (LangChain, CrewAI, GSD, Superpowers)
sits on top of. Dependency-free: just the Python stdlib + the `stave` CLI.

Architectural boundary: Stave reads JSON snapshots on disk. This wrapper's input is
ALWAYS a snapshot directory — it never converts Terraform/IaC. Producing the snapshot
is the consumer's (or a separate adapter's) job.
"""
from __future__ import annotations

import json
import shutil
import subprocess


def _engine(f: dict) -> str:
    cls = json.dumps(f.get("classification") or "").lower()
    cid = (f.get("control_id") or "").lower()
    return "souffle" if ("compound" in cls or "chain" in cls or "foothold" in cid) else "cel"


def _remediation_hint(f: dict) -> str:
    rem = f.get("remediation")
    if isinstance(rem, dict):
        return rem.get("description") or rem.get("action") or ""
    fp = f.get("fix_plan")
    if isinstance(fp, dict):
        return fp.get("command") or ""
    return ""


def verify(snapshot_path: str, *, pack: str = "", controls: str = "", now: str = "",
           stave_bin: str = "stave") -> dict:
    """Run Stave against a snapshot directory; return structured, agent-friendly findings.

    Returns:
        {status: "pass"|"fail", finding_count: int, findings: [
            {control_id, resource, severity, description, evidence, engine, remediation_hint}
        ], error: str|None}
    """
    binary = shutil.which(stave_bin) or stave_bin
    cmd = [binary, "apply", "-o", snapshot_path, "--format", "json"]
    if pack:
        cmd += ["--pack", pack]
    if controls:
        cmd += ["--controls", controls]
    if now:
        cmd += ["--now", now]

    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode not in (0, 3):  # 3 = violations found = a successful eval, not an error
        return {"status": "error", "finding_count": 0, "findings": [],
                "error": (p.stderr or p.stdout or f"stave exited {p.returncode}")[:500]}

    doc = json.loads(p.stdout)
    findings = []
    for f in doc.get("findings", []) or []:
        findings.append({
            "control_id": f.get("control_id", ""),
            "resource": f.get("asset_id", ""),
            "severity": (f.get("control_severity") or "").lower(),
            "description": (f.get("control_name") or "").strip(),
            "evidence": f.get("evidence", {}) or {},
            "engine": _engine(f),
            "remediation_hint": _remediation_hint(f),
        })
    return {
        "status": "fail" if findings else "pass",
        "finding_count": len(findings),
        "findings": findings,
        "error": None,
    }


def verify_text(snapshot_path: str, **kw) -> str:
    """Compact text summary — the default surface for LLM tool output."""
    r = verify(snapshot_path, **kw)
    if r["status"] == "error":
        return f"Stave error: {r['error']}"
    if r["finding_count"] == 0:
        return "PASS — Stave found 0 violations (deterministic)."
    lines = [f"FAIL — Stave found {r['finding_count']} deterministic violation(s):"]
    for f in r["findings"]:
        lines.append(f"  [{f['severity']}] {f['control_id']} on {f['resource']} — {f['description']}"
                     + (f"  Fix: {f['remediation_hint']}" if f['remediation_hint'] else ""))
    lines.append("These are proven violations, not suggestions. Address them before proceeding.")
    return "\n".join(lines)
