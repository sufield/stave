#!/usr/bin/env python3
"""Format Stave apply --format json output into a Pull Request comment.

Writes a markdown comment to --out and prints the finding count to stdout (the
action captures it for the strict-mode gate). Deterministic: same findings ->
same comment.
"""
import argparse
import json
import sys

_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MARK = "<!-- stave-verify -->"  # lets the action find/replace its own comment


def _short_arn(arn: str) -> str:
    # arn:aws:iam::123:role/x -> role/x ; keep non-ARNs as-is
    return arn.split(":")[-1] if arn.startswith("arn:") else arn


def render(doc: dict) -> tuple[str, int]:
    findings = doc.get("findings", []) or []
    n = len(findings)
    run = doc.get("run", {}) or {}
    engines = "CEL"  # apply output is CEL state-assertions; compound engines noted when present
    foot = (f"\n\n_Tool: `stave` {run.get('tool_version','')} · "
            f"snapshots: {run.get('snapshots','?')} · engines: {engines} · "
            f"deterministic — re-run to reproduce._\n{_MARK}")

    if n == 0:
        return (f"## 🛡️ Stave Security Verification — ✅ no findings\n\n"
                f"All evaluated controls passed.{foot}", 0)

    rows = []
    for f in sorted(findings, key=lambda x: _SEV_ORDER.get((x.get("control_severity") or "").lower(), 9)):
        sev = (f.get("control_severity") or "").lower()
        icon = _SEV_ICON.get(sev, "⚪")
        name = (f.get("control_name") or "").strip()
        rows.append(f"| {icon} {sev.title() or '?'} | `{f.get('control_id','')}` | "
                    f"`{_short_arn(f.get('asset_id',''))}` | {name} |")

    body = (f"## 🛡️ Stave Security Verification — {n} finding{'s' if n != 1 else ''}\n\n"
            f"| Severity | Control | Resource | Issue |\n"
            f"|---|---|---|---|\n" + "\n".join(rows) +
            f"\n\n**These are deterministic violations, not suggestions** — each is a proven "
            f"control failure with evidence in the Security tab.{foot}")
    return body, n


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    doc = json.load(open(a.findings))
    body, n = render(doc)
    open(a.out, "w").write(body)
    print(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
