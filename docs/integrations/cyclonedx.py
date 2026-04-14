#!/usr/bin/env python3
"""Enrich a CycloneDX SBOM with Stave finding annotations.

Usage:
    python3 cyclonedx.py --stave assessment.json --sbom sbom.json \
        [--out enriched-sbom.json]
"""
import argparse, json, sys
from datetime import datetime, timezone


def load_json(path):
    with open(path) as f:
        return json.load(f)


def enrich_sbom(sbom, stave_data):
    """Add Stave findings as CycloneDX vulnerabilities."""
    findings = stave_data.get("findings", [])
    assessed_at = stave_data.get("run", {}).get("now", "")

    vulns = []
    for f in findings:
        compliance = []
        for fw, req in (f.get("control_compliance") or {}).items():
            compliance.append({"framework": fw, "requirement": req})

        vuln = {
            "id": f.get("finding_id", f.get("control_id", "")),
            "source": {"name": "stave", "url": "https://stavecli.dev"},
            "ratings": [{
                "score": {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0}.get(
                    (f.get("control_severity") or "").lower(), 0.0
                ),
                "severity": (f.get("control_severity") or "").lower(),
                "method": "other",
            }],
            "description": (f.get("evidence") or {}).get("temporal_risk", ""),
            "recommendation": (f.get("remediation") or {}).get("action", ""),
            "properties": [
                {"name": "stave:control_id", "value": f.get("control_id", "")},
                {"name": "stave:finding_id", "value": f.get("finding_id", "")},
                {"name": "stave:assessed_at", "value": assessed_at},
            ],
        }

        for c in compliance:
            vuln["properties"].append({
                "name": f"stave:compliance:{c['framework']}",
                "value": c["requirement"],
            })

        affects = []
        asset_id = f.get("asset_id", "")
        if asset_id:
            affects.append({"ref": asset_id})
        vuln["affects"] = affects

        vulns.append(vuln)

    sbom["vulnerabilities"] = sbom.get("vulnerabilities", []) + vulns
    return sbom


def main():
    parser = argparse.ArgumentParser(description="Enrich CycloneDX SBOM with Stave findings")
    parser.add_argument("--stave", required=True, help="Path to out.v0.1 JSON")
    parser.add_argument("--sbom", required=True, help="Path to CycloneDX SBOM JSON")
    parser.add_argument("--out", default="", help="Output file (default: stdout)")
    args = parser.parse_args()

    stave_data = load_json(args.stave)
    sbom = load_json(args.sbom)

    enriched = enrich_sbom(sbom, stave_data)

    output = json.dumps(enriched, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
