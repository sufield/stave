#!/usr/bin/env python3
"""Join Stave assessment output with Trivy vulnerability JSON.

Usage:
    python3 trivy.py --stave assessment.json --trivy trivy-output.json \
        [--resource ARN] [--out unified.json]
"""
import argparse, json, sys
from datetime import datetime, timezone


def load_json(path):
    with open(path) as f:
        return json.load(f)


def parse_trivy_vulns(trivy_data):
    vulns = []
    for result in trivy_data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            cvss = v.get("CVSS", {})
            nvd = cvss.get("nvd", {})
            cvss_score = nvd.get("V3Score", 0.0)
            cvss_vector = nvd.get("V3Vector", "")

            vulns.append({
                "source": "trivy",
                "cve_id": v.get("VulnerabilityID", ""),
                "package_name": v.get("PkgName", ""),
                "package_version": v.get("InstalledVersion", ""),
                "fixed_version": v.get("FixedVersion", ""),
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity": v.get("Severity", "").lower(),
                "description": v.get("Description", ""),
            })
    return vulns


def build_unified_record(finding, vulns, assessed_at):
    compliance = []
    for fw, req in (finding.get("control_compliance") or {}).items():
        compliance.append({"framework": fw, "requirement": req})

    stave_severity = (finding.get("control_severity") or "").lower()
    max_cvss = max((v["cvss_score"] for v in vulns), default=0.0)

    note = ""
    if stave_severity in ("critical", "high") and max_cvss >= 7.0:
        note = (f"Stave {stave_severity} finding combined with CVSS {max_cvss:.1f} "
                f"vulnerability on the same resource")

    return {
        "schema_version": "1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "resource_arn": finding.get("asset_id", ""),
        "resource_type": finding.get("asset_type", ""),
        "stave": {
            "finding_id": finding.get("finding_id", ""),
            "control_id": finding.get("control_id", ""),
            "control_name": finding.get("control_name", ""),
            "severity": stave_severity,
            "attack_stage": "",
            "verdict": "fail",
            "finding_message": (finding.get("evidence") or {}).get("temporal_risk", ""),
            "compliance": compliance,
            "remediation": finding.get("remediation", {}),
            "assessed_at": assessed_at,
        },
        "vulnerabilities": vulns,
        "combined_risk": {
            "stave_severity": stave_severity,
            "max_vuln_cvss": max_cvss,
            "compound_risk_note": note,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Join Stave + Trivy output")
    parser.add_argument("--stave", required=True, help="Path to out.v0.1 JSON")
    parser.add_argument("--trivy", required=True, help="Path to Trivy JSON")
    parser.add_argument("--resource", default="", help="Filter to specific ARN")
    parser.add_argument("--out", default="", help="Output file (default: stdout)")
    args = parser.parse_args()

    stave_data = load_json(args.stave)
    trivy_data = load_json(args.trivy)

    findings = stave_data.get("findings", [])
    assessed_at = stave_data.get("run", {}).get("now", "")
    vulns = parse_trivy_vulns(trivy_data)

    records = []
    for f in findings:
        if args.resource and f.get("asset_id") != args.resource:
            continue
        records.append(build_unified_record(f, vulns, assessed_at))

    output = json.dumps(records, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
