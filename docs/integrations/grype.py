#!/usr/bin/env python3
"""Join Stave assessment output with Grype vulnerability JSON.

Usage:
    python3 grype.py --stave assessment.json --grype grype-output.json \
        [--resource ARN] [--out unified.json]
"""
import argparse, json, sys
from datetime import datetime, timezone


def load_json(path):
    with open(path) as f:
        return json.load(f)


def parse_grype_vulns(grype_data):
    vulns = []
    for match in grype_data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cvss_entries = vuln.get("cvss", [])
        cvss_score = 0.0
        cvss_vector = ""
        for c in cvss_entries:
            metrics = c.get("metrics", {})
            if metrics.get("baseScore", 0) > cvss_score:
                cvss_score = metrics["baseScore"]
                cvss_vector = c.get("vector", "")

        fix_versions = vuln.get("fix", {}).get("versions", [])
        vulns.append({
            "source": "grype",
            "cve_id": vuln.get("id", ""),
            "package_name": artifact.get("name", ""),
            "package_version": artifact.get("version", ""),
            "fixed_version": fix_versions[0] if fix_versions else "",
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": vuln.get("severity", "").lower(),
            "description": vuln.get("description", ""),
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
    parser = argparse.ArgumentParser(description="Join Stave + Grype output")
    parser.add_argument("--stave", required=True, help="Path to out.v0.1 JSON")
    parser.add_argument("--grype", required=True, help="Path to Grype JSON")
    parser.add_argument("--resource", default="", help="Filter to specific ARN")
    parser.add_argument("--out", default="", help="Output file (default: stdout)")
    args = parser.parse_args()

    stave_data = load_json(args.stave)
    grype_data = load_json(args.grype)

    findings = stave_data.get("findings", [])
    assessed_at = stave_data.get("run", {}).get("now", "")
    vulns = parse_grype_vulns(grype_data)

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
