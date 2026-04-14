#!/usr/bin/env python3
"""Enrich a CycloneDX SBOM with Stave findings and optionally upload to Dependency Track.

Step 1 (local, air-gapped):
    Reads Stave out.v0.1 JSON and a CycloneDX SBOM. Produces an enriched
    SBOM file with Stave findings as CycloneDX vulnerabilities.

Step 2 (optional, network):
    Uploads the enriched SBOM to a Dependency Track instance via its BOM
    upload API endpoint.

Usage:
    # Step 1 only — produce enriched SBOM locally
    python3 dependency-track.py --stave assessment.json --sbom sbom.json \
        --out enriched-sbom.json

    # Step 1 + Step 2 — enrich and upload
    python3 dependency-track.py --stave assessment.json --sbom sbom.json \
        --upload --dt-url https://dt.example.com --dt-api-key KEY \
        --project-name patient-api --project-version 1.2.3
"""
import argparse
import base64
import json
import sys
import urllib.request
import urllib.error


def load_json(path):
    with open(path) as f:
        return json.load(f)


def enrich_sbom(sbom, stave_data):
    """Add Stave findings as CycloneDX vulnerabilities (Step 1)."""
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
                "name": "stave:compliance:" + c["framework"],
                "value": c["requirement"],
            })

        asset_id = f.get("asset_id", "")
        if asset_id:
            vuln["affects"] = [{"ref": asset_id}]
        else:
            vuln["affects"] = []

        vulns.append(vuln)

    sbom["vulnerabilities"] = sbom.get("vulnerabilities", []) + vulns
    return sbom


def upload_to_dependency_track(sbom_json, dt_url, api_key, project_name, project_version):
    """Upload enriched SBOM to Dependency Track BOM upload API (Step 2).

    Uses the /api/v1/bom endpoint with base64-encoded BOM payload.
    Returns the API response or raises on failure.
    """
    url = dt_url.rstrip("/") + "/api/v1/bom"

    bom_bytes = json.dumps(sbom_json).encode("utf-8")
    bom_b64 = base64.b64encode(bom_bytes).decode("ascii")

    payload = {
        "projectName": project_name,
        "projectVersion": project_version,
        "autoCreate": True,
        "bom": bom_b64,
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": api_key,
        },
        method="PUT",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {"status": resp.status}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"Upload failed: HTTP {e.code} — {body}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Enrich CycloneDX SBOM with Stave findings and optionally upload to Dependency Track"
    )

    # Step 1 flags (local, air-gapped)
    parser.add_argument("--stave", required=True, help="Path to out.v0.1 JSON")
    parser.add_argument("--sbom", required=True, help="Path to CycloneDX SBOM JSON")
    parser.add_argument("--out", default="", help="Output file for enriched SBOM (default: stdout)")

    # Step 2 flags (optional, network)
    parser.add_argument("--upload", action="store_true", help="Upload enriched SBOM to Dependency Track")
    parser.add_argument("--dt-url", default="", help="Dependency Track base URL (e.g., https://dt.example.com)")
    parser.add_argument("--dt-api-key", default="", help="Dependency Track API key")
    parser.add_argument("--project-name", default="", help="Dependency Track project name")
    parser.add_argument("--project-version", default="", help="Dependency Track project version")

    args = parser.parse_args()

    # --- Step 1: Enrich SBOM locally ---
    stave_data = load_json(args.stave)
    sbom = load_json(args.sbom)

    enriched = enrich_sbom(sbom, stave_data)

    # Write enriched SBOM
    output = json.dumps(enriched, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(output + "\n")
        print(f"Enriched SBOM written to {args.out}", file=sys.stderr)
    else:
        if not args.upload:
            print(output)

    # --- Step 2: Upload to Dependency Track (optional) ---
    if args.upload:
        if not args.dt_url:
            print("--dt-url is required when --upload is set", file=sys.stderr)
            sys.exit(2)
        if not args.dt_api_key:
            print("--dt-api-key is required when --upload is set", file=sys.stderr)
            sys.exit(2)
        if not args.project_name:
            print("--project-name is required when --upload is set", file=sys.stderr)
            sys.exit(2)
        if not args.project_version:
            print("--project-version is required when --upload is set", file=sys.stderr)
            sys.exit(2)

        result = upload_to_dependency_track(
            enriched,
            args.dt_url,
            args.dt_api_key,
            args.project_name,
            args.project_version,
        )
        print(f"Upload successful: {json.dumps(result)}", file=sys.stderr)


if __name__ == "__main__":
    main()
