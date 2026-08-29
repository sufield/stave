#!/usr/bin/env python3
"""TRIAGE-XA denominator tool.

Walks botocore service-2.json models to discover cross-account mechanisms,
classifies each into (service, mechanism_class, direction) triples, and
joins against the Stave catalog to mark covered/uncovered pairs.

Usage:
    python3 tools/xa-inventory.py [--controls-dir internal/controls]
"""

import json
import os
import subprocess
import sys
from collections import defaultdict

BOTO_DATA = "/usr/lib/python3/dist-packages/botocore/data"
DEFAULT_CONTROLS = "internal/controls"

# --- Direction derivation (EGRESS-RESIDUE Part 3) ---
DIRECTION_MAP = {
    "resource-policy": "inbound-grant",
    "grant": "inbound-grant",
    "invitation-delegation": "inbound-grant",
    "trust-policy": "inbound-grant",
    "federation": "inbound-grant",
    "attribute-share": "outbound-flow",
    "ram-share": "outbound-flow",
    "association": "both",
    "access-point-policy": "inbound-grant",
    "access-entry": "inbound-grant",
    "pod-identity": "inbound-grant",
    "oidc-trust": "inbound-grant",
}

# --- Botocore service name → catalog directory name ---
SVC_TO_CATALOG = {
    "acm-pca": "acmpca",
    "apigateway": "apigateway",
    "apigatewayv2": "apigatewayv2",
    "backup": "backup",
    "cloudtrail": "cloudtrail",
    "codebuild": "codebuild",
    "codeartifact": "codeartifact",
    "comprehend": "comprehend",
    "ds": "directoryservice",
    "dynamodb": "dynamodb",
    "ec2": "ec2",
    "events": "eventbridge",
    "ecr": "ecr",
    "ecr-public": "ecr",
    "eks": "eks",
    "es": "opensearch",
    "fms": "fms",
    "gamelift": None,  # no catalog dir
    "glacier": "glacier",
    "glue": "glue",
    "iam": "iam",
    "kinesis": "kinesis",
    "kms": "kms",
    "lakeformation": "lakeformation",
    "lambda": "lambda",
    "lexv2-models": None,
    "license-manager": None,
    "logs": "cloudwatch",
    "lookoutequipment": None,
    "macie2": "macie",
    "marketplace-catalog": "marketplace",
    "mediaconvert": None,
    "mediastore": "mediastore",
    "migration-hub-refactor-spaces": None,
    "network-firewall": "networkfirewall",
    "networkmanager": None,
    "opensearch": "opensearch",
    "organizations": "org",
    "ram": "ram",
    "redshift": "redshift",
    "redshift-serverless": "redshift",
    "route53-recovery-control-config": "route53",
    "s3": "s3",
    "s3control": "s3",
    "schemas": None,
    "secretsmanager": "secretsmanager",
    "sns": "sns",
    "sqs": "sqs",
    "ssm": "ssm",
    "ssm-incidents": "ssm",
    "vpc-lattice": "vpclattice",
    "waf": "waf",
    "waf-regional": "waf",
    "wafv2": "waf",
    "xray": "xray",
}

# --- Resource-policy operation patterns ---
RESOURCE_POLICY_OPS = {
    "PutResourcePolicy", "GetResourcePolicy", "DeleteResourcePolicy",
    "PutBucketPolicy", "GetBucketPolicy", "DeleteBucketPolicy",
    "PutKeyPolicy", "GetKeyPolicy",
    "PutAccessPointPolicy", "PutAccessPointPolicyForObjectLambda",
    "SetVaultAccessPolicy",
    "PutBackupVaultAccessPolicy",  # backup
    "PutContainerPolicy",
    "PutPermission",  # events (EventBridge)
    "SetRepositoryPolicy", "PutRegistryPolicy",
    "PutDomainPermissionsPolicy",
    "PutPermissionPolicy",
    "PutPolicy",  # acm-pca
}

# Lambda/SQS/SNS AddPermission → resource-policy
ADD_PERMISSION_SVCS = {"lambda", "sqs", "sns"}

# SNS SetTopicAttributes / SQS SetQueueAttributes can set Policy
QUEUE_TOPIC_POLICY_OPS = {
    "sqs": "SetQueueAttributes",
    "sns": "SetTopicAttributes",
}


def load_latest_model(svc_name):
    svc_dir = os.path.join(BOTO_DATA, svc_name)
    if not os.path.isdir(svc_dir):
        return None
    versions = sorted(os.listdir(svc_dir))
    if not versions:
        return None
    model_path = os.path.join(svc_dir, versions[-1], "service-2.json")
    if not os.path.exists(model_path):
        return None
    with open(model_path) as f:
        return json.load(f)


def discover_pairs():
    """Discover all (service, mechanism, direction) triples from botocore."""
    pairs = []
    seen = set()

    def add(svc, mechanism):
        key = (svc, mechanism)
        if key not in seen:
            seen.add(key)
            direction = DIRECTION_MAP[mechanism]
            pairs.append({"service": svc, "mechanism": mechanism, "direction": direction})

    # Hardcoded pairs that aren't purely operation-discoverable
    add("iam", "trust-policy")
    add("iam", "federation")
    # apigateway: policy is embedded in CreateRestApi, not a dedicated op
    add("apigateway", "resource-policy")
    # dynamodb: PutResourcePolicy added 2023-09 but botocore 1.34.46 model (2012-08-10) predates it
    add("dynamodb", "resource-policy")

    for svc_name in sorted(os.listdir(BOTO_DATA)):
        model = load_latest_model(svc_name)
        if model is None:
            continue

        ops = set(model.get("operations", {}).keys())
        canonical = svc_name  # use botocore dir name as service identifier

        # Resource-policy detection
        for op in ops:
            if op in RESOURCE_POLICY_OPS:
                add(canonical, "resource-policy")
                break
        else:
            # Check AddPermission for lambda/sqs/sns
            if canonical in ADD_PERMISSION_SVCS and "AddPermission" in ops:
                add(canonical, "resource-policy")
            # Check queue/topic attribute setting
            elif canonical in QUEUE_TOPIC_POLICY_OPS:
                if QUEUE_TOPIC_POLICY_OPS[canonical] in ops:
                    add(canonical, "resource-policy")

        # KMS grants
        if canonical == "kms" and "CreateGrant" in ops:
            add("kms", "grant")

        # RAM shares
        if canonical == "ram" and "CreateResourceShare" in ops:
            add("ram", "ram-share")

        # EC2 attribute shares
        if canonical == "ec2":
            for op in ops:
                if op in ("ModifyImageAttribute", "ModifySnapshotAttribute", "ModifyFpgaImageAttribute"):
                    add("ec2", "attribute-share")
                    break

        # VPC peering / transit gateway peering (association)
        if canonical == "ec2":
            for op in ops:
                if op in ("CreateVpcPeeringConnection", "CreateTransitGatewayPeeringAttachment"):
                    add("ec2", "association")
                    break

        # OpenSearch cross-cluster
        if canonical in ("opensearch", "es"):
            if "CreateOutboundConnection" in ops or "CreateOutboundCrossClusterSearchConnection" in ops:
                add(canonical, "association")

        # GameLift VPC peering
        if canonical == "gamelift" and "CreateVpcPeeringConnection" in ops:
            add("gamelift", "association")

        # Redshift data shares
        if canonical == "redshift" and "AuthorizeDataShare" in ops:
            add("redshift", "association")

        # Lake Formation cross-account grants
        if canonical == "lakeformation" and "GrantPermissions" in ops:
            add("lakeformation", "association")

        # License Manager grants
        if canonical == "license-manager" and "CreateGrant" in ops:
            add("license-manager", "grant")

        # Organizations invitation
        if canonical == "organizations" and "InviteAccountToOrganization" in ops:
            add("organizations", "invitation-delegation")

        # Directory Service trust
        if canonical == "ds" and "CreateTrust" in ops:
            add("ds", "invitation-delegation")

        # Macie invitations
        if canonical == "macie2" and "CreateInvitations" in ops:
            add("macie2", "invitation-delegation")

        # Network Manager peering
        if canonical == "networkmanager" and "CreateTransitGatewayPeering" in ops:
            add("networkmanager", "association")

    # Add sub-mechanisms from XA-SCHEMA-FIRST that botocore ops alone don't surface:
    # - s3 access-point is a sub-mechanism of s3 resource-policy (PutAccessPointPolicy already found)
    #   but we want it as a separate entry for the schema-first check
    add("s3", "access-point-policy")
    # - EKS access entries (CreateAccessEntry is the operation)
    eks_model = load_latest_model("eks")
    if eks_model and "CreateAccessEntry" in eks_model.get("operations", {}):
        add("eks", "access-entry")
    # - EKS pod identity
    # pod identity is in eks-auth service
    eksauth = load_latest_model("eks-auth")
    if eksauth:
        add("eks", "pod-identity")
    # - IAM OIDC trust (sub-type of federation, separate for schema-first check)
    add("iam", "oidc-trust")

    return pairs


def catalog_dir_for(svc_name):
    """Map botocore service name to catalog directory name."""
    if svc_name in SVC_TO_CATALOG:
        return SVC_TO_CATALOG[svc_name]
    # Direct match attempt
    return svc_name if os.path.isdir(os.path.join(DEFAULT_CONTROLS, svc_name)) else None


def check_coverage(pairs, controls_dir):
    """Join pairs against the catalog. Mark each as COVERED or UNCOVERED."""
    xa_keywords = [
        "CROSSACCOUNT", "crossaccount", "cross_account", "cross-account",
        "EXTERNAL", "external_principal", "external_access",
        "PUBLIC", "public_access", "public.001",
        "POLICY.CROSSACCOUNT", "POLICY.PUBLIC",
    ]

    for pair in pairs:
        svc = pair["service"]
        mechanism = pair["mechanism"]
        cat_dir = catalog_dir_for(svc)

        if cat_dir is None:
            pair["covered"] = False
            pair["controls"] = []
            continue

        cat_path = os.path.join(controls_dir, cat_dir)
        if not os.path.isdir(cat_path):
            pair["covered"] = False
            pair["controls"] = []
            continue

        # Grep for cross-account/external/public controls in this service dir
        try:
            result = subprocess.run(
                ["grep", "-rl",
                 r"CROSSACCOUNT\|crossaccount\|cross_account\|EXTERNAL\|external.*principal\|PUBLIC\|public.*access\|cross.account",
                 cat_path, "--include=*.yaml"],
                capture_output=True, text=True, timeout=10
            )
            files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        except (subprocess.TimeoutExpired, Exception):
            files = []

        # For grant mechanism, also check grant-specific controls
        if mechanism == "grant":
            try:
                result2 = subprocess.run(
                    ["grep", "-rl", r"GRANT\|grant", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                grant_files = [f.strip() for f in result2.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + grant_files))
            except Exception:
                pass

        # For access-entry, check for access entry controls
        if mechanism == "access-entry":
            try:
                result3 = subprocess.run(
                    ["grep", "-rl", r"ACCESSENTRY\|access.entry", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                ae_files = [f.strip() for f in result3.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + ae_files))
            except Exception:
                pass

        # For oidc-trust, check for OIDC controls
        if mechanism == "oidc-trust":
            try:
                result4 = subprocess.run(
                    ["grep", "-rl", r"OIDC\|oidc", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                oidc_files = [f.strip() for f in result4.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + oidc_files))
            except Exception:
                pass

        # For federation, also check federation controls
        if mechanism == "federation":
            try:
                result5 = subprocess.run(
                    ["grep", "-rl", r"FEDERATION\|federation\|SAML\|OIDC", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                fed_files = [f.strip() for f in result5.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + fed_files))
            except Exception:
                pass

        # For trust-policy, check trust controls
        if mechanism == "trust-policy":
            try:
                result6 = subprocess.run(
                    ["grep", "-rl", r"TRUST\|trust.policy\|trust_policy", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                trust_files = [f.strip() for f in result6.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + trust_files))
            except Exception:
                pass

        # For pod-identity, check pod identity controls
        if mechanism == "pod-identity":
            try:
                result7 = subprocess.run(
                    ["grep", "-rl", r"PODIDENTITY\|pod.identity", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                pod_files = [f.strip() for f in result7.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + pod_files))
            except Exception:
                pass

        # For access-point-policy, check AP controls
        if mechanism == "access-point-policy":
            try:
                result8 = subprocess.run(
                    ["grep", "-rl", r"AP\.\|access.point\|ACCESSPOINT", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                ap_files = [f.strip() for f in result8.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + ap_files))
            except Exception:
                pass

        # For invitation-delegation, check invitation controls
        if mechanism == "invitation-delegation":
            try:
                result9 = subprocess.run(
                    ["grep", "-rl", r"INVITE\|invite\|DELEGATION\|delegation\|TRUST\|trust", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                inv_files = [f.strip() for f in result9.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + inv_files))
            except Exception:
                pass

        # For ram-share, check RAM share controls
        if mechanism == "ram-share":
            try:
                result10 = subprocess.run(
                    ["grep", "-rl", r"RAM\|ram.*share\|resource.share", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                ram_files = [f.strip() for f in result10.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + ram_files))
            except Exception:
                pass

        # For attribute-share, check image/snapshot sharing controls
        if mechanism == "attribute-share":
            try:
                result11 = subprocess.run(
                    ["grep", "-rl", r"SHARE\|share\|IMAGE\|SNAPSHOT\|AMI", cat_path, "--include=*.yaml"],
                    capture_output=True, text=True, timeout=10
                )
                share_files = [f.strip() for f in result11.stdout.strip().split("\n") if f.strip()]
                files = list(set(files + share_files))
            except Exception:
                pass

        # Extract control IDs from matched files
        control_ids = []
        for f in files[:5]:
            try:
                r = subprocess.run(
                    ["grep", "-m1", "^id:", f],
                    capture_output=True, text=True, timeout=5
                )
                if r.stdout.strip():
                    ctl_id = r.stdout.strip().replace("id: ", "").replace("id:", "").strip()
                    control_ids.append(ctl_id)
            except Exception:
                pass

        pair["covered"] = len(files) > 0
        pair["controls"] = control_ids


def run_known_answer_checks(pairs):
    """Check the 12 required pairs, forbidden absent, and direction checks."""
    pair_lookup = {(p["service"], p["mechanism"]): p for p in pairs}

    required = [
        ("iam", "trust-policy"),
        ("s3", "resource-policy"),
        ("kms", "resource-policy"),
        ("kms", "grant"),
        ("sqs", "resource-policy"),
        ("sns", "resource-policy"),
        ("lambda", "resource-policy"),
        ("ram", "ram-share"),
        ("iam", "federation"),
        ("secretsmanager", "resource-policy"),
        ("ecr", "resource-policy"),
        ("glacier", "resource-policy"),
    ]

    results = {"required_present": [], "required_missing": []}
    for svc, mech in required:
        if (svc, mech) in pair_lookup:
            results["required_present"].append(f"{svc}:{mech}")
        else:
            results["required_missing"].append(f"{svc}:{mech}")

    # Direction checks
    kms_grant = pair_lookup.get(("kms", "grant"))
    ec2_attr = pair_lookup.get(("ec2", "attribute-share"))
    results["direction_checks"] = {
        "kms:grant": kms_grant["direction"] if kms_grant else "MISSING",
        "ec2:attribute-share": ec2_attr["direction"] if ec2_attr else "MISSING",
    }

    return results


def run_schema_first_checks(pairs):
    """Check that XA-SCHEMA-FIRST entries show as covered."""
    pair_lookup = {(p["service"], p["mechanism"]): p for p in pairs}

    checks = [
        ("kms", "grant", "CTL.KMS.GRANT.EXTERNAL.001"),
        ("s3", "access-point-policy", "CTL.S3.AP.POLICY.EXTERNAL.001"),
        ("eks", "access-entry", "CTL.EKS.ACCESSENTRY.EXTERNAL.001"),
        ("iam", "oidc-trust", "CTL.IAM.TRUST.OIDC.UNSCOPED.001"),
    ]

    results = []
    for svc, mech, expected_ctl in checks:
        pair = pair_lookup.get((svc, mech))
        if pair is None:
            results.append({"pair": f"{svc}:{mech}", "status": "MISSING", "expected": expected_ctl})
        else:
            results.append({
                "pair": f"{svc}:{mech}",
                "status": "COVERED" if pair["covered"] else "UNCOVERED",
                "controls": pair.get("controls", []),
                "expected": expected_ctl,
            })

    return results


OOS_REASONS = {
    "codeguruprofiler": "negligible enterprise prevalence",
    "comprehend": "custom model sharing is niche; core risks covered by existing controls",
    "fms": "resource policy is for cross-org policy sharing; normal usage is within-org via delegated admin",
    "gamelift": "game hosting VPC peering; negligible enterprise prevalence",
    "lexv2-models": "chatbot model sharing; negligible prevalence",
    "license-manager": "license grants; negligible prevalence",
    "lookoutequipment": "industrial ML service; negligible prevalence",
    "marketplace-catalog": "seller-side catalog API; not relevant to buyer account security posture",
    "mediaconvert": "media transcoding queue sharing; negligible prevalence",
    "migration-hub-refactor-spaces": "migration tool; negligible prevalence",
    "networkmanager": "network manager peering/policies; negligible prevalence",
    "schemas": "EventBridge Schema Registry sharing; negligible prevalence",
}


def emit_checklist(pairs):
    """Emit data/frameworks/cross-account-v1.yaml checklist YAML."""
    lines = []
    lines.append("# Cross-Account Mechanism Coverage — generated by tools/xa-inventory.py")
    lines.append("# Do not hand-edit. Regenerate with: make xa-checklist")
    lines.append(f"standard: Cross-Account Mechanism Coverage v1")
    lines.append(f"total: {len(pairs)}")
    lines.append("")
    lines.append("checks:")

    for p in sorted(pairs, key=lambda x: (x["service"], x["mechanism"])):
        pair_id = f"{p['service']}:{p['mechanism']}"
        direction = p["direction"]
        covered = p.get("covered", False)
        controls = p.get("controls", [])

        lines.append("")
        lines.append(f"  - id: {pair_id}")
        lines.append(f"    service: {p['service']}")
        if covered and controls:
            ctrl_list = ", ".join(os.path.splitext(os.path.basename(c))[0] for c in controls[:3])
            lines.append(f"    description: \"{p['mechanism']} ({direction}) — {ctrl_list}\"")
            lines.append(f"    verdict: COVERED")
        else:
            lines.append(f"    description: \"{p['mechanism']} ({direction})\"")
            reason = OOS_REASONS.get(p["service"], "negligible prevalence")
            lines.append(f"    verdict: OOS")
            lines.append(f"    verdict_reason: \"{reason}\"")

    lines.append("")
    print("\n".join(lines))


def main():
    controls_dir = DEFAULT_CONTROLS
    checklist_mode = False
    args = sys.argv[1:]
    while args:
        if args[0] == "--controls-dir" and len(args) > 1:
            controls_dir = args[1]
            args = args[2:]
        elif args[0] == "--checklist":
            checklist_mode = True
            args = args[1:]
        else:
            args = args[1:]

    pairs = discover_pairs()
    check_coverage(pairs, controls_dir)

    if checklist_mode:
        emit_checklist(pairs)
        return

    print("=" * 70)
    print("TRIAGE-XA: Cross-Account Mechanism Denominator Tool")
    print("=" * 70)
    print()

    # --- OUTPUT 1: Total pair count by mechanism class and direction ---
    print("1. TOTAL PAIR COUNT BY MECHANISM CLASS AND DIRECTION")
    print("-" * 55)
    by_mechanism = defaultdict(int)
    by_direction = defaultdict(int)
    for p in pairs:
        by_mechanism[p["mechanism"]] += 1
        by_direction[p["direction"]] += 1

    for mech in sorted(by_mechanism):
        direction = DIRECTION_MAP.get(mech, "?")
        print(f"  {mech:30s}  {by_mechanism[mech]:3d}  ({direction})")
    print(f"  {'':30s}  ---")
    print(f"  {'TOTAL':30s}  {len(pairs):3d}")
    print()
    print(f"  By direction:")
    for d in sorted(by_direction):
        print(f"    {d:20s}  {by_direction[d]:3d}")
    print()

    # --- OUTPUT 2: Per-service projection ---
    print("2. PER-SERVICE PROJECTION")
    print("-" * 55)
    services = sorted(set(p["service"] for p in pairs))
    print(f"  Services with at least one mechanism: {len(services)}")
    print()
    for svc in services:
        mechs = [p["mechanism"] for p in pairs if p["service"] == svc]
        covered = all(p["covered"] for p in pairs if p["service"] == svc)
        status = "COVERED" if covered else "PARTIAL" if any(p["covered"] for p in pairs if p["service"] == svc) else "UNCOVERED"
        print(f"  {svc:35s}  {', '.join(mechs):45s}  {status}")
    print()

    # --- OUTPUT 3: UNCOVERED pair list ---
    print("3. UNCOVERED PAIRS")
    print("-" * 55)
    uncovered = [p for p in pairs if not p["covered"]]
    if uncovered:
        for p in sorted(uncovered, key=lambda x: (x["service"], x["mechanism"])):
            print(f"  {p['service']}:{p['mechanism']}  ({p['direction']})")
        print(f"\n  Total uncovered: {len(uncovered)}")
    else:
        print("  (none)")
    print()

    # --- OUTPUT 4: Known-answer results ---
    print("4. KNOWN-ANSWER CHECKS")
    print("-" * 55)
    ka = run_known_answer_checks(pairs)
    print(f"  Required pairs present: {len(ka['required_present'])}/12")
    for p in ka["required_present"]:
        print(f"    ✓ {p}")
    if ka["required_missing"]:
        print(f"  Required pairs MISSING:")
        for p in ka["required_missing"]:
            print(f"    ✗ {p}")
    print()
    print(f"  Direction checks:")
    for pair_name, direction in ka["direction_checks"].items():
        expected = "inbound-grant" if "grant" in pair_name else "outbound-flow"
        status = "✓" if direction == expected else "✗"
        print(f"    {status} {pair_name}: {direction} (expected {expected})")
    print()

    # --- OUTPUT 5: Schema-first coverage confirmation ---
    print("5. XA-SCHEMA-FIRST COVERAGE CONFIRMATION")
    print("-" * 55)
    sf = run_schema_first_checks(pairs)
    for check in sf:
        status_mark = "✓" if check["status"] == "COVERED" else "✗"
        ctrls = ", ".join(check.get("controls", [])[:3]) if check.get("controls") else check["expected"]
        print(f"  {status_mark} {check['pair']:30s}  {check['status']:10s}  {ctrls}")
    print()

    # Summary
    covered_count = sum(1 for p in pairs if p["covered"])
    print("=" * 70)
    print(f"SUMMARY: {len(pairs)} pairs, {covered_count} covered, {len(pairs) - covered_count} uncovered")
    print(f"         {len(services)} services with cross-account mechanisms")
    print("=" * 70)


if __name__ == "__main__":
    main()
