#!/usr/bin/env python3
"""Terraform AWS provider schema diff against Stave control predicates.

Quarterly gap discovery: extracts security-relevant arguments from
the Terraform AWS provider schema, cross-references against Stave
control field paths, and reports uncovered gaps.

Usage:
    # 1. Generate the schema (one-time per quarter):
    mkdir -p /tmp/tf-schema && cd /tmp/tf-schema
    cat > main.tf << 'EOF'
    terraform { required_providers { aws = { source = "hashicorp/aws", version = ">= 5.0" } } }
    provider "aws" { region = "us-east-1" }
    EOF
    terraform init && terraform providers schema -json > /tmp/tf-aws-schema.json

    # 2. Run the diff:
    python3 tools/tf-schema-diff/diff.py /tmp/tf-aws-schema.json

    # 3. JSON output for automation:
    python3 tools/tf-schema-diff/diff.py /tmp/tf-aws-schema.json --json > gaps.json
"""

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

SECURITY_KEYWORDS = [
    "encrypt", "kms", "public", "policy", "logging", "log",
    "auth", "mfa", "ssl", "tls", "vpc", "subnet", "security",
    "access", "rotation", "backup", "deletion", "protect",
    "multi_az", "redundan", "version", "scan", "monitor",
    "audit", "role", "principal", "permission", "boundary",
    "token", "credential", "session", "duration", "internet",
    "ingress", "egress", "isolation", "privileged", "root",
    "metadata", "imds", "acl", "cidr", "password",
]

TARGET_PREFIXES = [
    "aws_s3", "aws_iam", "aws_ec2", "aws_lambda", "aws_ecs",
    "aws_eks", "aws_rds", "aws_kms", "aws_secretsmanager",
    "aws_cloudtrail", "aws_guardduty", "aws_config",
    "aws_sagemaker", "aws_bedrock", "aws_sso", "aws_organizations",
    "aws_dynamodb", "aws_sns", "aws_sqs", "aws_elasticache",
    "aws_kinesis", "aws_batch", "aws_acm", "aws_lb",
    "aws_cloudfront", "aws_route53", "aws_waf",
    "aws_ecr", "aws_ssm", "aws_inspector", "aws_macie",
    "aws_securityhub", "aws_fms", "aws_vpc", "aws_security_group",
    "aws_efs", "aws_ebs",
]

NOISE_SEGMENTS = {
    "arn", "id", "tags", "tags_all", "name", "description",
    "create_date", "unique_id", "status", "owner_id",
    "timeouts", "force_destroy", "name_prefix", "create",
    "delete", "update", "read",
}

STRONG_KEYWORDS = [
    "encrypt", "kms_key", "public_access", "logging",
    "deletion_protection", "backup", "multi_az", "ssl_policy",
    "tls", "password_policy", "rotation", "access_log",
    "security_group", "subnet", "vpc_config", "privileged",
    "root_access", "metadata_options", "scan_on_push", "audit",
    "monitoring", "guard", "content_policy",
    "sensitive_information_policy", "ingress", "egress", "acl",
    "permission",
]


def extract_attrs(block, prefix=""):
    attrs = []
    if "attributes" in block:
        for name, attr_schema in block["attributes"].items():
            path = f"{prefix}.{name}" if prefix else name
            attrs.append({
                "path": path,
                "type": str(attr_schema.get("type", "unknown")),
                "description": attr_schema.get("description", "")[:200],
            })
    if "block_types" in block:
        for name, bt in block["block_types"].items():
            path = f"{prefix}.{name}" if prefix else name
            if "block" in bt:
                attrs.extend(extract_attrs(bt["block"], path))
    return attrs


def load_stave_fields(controls_dir):
    result = subprocess.run(
        ["grep", "-rh", "field:", str(controls_dir), "--include=*.yaml"],
        capture_output=True, text=True,
    )
    fields = set()
    for line in result.stdout.splitlines():
        field = line.strip().split("field:")[-1].strip().strip('"').strip("'")
        if field:
            cleaned = field.lower()
            if cleaned.startswith("properties."):
                cleaned = cleaned[len("properties."):]
            fields.add(cleaned)
            fields.add(cleaned.replace("_", ""))
            fields.add(cleaned.replace(".", "_"))
            for seg in cleaned.split("."):
                fields.add(seg)
                fields.add(seg.replace("_", ""))
    return fields


def run(schema_path, controls_dir, json_output=False):
    with open(schema_path) as f:
        schema = json.load(f)

    provider_key = "registry.terraform.io/hashicorp/aws"
    resources = schema["provider_schemas"][provider_key]["resource_schemas"]

    # Extract security-relevant arguments from target resources
    security_args = {}
    total_attrs = 0
    total_target = 0
    for res_type, res_schema in resources.items():
        if not any(res_type.startswith(p) for p in TARGET_PREFIXES):
            continue
        total_target += 1
        block = res_schema.get("block", {})
        attrs = extract_attrs(block)
        total_attrs += len(attrs)
        sec_attrs = [
            a for a in attrs
            if any(
                kw in a["path"].lower() or kw in a.get("description", "").lower()
                for kw in SECURITY_KEYWORDS
            )
        ]
        if sec_attrs:
            security_args[res_type] = sec_attrs

    total_sec = sum(len(v) for v in security_args.values())

    # Cross-reference against Stave controls
    stave_fields = load_stave_fields(controls_dir)

    gaps = {}
    covered_count = 0
    for res_type, args in security_args.items():
        for arg in args:
            path_lower = arg["path"].lower()
            path_no_under = path_lower.replace("_", "")
            segments = path_lower.split(".")
            leaf = segments[-1] if segments else path_lower
            leaf_no_under = leaf.replace("_", "")

            is_covered = (
                leaf in stave_fields
                or leaf_no_under in stave_fields
                or path_lower in stave_fields
                or path_no_under in stave_fields
            )
            if is_covered:
                covered_count += 1
            else:
                gaps.setdefault(res_type, []).append(arg)

    total_gaps = sum(len(v) for v in gaps.values())

    # Strong-signal filtering
    strong_gaps = []
    for rt, args in gaps.items():
        parts = rt.split("_")
        svc = parts[1] if len(parts) > 1 else rt
        for a in args:
            path = a["path"]
            if any(seg in NOISE_SEGMENTS for seg in path.split(".")):
                continue
            if any(kw in path.lower() for kw in STRONG_KEYWORDS):
                strong_gaps.append({
                    "resource": rt,
                    "service": svc,
                    "path": path,
                    "description": a.get("description", "")[:120],
                })

    if json_output:
        report = {
            "total_resource_types": len(resources),
            "target_resource_types": total_target,
            "total_arguments": total_attrs,
            "security_relevant": total_sec,
            "covered": covered_count,
            "gaps": total_gaps,
            "coverage_pct": round(covered_count * 100 / total_sec, 1) if total_sec else 0,
            "strong_signal_gaps": len(strong_gaps),
            "gaps_by_service": dict(Counter(g["service"] for g in strong_gaps).most_common()),
            "strong_gaps": strong_gaps,
        }
        json.dump(report, sys.stdout, indent=2)
        print()
        return

    print(f"Provider: hashicorp/aws")
    print(f"Resource types in scope: {total_target} (of {len(resources)})")
    print(f"Total arguments analyzed: {total_attrs:,}")
    print(f"Security-relevant arguments: {total_sec:,}")
    print(f"Covered by Stave predicates: {covered_count}")
    print(f"Uncovered gaps (broad): {total_gaps:,}")
    print(f"Coverage: {covered_count*100/total_sec:.1f}%")
    print(f"Strong-signal gaps: {len(strong_gaps)}")
    print()

    svc_counts = Counter(g["service"] for g in strong_gaps)
    svc_items = {}
    for g in strong_gaps:
        svc_items.setdefault(g["service"], []).append(g)

    print("Strong-signal gaps by service:")
    for svc, count in svc_counts.most_common(15):
        print(f"  {svc}: {count}")
        for item in svc_items[svc][:3]:
            print(f"    {item['resource']}.{item['path']}")
        if count > 3:
            print(f"    ... +{count-3} more")


def main():
    parser = argparse.ArgumentParser(description="Terraform AWS schema diff against Stave controls")
    parser.add_argument("schema", help="Path to terraform providers schema JSON")
    parser.add_argument("--controls", default="controls", help="Stave controls directory")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()
    run(args.schema, args.controls, json_output=args.json)


if __name__ == "__main__":
    main()
