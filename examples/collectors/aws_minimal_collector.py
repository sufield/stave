#!/usr/bin/env python3
"""
aws_minimal_collector.py  —  SAMPLE collector. NOT part of the stave binary.

Turns a live AWS account into a Stave observation snapshot (obs.v0.1) using only
boto3 + read-only API calls. No Steampipe, no extra infrastructure.

Collection is intentionally OUTSIDE Stave: the core stays air-gapped, deterministic,
and credential-free, and only ever reads the snapshot this script emits. Copy it,
extend it, own it — adding an asset type is one map_* function.

    pip install boto3
    python3 aws_minimal_collector.py --region us-east-1 --out ./observations
    ./stave validate --observations ./observations      # confirm shape FIRST
    ./stave apply    --observations ./observations --format json

Read-only. Uses your existing AWS credentials (env / profile / role). Point it at a
vulnerable-lab account or your own.

IMPORTANT — the `properties` paths below are ILLUSTRATIVE. Confirm the exact paths your
catalog expects with:  ./stave contract show <asset_type>   (or `stave forge paths`)
and adjust the map_* functions. `stave validate` is your safety net for the envelope.
"""
import argparse, json, os, sys, datetime
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    sys.exit("pip install boto3")


def asset(asset_id, asset_type, properties):
    return {"id": asset_id, "type": asset_type,
            "vendor": "aws", "properties": properties}


def map_password_policy(sess, account_id):
    iam = sess.client("iam")
    try:
        p = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError:
        return []
    return [asset(
        f"arn:aws:iam::{account_id}:account-password-policy",
        "aws_iam_password_policy",
        {"identity": {
            "kind": "password_policy",
            "password_policy": {
                "max_password_age": p.get("MaxPasswordAge", 0),
                "minimum_length": p.get("MinimumPasswordLength"),
                "reuse_prevention_count": p.get("PasswordReusePrevention", 0),
                "require_symbols": p.get("RequireSymbols", False),
                "require_numbers": p.get("RequireNumbers", False),
                "require_uppercase": p.get("RequireUppercaseCharacters", False),
                "require_lowercase": p.get("RequireLowercaseCharacters", False),
            }
        }})]


def map_s3(sess, account_id):
    s3 = sess.client("s3")
    out = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        enc = True
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            enc = False
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            bpa = all(pab.values())
        except ClientError:
            bpa = False
        try:
            ver = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        except ClientError:
            ver = False
        try:
            log = "LoggingEnabled" in s3.get_bucket_logging(Bucket=name)
        except ClientError:
            log = False
        # In-transit enforcement: bucket policy denies non-SSL requests
        in_transit = False
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            import json as _json
            stmts = _json.loads(pol["Policy"]).get("Statement", [])
            for st in stmts:
                cond = st.get("Condition", {}).get("Bool", {})
                if st.get("Effect") == "Deny" and cond.get("aws:SecureTransport") == "false":
                    in_transit = True
        except ClientError:
            pass
        # Public read access: bucket policy grants Principal:* read actions
        public_read = False
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            import json as _json
            stmts = _json.loads(pol["Policy"]).get("Statement", [])
            for st in stmts:
                princ = st.get("Principal", {})
                if st.get("Effect") == "Allow" and (princ == "*" or (isinstance(princ, dict) and princ.get("AWS") == "*")):
                    public_read = True
        except ClientError:
            pass
        out.append(asset(
            f"arn:aws:s3:::{name}", "aws_s3_bucket",
            {"storage": {
                "kind": "bucket",
                "name": name,
                "versioning": {"enabled": ver},
                "logging": {"enabled": log},
                "encryption": {"in_transit_enforced": in_transit},
                "access": {"public_read": public_read},
            }}))
    return out


def map_security_groups(sess, account_id):
    ec2 = sess.client("ec2")
    out = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        has_open = False
        has_broad_cidr = False
        has_port_range = False
        high_risk = False
        icmp = False
        known_ports = {22, 3389, 1433, 3306, 5432, 27017, 25}
        for rule in sg.get("IpPermissions", []):
            for rng in rule.get("IpRanges", []):
                cidr = rng.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    has_open = True
                elif not cidr.endswith("/32"):
                    has_broad_cidr = True
                fp = rule.get("FromPort")
                tp = rule.get("ToPort")
                if rule.get("IpProtocol") == "icmp":
                    icmp = True
                if fp is not None and tp is not None and fp != tp:
                    has_port_range = True
                if fp is not None and fp in known_ports:
                    high_risk = True
        out.append(asset(
            f"arn:aws:ec2:{sess.region_name}:{account_id}:security-group/{sg['GroupId']}",
            "aws_ec2_security_group",
            {"network": {
                "kind": "security_group",
                "security_group": {
                    "has_broad_cidr": has_broad_cidr or has_open,
                    "high_risk_ports_exposed": high_risk,
                    "icmp_all_types_from_internet": icmp,
                    "has_broad_port_range": has_port_range,
                    "is_unused": False,
                }
            }, "compute": {
                "kind": "security_group",
                "inbound_rules": {
                    "broad_cidr_non_http": has_broad_cidr or has_open,
                    "high_risk_ports_unrestricted": high_risk,
                }
            }}))
    return out


def map_iam_roles(sess, account_id):
    iam = sess.client("iam")
    out = []
    for role in iam.list_roles().get("Roles", []):
        name = role["RoleName"]
        has_inline = len(iam.list_role_policies(RoleName=name).get("PolicyNames", [])) > 0
        trust = role.get("AssumeRolePolicyDocument", {})
        has_wildcard_trust = False
        for st in trust.get("Statement", []):
            p = st.get("Principal", {})
            if p == "*" or (isinstance(p, dict) and p.get("AWS") == "*"):
                has_wildcard_trust = True
        out.append(asset(
            role["Arn"], "aws_iam_role",
            {"identity": {
                "kind": "role",
                "policies": {"has_inline_policies": has_inline},
                "trust_policy": {"has_wildcard_principal": has_wildcard_trust},
            }}))
    return out


COLLECTORS = [map_password_policy, map_s3, map_security_groups, map_iam_roles]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    ap.add_argument("--profile")
    ap.add_argument("--out", default="./observations")
    args = ap.parse_args()

    sess = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = sess.client("sts").get_caller_identity()["Account"]

    assets = []
    for fn in COLLECTORS:
        try:
            assets += fn(sess, account_id)
        except Exception as e:
            print(f"warn: {fn.__name__}: {e}", file=sys.stderr)

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    snapshot = {
        "schema_version": "obs.v0.1",
        "source": "collected",
        "generated_by": {"source_type": "aws.boto3"},
        "captured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "assets": assets,
    }
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"{ts}.json")
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2)
    print(f"wrote {len(assets)} assets -> {path}")
    print("next: ./stave validate --observations", args.out)


if __name__ == "__main__":
    main()
