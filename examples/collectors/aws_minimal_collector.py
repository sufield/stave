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
        actions = set()
        for pol_name in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=name, PolicyName=pol_name)["PolicyDocument"]
            actions |= _collect_actions_from_statements(doc.get("Statement", []))
        actions |= _collect_attached_policy_actions(
            iam, iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []))
        escalation, has_admin = _compute_escalation(actions)
        out.append(asset(
            role["Arn"], "aws_iam_role",
            {"identity": {
                "kind": "role",
                "policies": {
                    "has_inline_policies": has_inline,
                    "has_admin_access": has_admin,
                },
                "trust_policy": {"has_wildcard_principal": has_wildcard_trust},
                "escalation": escalation,
            }}))
    return out


ESCALATION_ACTIONS = {
    "attach_user_policy_self": {"iam:AttachUserPolicy"},
    "attach_role_policy": {"iam:AttachRolePolicy"},
    "attach_group_policy": {"iam:AttachGroupPolicy"},
    "put_user_policy_self": {"iam:PutUserPolicy"},
    "put_role_policy": {"iam:PutRolePolicy"},
    "put_group_policy": {"iam:PutGroupPolicy"},
    "add_user_to_group": {"iam:AddUserToGroup"},
    "create_policy_version": {"iam:CreatePolicyVersion"},
    "set_default_policy_version": {"iam:SetDefaultPolicyVersion"},
    "create_access_key": {"iam:CreateAccessKey"},
    "create_login_profile": {"iam:CreateLoginProfile"},
    "update_login_profile": {"iam:UpdateLoginProfile"},
    "assume_role": {"sts:AssumeRole"},
}

COMPOUND_ESCALATION_ACTIONS = {
    "passrole_createfunction": {
        "required": [{"iam:PassRole"}, {"lambda:CreateFunction"}],
        "invocation": {"lambda:InvokeFunction", "lambda:CreateFunctionUrlConfig"},
    },
}


def _collect_actions_from_statements(statements):
    """Extract Allow actions from a list of policy statements."""
    actions = set()
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        acts = st.get("Action", [])
        if isinstance(acts, str):
            acts = [acts]
        actions.update(acts)
    return actions


def _collect_attached_policy_actions(iam, attached_policies):
    """Extract Allow actions from attached managed policies."""
    actions = set()
    for att in attached_policies:
        try:
            arn = att["PolicyArn"]
            ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
            actions |= _collect_actions_from_statements(doc.get("Statement", []))
        except ClientError:
            pass
    return actions


def _compute_escalation(actions):
    """Compute escalation booleans from a set of IAM actions."""
    def _has_action(required):
        if "*" in actions:
            return True
        for act in required:
            if act in actions:
                return True
            svc = act.split(":")[0] + ":*"
            if svc in actions:
                return True
        return False

    escalation = {}
    for key, required_actions in ESCALATION_ACTIONS.items():
        escalation[key] = {"present": _has_action(required_actions)}

    for key, spec in COMPOUND_ESCALATION_ACTIONS.items():
        all_required = all(_has_action(grp) for grp in spec["required"])
        has_invoke = _has_action(spec["invocation"])
        escalation[key] = {"present": all_required and has_invoke}

    has_admin = "*" in actions or "iam:*" in actions
    return escalation, has_admin


def _policy_grants(iam, user_name):
    """Transcribe policy shape as flat escalation booleans."""
    actions = set()
    for pol_name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
        doc = iam.get_user_policy(UserName=user_name, PolicyName=pol_name)["PolicyDocument"]
        actions |= _collect_actions_from_statements(doc.get("Statement", []))
    actions |= _collect_attached_policy_actions(
        iam, iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", []))
    for grp in iam.list_groups_for_user(UserName=user_name).get("Groups", []):
        gname = grp["GroupName"]
        for pol_name in iam.list_group_policies(GroupName=gname).get("PolicyNames", []):
            doc = iam.get_group_policy(GroupName=gname, PolicyName=pol_name)["PolicyDocument"]
            actions |= _collect_actions_from_statements(doc.get("Statement", []))
        actions |= _collect_attached_policy_actions(
            iam, iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", []))

    escalation, has_admin = _compute_escalation(actions)
    return escalation, has_admin, actions


def map_iam_users(sess, account_id):
    iam = sess.client("iam")
    out = []
    for user in iam.list_users().get("Users", []):
        name = user["UserName"]
        has_inline = len(iam.list_user_policies(UserName=name).get("PolicyNames", [])) > 0
        escalation, has_admin, _ = _policy_grants(iam, name)
        out.append(asset(
            user["Arn"], "aws_iam_user",
            {"identity": {
                "kind": "user",
                "policies": {
                    "has_inline_policies": has_inline,
                    "has_admin_access": has_admin,
                },
                "escalation": escalation,
            }}))
    return out


COLLECTORS = [map_password_policy, map_s3, map_security_groups, map_iam_roles, map_iam_users]


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
        "source": "deployed",
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
