#!/usr/bin/env bash
#
# AWS snapshot collector for Stave (collect-only)
#
# Gathers read-only AWS CLI JSON into a raw/ directory, then calls
# `stave transform` to convert it into obs.v0.1 observations. This script does NO
# mapping: the snapshot→observation logic lives entirely in the embedded jq
# filters (the single source of truth). This script only collects raw API output
# and supplies the per-resource join keys (by filename for S3/IAM-inline, by an
# annotation for IAM-role enrichment).
#
# Usage:
#   bash scripts/aws-snapshot.sh [output-directory]
#
# Layout produced under <output-directory>/:
#   raw/            raw AWS CLI JSON (collected here)
#   observations/   obs.v0.1 written by `stave transform`
#
# Environment:
#   AWS_PROFILE / AWS_REGION   Standard AWS CLI selectors.
#   STAVE                      Path to the stave binary (default: stave on PATH).
#
# Prerequisites:
#   - AWS CLI v2 with read-only credentials (SecurityAudit is sufficient).
#   - jq on PATH (lists resource names and stamps role join keys).
#   - stave on PATH (the converter).
#
# Coverage: S3, IAM (roles/users/groups/password policy/inline policies), EBS,
# EC2 (instances, security groups), CloudTrail, AWS Config, OpenSearch,
# CloudWatch alarms. Some calls below feed filters still in development (admin
# analysis, SES, KMS, event selectors, ENIs, instance user-data); they are
# collected now so a snapshot is complete when those filters land — `stave
# transform` simply skips raw files it has no filter for yet.
#
# Exit codes: 0 observations written; 1 missing prerequisite.
# All AWS calls are read-only; nothing leaves the local filesystem.

set -uo pipefail

OUTPUT_DIR="${1:-./my-snapshot}"
RAW_DIR="$OUTPUT_DIR/raw"
OBS_DIR="$OUTPUT_DIR/observations"
STAVE="${STAVE:-stave}"
mkdir -p "$RAW_DIR" "$OBS_DIR"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "ERROR: required tool '$1' not found on PATH" >&2
		exit 1
	}
}
need aws
need jq
need "$STAVE"

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")

# cap <relative-output> <fallback-json> : run the AWS CLI command on stdin,
# writing non-empty output to RAW_DIR/<relative-output>; on failure/empty write
# the fallback (or, if fallback is "-", remove the file so transform skips it).
cap() {
	local out="$RAW_DIR/$1" fb="$2"
	if cat >"$out.tmp" 2>/dev/null && [ -s "$out.tmp" ]; then
		mv "$out.tmp" "$out"
	else
		rm -f "$out.tmp"
		if [ "$fb" = "-" ]; then rm -f "$out"; else printf '%s\n' "$fb" >"$out"; fi
	fi
}

echo "==> Collecting raw AWS snapshots into $RAW_DIR (read-only)"

# ----- IAM -----------------------------------------------------------------
echo "  IAM"
aws iam get-account-authorization-details 2>/dev/null | cap iam-authorization-details.json '-'
aws iam get-account-password-policy 2>/dev/null | cap iam-password-policy.json '-'

aws iam list-roles 2>/dev/null | cap iam-roles.json '{"Roles":[]}'
while IFS=$'\t' read -r role arn; do
	[ -z "$role" ] && continue
	case "$role" in AWSServiceRole*) continue ;; esac
	aws iam list-attached-role-policies --role-name "$role" 2>/dev/null \
		| jq --arg arn "$arn" '. + {RoleArn: $arn}' | cap "iam-attached-$role.json" "{\"RoleArn\":\"$arn\",\"AttachedPolicies\":[]}"
	aws iam list-role-tags --role-name "$role" 2>/dev/null \
		| jq --arg arn "$arn" '. + {RoleArn: $arn}' | cap "iam-tags-$role.json" "{\"RoleArn\":\"$arn\",\"Tags\":[]}"
done < <(jq -r '.Roles[] | "\(.RoleName)\t\(.Arn)"' "$RAW_DIR/iam-roles.json" 2>/dev/null)

aws iam list-users 2>/dev/null | cap iam-users.json '{"Users":[]}'
while read -r user; do
	[ -z "$user" ] && continue
	# user-inline-<user>.json is filename-keyed (raw {"PolicyNames":[...]}).
	aws iam list-user-policies --user-name "$user" 2>/dev/null | cap "user-inline-$user.json" '-'
done < <(jq -r '.Users[].UserName' "$RAW_DIR/iam-users.json" 2>/dev/null)

aws iam list-groups 2>/dev/null | cap iam-groups.json '{"Groups":[]}'
while read -r group; do
	[ -z "$group" ] && continue
	aws iam list-group-policies --group-name "$group" 2>/dev/null | cap "group-inline-$group.json" '-'
done < <(jq -r '.Groups[].GroupName' "$RAW_DIR/iam-groups.json" 2>/dev/null)

# ----- S3 ------------------------------------------------------------------
echo "  S3 buckets"
aws s3api list-buckets 2>/dev/null | cap s3-buckets.json '{"Buckets":[]}'
for bucket in $(jq -r '.Buckets[].Name' "$RAW_DIR/s3-buckets.json" 2>/dev/null); do
	aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null | cap "s3-pab-$bucket.json" '{"PublicAccessBlockConfiguration":{}}'
	aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null | cap "s3-encryption-$bucket.json" '{"ServerSideEncryptionConfiguration":{}}'
	aws s3api get-bucket-tagging --bucket "$bucket" 2>/dev/null | cap "s3-tags-$bucket.json" '{"TagSet":[]}'
done

# ----- EC2 -----------------------------------------------------------------
echo "  EC2"
aws ec2 describe-volumes 2>/dev/null | cap ec2_volumes.json '{"Volumes":[]}'
aws ec2 describe-security-groups 2>/dev/null | cap ec2_security_groups.json '{"SecurityGroups":[]}'
# For SG is_unused (filter in development): which ENIs reference which SG.
aws ec2 describe-network-interfaces 2>/dev/null | cap ec2_network_interfaces.json '-'
aws ec2 describe-instances 2>/dev/null | cap ec2_instances.json '{"Reservations":[]}'
while read -r instance; do
	[ -z "$instance" ] && continue
	# user-data for has_secrets (filter in development).
	aws ec2 describe-instance-attribute --instance-id "$instance" --attribute userData 2>/dev/null | cap "ec2-userdata-$instance.json" '-'
done < <(jq -r '.Reservations[].Instances[].InstanceId' "$RAW_DIR/ec2_instances.json" 2>/dev/null)

# ----- CloudTrail ----------------------------------------------------------
echo "  CloudTrail"
aws cloudtrail describe-trails 2>/dev/null | cap cloudtrail_trails.json '{"trailList":[]}'
while read -r trail; do
	[ -z "$trail" ] && continue
	# event selectors for data_events_s3 (filter in development).
	aws cloudtrail get-event-selectors --trail-name "$trail" 2>/dev/null | cap "cloudtrail-eventselectors-$trail.json" '-'
done < <(jq -r '.trailList[].Name' "$RAW_DIR/cloudtrail_trails.json" 2>/dev/null)

# ----- AWS Config ----------------------------------------------------------
echo "  AWS Config"
aws configservice describe-configuration-recorders 2>/dev/null | cap config_recorders.json '{"ConfigurationRecorders":[]}'

# ----- OpenSearch ----------------------------------------------------------
echo "  OpenSearch"
aws opensearch list-domain-names 2>/dev/null | cap es_domains.json '{"DomainNames":[]}'
while read -r domain; do
	[ -z "$domain" ] && continue
	aws opensearch describe-domain --domain-name "$domain" 2>/dev/null | cap "es_domain_$domain.json" '-'
done < <(jq -r '.DomainNames[].DomainName' "$RAW_DIR/es_domains.json" 2>/dev/null)

# ----- CloudWatch ----------------------------------------------------------
echo "  CloudWatch alarms"
aws cloudwatch describe-alarms 2>/dev/null | cap cloudwatch_alarms.json '{"MetricAlarms":[]}'

# ----- KMS -----------------------------------------------------------------
# get-key-rotation-status is self-describing (returns KeyId as the full ARN);
# get-key-policy carries no key identity, so stamp it with the KeyArn.
echo "  KMS"
aws kms list-keys 2>/dev/null | cap kms_keys.json '{"Keys":[]}'
while IFS=$'\t' read -r keyid keyarn; do
	[ -z "$keyid" ] && continue
	aws kms get-key-rotation-status --key-id "$keyid" 2>/dev/null | cap "kms-rotation-$keyid.json" '-'
	aws kms get-key-policy --key-id "$keyid" --policy-name default 2>/dev/null \
		| jq --arg arn "$keyarn" '. + {KeyArn: $arn}' | cap "kms-policy-$keyid.json" '-'
done < <(jq -r '.Keys[] | "\(.KeyId)\t\(.KeyArn)"' "$RAW_DIR/kms_keys.json" 2>/dev/null)

# ----- SES (filters in development) ---------------------------------------
echo "  SES"
aws ses list-identities 2>/dev/null | cap ses_identities.json '{"Identities":[]}'
while read -r ident; do
	[ -z "$ident" ] && continue
	aws ses get-identity-dkim-attributes --identities "$ident" 2>/dev/null | cap "ses-dkim-$ident.json" '-'
	aws ses list-identity-policies --identity "$ident" 2>/dev/null | cap "ses-policies-$ident.json" '-'
done < <(jq -r '.Identities[]' "$RAW_DIR/ses_identities.json" 2>/dev/null)

# ----- convert (the .jq filters are the single source of truth) ------------
echo ""
echo "==> Converting raw snapshots → obs.v0.1 (stave transform)"
"$STAVE" transform -i "$RAW_DIR" -o "$OBS_DIR" --account "$ACCOUNT" --eval-time "$NOW"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Next steps:"
echo "  stave apply --observations $OBS_DIR"
echo ""
echo "  # machine-readable:"
echo "  stave apply --observations $OBS_DIR --format json | jq '.findings | length'"
