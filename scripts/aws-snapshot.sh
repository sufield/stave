#!/usr/bin/env bash
#
# Minimal AWS snapshot collector for Stave
#
# Produces a single obs.v0.1 snapshot file under <output-dir>/ containing
# read-only configuration data for the user's S3 buckets and IAM roles.
# Suitable for `stave apply --observations <output-dir>` to produce the
# first compound finding on the user's own account in under 5 minutes.
#
# Usage:
#   bash scripts/aws-snapshot.sh [output-directory]
#
# Environment:
#   AWS_PROFILE      Standard AWS CLI profile selector.
#   AWS_REGION       Standard AWS CLI region selector.
#
# Prerequisites:
#   - AWS CLI v2 configured with read-only credentials (the
#     SecurityAudit managed policy is sufficient).
#   - jq on PATH.
#
# Scope (deliberate, do not expand without a follow-up iteration):
#   - S3 buckets: name, public-access-block, encryption-at-rest, tagging.
#   - IAM roles (excluding AWSServiceRole*): name, trust policy's
#     trusted services, attached managed-policy ARNs, tags.
#
# This is the minimal collector for the "my own data" onboarding step.
# It is not a full extractor — policy-statement analysis,
# cross-account-trust derivation, ghost-reference resolution, and
# every service beyond S3 + IAM are out of scope here. See
# docs/extractor-prompt.md for the full extractor template.
#
# Exit codes:
#   0  snapshot written
#   1  missing prerequisite (aws or jq)
#   2  AWS API call failed in a non-recoverable way
#
# The script is air-gap-aware on its outputs: it never sends data
# outside the local filesystem. All AWS calls are read-only.

set -uo pipefail

OUTPUT_DIR="${1:-./my-snapshot}"
mkdir -p "$OUTPUT_DIR"

# ----- prerequisites -------------------------------------------------------

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "ERROR: required tool '$1' not found on PATH" >&2
		exit 1
	}
}
need aws
need jq

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SNAPSHOT_FILE="$OUTPUT_DIR/snapshot-$(date -u +"%Y%m%dT%H%M%SZ").json"

echo "==> Collecting AWS snapshot"
echo "    Output: $SNAPSHOT_FILE"
echo "    Timestamp: $TIMESTAMP"
echo ""

# Accumulator. The script appends one JSON object per asset into a temp
# file, then jq -s wraps them into the obs.v0.1 envelope at the end.
ASSETS_TMP=$(mktemp)
trap 'rm -f "$ASSETS_TMP"' EXIT INT TERM

# ----- S3 buckets ---------------------------------------------------------

echo "==> S3 buckets"
S3_COUNT=0
BUCKETS=$(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null) || {
	echo "  WARN: list-buckets failed (insufficient permissions?); skipping S3" >&2
	BUCKETS=""
}

for bucket in $BUCKETS; do
	echo "  $bucket"

	# Every per-bucket API can fail for valid reasons (no policy, no
	# encryption, no tags, no PAB). Each failure falls back to an empty
	# JSON shape so the resulting observation still validates.
	PAB=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null \
		| jq '.PublicAccessBlockConfiguration // {}' 2>/dev/null) || PAB="{}"
	PAB="${PAB:-{\}}"

	ENCRYPTION=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null \
		| jq '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault // {}' 2>/dev/null) || ENCRYPTION="{}"
	ENCRYPTION="${ENCRYPTION:-{\}}"

	TAGS=$(aws s3api get-bucket-tagging --bucket "$bucket" 2>/dev/null \
		| jq '(.TagSet // []) | map({(.Key): .Value}) | add // {}' 2>/dev/null) || TAGS="{}"
	TAGS="${TAGS:-{\}}"

	# Build the asset. The shape mirrors the fixtures under
	# examples/demo-s3-*/fixtures/observations/ so it satisfies the
	# controls that read properties.storage.controls.public_access_block.*
	# and properties.storage.tags out of the box.
	jq -n \
		--arg id "$bucket" \
		--arg arn_id "aws:s3:::$bucket" \
		--argjson pab "$PAB" \
		--argjson encryption "$ENCRYPTION" \
		--argjson tags "$TAGS" \
		'{
			id: $id,
			type: "aws_s3_bucket",
			vendor: "aws",
			properties: {
				storage: {
					kind: "bucket",
					name: $id,
					id: $arn_id,
					controls: {
						public_access_block: {
							block_public_acls:       ($pab.BlockPublicAcls       // false),
							block_public_policy:     ($pab.BlockPublicPolicy     // false),
							ignore_public_acls:      ($pab.IgnorePublicAcls      // false),
							restrict_public_buckets: ($pab.RestrictPublicBuckets // false)
						},
						public_access_fully_blocked: (
							($pab.BlockPublicAcls // false)
							and ($pab.BlockPublicPolicy // false)
							and ($pab.IgnorePublicAcls // false)
							and ($pab.RestrictPublicBuckets // false)
						)
					},
					encryption: {
						algorithm: ($encryption.SSEAlgorithm // "none"),
						kms_key_id: ($encryption.KMSMasterKeyID // null)
					},
					tags: $tags
				}
			}
		}' >> "$ASSETS_TMP"
	S3_COUNT=$((S3_COUNT + 1))
done

echo "    → $S3_COUNT buckets"
echo ""

# ----- IAM roles ----------------------------------------------------------

echo "==> IAM roles"
IAM_COUNT=0
ROLES=$(aws iam list-roles --query 'Roles[].RoleName' --output text 2>/dev/null) || {
	echo "  WARN: list-roles failed (insufficient permissions?); skipping IAM" >&2
	ROLES=""
}

for role in $ROLES; do
	# Skip AWS service-linked roles. Their trust policies and tags are
	# AWS-managed; including them inflates the asset count without
	# producing actionable findings.
	[[ "$role" == AWSServiceRole* ]] && continue

	echo "  $role"

	ROLE_DOC=$(aws iam get-role --role-name "$role" 2>/dev/null) || ROLE_DOC='{}'
	ROLE_ARN=$(echo "$ROLE_DOC" | jq -r '.Role.Arn // empty')
	[ -z "$ROLE_ARN" ] && continue

	# trusted_services comes from AssumeRolePolicyDocument's Statement[].Principal.Service.
	# AWS returns Principal.Service as either a string or array; the jq
	# below normalises both shapes into a flat unique list.
	TRUSTED=$(echo "$ROLE_DOC" \
		| jq -c '[
			(.Role.AssumeRolePolicyDocument.Statement // [])[]
			| .Principal.Service?
			| if type == "array" then .[] else . end
		] | map(select(. != null)) | unique' 2>/dev/null) || TRUSTED='[]'

	POLICY_ARNS=$(aws iam list-attached-role-policies --role-name "$role" 2>/dev/null \
		| jq -c '[(.AttachedPolicies // [])[].PolicyArn]' 2>/dev/null) || POLICY_ARNS='[]'
	POLICY_ARNS="${POLICY_ARNS:-[]}"

	TAGS=$(aws iam list-role-tags --role-name "$role" 2>/dev/null \
		| jq '(.Tags // []) | map({(.Key): .Value}) | add // {}' 2>/dev/null) || TAGS="{}"
	TAGS="${TAGS:-{\}}"

	# is_admin_equivalent: a coarse heuristic. The AWS-managed
	# AdministratorAccess policy ARN is the canonical signal. Full
	# detection requires expanding inline policies and resolving
	# wildcard actions — out of scope for the minimal collector.
	HAS_ADMIN=$(echo "$POLICY_ARNS" \
		| jq 'any(. == "arn:aws:iam::aws:policy/AdministratorAccess")')

	jq -n \
		--arg id "$ROLE_ARN" \
		--arg role_name "$role" \
		--argjson trusted "$TRUSTED" \
		--argjson policy_arns "$POLICY_ARNS" \
		--argjson tags "$TAGS" \
		--argjson has_admin "$HAS_ADMIN" \
		'{
			id: $id,
			type: "aws_iam_role",
			vendor: "aws",
			properties: {
				identity: {
					kind: "role",
					name: $role_name,
					trusted_services: $trusted,
					is_admin_equivalent: $has_admin,
					attached_policy_arns: $policy_arns,
					tags: $tags
				}
			}
		}' >> "$ASSETS_TMP"
	IAM_COUNT=$((IAM_COUNT + 1))
done

echo "    → $IAM_COUNT roles (excluding AWSServiceRole*)"
echo ""

# ----- assemble the snapshot ----------------------------------------------

# jq -s wraps the stream of objects into the obs.v0.1 envelope.
# generated_by.source_type is required by `stave apply` unless
# --allow-unknown-input is passed; aws.cli read-only is the right
# value here.
jq -s --arg captured_at "$TIMESTAMP" \
   '{
	schema_version: "obs.v0.1",
	captured_at: $captured_at,
	source: "deployed",
	generated_by: {
		source_type: "aws.cli",
		tool: "stave-aws-snapshot",
		tool_version: "0.1.0",
		provider: "aws"
	},
	assets: .
   }' "$ASSETS_TMP" > "$SNAPSHOT_FILE"

TOTAL=$((S3_COUNT + IAM_COUNT))
echo "════════════════════════════════════════════════════════════"
echo "Snapshot written: $TOTAL assets → $SNAPSHOT_FILE"
echo ""
echo "Next steps:"
echo "  stave apply --observations $OUTPUT_DIR --allow-unknown-input"
echo ""
echo "The --allow-unknown-input flag is required: this snapshot's"
echo "source_type ('aws.cli') is not in stave's built-in connector"
echo "manifest. The flag tells stave to evaluate anyway."
echo ""
echo "For machine-readable output:"
echo "  stave apply --observations $OUTPUT_DIR --allow-unknown-input \\"
echo "       --format json | jq '.findings | length'"
echo ""
echo "To see compound chains:"
echo "  stave apply --observations $OUTPUT_DIR --allow-unknown-input \\"
echo "       --format json | jq '.chains[]?'"
