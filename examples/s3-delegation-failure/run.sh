#!/usr/bin/env bash
# S3 vendor delegation failure — fixture demo for the new
# chains/delegated_control_failure.yaml chain (5 members,
# threshold=3, severity=critical).
#
# Members (all fire on a single S3 bucket asset; default
# asset.ID grouping applies, no scope_field needed):
#   CTL.S3.DELEGATION.KNOWN.001       — unregistered external principal
#   CTL.S3.DELEGATION.SCOPE.001       — actions exceed declared scope
#   CTL.S3.DELEGATION.LIFECYCLE.001   — vendor review_date overdue
#   CTL.S3.DELEGATION.REVOCABLE.001   — customer cannot revoke
#   CTL.S3.DELEGATION.ESCALATION.001  — vendor can make bucket public
#
# Threshold 3 of 5 distinguishes systemic governance breakdown
# from a single overdue review.
set -uo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"
# shellcheck source=../lib/raw_flag.sh
source "$example_root/lib/raw_flag.sh"
parse_raw_flag "$@"

writeup="$script_dir/fixtures/writeup-config/observations"
remediated="$script_dir/fixtures/remediated-config/observations"

apply_filtered() {
    local obs=$1
    "$stave_bin" apply \
        --observations "$obs" \
        --controls "$stave_root/controls/s3/delegation" \
        --eval-time 2026-05-10T12:00:00Z --format json 2>/dev/null \
      | jq '{
            controls: ([.findings[] | select(.control_id | startswith("CTL.S3.DELEGATION")) | .control_id] | sort | unique),
            chains:   ([(.chain_findings // [])[] | select((.chain // .chain_id) | contains("delegat")) | (.chain // .chain_id)] | sort | unique),
            chain_severities: ([(.chain_findings // [])[] | select((.chain // .chain_id) | contains("delegat"))] | map({chain: (.chain // .chain_id), severity}))
          }'
}

fmt_section "Before — writeup-config (customer-data-lake, delegated to a vendor)"
apply_filtered "$writeup"

fmt_section "After — remediated-config"
apply_filtered "$remediated"

fmt_section "Interpretation"
cat <<'EOF'
The bucket customer-data-lake is owned by data-engineering and
tagged data-classification=confidential. Two external principals
have control-level access:

  arn:aws:iam::999988887777:role/AcmeDataPipeline
    Declared scope: PutObject + GetObject on raw-data/*
    Actual permissions: PutObject + GetObject + DeleteObject
                        + PutBucketPolicy
    Vendor review:  2025-06-01 (344 days overdue)

  arn:aws:iam::333322221111:role/UnknownRole
    Not registered in controldata/taxonomy/vendor_registry.yaml.
    Nobody knows why this principal has access.

All five delegation controls fire on the writeup. The compound
chain delegated_control_failure (threshold 3 of 5, severity
critical) composes them: the failure isn't one missing piece,
it's systemic governance breakdown. Three or more concurrent
defects say the delegation was never properly governed.

The distinction this demo carries:
  Orphan bucket           = no owner. The bucket is forgotten.
  Delegation failure      = owner exists; control transferred to
                            a weaker party without safety
                            continuity. Ownership exists.
                            Assurance does not.

Single-resource scanners report "cross-account access detected"
and stop. Stave's compound output reads: "this vendor can
rewrite your bucket policy, you cannot revoke it, the review is
344 days overdue, and an unknown account has the same access."

The remediation: register or remove every external principal,
scope the registered vendor's actions to its declared purpose,
remove PutBucketPolicy/PutBucketAcl from vendor permissions,
refresh the review date, and ensure the customer's IAM retains
revoke capability. The five predicates flip, the chain goes
silent.

Complementary to chains/vendor_attack_path.yaml — that chain
asks whether the vendor CAN reach the bucket (confused-deputy);
this chain asks whether the delegation governance is intact.
Both may fire on the same bucket. Different narratives, both
valid.
EOF
