#!/usr/bin/env bash
# ECS SSRF credential theft — fixture demo for the existing
# chains/ecs_ssrf_credential_theft.yaml chain (3 members,
# threshold=2, severity=critical).
#
# Members:
#   CTL.ECS.TASKMETADATA.001         — task role over-privileged
#   CTL.ECS.METADATA.CREDENTIAL.001  — metadata credential scoping disabled
#   CTL.VPC.SG.EGRESS.001            — security group permits unrestricted egress
#
# The chain composes by asset.ID; the writeup fixture lands the
# 2 ECS controls on the task-definition asset (which meets the
# threshold of 2) and adds the SG fact as the third leg of the
# attack story.
set -euo pipefail
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
        --eval-time 2026-05-10T12:00:00Z --format json 2>/dev/null \
      | jq '{
            controls: ([.findings[] | select(.control_id | test("CTL\\.(ECS|VPC)"))] | map(.control_id) | sort | unique),
            chains:   ([(.chain_findings // [])[]] | map(.chain_id // .chain) | sort | unique),
            chain_severities: ([(.chain_findings // [])[]] | map({chain: (.chain_id // .chain), severity}))
          }'
}

fmt_section "Before — writeup-config (SSRF credential-theft set up)"
apply_filtered "$writeup"

fmt_section "After — remediated-config"
apply_filtered "$remediated"

fmt_section "Interpretation"
cat <<'EOF'
The writeup fixture stages the canonical ECS SSRF credential-theft
attack pattern:

  1. ECS task definition has an over-privileged task IAM role
     (TASKMETADATA fires)
  2. The task does NOT scope which containers can reach the
     169.254.170.2 metadata endpoint (METADATA.CREDENTIAL fires)
  3. The task's security group permits unrestricted egress, so a
     stolen credential can be exfiltrated to attacker infrastructure
     (VPC.SG.EGRESS fires)

The chain `ecs_ssrf_credential_theft` (threshold=2, severity=critical)
composes the two ECS findings on the task-definition asset and fires.
Stave's compound output reads "this configuration is one HTTP
request away from credential theft" — operators see the compound
verdict before they see the individual triage queue.

The remediation set scopes the task role, enables container-level
credential scoping, and locks down egress. Each predicate flips,
all three controls go silent, and the chain does not fire.

Two residual findings on the writeup (CTL.S3.PUBLIC.PREFIX.001 ×
2) come from a catalog-coverage absence-check that fires when no
storage evidence is present. They are outside the chain and the
runner filters them out so the demo focuses on the SSRF chain.
EOF
