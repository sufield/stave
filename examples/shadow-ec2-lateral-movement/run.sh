#!/usr/bin/env bash
# Shadow EC2 lateral movement — fixture demo for the new
# chains/shadow_ec2_lateral_movement.yaml chain (3 members,
# threshold=3, severity=critical).
#
# Members (all evaluate kind=instance on the same EC2 asset):
#   CTL.EC2.INSTANCE.STOPPED.AGED.001  — lifecycle staleness
#   CTL.EC2.PROFILE.OVERBROAD.001      — instance-profile overprivilege
#   CTL.EC2.NETWORK.DUALHOMED.001      — bridges two security zones
#
# Threshold 3 of 3 — all axes must co-occur on the same EC2
# instance asset. asset.ID grouping (no scope_field needed).
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
        --controls "$stave_root/controls/ec2" \
        --now 2026-05-10T12:00:00Z \
        --allow-unknown-input --format json 2>/dev/null \
      | jq '{
            controls: ([.findings[] | select(.control_id | test("INCOMPLETE") | not) | .control_id] | sort | unique),
            chains:   ([(.chain_findings // [])[]] | map(.chain // .chain_id) | sort | unique),
            chain_severities: ([(.chain_findings // [])[]] | map({chain: (.chain // .chain_id), severity}))
          }'
}

fmt_section "Before — writeup-config (dormant test instance, broad role, dual-homed)"
apply_filtered "$writeup"

fmt_section "After — remediated-config"
apply_filtered "$remediated"

fmt_section "Interpretation"
cat <<'EOF'
This EC2 instance was created in 2024 for a one-time migration
test. It has been stopped for 180 days. Its IAM instance profile
(LegacyMigrationTestRole) is overprivileged — it has more
permissions than the migration ever required, and nobody has
scoped it back. Its ENIs sit in two subnets at once:
subnet-staging-001 AND subnet-prod-tier-007 — the instance
literally bridges two security zones.

  Stopped (180 d)  +  Overprivileged role  +  Dual-homed
       │                    │                     │
       ▼                    ▼                     ▼
   Not in              IAM access            Production-side
   monitoring          to many               network reach
   scope               services              from a single
                                             pivot instance

An attacker who starts this instance — or who reaches its
profile through any other path (a CI/CD pipeline that can
assume the role, a misconfigured trust policy, a stolen
credential) — inherits broad IAM permissions plus a network
position that crosses the staging/production boundary. The
instance is the cheapest path into production, and nobody is
watching it because the dashboard filters out stopped
resources.

The chain `shadow_ec2_lateral_movement` (threshold 3 of 3,
severity critical) composes three findings on the same EC2
instance asset:

  STOPPED.AGED.001    instance.stopped_age_exceeds_threshold
  PROFILE.OVERBROAD   instance_profile.is_overprivileged
  NETWORK.DUALHOMED   instance.spans_security_zones

A scanner that walks instances state-by-state sees stopped → no
findings. A scanner that audits IAM roles sees an overbroad
policy and tickets it. A scanner that audits VPC segmentation
sees a dual-homed ENI and tickets that. None of those scanners
joins the three observations onto the same asset and reports
the actual story: "this forgotten instance is your shortest
path from low-trust into prod."

In remediation the instance is restarted into a dedicated
staging VPC (spans_security_zones=false), its role is scoped
(is_overprivileged=false), and the dormancy threshold no longer
applies (state=running, stopped_age_exceeds_threshold=false).
All three predicates flip, all three controls go silent, and
the chain does not fire.
EOF
