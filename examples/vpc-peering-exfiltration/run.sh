#!/usr/bin/env bash
# VPC peering exfiltration — fixture demo for the existing
# chains/vpc_peering_exposure.yaml chain (2 members,
# threshold=2, severity=critical).
#
# Members:
#   CTL.VPC.PEERING.CROSSACCOUNT.001 — peer account outside the org
#   CTL.VPC.PEERING.ROUTES.001       — route to full peer VPC CIDR
#
# The two member predicates require mutually exclusive `kind`
# values (peering_connection vs route_table), so the chain
# carries scope_field=properties.network.peering.id — both
# findings group by the peering connection ID rather than by
# asset.ID.
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
        --controls "$stave_root/controls/vpc/peering" \
        --now 2026-05-10T12:00:00Z --format json 2>/dev/null \
      | jq '{
            controls: ([.findings[].control_id] | sort | unique),
            chains:   ([(.chain_findings // [])[]] | map(.chain // .chain_id) | sort | unique),
            chain_severities: ([(.chain_findings // [])[]] | map({chain: (.chain // .chain_id), severity}))
          }'
}

fmt_section "Before — writeup-config (legacy peering still routes to prod)"
apply_filtered "$writeup"

fmt_section "After — remediated-config"
apply_filtered "$remediated"

fmt_section "Interpretation"
cat <<'EOF'
A forgotten VPC peering connection — set up two years ago for a
vendor integration that has since ended — still bridges the
production VPC to an external AWS account (444455556666, not a
member of the organization). The production route table still
carries a route to the full peer VPC CIDR (10.200.0.0/16), so
any resource in the prod VPC has IP-layer reachability into the
external account's network. The external account's security
posture — its IAM, its workloads, its compromises — is outside
organizational control.

  Production VPC (10.0.0.0/16, account 111122223333)
        │  route 10.200.0.0/16 -> pcx-0abc...
        ▼
  Legacy Peer VPC (10.200.0.0/16, account 444455556666)
        │  no SCPs, no centralized CloudTrail
        ▼  Data exfiltrated through the peer; the prod-side
           audit trail shows a routine internal flow.

The chain `vpc_peering_exposure` composes two findings:

  CROSSACCOUNT.001 — peer_account_in_org == false
                     (fires on the peering connection asset)
  ROUTES.001       — peering_route.has_broad_destination == true
                     (fires on the route-table asset)

These are two assets of two different kinds. The chain groups
them via scope_field=properties.network.peering.id (the peering
ARN both observations carry). Threshold 2 of 2, severity
critical.

In remediation the peer account moves inside the organization
(peer_account_in_org=true) and the broad /16 route is replaced
with a /24 route to a single application subnet. Both predicates
flip, both controls go silent, the chain does not fire.
EOF
