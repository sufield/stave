#!/usr/bin/env bash
# EC2 IMDS SSRF chain — fixture demo for the existing
# chains/ec2_imds_container_escalation.yaml chain (3 members,
# threshold=2, severity=high).
#
# Members:
#   CTL.EC2.IMDSV2.001       — IMDSv2 not required (Capital One pattern: IMDSv1 still allowed)
#   CTL.EC2.IMDSV2.002       — container reaches IMDS via host or bridge network with hop > 1
#   CTL.EC2.IMDS.HOPLIMIT.001 — IMDS hop limit excessive
#
# Note: IMDSV2.001 (imdsv2_required=false) and IMDSV2.002
# (imdsv2_required=true + container bypass) are mutually
# exclusive on a single asset. The chain's threshold of 2
# is met by IMDSV2.001 + HOPLIMIT.001 — the canonical IMDSv1
# pattern that powered the Capital One breach.
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
    local tmp
    tmp=$(mktemp)
    "$stave_bin" apply \
        --observations "$obs" \
        --eval-time 2026-05-10T12:00:00Z \
        --max-unsafe 168h --format json > "$tmp" 2>/dev/null || rc=$?
    rc=${rc:-0}
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
        echo "stave apply exited $rc (unexpected)" >&2
        rm -f "$tmp"
        exit "$rc"
    fi
    jq '{
        controls: ([.findings[] | select(.control_id | test("CTL\\.EC2"))] | map(.control_id) | sort | unique),
        chains:   ([(.chain_findings // [])[]] | map(.chain_id // .chain) | sort | unique),
        chain_severities: ([(.chain_findings // [])[]] | map({chain: (.chain_id // .chain), severity}))
      }' "$tmp"
    rm -f "$tmp"
    unset rc
}

fmt_section "Before — writeup-config (Capital One IMDS pattern)"
apply_filtered "$writeup"

fmt_section "After — remediated-config (IMDSv2 + hop=1)"
apply_filtered "$remediated"

fmt_section "Interpretation"
cat <<'EOF'
The writeup fixture stages the canonical IMDS credential-theft
pattern that powered the Capital One breach:

  1. IMDSv1 is still permitted (`imdsv2_required: false`) —
     a single GET to 169.254.169.254 returns role credentials,
     no token PUT required (CTL.EC2.IMDSV2.001 fires).
  2. The IMDS hop limit is set above 1 — a containerized
     workload (Docker, ECS-on-EC2) running on the instance
     can bridge to the metadata service through the additional
     hop (CTL.EC2.IMDS.HOPLIMIT.001 fires).

Threshold 2 of 3 met. The chain `ec2_imds_container_escalation`
(severity: high) composes both findings on the instance asset
and fires.

The remediation flips both predicates:
  • imdsv2_required: true   — IMDSv2 PUT-token required
  • imds_hop_limit_excessive: false  — hop limit = 1 means
    only the instance itself can reach IMDS; containers cannot.
Either change alone breaks the chain; together they leave a
post-Capital-One-hardened configuration. All three controls go
silent on the remediated fixture and the chain does not fire.

The third chain member (CTL.EC2.IMDSV2.002) covers the inverse
case: imdsv2_required=true but a container with host-network
or bridge+hop>1 still reaches IMDS. IMDSV2.001 and IMDSV2.002
are mutually exclusive on a single asset (imdsv2_required is
either true or false), so the chain's threshold of 2 is met
by either pair: {.001, HOPLIMIT} (this fixture) or
{.002, HOPLIMIT} (a separate container-bridge fixture, not
shipped here — the IMDSv1 pattern is the one with historical
weight).
EOF
