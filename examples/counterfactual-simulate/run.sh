#!/usr/bin/env bash
# Counterfactual remediation simulator over a Stave assessment.
#
# Pipeline:
#   stave apply --format json   →  assessment.json
#   chains.yaml                  (chain definitions)
#   simulate.py --fix CONTROL_ID  →  posture delta + chain deactivations
#
# Pure-stdlib Python; no SAT/SMT solver needed for the
# "what if I removed THESE finding rows?" question.
#
# This example replaces `internal/app/simulate/` per the
# core-audit thin-core contract.
set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
runner="$script_dir/simulate.py"
assessment="$script_dir/fixtures/assessment.json"
chains="$script_dir/fixtures/chains.yaml"

# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"

fmt_section "Scenario 1 — fix one MFA control"
python3 "$runner" --assessment "$assessment" --chains-file "$chains" \
    --fix CTL.COGNITO.MFA.001

fmt_section "Scenario 2 — fix both s3_phi_exposure leads"
python3 "$runner" --assessment "$assessment" --chains-file "$chains" \
    --fix CTL.S3.PUBLIC.001 --fix CTL.S3.ENCRYPT.001

fmt_section "Scenario 3 — fix all three weakauth members"
python3 "$runner" --assessment "$assessment" --chains-file "$chains" \
    --fix CTL.COGNITO.PASSWORD.001 \
    --fix CTL.COGNITO.MFA.001 \
    --fix CTL.COGNITO.LOCKOUT.NONE.001

fmt_section "Scenario 4 — JSON output"
python3 "$runner" --assessment "$assessment" --chains-file "$chains" \
    --fix CTL.S3.PUBLIC.001 --format json

fmt_section "Interpretation"
cat <<'EOF'
Scenario 1: fix CTL.COGNITO.MFA.001 only. cognito_weakauth's
threshold is 2; the remaining 2 members (PASSWORD + LOCKOUT)
still meet it, so the chain stays active. Score gain is the
single-finding contribution (medium → ~+5.6).

Scenario 2: fix two members of s3_phi_exposure (PUBLIC and
ENCRYPT). The chain has 1 remaining failing member (LOGGING)
which is below the threshold of 2, so the chain DEACTIVATES.
Score gain combines the finding deductions saved (critical +
high) plus a +2 chain-deactivation bonus.

Scenario 3: fix all three cognito_weakauth members. Chain
deactivates; score reflects 3 fewer findings + chain bonus.
This is the "fix the whole compound" path the operator should
prioritise — single-control fixes inside a compound chain rarely
move the needle.

Per the core-audit migration plan, this Python script is the
external replacement for internal/app/simulate/. Same arithmetic
(set difference for findings, threshold check for chains, the
proportional improvement model for score), no Stave Go internals.
EOF
