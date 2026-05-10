#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
# shellcheck source=../lib/cognito_demo.sh
source "$example_root/lib/cognito_demo.sh"

cognito_demo_run \
    "Cognito Iteration 3 — 8 auth-baseline controls + 2 compound chains" \
    'CTL\.COGNITO\.(PASSWORD|MFA|LOCKOUT|SELFREG|RECOVERY)' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    "recovery-bypass-config:scenario:$script_dir/fixtures/recovery-bypass-config/observations" \
    <<'EOF'
Iteration 3 covers password policy + MFA + lockout +
self-registration + recovery-bypass controls — the
authentication baseline every compliance auditor checks first.
Two catalog chains: cognito_weakauth and cognito_recoverybypass.

Before — writeup-config: a user pool with weak password
policy, MFA off, no lockout, and self-registration open.
6 individual findings + cognito_weakauth chain fires (3-of-3
members hit, threshold 2 met). The marketing headline:
"MFA off + 6-character passwords + no lockout =
brute-forceable in minutes."

After — remediated-config: same pool with strong password +
MFA enforced + lockout + admin-only registration. 0 findings,
0 chains.

Scenario — recovery-bypass-config: MFA IS enforced on the
happy-path login, BUT the recovery flow doesn't require MFA
AND the only second factor is SMS. RECOVERY.NOMFA fires;
MFA.SMSONLY fires; cognito_recoverybypass chain fires
(threshold 2, both members hit). The headline: "MFA is
theatre — an attacker takes over via the recovery flow
without facing the second factor."

In an AWS workflow: HIPAA / SOC 2 / PCI-DSS auditors need
strong authentication. The recovery-bypass scenario is the
most-commonly missed misconfiguration — teams enable MFA but
leave the recovery path open. Stave catches it through the
chain that composes "MFA enforced" + "recovery doesn't
require MFA" — neither of which is a violation in isolation.
EOF
