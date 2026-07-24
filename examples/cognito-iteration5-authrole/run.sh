#!/usr/bin/env bash
set -uo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
# shellcheck source=../lib/cognito_demo.sh
source "$example_root/lib/cognito_demo.sh"
source "$example_root/lib/raw_flag.sh"
parse_raw_flag "$@"
set -- "${RAW_FLAG_ARGS[@]}"

cognito_demo_run \
    "Cognito Iteration 5 — 7 auth-role controls + escalation chain" \
    'CTL\.COGNITO\.IDPOOL\.(AUTHROLE|ROLEMAPPING|CLASSICFLOW|PROVIDER)' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    <<'EOF'
Iteration 5 covers the authenticated identity-pool role —
overprivilege, escalation primitives, role mapping, classic
flow, provider validation. Catalog chain:
cognito_authrole_escalation (4 members, threshold 2).

Before — writeup-config: identity pool whose authenticated
role has every escalation primitive (broad permissions,
iam:PassRole, sts:AssumeRole-to-admin, cross-account access)
AND no role mapping AND classic flow allowed AND no provider
audience validation. All 7 controls fire; the chain fires
(4-of-4 members hit). The marketing headline: "any signed-in
user is one or two API calls away from arbitrary privileges."

After — remediated-config: every flag flipped safe. 0
findings, 0 chains.

In an AWS workflow: Cognito identity pools mint AWS
credentials for authenticated users; the authenticated role
defines what those credentials can do. Default-role mistakes
(broad permissions for "all signed-in users") show up in
this iteration. The escalation chain is the worst-case shape
where multiple primitives stack: a user can pass any role,
assume admin, OR exploit broad permissions directly.
EOF
