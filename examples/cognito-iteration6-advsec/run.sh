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
    "Cognito Iteration 6 — 6 advanced-security / verify / domain controls" \
    'CTL\.COGNITO\.(ADVANCED|ADVSEC|VERIFY|DOMAIN)' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    <<'EOF'
Iteration 6 covers Cognito's advanced-security features
(risk-based adaptive auth, compromised-credential detection,
device tracking), email/phone verification, and custom-domain
HTTPS enforcement. No compound chain in the catalog or plan
for this iteration — each finding is independently
actionable.

Before — writeup-config: a user pool with advanced security
off, device tracking off, email/phone unverified, SMS MFA
enabled, custom domain not HTTPS, ACM cert expired. 6
individual findings.

After — remediated-config: every flag safe. 0 findings.

Notable catalog observation: the fixture splits its
observation across two user-pool entries because the catalog
uses two different `kind` discriminators (user_pool vs
cognito_user_pool) across its cognito control families. A
single asset can only declare one kind, so fixtures targeting
both groups need two entries. Same content-review issue
flagged in iteration 3.

In an AWS workflow: advanced security is the Cognito feature
that detects credential-stuffing and auto-blocks risky
sign-ins. Disabling it (or running in audit-only mode)
removes the active defence; this iteration's controls catch
the misconfigurations that turn advanced security from
defense to decoration.
EOF
