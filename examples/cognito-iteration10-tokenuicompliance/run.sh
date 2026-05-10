#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
# shellcheck source=../lib/cognito_demo.sh
source "$example_root/lib/cognito_demo.sh"
source "$example_root/lib/raw_flag.sh"
parse_raw_flag "$@"
set -- "${RAW_FLAG_ARGS[@]}"

cognito_demo_run \
    "Cognito Iteration 10 — 13 token / UI / compliance / cross-account controls" \
    'CTL\.COGNITO\.(TOKEN|HOSTEDUI|RESOURCESRV|COMPLIANCE|CROSSACCT)' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    <<'EOF'
Iteration 10 closes the gap-closure plan with the residual
controls that didn't fit earlier groupings — refresh-token
rotation, hosted UI defaults, OAuth CORS, resource-server
design, encryption at rest with CMK, region compliance,
tagging compliance, log retention, cross-account Lambda /
SAML / OIDC trust. Spans 4 asset types.

Before — writeup-config: every flag set unsafely across
13 controls. 13 individual findings.

After — remediated-config: every flag safe. 0 findings.

Cross-account checks rely on collector-side joins: the
collector compares the Lambda ARN's account ID against the
user pool's account ID; resolves the OIDC issuer URL and
checks the account of any AWS-hosted issuer; compares the
SAML IdP metadata against an allow-list of trusted IdP
organisations. Same denormalisation pattern as Iteration 1's
ghost references.

In an AWS workflow: this iteration catches the residual
posture controls that compliance auditors check and
production engineers forget — encryption with a
customer-managed KMS key, log retention meeting compliance
windows, cross-account trust to authorised organisations
only. The plan-original 15 became 13 because TOKEN.NOREVOKE
and TOKEN.ACCESSLONG are already covered by Iteration 4's
app-client family.
EOF
