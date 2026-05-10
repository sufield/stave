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
    "Cognito Iteration 9 — 6 lifecycle / orphan controls" \
    'CTL\.COGNITO\.ORPHAN\.' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    <<'EOF'
Iteration 9 covers dormant resources and orphan references —
user pools with no clients, dormant pools with zero users,
identity pools with no providers, app clients that haven't
been used, resource servers that no client references,
triggers attached to decommissioned flows. Spans 4 asset
types, including the new aws_cognito_resource_server.

Before — writeup-config: 4 distinct asset entries, each in
the "orphan" state — dormant user pool with no clients,
dormant app client, identity pool with no providers, orphan
resource server. 6 individual findings.

After — remediated-config: each asset in an active /
referenced state. 0 findings.

Catalog observation: introduces aws_cognito_resource_server
as a new asset type. The collector enumerates resource
servers and cross-checks app clients' allowed_o_auth_scopes,
stamping is_resource_server_orphan on the resource-server
asset — same denormalisation pattern as previous
iterations.

In an AWS workflow: dormant resources are an attack-surface
liability. An app client nobody uses still has a client
secret; an orphan resource server still defines scopes
clients could request. Pruning lifecycle debris reduces the
account's attack surface and makes the active configuration
easier to review.
EOF
