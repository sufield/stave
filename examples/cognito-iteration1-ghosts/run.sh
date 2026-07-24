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
    "Cognito Iteration 1 — 14 ghost-reference controls + 2 compound chains" \
    'CTL\.COGNITO\.GHOST\.' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    "authflow-gap-config:scenario:$script_dir/fixtures/authflow-gap-config/observations" \
    <<'EOF'
Iteration 1 covers 15 ghost-reference controls (10 Lambda
trigger types, plus identity-pool / SAML metadata / domain
cert / domain DNS / resource-server reference checks) and the
two compound chains they participate in: cognito_ghost_authflow
and cognito_ghost_idchain.

Before — writeup-config: a multi-asset observation where every
Cognito ghost flag is set unsafely. All 14 ghost controls fire,
plus cognito_ghost_idchain (3-of-4 SAML/cert/DNS members hit
on the same user-pool asset).

After — remediated-config: same asset shape with every flag set
safely. Zero ghost findings; zero chain firings.

Scenario — authflow-gap-config: a single user pool whose
pre_authentication AND custom-auth challenge triggers (define,
create, verify) are all ghost. The 4 individual controls fire
on 4 distinct asset.IDs (one per trigger). Without the
scope_field engine fix this commit shipped, the
cognito_ghost_authflow chain would NOT fire because the chain
engine grouped only by asset.ID. With scope_field set on
properties.identity.cognito.user_pool_id, the chain reunites
the 4 triggers under one logical user pool and fires.

In an AWS workflow: a CloudFormation stack tears down a Lambda
function that's still wired as a Cognito trigger. The user pool
keeps the ARN reference but invocation fails at runtime. Stave
detects the dangling reference at the next collection cycle and
the chain elevates the finding's severity when multiple
triggers on the same pool are broken simultaneously.
EOF
