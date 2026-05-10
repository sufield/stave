#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
# shellcheck source=../lib/cognito_demo.sh
source "$example_root/lib/cognito_demo.sh"

cognito_demo_run \
    "Cognito Pre-Sign-Up Ghost Lambda — Iteration 1 de-risk" \
    'CTL.COGNITO.GHOST.PRESIGNUP\.001' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    <<'EOF'
Cognito user pools can register Lambda functions as triggers
for sign-up, sign-in, and post-confirmation flows. If the
configured Lambda gets deleted but the trigger reference
remains, every sign-up attempt fails because Cognito
invokes a function that no longer exists. The user pool
console still shows the trigger as configured (the ARN is
still there); only the runtime invocation surfaces the
failure.

Before — writeup-config: an identity-provider asset shows
trigger_type=pre_sign_up, trigger_lambda_arn pointing at
acme-presignup, and trigger_lambda_exists=false (the
collector cross-checked the Lambda inventory and the
function isn't there). has_ghost_trigger=true is the
collector-derived boolean the catalog reads.
CTL.COGNITO.GHOST.PRESIGNUP.001 fires.

After — remediated-config: the same user pool plus the
acme-presignup Lambda function as a separate asset.
trigger_lambda_exists is now true; has_ghost_trigger is
false; the control passes.

In an AWS workflow: a routine cleanup removes a Lambda
function that someone else's user pool depends on. Without
this control, the breakage is silent until the next
end-user sign-up fails in production. With it, the catalog
flags the dangling reference at the next collection cycle —
ahead of the user-visible outage.
EOF
