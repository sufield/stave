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
    "Cognito Iteration 4 — 15 app-client controls + 2 compound chains" \
    'CTL\.COGNITO\.CLIENT\.' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    "open-redirect-config:scenario:$script_dir/fixtures/open-redirect-config/observations" \
    <<'EOF'
Iteration 4 covers OAuth flow security, token validity, and
callback-URL hygiene on aws_cognito_user_pool_client assets.
15 individual controls plus 2 catalog chains:
cognito_client_openredirect and cognito_client_longtoken.

Before — writeup-config: an app client with every flag set
unsafely — implicit flow allowed, all OAuth flows enabled,
all scopes enabled, callback URLs include http://, localhost,
and wildcard, no client secret, attribute read/write all,
access token > 1h, refresh token > 30 days, no logout URL,
token revocation off, user-existence-error leakage on. All
15 controls fire; both compound chains fire.

After — remediated-config: every flag safe. 0 findings, 0
chains.

Scenario — open-redirect-config: focused fixture isolating
the OPENREDIRECT compound. Just two flags set unsafely:
allows_implicit_flow=true and callback_has_wildcard=true.
2 individual findings + cognito_client_openredirect chain
fires (threshold 2 met). The marketing headline: "implicit
flow returns the token in the URL fragment + wildcard
callback URL accepts attacker-controlled redirect targets =
token theft via crafted phishing URL."

In an AWS workflow: developers tend to enable broad OAuth
configurations during prototype phases ("just allow everything,
we'll lock it down later"). Stave catches the
flow + callback-URL + token-validity surface as one cohesive
hygiene story; the OPENREDIRECT chain is the highest-severity
compound because it's a known active-attack pattern.
EOF
