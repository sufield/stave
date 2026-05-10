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
    "Cognito Iteration 7 — 12 federation-provider hygiene controls" \
    'CTL\.COGNITO\.(SAML|OIDC|SOCIAL)' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    <<'EOF'
Iteration 7 covers SAML / OIDC / social-identity provider
configuration hygiene — metadata expiry, signing,
encryption, attribute mapping, OIDC issuer reachability,
secret rotation, scope breadth, social-provider domain
restriction. No compound chain by design — each
misconfiguration is independently actionable.

Before — writeup-config: a user pool with SAML metadata
expired, static (not auto-refreshed) metadata, assertions
unsigned + unencrypted, signing cert expired, incomplete
attribute mapping, OIDC issuer unreachable, OIDC secret
rotation overdue, OIDC scopes too broad, social provider
using test credentials, social email unverified, social
allows any domain. 12 individual findings.

After — remediated-config: every flag safe. 0 findings.

Catalog observation: several Iteration 7 checks describe
network conditions (SAML metadata reachability, OIDC issuer
resolution, signing cert expiry) that the catalog reduces to
per-asset booleans. The collector does the network probe /
cert parse and stamps the resulting boolean; Stave reads it.
Works under the assumption the collector ran recently enough
to reflect current state — collector freshness is a
deployment concern, not a Stave engine concern.

In an AWS workflow: federation misconfigurations are silent
because the federation flow is async — broken SAML metadata
means the sign-in fails for users without surfacing in
infrastructure metrics. This iteration catches the
configuration-time signals that prevent runtime federation
breakage.
EOF
