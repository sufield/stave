#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
# shellcheck source=../lib/cognito_demo.sh
source "$example_root/lib/cognito_demo.sh"

cognito_demo_run \
    "Cognito Iteration 2 — 7 unauth controls + 2 compound chains + cross-resource compound" \
    'CTL\.COGNITO\.(IDENTITY\.GUEST|IDPOOL\.UNAUTH)|CTL\.S3\.MARKER\.PHI' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    "cross-resource-config:scenario:$script_dir/fixtures/cross-resource-config/observations" \
    <<'EOF'
Iteration 2 ships 7 individual controls for unauthenticated
identity-pool misconfiguration plus 2 catalog chains
(cognito_unauth_escalation, cognito_unauth_s3public). The
cross-resource fixture exercises the marker-control engine
feature: a non-violation marker on a PHI bucket composes with
a Cognito-side violation through a chain's scope_field.

Before — writeup-config: an identity pool with
allow_unauthenticated=true and every unauth-role flag (broad,
IAM, S3, DDB, Lambda, unused) set unsafely. All 7 individual
controls fire; both compound chains fire.

After — remediated-config: same identity pool with
allow_unauthenticated=false and every detail flag safe. Zero
findings, zero chains.

Scenario — cross-resource-config: an identity pool whose
unauthenticated role has S3 access targeting a PHI bucket
(arn:aws:s3:::acme-phi-records) AND that bucket carries
data-classification=phi. The PHI marker
(CTL.S3.MARKER.PHI.001, type: marker) fires on the bucket
side; UNAUTH.BROAD/UNAUTH.S3/IDENTITY.GUEST fire on the
identity-pool side. cognito_unauth_phi_s3 chain composes them
via scope_field on the bucket ARN, producing a CRITICAL
compound finding.

In an AWS workflow: this is the marketing headline finding —
"your Cognito identity pool gives anonymous AWS credentials
that can read PHI from a HIPAA-tagged bucket." Without marker
controls, the bucket-side fact (PHI tag) wouldn't enter chain
detection because tagging isn't a violation. With markers, the
catalog can compose violations on the access path with facts
about the data classification on the resource — a class of
cross-resource compound that needed the Iteration 2 engine
work.
EOF
