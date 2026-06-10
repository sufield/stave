#!/usr/bin/env bash
# Boolean compound-of-finding regression check via pysat.
#
# Pipeline per fixture:
#   stave export-sir --format jsonl  →  facts.jsonl
#   facts.jsonl + compound_rules.py  →  pysat (Glucose3)
#   prints SAFE / UNSAFE per fixture, listing fired compounds
#
# Each compound is an AND over control IDs whose simultaneous
# firing constitutes an unsafe configuration. SAT scales the
# boolean-AND check across the full control catalog at near-
# zero per-rule cost — the right layer when the question is
# "which compound shapes light up given these flags?"

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
repo_root=$(cd "$stave_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
runner="$script_dir/run.py"
venv_python=${PYSAT_VENV:-$repo_root/.tools-venv}/bin/python3
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
    exit 1
fi
if [[ ! -x "$venv_python" ]]; then
    echo "python venv not found at $venv_python"
    echo "create with:"
    echo "  python3 -m venv $repo_root/.tools-venv"
    echo "  $repo_root/.tools-venv/bin/pip install python-sat"
    exit 1
fi

run_one() {
    local label=$1
    local controls=$2
    local obs_dir=$3
    local mode=${4:-check}

    local facts="$work_dir/$label.jsonl"
    "$stave_bin" export-sir \
        --controls "$controls" \
        --observations "$obs_dir" \
        --now 2026-01-09T00:00:00Z \
        --format jsonl > "$facts" 2>/dev/null

    "$venv_python" "$runner" "$label" "$facts" "$mode"
}

# Rhino vulnerable — should hit rhino_passrole_compound,
# possibly exploitable_overperm_compound depending on which
# wildcard controls fire.
run_one "rhino-vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations"

run_one "rhino-remediated" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/remediated/observations"

# Cognito self-register chain — should hit cognito_open_door
# on writeup if both COGNITO.SELFREG and IAM.WILDCARD fire.
run_one "cognito-writeup" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations"

run_one "cognito-remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations"

# Staging endpoint exposed — the environment-aware staleness control
# AND the public-list control fire on the same demo-tagged bucket,
# triggering the staging_endpoint_exposed compound. The public negative
# (active-staging) is stale-but-not-public, so no compound fires. Uses
# the example's local controls (CTL.LIFECYCLE.STAGING.STALE.001 +
# CTL.S3.PUBLIC.LIST.002 are not in the default catalog).
run_one "staging-stale-public" \
    "$example_root/staging-stale-endpoint/controls" \
    "$example_root/staging-stale-endpoint/fixtures/stale-staging-public/observations"

run_one "staging-active" \
    "$example_root/staging-stale-endpoint/controls" \
    "$example_root/staging-stale-endpoint/fixtures/active-staging/observations"

# Bedrock agent overpermissioned
run_one "bedrock-agent" \
    "$stave_root/controls" \
    "$example_root/bedrock-agent-overpermissioned/fixtures/writeup-config/observations"

# Shadow admin detection
run_one "shadow-admin" \
    "$stave_root/controls" \
    "$example_root/shadow-admin-detection/fixtures/writeup-config/observations"

# VPC peering exfiltration
run_one "vpc-peering" \
    "$stave_root/controls" \
    "$example_root/vpc-peering-exfiltration/fixtures/writeup-config/observations"

# S3 delegation failure
run_one "s3-delegation" \
    "$stave_root/controls" \
    "$example_root/s3-delegation-failure/fixtures/writeup-config/observations"

# Cognito iteration 1 ghosts
run_one "cognito-iteration1-ghosts" \
    "$stave_root/controls" \
    "$example_root/cognito-iteration1-ghosts/fixtures/writeup-config/observations"

# Rhino-remediated → what-if: smallest set of additional
# findings that would tip the configuration into unsafe.
# The genuine SAT scaling demonstration — picks a minimal
# trigger across the candidate space.
run_one "rhino-remediated-what-if" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/remediated/observations" \
    "what-if"
