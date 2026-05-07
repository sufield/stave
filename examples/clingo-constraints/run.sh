#!/usr/bin/env bash
# Clingo/ASP constraint check across multiple Stave fixtures.
#
# Pipeline per fixture:
#   stave export-sir --format jsonl  →  facts.jsonl
#   facts.jsonl + constraints.lp     →  Clingo grounder/solver
#   prints every grounded violation atom + latent risks
#
# Each rule in constraints.lp captures a known-unsafe
# configuration shape. Clingo's stable-model semantics
# enumerates the full set of satisfying triples — the
# answer Z3 cannot give in one query.
#
# Tooling:
#   The clingo Python package (`pip install clingo`) ships the
#   solver as a library, no system binary needed. Set CLINGO_VENV
#   to the venv with clingo installed; default is
#   .tools-venv at the repo root.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
repo_root=$(cd "$stave_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
constraints="$script_dir/constraints.lp"
runner="$script_dir/run.py"
venv_python=${CLINGO_VENV:-$repo_root/.tools-venv}/bin/python3
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
    echo "  $repo_root/.tools-venv/bin/pip install clingo"
    exit 1
fi

run_one() {
    local label=$1
    local controls=$2
    local obs_dir=$3

    local facts="$work_dir/$label.jsonl"
    "$stave_bin" export-sir \
        --controls "$controls" \
        --observations "$obs_dir" \
        --now 2026-01-09T00:00:00Z \
        --format jsonl > "$facts" 2>/dev/null

    "$venv_python" "$runner" "$label" "$facts" "$constraints"
}

# Multi-hop trust chain — V2 (privesc_chain_2hop) should
# fire on vulnerable, vanish on remediated.
run_one "multi-hop-vulnerable" \
    "$example_root/iam-multi-hop-trust/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/vulnerable/observations"
run_one "multi-hop-remediated" \
    "$example_root/iam-multi-hop-trust/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/remediated/observations"

# Rhino vulnerable — V1 (exploitable_overperm) fires on
# every role with a finding + service trust.
run_one "rhino-vulnerable" \
    "$example_root/iam-21-privesc-5-patterns/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations"
run_one "rhino-remediated" \
    "$example_root/iam-21-privesc-5-patterns/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/remediated/observations"

# Cognito self-register chain — V3 (unauth) and V4
# (self_register_broad_s3) fire on writeup-config; both
# vanish on remediated.
run_one "cognito-writeup" \
    "$example_root/cognito-self-register-to-aws-creds/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations"
run_one "cognito-remediated" \
    "$example_root/cognito-self-register-to-aws-creds/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations"

# Bybit pattern — V6 (production_wildcard_pair) fires on
# bybit-pattern-before because the developer's wildcard
# matches a production-tagged bucket. Coarser than the
# SMT bybit query (no prefix-match), but ASP expresses it
# without bespoke string theory.
run_one "bybit-before" \
    "$example_root/iam-overpermission-wildcard/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-before/observations"
run_one "bybit-after" \
    "$example_root/iam-overpermission-wildcard/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-after/observations"
