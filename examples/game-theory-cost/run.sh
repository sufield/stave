#!/usr/bin/env bash
# Game-theoretic cost-to-compromise + ROI ranking across the
# harness fixtures.
#
# Pipeline per fixture:
#   stave export-sir --format jsonl  →  facts.jsonl
#   cost_model.py                    →  attacker paths + ROI
#                                       ranking + recommended
#                                       remediation
#
# The output turns security findings into a financial decision:
# "$50 to block a $300 attack" instead of "fix this critical
# finding."

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
runner="$script_dir/cost_model.py"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
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
        --eval-time 2026-01-09T00:00:00Z \
        --format jsonl > "$facts" 2>/dev/null

    python3 "$runner" "$label" "$facts"
}

# Cognito self-register chain — writeup has 2 paths;
# remediated has 0 (both gates closed).
run_one "Cognito writeup-config" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations"
run_one "Cognito remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations"

# Multi-hop privesc — chain depth scales attacker cost.
run_one "Multi-hop vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/vulnerable/observations"
run_one "Multi-hop remediated" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/remediated/observations"

# Rhino — compute-trust + PassRole shape requires both
# contributed_by AND trusts_service. Hygiene-only fixtures
# show no path under this model.
run_one "Rhino vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations"
run_one "Rhino remediated" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/remediated/observations"

# Bybit wildcard — the wildcard-shape detector here is the
# literal "*" check; bybit's prefix wildcard
# ("arn:...:company-frontend-*") doesn't match. Z3+SMT's
# str.prefixof is the right tool for that case.
run_one "Bybit before" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-before/observations"
run_one "Bybit after" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-after/observations"
