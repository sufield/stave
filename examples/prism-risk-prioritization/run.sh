#!/usr/bin/env bash
# Probabilistic risk prioritisation across the harness fixtures.
#
# Pipeline per fixture:
#   stave export-sir --format jsonl  →  facts.jsonl
#   risk_model.py                    →  P(exploitation) + per-shape breakdown
#
# Z3 says "this path exists" (yes/no). The risk model assigns
# each shape a probability conditioned on the specific facts
# present. The fixture's overall P(exploitation) is the max
# across applicable shapes — the worst-case attack the
# configuration permits.
#
# Pure-stdlib Python; no PRISM, no Java, no pip install
# required. The full PRISM model template lives at
# `model.pm` for organisations that want temporal-property
# verification (steady-state, eventually-detected) on top of
# the simple multiplications we ship here.

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
runner="$script_dir/risk_model.py"
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

# Cognito self-register chain — anonymous reach + self-register
# both fire on writeup; both vanish on remediated. Highest
# exploitation probability across the fixture set.
run_one "Cognito writeup-config" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations"
run_one "Cognito remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations"

# Multi-hop privesc — chain depth drives the exponential.
# 3-hop chain on vulnerable, 1-hop edges on remediated.
run_one "Multi-hop vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/vulnerable/observations"
run_one "Multi-hop remediated" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/remediated/observations"

# Rhino — overperm + compute trust ranks elevated when both
# sides overlap on a role. Hygiene-only fixtures stay LOW.
run_one "Rhino vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations"
run_one "Rhino remediated" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/remediated/observations"

# Bybit — wildcard resource shape detects only when BOTH the
# wildcard action and wildcard resource overlap on the same
# role. The bybit fixture's developer policy uses a wildcard
# pattern (not literal "*"), so this shape does not flag.
# Z3+SMT's str.prefixof catches that case.
run_one "Bybit before" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-before/observations"
run_one "Bybit after" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-after/observations"
