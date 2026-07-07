#!/usr/bin/env bash
# Temporal-safety state-space exploration across the harness fixtures.
#
# Pipeline per fixture:
#   stave export-sir --format jsonl  →  facts.jsonl
#   temporal_check.py                →  initial state + reachable
#                                       states + drift margin
#
# The Python runner is the foundational path; the .tla / .cfg
# files in this directory model the same state machine for TLC,
# which is the right tool when you need temporal-logic
# properties (always/eventually) on top of safety.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
runner="$script_dir/temporal_check.py"
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

# Cognito self-register: writeup violates 3 of 4 invariants;
# remediated still violates 2 (auth role is still broad). The
# delta surfaces the residual config risk.
run_one "Cognito writeup-config" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations"
run_one "Cognito remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations"

# Multi-hop, rhino, bybit: not directly modeled by the booleans
# in this state machine. The model focuses on Cognito + auth-role
# breadth + logging + SCP; runs on those fixtures show whether the
# chosen knobs apply (often: not). That's a meaningful negative
# signal — drift margin only matters when the knobs are present.
run_one "Multi-hop vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/vulnerable/observations"
run_one "Multi-hop remediated" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/remediated/observations"

run_one "Rhino vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations"
run_one "Rhino remediated" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/remediated/observations"

run_one "Bybit before" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-before/observations"
run_one "Bybit after" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-after/observations"
