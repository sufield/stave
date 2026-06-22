#!/usr/bin/env bash
# SWI-Prolog proof-tree reasoning across the engine fixtures.
#
# Pipeline per fixture:
#   stave export-sir --format jsonl  →  facts.jsonl
#   transform-to-pl.sh               →  facts.pl (Prolog)
#   swipl reasoning.pl               →  proof trees printed
#
# Each successful proof carries the derivation chain in the
# `Proof` accumulator, which print_proof renders as an
# indented step-by-step trace. The shape — `subject --[verb]
# --> object` per line — maps to one `evaluated_value` per
# step in an AI agent's reasoning trace.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
reasoning="$script_dir/reasoning.pl"
transform="$script_dir/transform-to-pl.sh"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
    exit 1
fi
if ! command -v swipl >/dev/null 2>&1; then
    echo "swipl not found on PATH (apt install swi-prolog / brew install swi-prolog)"
    exit 1
fi

run_one() {
    local label=$1
    local controls=$2
    local obs_dir=$3

    local jsonl="$work_dir/$label.jsonl"
    local facts="$work_dir/$label.pl"
    "$stave_bin" export-sir \
        --controls "$controls" \
        --observations "$obs_dir" \
        --now 2026-01-09T00:00:00Z \
        --format jsonl > "$jsonl" 2>/dev/null

    bash "$transform" "$jsonl" "$facts"

    echo "============================================================"
    echo "  $label"
    echo "============================================================"
    swipl -q -g "consult('$facts'), consult('$reasoning'), run_queries, halt." 2>&1
    echo
}

# Cognito self-register: anonymous + self-register chains
# both reachable on writeup, neither on remediated.
run_one "Cognito writeup-config" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations"
run_one "Cognito remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations"

# Multi-hop privesc: 6 paths on vulnerable (1-hop ×3 + 2-hop
# ×2 + 3-hop ×1). 2 paths on remediated (the surviving
# disconnected single-hop edges).
run_one "Multi-hop vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/vulnerable/observations"
run_one "Multi-hop remediated" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/remediated/observations"

# Rhino: contributed_by attaches to the rhino-attacker user
# (not the trusted roles), so exploitable_role does not fire
# under the same-subject constraint. Demonstrates the same
# blind spot Clingo exhibits — different from Z3/Soufflé.
run_one "Rhino vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations"
