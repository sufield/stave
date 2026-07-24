#!/usr/bin/env bash
# Soufflé blast-radius reachability across the SMT-paired fixtures.
#
# Pipeline per fixture:
#   stave export-sir --format jsonl   →  facts.jsonl
#   transform.sh                      →  per-predicate .facts TSVs
#   souffle -F facts/ -D out/ reach.dl → per-relation .csv outputs
#
# Reports the count per output relation. The interesting read
# is the *delta* between vulnerable and remediated fixtures —
# that's the quantified blast-radius reduction the remediation
# achieved. Z3 says "exists / not exists"; Soufflé says "how
# wide?" with a number.

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
program="$script_dir/reachability.dl"
transform="$script_dir/transform.sh"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
    exit 1
fi
if ! command -v souffle >/dev/null 2>&1; then
    echo "souffle not found on PATH"
    echo "install via: extract from .deb on https://github.com/souffle-lang/souffle/releases"
    echo "  curl -fsSL https://github.com/souffle-lang/souffle/releases/download/2.5/x86_64-ubuntu-2404-souffle-2.5-Linux.deb -o /tmp/s.deb"
    echo "  dpkg-deb -x /tmp/s.deb /tmp/sx && cp /tmp/sx/usr/bin/souffle* \$HOME/.local/bin/"
    echo "  export PATH=\$HOME/.local/bin:\$PATH"
    exit 1
fi

run_one() {
    local label=$1
    local controls=$2
    local obs_dir=$3

    local facts_jsonl="$work_dir/$label.jsonl"
    local facts_dir="$work_dir/$label-facts"
    local out_dir="$work_dir/$label-out"
    mkdir -p "$out_dir"

    "$stave_bin" export-sir \
        --controls "$controls" \
        --observations "$obs_dir" \
        --eval-time 2026-01-09T00:00:00Z \
        --format jsonl > "$facts_jsonl" 2>/dev/null

    bash "$transform" "$facts_jsonl" "$facts_dir"
    souffle -F "$facts_dir" -D "$out_dir" "$program" >/dev/null 2>&1

    echo "=== $label ==="
    for relation in reachable anonymous_reachable self_register_reachable production_reachable exploitable_overperm privesc_chain; do
        local count=0
        if [[ -f "$out_dir/$relation.csv" ]]; then
            count=$(wc -l < "$out_dir/$relation.csv")
        fi
        printf "  %-26s %d\n" "$relation:" "$count"
    done
    echo
}

# Cognito self-register chain — the four-finding cascade.
# anonymous_reachable + self_register_reachable both shrink to 0
# on remediated.
run_one "Cognito writeup-config" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations"
run_one "Cognito remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations"

# Multi-hop assume chain — privesc_chain enumerates with hop
# counts. Three hops on vulnerable → six chain rows
# (1+2+3 prefixes); zero on remediated.
run_one "Multi-hop vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/vulnerable/observations"
run_one "Multi-hop remediated" \
    "$stave_root/controls" \
    "$example_root/iam-multi-hop-trust/fixtures/remediated/observations"

# Rhino — exploitable_overperm fires when contributed_by AND
# trusts_service overlap. The Rhino-attack fixture has contributed_by
# on the rhino-attacker user (not on the trusted roles), so the
# join produces zero — but the *components* are visible in
# reachable, which is the blast-radius read.
run_one "Rhino vulnerable" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/rhino-vulnerable/observations"
run_one "Rhino remediated" \
    "$stave_root/controls" \
    "$example_root/iam-21-privesc-5-patterns/fixtures/remediated/observations"

# Bybit — production_reachable fires when has_tag emits
# environment=production AND a reachable triple targets that
# bucket. The bybit fixture has both halves; production_reachable
# vanishes on bybit-pattern-after where the wildcard policy is
# scoped down to specific (non-production) ARNs.
run_one "Bybit before" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-before/observations"
run_one "Bybit after" \
    "$stave_root/controls" \
    "$example_root/iam-overpermission-wildcard/fixtures/bybit-pattern-after/observations"
