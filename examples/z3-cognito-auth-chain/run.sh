#!/usr/bin/env bash
# Cognito authenticated → IAM-granted S3 chain, with two
# queries that isolate the registration gate as the choke
# point.
#
# Two queries, two fixtures, four verdicts:
#
#   query-auth-chain          assumes someone is authenticated
#   query-self-register-chain extends with anonymous → register
#                              → authenticated, gated on
#                              self_registration_unrestricted
#
# Fixture                | auth-chain | self-register-chain
# -----------------------+------------+--------------------
# writeup-config         | sat        | sat
# remediated-config      | sat        | unsat
#
# The auth-chain stays SAT on remediated because the auth
# role's S3 grants didn't disappear — they were narrowed
# to per-user-prefix scoping (still SAT, narrower witness).
# Only the self-register-chain flips to UNSAT, isolating
# the user pool's registration gate as the actual choke
# point. The role is still a footgun if any other onboarding
# path admits an attacker.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
fixture_root="$example_root/cognito-self-register-to-aws-creds"
control_dir="$fixture_root/controls"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
    exit 1
fi
if ! command -v z3 >/dev/null 2>&1; then
    echo "z3 not found on PATH (apt install z3 / brew install z3)"
    exit 1
fi
have_cvc5=0
if command -v cvc5 >/dev/null 2>&1; then
    have_cvc5=1
fi

# Build facts.smt2 once per fixture, reuse across queries.
write_facts() {
    local fixture=$1
    local out_file=$2
    "$stave_bin" export-sir \
        --controls "$control_dir" \
        --observations "$fixture_root/fixtures/$fixture/observations" \
        --now 2026-01-09T00:00:00Z \
        --format smt2 > "$out_file" 2>/dev/null
}

solve_with_z3() {
    local facts=$1
    local query=$2
    cat "$facts" "$query" | z3 -in 2>&1 | head -n 1 | tr -d '[:space:]'
}

solve_with_cvc5() {
    local facts=$1
    local query=$2
    cat "$facts" "$query" | cvc5 --lang smt2 --finite-model-find --produce-models 2>&1 | head -n 1 | tr -d '[:space:]'
}

run_one() {
    local query_label=$1
    local query_path=$2
    local fixture_label=$3
    local fixture_path=$4
    local expected=$5

    local z3_verdict cvc5_verdict
    z3_verdict=$(solve_with_z3 "$fixture_path" "$query_path")

    if (( have_cvc5 )); then
        cvc5_verdict=$(solve_with_cvc5 "$fixture_path" "$query_path")
        printf '  %-18s  expected=%-5s  z3=%-5s  cvc5=%-5s' "$fixture_label" "$expected" "$z3_verdict" "$cvc5_verdict"
    else
        cvc5_verdict="(skipped)"
        printf '  %-18s  expected=%-5s  z3=%-5s  cvc5=%-9s' "$fixture_label" "$expected" "$z3_verdict" "$cvc5_verdict"
    fi

    local status="OK"
    local fail=0
    if [[ "$z3_verdict" != "$expected" ]]; then
        status="FAIL (z3 disagrees with expected)"
        fail=1
    elif (( have_cvc5 )) && [[ "$cvc5_verdict" != "$z3_verdict" ]]; then
        status="FAIL (cvc5 disagrees with z3)"
        fail=1
    fi
    printf '  %s\n' "$status"
    return $fail
}

write_facts "writeup-config"    "$work_dir/writeup.smt2"
write_facts "remediated-config" "$work_dir/remediated.smt2"

failures=0

echo "=== auth-chain (anyone authenticated reaches S3) ==="
run_one "auth"   "$script_dir/query-auth-chain.smt2" \
        "writeup-config"    "$work_dir/writeup.smt2"    "sat" || failures=$((failures+1))
run_one "auth"   "$script_dir/query-auth-chain.smt2" \
        "remediated-config" "$work_dir/remediated.smt2" "sat" || failures=$((failures+1))

echo
echo "=== self-register-chain (anonymous reaches S3 by registering) ==="
run_one "selfreg" "$script_dir/query-self-register-chain.smt2" \
        "writeup-config"    "$work_dir/writeup.smt2"    "sat"   || failures=$((failures+1))
run_one "selfreg" "$script_dir/query-self-register-chain.smt2" \
        "remediated-config" "$work_dir/remediated.smt2" "unsat" || failures=$((failures+1))

if (( have_cvc5 == 0 )); then
    echo
    echo "note: cvc5 not on PATH — cross-check skipped."
fi

if (( failures > 0 )); then
    echo
    echo "$failures verdict(s) did not match expectation"
    exit 1
fi
