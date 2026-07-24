#!/usr/bin/env bash
# First multi-fact chain query against the Stave SMT-LIB facts
# export. The chain Z3 reasons over:
#
#   anonymous visitor
#     → Cognito identity pool with allow_unauthenticated=true
#     → mapped IAM role (maps_unauth_to)
#     → role grants an S3 read action on an S3 resource
#
# The query is a four-step composition. CEL evaluates each step
# independently. SMT composes them.
#
# Vulnerable fixture (`writeup-config`):
#   The Cognito identity pool allows unauthenticated identities;
#   the unauth role grants s3:GetObject + s3:ListBucket on
#   app-public-assets. Z3 + cvc5 both expect SAT with a
#   witness naming the (pool, role, action, resource) chain.
#
# Remediated fixture (`remediated-config`):
#   The pool sets allow_unauthenticated=false; no unauth role
#   is mapped. The closed-world axiom restricts
#   allows_unauthenticated to false everywhere. Z3 + cvc5 both
#   expect UNSAT.
#
# This is the first SMT-derived result that needs the chain
# composition — no individual CEL control flags the
# unauth-role-with-narrow-S3-read configuration as unsafe
# (the bucket is intentionally public). The composition is
# the security property; the witness names the path.

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
fixture_root="$example_root/cognito-self-register-to-aws-creds"
query="$script_dir/query.smt2"
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

solve_with_z3() {
    local facts=$1
    cat "$facts" "$query" | z3 -in 2>&1 | head -n 1 | tr -d '[:space:]'
}

solve_with_cvc5() {
    local facts=$1
    # --finite-model-find: cvc5's default quantifier strategy
    #   returns `unknown` on the universal closed-world axioms;
    #   finite-model-finding decides both directions.
    # --produce-models: silence the get-value error wrapper.
    cat "$facts" "$query" | cvc5 --lang smt2 --finite-model-find --produce-models 2>&1 | head -n 1 | tr -d '[:space:]'
}

run_one() {
    local label=$1
    local obs_dir=$2
    local expected=$3

    local facts="$work_dir/$label.smt2"
    "$stave_bin" export-sir \
        --controls "$control_dir" \
        --observations "$obs_dir" \
        --eval-time 2026-01-09T00:00:00Z \
        --format smt2 > "$facts" 2>/dev/null

    local z3_verdict cvc5_verdict
    z3_verdict=$(solve_with_z3 "$facts")

    if (( have_cvc5 )); then
        cvc5_verdict=$(solve_with_cvc5 "$facts")
        printf '%-18s  expected=%-5s  z3=%-5s  cvc5=%-5s' "$label" "$expected" "$z3_verdict" "$cvc5_verdict"
    else
        cvc5_verdict="(skipped)"
        printf '%-18s  expected=%-5s  z3=%-5s  cvc5=%-9s' "$label" "$expected" "$z3_verdict" "$cvc5_verdict"
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

failures=0
run_one "writeup-config"    "$fixture_root/fixtures/writeup-config/observations"    "sat"   || failures=$((failures+1))
run_one "remediated-config" "$fixture_root/fixtures/remediated-config/observations" "unsat" || failures=$((failures+1))

if (( have_cvc5 == 0 )); then
    echo
    echo "note: cvc5 not on PATH — cross-check skipped."
    echo "      install from https://github.com/cvc5/cvc5/releases for solver-agreement validation."
fi

if (( failures > 0 )); then
    echo
    echo "$failures verdict(s) did not match expectation"
    exit 1
fi
