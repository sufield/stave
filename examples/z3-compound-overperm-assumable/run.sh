#!/usr/bin/env bash
# Compound-query runner: overpermission ∧ compute-assumable.
#
# The chain Z3 reasons over:
#   role with contributed_by(CTL.IAM.POLICY.RESOURCE.WILDCARD.001)
#     AND
#   role with trusts_service in compute-principal set
#
# Both fixtures from examples/iam-overpermission-wildcard/:
#   before  → overpermissioned Lambda role with lambda.amazonaws.com
#             trust → SAT (PassRole exploit shape present)
#   after   → scoped policy, no overpermission finding → UNSAT
#             (the trust is unchanged but the first conjunct is
#              false; the conjunction collapses)
#
# Cross-checked with cvc5 when available.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
fixture_root="$example_root/iam-overpermission-wildcard"
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
        --now 2026-01-09T00:00:00Z \
        --format smt2 > "$facts" 2>/dev/null

    local z3_verdict cvc5_verdict
    z3_verdict=$(solve_with_z3 "$facts")

    if (( have_cvc5 )); then
        cvc5_verdict=$(solve_with_cvc5 "$facts")
        printf '%-12s  expected=%-5s  z3=%-5s  cvc5=%-5s' "$label" "$expected" "$z3_verdict" "$cvc5_verdict"
    else
        cvc5_verdict="(skipped)"
        printf '%-12s  expected=%-5s  z3=%-5s  cvc5=%-9s' "$label" "$expected" "$z3_verdict" "$cvc5_verdict"
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
run_one "before"  "$fixture_root/fixtures/before/observations"  "sat"   || failures=$((failures+1))
run_one "after"   "$fixture_root/fixtures/after/observations"   "unsat" || failures=$((failures+1))

if (( have_cvc5 == 0 )); then
    echo
    echo "note: cvc5 not on PATH — cross-check skipped."
fi

if (( failures > 0 )); then
    echo
    echo "$failures verdict(s) did not match expectation"
    exit 1
fi
