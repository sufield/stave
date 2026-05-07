#!/usr/bin/env bash
# Pipe Stave's SMT-LIB facts export plus query.smt2 through every
# available SMT solver and assert the verdict matches the
# fixture's expected state. All available solvers must agree on
# every fixture; any disagreement is a hard failure.
#
# Vulnerable fixture (`before`):
#   The Lambda role has `s3:*` on `*`. Stave's
#   CTL.IAM.POLICY.RESOURCE.WILDCARD.001 control fires.
#   Solvers expect sat (an asset with the offending exposure
#   window exists).
#
# Remediated fixture (`after`):
#   The role's policy is scoped. The control does not fire.
#   Solvers expect unsat (no asset has the offending exposure).
#
# Solver coverage:
#   z3   — required (used as the canonical reference verdict)
#   cvc5 — optional; if installed, runs in cross-check mode and
#          its verdict must match z3's. cvc5's default quantifier
#          strategy can return `unknown` on the closed-world
#          axioms; --finite-model-find treats the fact base as a
#          finite-model search, which decides both directions.
#
# Cross-check rationale:
#   Different solvers exercise different code paths through the
#   same SMT-LIB input. Agreement raises confidence that the
#   verdict reflects the encoded semantics rather than a
#   solver-specific quirk. Disagreement either points at a real
#   solver bug (rare) or — far more common — at an encoding
#   ambiguity Stave should fix.

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

# solve_with_z3 / solve_with_cvc5 each return only the first
# whitespace-stripped output line — that is the verdict
# (sat | unsat | unknown). Trailing diagnostic lines (e.g.
# get-value errors after unsat) are ignored.
solve_with_z3() {
    local facts=$1
    cat "$facts" "$query" | z3 -in 2>&1 | head -n 1 | tr -d '[:space:]'
}

solve_with_cvc5() {
    local facts=$1
    # --finite-model-find: treat the fact base as a finite-model
    #   search; cvc5's default quantifier instantiator returns
    #   `unknown` on the universal closed-world axioms.
    # --produce-models: silence the get-value error wrapper; the
    #   verdict is what we read.
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
    echo "      install from https://github.com/cvc5/cvc5/releases for solver-agreement validation."
fi

if (( failures > 0 )); then
    echo
    echo "$failures verdict(s) did not match expectation"
    exit 1
fi
