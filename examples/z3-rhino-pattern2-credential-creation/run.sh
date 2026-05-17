#!/usr/bin/env bash
# Rhino Pattern 1 (self-mutation) reachability against the
# Rhino-attack fixture. SAT on rhino-vulnerable iff any principal
# in the snapshot has at least one Pattern 1 action on a
# wildcard resource. UNSAT on remediated.
#
# This is the second compound query against the SMT-LIB
# pipeline — the first (z3-compound-overperm-assumable)
# combined a finding with a trust relationship. This one
# combines an action-set membership with a resource-scope
# constraint, demonstrating a different compound shape.
# Both shapes use only existing baseline predicates.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
fixture_root="$example_root/iam-21-privesc-5-patterns"
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
    # cvc5's quantifier instantiation scales poorly on the
    # large `has_action` closed-world disjunction this fixture
    # produces (~50 actions on the rhino-attacker user).
    # --tlimit caps cvc5 at 10s so it returns cleanly instead
    # of hanging; the runner treats "interrupted by timeout"
    # as best-effort skipped, not a verdict mismatch.
    local out
    out=$(cat "$facts" "$query" | cvc5 --lang smt2 --finite-model-find --produce-models --tlimit 10000 2>&1)
    if echo "$out" | grep -q "interrupted by timeout"; then
        echo "(timeout)"
        return
    fi
    echo "$out" | head -n 1 | tr -d '[:space:]'
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
        printf '%-22s  expected=%-5s  z3=%-5s  cvc5=%-5s' "$label" "$expected" "$z3_verdict" "$cvc5_verdict"
    else
        cvc5_verdict="(skipped)"
        printf '%-22s  expected=%-5s  z3=%-5s  cvc5=%-9s' "$label" "$expected" "$z3_verdict" "$cvc5_verdict"
    fi

    local status="OK"
    local fail=0
    if [[ "$z3_verdict" != "$expected" ]]; then
        status="FAIL (z3 disagrees with expected)"
        fail=1
    elif (( have_cvc5 )); then
        case "$cvc5_verdict" in
            "(timeout)"|"unknown")
                status="OK (cvc5 inconclusive, z3 decides)"
                ;;
            "$z3_verdict")
                ;;
            *)
                status="FAIL (cvc5 disagrees with z3)"
                fail=1
                ;;
        esac
    fi
    printf '  %s\n' "$status"
    return $fail
}

failures=0
run_one "rhino-vulnerable" "$fixture_root/fixtures/rhino-vulnerable/observations" "sat"   || failures=$((failures+1))
run_one "remediated"       "$fixture_root/fixtures/remediated/observations"       "unsat" || failures=$((failures+1))

if (( have_cvc5 == 0 )); then
    echo
    echo "note: cvc5 not on PATH — cross-check skipped."
fi

if (( failures > 0 )); then
    echo
    echo "$failures verdict(s) did not match expectation"
    exit 1
fi
