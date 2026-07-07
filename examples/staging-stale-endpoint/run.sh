#!/usr/bin/env bash
# staging-stale-endpoint — SMT-LIB file-boundary verification.
#
# This example ships four fixtures modeling distinct states rather
# than a vulnerable/remediated pair, so the matrix's heuristic
# before/after pick has no clean baseline to diff against. The
# blocker recorded in SMT-QUERY-GAPS.md was fixture-pair selection,
# not a projector gap. This runner resolves it by selecting all four
# fixtures explicitly and asserting the per-fixture verdict.
#
# The query (query.smt2) asks the COMPOUND security question — "does
# any asset carry a non-production environment tag AND allow public
# listing?" — which the `staging_endpoint_exposed` chain escalates to
# HIGH. Both inputs are raw projected facts (has_tag, has_public_list),
# so the solver derives the verdict itself rather than trusting CEL's
# contributed_by. The pure staleness dimension is not independently
# solver-decidable (dormancy is not projected as a raw fact); see the
# query header and SMT-QUERY-GAPS.md.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root="$script_dir"
stave_root=$(cd "$example_root/../.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
control_dir="$example_root/controls"
query="$script_dir/query.smt2"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

[[ -x "$stave_bin" ]] || { echo "build with: cd $stave_root && make build"; exit 1; }
command -v z3 >/dev/null 2>&1 || { echo "z3 not found on PATH"; exit 1; }
have_cvc5=0
command -v cvc5 >/dev/null 2>&1 && have_cvc5=1

solve_z3()   { local out; out=$(timeout 30 z3 -in 2>&1 || true); printf '%s' "${out%%$'\n'*}" | tr -d '[:space:]'; }
solve_cvc5() { local out; out=$(timeout 30 cvc5 --lang smt2 --finite-model-find --produce-models 2>&1 || true); printf '%s' "${out%%$'\n'*}" | tr -d '[:space:]'; }

run_one() {
    local label=$1 fixture=$2 expected=$3
    local facts="$work_dir/$label.smt2"
    "$stave_bin" export-sir --controls "$control_dir" \
        --observations "$example_root/fixtures/$fixture/observations" \
        --eval-time 2026-01-09T00:00:00Z --format smt2 > "$facts" 2>/dev/null
    local z3_v cvc5_v="(skipped)"
    z3_v=$(cat "$facts" "$query" | solve_z3)
    if (( have_cvc5 )); then
        cvc5_v=$(cat "$facts" "$query" | solve_cvc5)
    fi
    printf '%-22s  expected=%-5s  z3=%-5s  cvc5=%-9s' "$label" "$expected" "$z3_v" "$cvc5_v"
    if [[ "$z3_v" != "$expected" ]]; then
        printf '  FAIL\n'; return 1
    elif (( have_cvc5 )) && [[ "$cvc5_v" != "$z3_v" ]]; then
        printf '  FAIL (cvc5 disagrees with z3)\n'; return 1
    fi
    printf '  OK\n'
}

failures=0
run_one "stale-staging"        "stale-staging"        "unsat" || failures=$((failures+1))
run_one "active-staging"       "active-staging"       "unsat" || failures=$((failures+1))
run_one "prod-dormant"         "prod-dormant"         "unsat" || failures=$((failures+1))
run_one "stale-staging-public" "stale-staging-public" "sat"   || failures=$((failures+1))
exit $((failures > 0))
