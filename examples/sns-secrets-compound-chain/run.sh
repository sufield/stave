#!/usr/bin/env bash
# Iter 14 / sns-secrets-compound-chain — SMT-LIB file-boundary
# verification. Pipes Stave's exported facts plus query.smt2
# through Z3 (and cvc5 / Yices when present) and asserts the
# verdicts: sat on the vulnerable fixture, unsat on the
# remediated counterpart.

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root="$script_dir"
stave_root=$(cd "$example_root/../.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
control_dir="$example_root/controls"
query="$script_dir/query.smt2"
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
have_cvc5=0;  command -v cvc5      >/dev/null 2>&1 && have_cvc5=1
have_yices=0; command -v yices-smt2 >/dev/null 2>&1 && have_yices=1

solve_z3()    { local out; out=$(timeout 30 z3 -in 2>&1 || true); printf '%s' "${out%%$'\n'*}" | tr -d '[:space:]'; }
solve_cvc5()  { local out; out=$(timeout 30 cvc5 --lang smt2 --finite-model-find --produce-models 2>&1 || true); printf '%s' "${out%%$'\n'*}" | tr -d '[:space:]'; }
solve_yices() { local out; out=$(timeout 30 yices-smt2 2>&1 || true); printf '%s' "${out%%$'\n'*}" | tr -d '[:space:]'; }

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

    local z3_v cvc5_v yices_v
    z3_v=$(cat "$facts" "$query" | solve_z3)
    cvc5_v=$(( have_cvc5 ))   && cvc5_v=$(cat "$facts" "$query" | solve_cvc5)   || cvc5_v="(skipped)"
    yices_v=$(( have_yices )) && yices_v=$(cat "$facts" "$query" | solve_yices) || yices_v="(skipped)"

    printf '%-20s  expected=%-5s  z3=%-5s  cvc5=%-9s  yices=%-9s' \
        "$label" "$expected" "$z3_v" "$cvc5_v" "$yices_v"

    local fail=0
    if [[ "$z3_v" != "$expected" ]]; then
        printf '  FAIL (z3 disagrees with expected)\n'; fail=1
    elif (( have_cvc5 )) && [[ "$cvc5_v" != "$z3_v" ]]; then
        printf '  FAIL (cvc5 disagrees with z3)\n';     fail=1
    elif (( have_yices )) && [[ "$yices_v" != "$z3_v" ]]; then
        printf '  FAIL (yices disagrees with z3)\n';    fail=1
    else
        printf '  OK\n'
    fi
    return $fail
}

failures=0
run_one "writeup-config"    "$example_root/fixtures/writeup-config/observations"    "sat"   || failures=$((failures+1))
run_one "remediated-config" "$example_root/fixtures/remediated-config/observations" "unsat" || failures=$((failures+1))

if (( failures > 0 )); then
    echo
    echo "$failures verdict(s) did not match expectation"
    exit 1
fi
