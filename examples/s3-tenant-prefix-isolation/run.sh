#!/usr/bin/env bash
# PR 3.5 / s3-tenant-prefix-isolation — SMT-LIB file-boundary
# verification using the purposeFlagFacts projector.
#
# The fixtures' discriminator is a semicolon-delimited key=value
# string on the appsigner:s3:acme-uploads IDENTITY's `purpose`
# field. Until the 2026-05-28 SIR-boundary change that added
# IdentityFact.Properties + extended purposeFlagFacts to walk
# identities, no solver-side query could see this field — the
# data was dropped at SIR projection time.
#
# Now: purposeFlagFacts emits one has_purpose_flag(identity, "k=v")
# triple per parsed pair, and the query asks whether any identity
# carries enforce_prefix=false.

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
    local label=$1 obs_dir=$2 expected=$3
    local facts="$work_dir/$label.smt2"
    "$stave_bin" export-sir --controls "$control_dir" --observations "$obs_dir" \
        --now 2026-01-15T00:00:00Z --format smt2 > "$facts" 2>/dev/null
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
run_one "before"  "$example_root/fixtures/before/observations"  "sat"   || failures=$((failures+1))
run_one "after"   "$example_root/fixtures/after/observations"   "unsat" || failures=$((failures+1))
exit $((failures > 0))
