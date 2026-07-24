#!/usr/bin/env bash
# Bybit tag-aware compound — does any developer's wildcard
# resource pattern prefix-match a production-tagged S3 bucket?
#
# Vulnerable fixture (`bybit-pattern-before`):
#   developer-frontend user has Resource: company-frontend-* on
#   PutObject. The wildcard incidentally matches the production
#   frontend bucket (tagged environment=production).
#   → SAT with witness naming all four chain elements.
#
# Remediated fixture (`bybit-pattern-after`):
#   developer's policy is split into specific ARNs (no wildcard
#   pattern remains for full read/write). Object-prefix globs
#   like company-frontend-prod/* don't prefix-match the bucket
#   ARN itself.
#   → UNSAT.
#
# Cross-checked with cvc5 when available.

set -uo pipefail

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
    # The query uses str.++ / str.suffixof / str.prefixof —
    # cvc5's finite-model-find handles them in our fixture
    # size; tlimit is set to 30s as a safety net for larger
    # tag fact sets.
    local out
    out=$(cat "$facts" "$query" | cvc5 --lang smt2 --finite-model-find --produce-models --tlimit 30000 2>&1)
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
        --eval-time 2026-01-09T00:00:00Z \
        --format smt2 > "$facts" 2>/dev/null

    local z3_verdict cvc5_verdict
    z3_verdict=$(solve_with_z3 "$facts")

    if (( have_cvc5 )); then
        cvc5_verdict=$(solve_with_cvc5 "$facts")
        printf '%-22s  expected=%-5s  z3=%-5s  cvc5=%-9s' "$label" "$expected" "$z3_verdict" "$cvc5_verdict"
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
run_one "bybit-pattern-before" "$fixture_root/fixtures/bybit-pattern-before/observations" "sat"   || failures=$((failures+1))
run_one "bybit-pattern-after"  "$fixture_root/fixtures/bybit-pattern-after/observations"  "unsat" || failures=$((failures+1))

if (( have_cvc5 == 0 )); then
    echo
    echo "note: cvc5 not on PATH — cross-check skipped."
fi

if (( failures > 0 )); then
    echo
    echo "$failures verdict(s) did not match expectation"
    exit 1
fi
