#!/usr/bin/env bash
# Run every verify_encoding test case in this directory.
# Each test case is a triple:
#   <name>.facts.jsonl       fact records under test
#   observations/            observation JSON the facts claim to come from
#   <name>.expected.txt      expected verifier output
#
# Test pass = byte-exact match against the expected golden.
# verify_encoding.py exits 0 on no mismatches and 1 otherwise;
# the test runner ignores that exit code (it's the diff that
# decides pass/fail).

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
explain_dir=$(cd "$script_dir/../.." && pwd)
verifier="$explain_dir/verify_encoding.py"
obs_dir="$script_dir/observations"

failures=0
pass=0

for input in "$script_dir"/*.facts.jsonl; do
    name=$(basename "$input" .facts.jsonl)
    expected="$script_dir/${name}.expected.txt"
    if [[ ! -f "$expected" ]]; then
        echo "  ✗ $name — expected file missing"
        failures=$((failures + 1))
        continue
    fi
    actual_file=$(mktemp)
    NO_COLOR=1 python3 "$verifier" "$input" "$obs_dir" > "$actual_file" || true
    if diff -u "$expected" "$actual_file" > /dev/null; then
        echo "  ✓ $name"
        pass=$((pass + 1))
    else
        echo "  ✗ $name — output differs from expected:"
        diff -u "$expected" "$actual_file" | sed 's/^/      /'
        failures=$((failures + 1))
    fi
    rm -f "$actual_file"
done

total=$((pass + failures))
echo ""
echo "$pass/$total tests passed"
exit "$failures"
