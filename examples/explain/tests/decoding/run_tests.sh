#!/usr/bin/env bash
# Run every decoding-format test case in this directory.
# Each test case is a pair:
#   <name>.input.json     verdict + invariant + contributing facts
#   <name>.expected.txt   expected human-readable output
#
# The test feeds the JSON into verdict.py with NO_COLOR=1 (so
# the diff is golden-friendly) and compares to the expected
# file. Exit non-zero on any mismatch.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
explain_dir=$(cd "$script_dir/../.." && pwd)
formatter="$explain_dir/verdict.py"

failures=0
pass=0

for input in "$script_dir"/*.input.json; do
    name=$(basename "$input" .input.json)
    expected="$script_dir/${name}.expected.txt"
    if [[ ! -f "$expected" ]]; then
        echo "  ✗ $name — expected file missing"
        failures=$((failures + 1))
        continue
    fi
    actual_file=$(mktemp)
    NO_COLOR=1 python3 "$formatter" "$input" > "$actual_file"
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
