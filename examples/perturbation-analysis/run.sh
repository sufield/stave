#!/usr/bin/env bash
# Round-trip the perturbation-analysis pipeline:
#
#   stave export-sir (before, after) → JSONL + SMT2 facts
#   diff.py JSONL pair               → delta.json
#   compile forbidden_state queries  → queries/
#   impact.py SMT2 pair + queries    → impact.json
#
# Demo fixture: examples/z3-forbidden-state's writeup-config (PHI
# bucket reachable by external account) vs remediated-config (same
# bucket, external_account_ids cleared). The forbidden_state query
# auto-compiled from CTL.S3.ACCESS.EXTERNAL.ORG.001 distinguishes
# them — SAT before, UNSAT after.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
stave_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$stave_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
fixtures="$stave_root/examples/z3-forbidden-state/fixtures"
forbidden_dir="$stave_root/examples/z3-forbidden-state"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
    exit 1
fi
if ! command -v z3 >/dev/null 2>&1; then
    echo "z3 not found on PATH (sudo apt install z3 | brew install z3)"
    exit 1
fi

now=2026-05-09T12:00:00Z

echo "=== Perturbation analysis ==="
echo "  before: $fixtures/writeup-config (PHI bucket + external account)"
echo "  after:  $fixtures/remediated-config (PHI bucket, external account removed)"
echo ""

echo "Exporting SIR facts (before / after) ..."
"$stave_bin" export-sir --format jsonl \
    --observations "$fixtures/writeup-config/observations" --now "$now" \
    > "$work_dir/before.jsonl" 2>/dev/null
"$stave_bin" export-sir --format jsonl \
    --observations "$fixtures/remediated-config/observations" --now "$now" \
    > "$work_dir/after.jsonl" 2>/dev/null
"$stave_bin" export-sir --format smt2 \
    --observations "$fixtures/writeup-config/observations" --now "$now" \
    > "$work_dir/before.smt2" 2>/dev/null
"$stave_bin" export-sir --format smt2 \
    --observations "$fixtures/remediated-config/observations" --now "$now" \
    > "$work_dir/after.smt2" 2>/dev/null
echo "  $(wc -l < "$work_dir/before.jsonl") before / $(wc -l < "$work_dir/after.jsonl") after"
echo ""

echo "Computing fact-set delta ..."
python3 "$script_dir/diff.py" "$work_dir/before.jsonl" "$work_dir/after.jsonl" "$work_dir/delta.json"
echo ""

echo "Compiling forbidden_state queries ..."
"$stave_bin" export-invariants --format json > "$work_dir/invariants.json" 2>/dev/null
python3 "$forbidden_dir/compile.py" "$work_dir/invariants.json" "$work_dir/queries" 2>&1 | tail -3
echo ""

echo "Running queries against before / after SMT facts ..."
python3 "$script_dir/impact.py" \
    "$work_dir/before.smt2" "$work_dir/after.smt2" \
    "$work_dir/queries" "$work_dir/delta.json" "$work_dir/impact.json"
echo ""

echo "=== Delta summary ==="
jq '{added: (.added_facts | length), removed: (.removed_facts | length), unchanged: .unchanged_facts}' "$work_dir/delta.json"
echo ""

echo "=== Impact summary ==="
jq '.summary' "$work_dir/impact.json"
echo ""

echo "=== Resolved unsafe states ==="
jq '.resolved_unsafe_states[] | {query: .query, before: .before, after: .after, removed_fact_count: (.removed_fact_ids | length)}' "$work_dir/impact.json"
