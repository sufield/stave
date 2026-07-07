#!/usr/bin/env bash
# Round-trip the perturbation-analysis pipeline:
#
#   stave export-sir (before, after) → JSONL fact pairs
#   diff.py JSONL pair               → delta.json
#   stave export-controls          → invariants.json
#   impact.py obs pair + invariants  → impact.json (regressions / improvements)

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
fixtures="$stave_root/examples/z3-forbidden-state/fixtures"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"
# shellcheck source=../lib/raw_flag.sh
source "$example_root/lib/raw_flag.sh"
parse_raw_flag "$@"
set -- "${RAW_FLAG_ARGS[@]}"

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

if [[ "$FMT_RAW" != "1" ]]; then
    fmt_section "Perturbation Analysis — before/after fact-set diff + verdict flips"
    fmt_kv "before fixture" "z3-forbidden-state/writeup-config (PHI + external account)"
    fmt_kv "after fixture"  "z3-forbidden-state/remediated-config (external account cleared)"
    echo ""
fi

"$stave_bin" export-sir --format jsonl \
    --observations "$fixtures/writeup-config/observations" --eval-time "$now" \
    > "$work_dir/before.jsonl" 2>/dev/null
"$stave_bin" export-sir --format jsonl \
    --observations "$fixtures/remediated-config/observations" --eval-time "$now" \
    > "$work_dir/after.jsonl" 2>/dev/null

python3 "$script_dir/diff.py" "$work_dir/before.jsonl" "$work_dir/after.jsonl" "$work_dir/delta.json" >/dev/null 2>&1
"$stave_bin" export-controls --format json > "$work_dir/invariants.json" 2>/dev/null
python3 "$script_dir/impact.py" \
    "$fixtures/writeup-config/observations" \
    "$fixtures/remediated-config/observations" \
    "$work_dir/invariants.json" \
    "$work_dir/delta.json" "$work_dir/impact.json" >/dev/null 2>&1

if [[ "$FMT_RAW" == "1" ]]; then
    printf '### delta.json\n'
    cat "$work_dir/delta.json"
    printf '\n### impact.json\n'
    cat "$work_dir/impact.json"
    exit 0
fi

# --- Diff layer ------------------------------------------------
total_before=$(jq '.total_before' "$work_dir/delta.json")
total_after=$(jq '.total_after' "$work_dir/delta.json")
added=$(jq '.added_facts | length' "$work_dir/delta.json")
removed=$(jq '.removed_facts | length' "$work_dir/delta.json")
unchanged=$(jq '.unchanged_facts' "$work_dir/delta.json")

fmt_block_header "Fact-set delta (full SIR JSONL)"
fmt_kv "total before"   "$total_before"
fmt_kv "total after"    "$total_after"
fmt_kv "facts added"    "$added"
fmt_kv "facts removed"  "$removed"
fmt_kv "facts unchanged" "$unchanged"
if [[ "$removed" -gt 0 ]]; then
    mapfile -t removed_summary < <(jq -r '.removed_facts[] | "\(.predicate)(\(.subject), \(.object))   evidence: \(.evidence)"' "$work_dir/delta.json")
    echo ""
    printf '  %sRemoved fact records%s\n' "$FMT_DIM" "$FMT_RESET"
    fmt_violations "${removed_summary[@]}"
fi
if [[ "$added" -gt 0 ]]; then
    mapfile -t added_summary < <(jq -r '.added_facts[] | "\(.predicate)(\(.subject), \(.object))   evidence: \(.evidence)"' "$work_dir/delta.json")
    echo ""
    printf '  %sAdded fact records%s\n' "$FMT_DIM" "$FMT_RESET"
    fmt_violations "${added_summary[@]}"
fi
echo ""

# --- Impact layer ----------------------------------------------
regressions=$(jq '.summary.regressions' "$work_dir/impact.json")
improvements=$(jq '.summary.improvements' "$work_dir/impact.json")
no_change=$(jq '.summary.no_change' "$work_dir/impact.json")

fmt_block_header "Verdict-flip impact (forbidden_state queries × before / after)"
fmt_findings "$regressions" "regression(s) — invariants newly reachable"

if [[ "$regressions" -gt 0 ]]; then
    mapfile -t reg_summary < <(jq -r '.new_unsafe_states[] | "\(.query): unsat → sat — perturbation introduced facts that make the forbidden state reachable"' "$work_dir/impact.json")
    fmt_violations "${reg_summary[@]}"
fi
if [[ "$improvements" -gt 0 ]]; then
    printf '  %s✓ %s improvement(s) — invariants newly proved unreachable%s\n' "$FMT_GREEN" "$improvements" "$FMT_RESET"
    mapfile -t imp_summary < <(jq -r '.resolved_unsafe_states[] | "\(.query): sat → unsat — perturbation removed facts that previously made the forbidden state reachable"' "$work_dir/impact.json")
    fmt_safe_list "${imp_summary[@]}"
fi
if [[ "$no_change" -gt 0 ]]; then
    printf '  %s· %s unchanged verdict(s)%s\n' "$FMT_DIM" "$no_change" "$FMT_RESET"
fi
echo ""

# --- Verify the encoding (Iteration 3 hook) -----------------
fmt_block_header "Encoding verifier — does each emitted fact match its observation?"
echo ""
python3 "$example_root/explain/verify_encoding.py" \
    "$work_dir/before.jsonl" \
    "$fixtures/writeup-config/observations" || true
echo ""
python3 "$example_root/explain/verify_encoding.py" \
    "$work_dir/after.jsonl" \
    "$fixtures/remediated-config/observations" || true
echo ""

fmt_interpretation <<EOF
The diff layer reads the full SIR fact-set: $total_before facts
before, $total_after after, with $removed removed and $added
added. fact_id is a deterministic SHA-256 over (subject,
predicate, object), so the diff is an exact set operation —
identical (subject, predicate, object) tuples produce identical
fact_ids and the comparison is order-independent.

The two removed fact records are contributed_by(<bucket>,
CTL.S3.ACCESS.*) exposure-window facts. These disappear because
clearing external_account_ids stops the corresponding control
predicates from firing on the bucket; the bucket exits the
exposure window and the contributed_by trace closes.

The impact layer asks the same question the
z3-forbidden-state demo asks, but for both snapshots: did the
fact-set change move any forbidden_state from reachable (SAT)
to unreachable (UNSAT) or vice versa?

In this demo: 1 IMPROVEMENT — CTL.S3.ACCESS.EXTERNAL.ORG.001's
forbidden_state flipped sat → unsat, attributable to the 2
removed contributed_by facts. No regressions; the perturbation
strictly improved the security posture.

In an AWS workflow: a developer commits a bucket-policy change
(removing external account 222233334444 from the access list).
This tool runs against the before/after SIR and reports —
within seconds — exactly which invariants the change moved and
which facts caused the move. The reverse case (a regression)
would block the commit; the improvement case is what you'd
expect from a remediation.
EOF
