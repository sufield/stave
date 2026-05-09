#!/usr/bin/env bash
# Round-trip the forbidden_state pipeline for the writeup and
# remediated fixtures: export invariants → compile each
# forbidden_state to SMT-LIB → bind observation values → run Z3.
#
#   stave export-invariants --format json        →  invariants.json
#   compile.py invariants.json queries/          →  *.query.smt2
#   obs_to_facts.py + observations/              →  facts.smt2
#   z3 -in (cat facts.smt2 query.smt2)           →  sat / unsat per control
#
# SAT  = the forbidden state matches the observation → VIOLATION
# UNSAT = the forbidden state is impossible given the observation → SAFE

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
    exit 1
fi
if ! command -v z3 >/dev/null 2>&1; then
    echo "z3 not found on PATH"
    echo "install with: sudo apt install z3   |   brew install z3"
    exit 1
fi

invariants="$work_dir/invariants.json"
queries_dir="$work_dir/queries"

"$stave_bin" export-invariants --format json > "$invariants" 2>/dev/null
fs_count=$(jq '[.invariants[] | select((.forbidden_state.combine // "") != "")] | length' "$invariants")
echo "=== Forbidden State: Auto-Generated Z3 Queries ==="
echo "  $(jq '.invariants | length' "$invariants") invariants exported"
echo "  $fs_count with forbidden_state blocks"
echo ""

if [[ "$fs_count" -eq 0 ]]; then
    echo "No forbidden_state blocks found. Add one to a control YAML first."
    exit 0
fi

python3 "$script_dir/compile.py" "$invariants" "$queries_dir" >&2
echo ""

run_one() {
    local label=$1
    local obs_dir=$2

    local facts="$work_dir/$label.facts.smt2"
    python3 "$script_dir/obs_to_facts.py" "$invariants" "$obs_dir" "$facts" >&2

    echo "--- fixture: $label"
    for query in "$queries_dir"/*.query.smt2; do
        local control_id
        control_id=$(basename "$query" .query.smt2)
        local verdict
        verdict=$( { cat "$query" "$facts"; echo '(check-sat)'; } | z3 -in 2>&1 | head -1)
        case "$verdict" in
            sat)   verdict="VIOLATION   forbidden state is reachable" ;;
            unsat) verdict="SAFE        forbidden state is impossible" ;;
            *)     verdict="INCONCLUSIVE $verdict" ;;
        esac
        printf "  %-45s %s\n" "$control_id" "$verdict"
    done
    echo ""
}

run_one "writeup-config"    "$script_dir/fixtures/writeup-config/observations"
run_one "remediated-config" "$script_dir/fixtures/remediated-config/observations"

echo "Each query was auto-generated from the control's forbidden_state YAML block."
echo "No hand-written query.smt2 needed."
