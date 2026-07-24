#!/usr/bin/env bash
# Round-trip the forbidden_state pipeline for the writeup and
# remediated fixtures: export invariants → compile each
# forbidden_state to SMT-LIB → bind observation values → run Z3.
#
#   stave export-controls --format json        →  invariants.json
#   compile.py invariants.json queries/          →  *.query.smt2
#   obs_to_facts.py + observations/              →  facts.smt2
#   z3 -in (cat facts.smt2 query.smt2)           →  sat / unsat per control

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
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
    echo "z3 not found on PATH"
    echo "install with: sudo apt install z3   |   brew install z3"
    exit 1
fi

if [[ "$FMT_RAW" != "1" ]]; then
    fmt_section "Forbidden State — auto-generated Z3 invariants from YAML"
fi

invariants="$work_dir/invariants.json"
queries_dir="$work_dir/queries"

"$stave_bin" export-controls --format json > "$invariants" 2>/dev/null
total=$(jq '.invariants | length' "$invariants")
fs_count=$(jq '[.invariants[] | select((.forbidden_state.combine // "") != "")] | length' "$invariants")
if [[ "$FMT_RAW" != "1" ]]; then
    fmt_kv "invariants exported" "$total"
    fmt_kv "with forbidden_state" "$fs_count"
    echo ""
fi

if [[ "$fs_count" -eq 0 ]]; then
    echo "No forbidden_state blocks found. Add one to a control YAML first."
    exit 0
fi

python3 "$script_dir/compile.py" "$invariants" "$queries_dir" >&2
if [[ "$FMT_RAW" != "1" ]]; then
    echo ""
fi

run_one() {
    local label=$1
    local obs_dir=$2
    local block_kind=$3   # "before" or "after"

    if [[ "$FMT_RAW" != "1" ]]; then
        case "$block_kind" in
            before) fmt_before "$label" ;;
            after)  fmt_after "$label" ;;
        esac
    fi

    local facts="$work_dir/$label.facts.smt2"
    python3 "$script_dir/obs_to_facts.py" "$invariants" "$obs_dir" "$facts" >/dev/null 2>&1

    local violation_count=0
    local safe_count=0
    declare -a violations_jsonl=()
    declare -a safes_jsonl=()
    for query in "$queries_dir"/*.query.smt2; do
        local control_id
        control_id=$(basename "$query" .query.smt2)
        local verdict
        verdict=$( { cat "$query" "$facts"; echo '(check-sat)'; } | z3 -in 2>&1 | head -1)
        if [[ "$FMT_RAW" == "1" ]]; then
            printf '### %s %s\n%s\n' "$label" "$control_id" "$verdict"
            continue
        fi
        # Pull the catalog's human-readable name + description for
        # this control from the invariants export so the output
        # explains what the control IS, not just its ID.
        local entry
        entry=$(jq --arg id "$control_id" --arg verdict "$verdict" '
            .invariants[] | select(.id == $id) | {
                id: .id,
                name: (
                    if $verdict == "sat" then "verdict: SAT — forbidden state is reachable"
                    elif $verdict == "unsat" then "verdict: UNSAT — forbidden state is unreachable"
                    else "verdict: " + $verdict + " — solver could not decide" end
                ),
                description: ((.description // "") | gsub("^\\s+|\\s+$"; ""))
            }
        ' "$invariants")
        case "$verdict" in
            sat)
                violation_count=$((violation_count + 1))
                violations_jsonl+=("$entry")
                ;;
            unsat)
                safe_count=$((safe_count + 1))
                safes_jsonl+=("$entry")
                ;;
            *)
                violations_jsonl+=("$entry")
                ;;
        esac
    done
    if [[ "$FMT_RAW" == "1" ]]; then
        return
    fi
    fmt_findings "$violation_count" "violation(s)"
    if [[ ${#violations_jsonl[@]} -gt 0 ]]; then
        local arr
        arr=$(printf '%s\n' "${violations_jsonl[@]}" | jq -s '.')
        fmt_findings_with_descriptions "$FMT_RED" "$arr"
    fi
    if [[ ${#safes_jsonl[@]} -gt 0 ]]; then
        local arr
        arr=$(printf '%s\n' "${safes_jsonl[@]}" | jq -s '.')
        fmt_findings_with_descriptions "$FMT_GREEN" "$arr"
    fi
    echo ""
}

run_one "writeup-config"    "$script_dir/fixtures/writeup-config/observations"    before
run_one "remediated-config" "$script_dir/fixtures/remediated-config/observations" after

if [[ "$FMT_RAW" == "1" ]]; then
    exit 0
fi

fmt_interpretation <<'EOF'
The reference control CTL.S3.ACCESS.EXTERNAL.ORG.001 carries a
forbidden_state block in its YAML. compile.py walks that
predicate tree and emits an SMT-LIB query that asks: "given the
asset properties Stave observed, is the forbidden state
reachable?"

Before — writeup-config: an S3 bucket tagged
data-classification=phi has external_account_ids set to
["222233334444"]. The forbidden state (PHI bucket reachable by
an external principal) is satisfied: SAT.

After — remediated-config: same bucket, external_account_ids
cleared to []. obs_to_facts.py renders the empty list as the
"__absent__" sentinel; the predicate "external account list is
present" is false; the forbidden state is unreachable: UNSAT.

The pipeline takes a YAML invariant ("this state must never
exist") to a machine-verifiable SMT proof end-to-end. No
hand-written query needed; the catalog is the source of truth.
EOF
