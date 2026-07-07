#!/usr/bin/env bash
# Reasoning-trace linker — reads what `make demo-no-graph` left in
# results/ and emits one unified reasoning-trace.json that connects
# CEL findings to their contributing SIR facts and surfaces every
# engine's verdict against the same fact base.
#
# Pre-req: the demo must have produced its results. From the repo
# root:
#
#   cd demos/nodes-2026 && make demo-no-graph
#   bash stave/examples/reasoning-trace/run.sh

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
repo_root=$(cd "$stave_root/.." && pwd)
demo_results="$repo_root/demos/nodes-2026/results"

# venv for the linker (PyYAML and other deps live here on dev hosts).
if [[ -f "$repo_root/.tools-venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$repo_root/.tools-venv/bin/activate"
fi

if [[ ! -d "$demo_results" ]]; then
    cat <<EOF >&2
no demo results at $demo_results

run the demo first:
    cd $repo_root/demos/nodes-2026 && make demo-no-graph

then re-run this script.
EOF
    exit 1
fi

run_one() {
    local fixture=$1
    local findings=$2
    local out="$script_dir/results/$fixture/reasoning-trace.json"

    echo "=== $fixture ==="
    python3 "$script_dir/link.py" \
        --findings "$findings" \
        --facts "$demo_results/facts-$fixture.jsonl" \
        --prove "$demo_results/prove-summary.json" \
        --enumerate "$demo_results/enumerate-summary.json" \
        --quantify "$demo_results/quantify-summary.json" \
        --contrast "$demo_results/contrast-summary.json" \
        --fixture "capital-one/$fixture" \
        --eval-time "2026-01-09T00:00:00Z" \
        --output "$out"
    echo
}

mkdir -p "$script_dir/results"

# capital-one (writeup) — the demo's primary fixture; full results
# from every engine.
run_one "capital-one" "$demo_results/findings-capital-one.json"

# remediated — same fact base after the five config changes; CEL
# emits 0 findings, Z3 flips to unsat, risk drops to 0%. The trace
# is still useful: chain steps disappear, consensus flips to SAFE.
# facts-remediated.jsonl isn't currently emitted by the demo (only
# the .smt2 form is). Skip remediated when the JSONL is absent
# rather than fail.
if [[ -f "$demo_results/facts-remediated.jsonl" ]]; then
    run_one "remediated" "$demo_results/findings-remediated.json"
else
    echo "(skip remediated: facts-remediated.jsonl not present in demo output)"
fi
