#!/usr/bin/env bash
# Compliance evidence generator across the harness fixtures.
#
# Pipeline per (fixture, framework) pair:
#   stave apply       → findings.json
#   stave export-sir  → facts.jsonl
#   generate_evidence → evidence-packet.md + control-matrix.csv
#                        + executive-summary.md

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
repo_root=$(cd "$stave_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
catalog="$stave_root/controls"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

# Activate venv with PyYAML if it exists.
if [[ -f "$repo_root/.tools-venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$repo_root/.tools-venv/bin/activate"
fi
# Ensure PyYAML is reachable.
if ! python3 -c "import yaml" 2>/dev/null; then
    if [[ -d "$repo_root/.tools-venv" ]]; then
        "$repo_root/.tools-venv/bin/pip" install --quiet pyyaml >/dev/null 2>&1 || true
    fi
fi

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin"
    echo "build with: cd $stave_root && make build"
    exit 1
fi

run_one() {
    local label=$1
    local controls=$2
    local obs_dir=$3
    local framework=$4

    local findings="$work_dir/$label.findings.json"
    local facts="$work_dir/$label.facts.jsonl"
    local out="$script_dir/results/$label-$framework"
    mkdir -p "$out"

    "$stave_bin" apply \
        --controls "$controls" \
        --observations "$obs_dir" \
        --eval-time 2026-01-09T00:00:00Z \
        --format json > "$findings" 2>/dev/null || true
    "$stave_bin" export-sir \
        --controls "$controls" \
        --observations "$obs_dir" \
        --eval-time 2026-01-09T00:00:00Z \
        --format jsonl > "$facts" 2>/dev/null

    echo "=== $label / $framework ==="
    python3 "$script_dir/generate_evidence.py" \
        --framework "$framework" \
        --findings "$findings" \
        --facts "$facts" \
        --catalog "$catalog" \
        --output "$out" \
        --eval-time 2026-01-09T00:00:00Z
    echo
}

mkdir -p "$script_dir/results"

# SOC 2 against the cognito pair (writeup vs remediated).
run_one "cognito-writeup" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations" \
    "soc2-cc"
run_one "cognito-remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations" \
    "soc2-cc"

# HIPAA on the same pair — same Stave findings, different
# regulatory mapping, derived from each control's compliance.hipaa
# metadata.
run_one "cognito-writeup" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/writeup-config/observations" \
    "hipaa-technical"
run_one "cognito-remediated" \
    "$stave_root/controls" \
    "$example_root/cognito-self-register-to-aws-creds/fixtures/remediated-config/observations" \
    "hipaa-technical"
