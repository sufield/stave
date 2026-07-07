#!/usr/bin/env bash
# Generic Cognito-iteration demo runner.
#
# Sourced by per-iteration run.sh scripts; provides one
# function — cognito_demo_run — that:
#
#   1. Renders the section header from the title argument.
#   2. For each fixture (label:path), runs `stave apply`,
#      counts findings matching the supplied regex, and
#      lists the controls + chain firings under a colored
#      Before/After block.
#   3. Reads stdin as the interpretation prose and renders
#      it under an Interpretation block.
#
# Usage shape:
#
#   source "$example_root/lib/format.sh"
#   source "$example_root/lib/cognito_demo.sh"
#
#   cognito_demo_run \
#       "Cognito Iteration N — <theme>" \
#       'CTL.COGNITO.<regex>' \
#       'writeup-config:before:<path>' \
#       'remediated-config:after:<path>' \
#       <<'EOF'
#   Plain-language interpretation of what changed and why.
#   EOF
#
# Each fixture argument is colon-separated:
#   <label>:<before|after|scenario>:<observations-dir>
#
# The block kind decides the section header (Before / After /
# Scenario). Use "scenario" for fixtures that aren't part of a
# before/after pair (e.g. iteration 1's authflow-gap-config).

set -euo pipefail

# Resolve once on first source.
_COGNITO_DEMO_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=format.sh
source "$_COGNITO_DEMO_LIB_DIR/format.sh"

cognito_demo_run() {
    local title=$1
    local control_regex=$2
    shift 2

    # FMT_RAW=1 (set by the caller after parsing --raw via
    # examples/lib/raw_flag.sh) routes the output through
    # `stave apply --format json` for every fixture without
    # the human-readable framing — tools that consume the
    # demo output programmatically can skip the rendering
    # layer this way.
    local raw_mode=${FMT_RAW:-0}

    local fixtures=()
    while [[ $# -gt 0 ]]; do
        fixtures+=("$1")
        shift
    done

    local example_root
    example_root="$(cd "$_COGNITO_DEMO_LIB_DIR/.." && pwd)"
    local stave_root
    stave_root="$(cd "$example_root/.." && pwd)"
    local stave_bin=${STAVE_BIN:-$stave_root/stave}

    if [[ ! -x "$stave_bin" ]]; then
        echo "stave binary not found at $stave_bin (run: cd $stave_root && make build)" >&2
        return 1
    fi

    if [[ "$raw_mode" != "1" ]]; then
        fmt_section "$title"
    fi

    local fixture
    for fixture in "${fixtures[@]}"; do
        local label kind obs_dir
        IFS=':' read -r label kind obs_dir <<<"$fixture"

        local out
        out=$("$stave_bin" apply \
            --observations "$obs_dir" \
            --eval-time 2026-05-09T12:00:00Z \
            --format json 2>/dev/null) || true

        if [[ "$raw_mode" == "1" ]]; then
            # Raw mode: emit one JSON document per fixture
            # delimited by a header comment line. Downstream
            # consumers split on the marker.
            printf '### fixture: %s (%s)\n' "$label" "$kind"
            printf '%s\n' "$out"
            continue
        fi

        case "$kind" in
            before) fmt_before "$label" ;;
            after)  fmt_after "$label" ;;
            *)      fmt_block_header "$(echo "${kind^}") — $label" ;;
        esac

        # Project findings to the {id, name, description, fix}
        # quads the renderer consumes. Dedupe by control_id so
        # multiple findings on different assets for the same
        # control collapse into one row — the description and
        # remediation are identical across them.
        local findings_json
        findings_json=$(jq --arg re "$control_regex" '
            [.findings[]
              | select(.control_id | test($re))
              | {
                  id: .control_id,
                  name: (.control_name // ""),
                  description: ((.control_description // "") | gsub("^\\s+|\\s+$"; "")),
                  fix: ((.remediation.action // .remediation_action // "") | gsub("^\\s+|\\s+$"; "")),
                }]
            | group_by(.id) | map(.[0])
            | sort_by(.id)
        ' <<<"$out")
        local count
        count=$(jq 'length' <<<"$findings_json")

        local chains_json
        chains_json=$(jq '
            [(.chain_findings // [])[]
              | {
                  id: .chain,
                  name: ("severity: " + (.severity // "?")),
                  description: ((.description // .narrative // "") | gsub("^\\s+|\\s+$"; "")),
                }]
            | group_by(.id) | map(.[0])
            | sort_by(.id)
        ' <<<"$out")
        local chain_count
        chain_count=$(jq 'length' <<<"$chains_json")

        fmt_findings "$count" "matching control finding(s)"
        if [[ "$count" -gt 0 ]]; then
            # fmt_findings_with_descriptions emits the
            # remediation.action carried on each finding's .fix
            # field as a "Fix:" callout immediately after the
            # description — the iteration plan's 6-step pattern
            # presents Encode/Solve/Explain/Fix interleaved per
            # control, not as a separate trailer.
            fmt_findings_with_descriptions "$FMT_RED" "$findings_json"
        fi

        if [[ "$chain_count" -gt 0 ]]; then
            fmt_chains "$chain_count"
            fmt_findings_with_descriptions "$FMT_YELLOW" "$chains_json"
        fi
        echo ""
    done

    # Pipe stdin into the interpretation block. In --raw mode
    # the stdin (interpretation prose) is consumed silently so
    # the heredoc the caller passes doesn't leak into the
    # script's output stream as raw text.
    if [[ ! -t 0 ]]; then
        if [[ "$raw_mode" == "1" ]]; then
            cat > /dev/null
        else
            fmt_interpretation
        fi
    fi
}
