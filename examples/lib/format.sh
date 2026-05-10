#!/usr/bin/env bash
# Shared output formatting for examples/. Source this from
# example run.sh scripts:
#
#     source "$stave_root/examples/lib/format.sh"
#     fmt_section "Cognito Iteration 2"
#     fmt_before  "writeup-config"
#     fmt_findings 7 "controls fired"
#     fmt_after   "remediated-config"
#     fmt_findings 0 "controls fired"
#     fmt_interpretation <<'EOF'
#     The before snapshot exposes anonymous AWS credentials ...
#     EOF
#
# Colors are TTY-aware: when stdout is not a terminal (CI logs,
# pipes, redirects, NO_COLOR=1) all formatting drops to plain
# ASCII so goldens compare cleanly. Set FORCE_COLOR=1 to override.

# shellcheck disable=SC2034  # variables are used by sourcing scripts

if [[ "${FORCE_COLOR:-0}" == "1" ]]; then
    _COLOR=1
elif [[ -n "${NO_COLOR:-}" ]]; then
    _COLOR=0
elif [[ -t 1 ]]; then
    _COLOR=1
else
    _COLOR=0
fi

if [[ $_COLOR -eq 1 ]]; then
    FMT_RESET=$'\e[0m'
    FMT_BOLD=$'\e[1m'
    FMT_DIM=$'\e[2m'
    FMT_RED=$'\e[31m'
    FMT_GREEN=$'\e[32m'
    FMT_YELLOW=$'\e[33m'
    FMT_BLUE=$'\e[34m'
    FMT_MAGENTA=$'\e[35m'
    FMT_CYAN=$'\e[36m'
else
    FMT_RESET=""
    FMT_BOLD=""
    FMT_DIM=""
    FMT_RED=""
    FMT_GREEN=""
    FMT_YELLOW=""
    FMT_BLUE=""
    FMT_MAGENTA=""
    FMT_CYAN=""
fi

# fmt_section "Title"
# Heavy section header bordered with ═══.
fmt_section() {
    local title=$1
    local line
    line=$(printf '═%.0s' $(seq 1 $((${#title} + 4))))
    printf '\n%s%s%s%s\n' "$FMT_BOLD" "$FMT_CYAN" "$line" "$FMT_RESET"
    printf '%s%s%s  %s%s%s\n' "$FMT_BOLD" "$FMT_CYAN" "" "$title" "" "$FMT_RESET"
    printf '%s%s%s%s\n\n' "$FMT_BOLD" "$FMT_CYAN" "$line" "$FMT_RESET"
}

# fmt_block_header "Before — writeup-config"
# Light section header for Before / After / Interpretation blocks.
fmt_block_header() {
    local label=$1
    printf '%s▼ %s%s\n' "$FMT_BOLD" "$label" "$FMT_RESET"
}

# fmt_before "<fixture name>"
fmt_before() {
    fmt_block_header "Before — $1"
}

# fmt_after "<fixture name>"
fmt_after() {
    fmt_block_header "After — $1"
}

# fmt_interpretation
# Reads multi-line prose from stdin, emits indented under an
# "Interpretation" header. Use here-doc:
#   fmt_interpretation <<'EOF'
#   Plain-language explanation of what changed and why.
#   EOF
fmt_interpretation() {
    fmt_block_header "Interpretation"
    while IFS= read -r line; do
        printf '  %s\n' "$line"
    done
    printf '\n'
}

# fmt_findings <count> [<label>]
# Color the count red when > 0, green when == 0. Optional label
# (default: "findings"). Used to summarise stave apply output.
fmt_findings() {
    local count=$1
    local label=${2:-findings}
    local color marker
    if [[ "$count" == "0" ]]; then
        color=$FMT_GREEN
        marker="✓"
    else
        color=$FMT_RED
        marker="✗"
    fi
    printf '  %s%s %s %s%s\n' "$color" "$marker" "$count" "$label" "$FMT_RESET"
}

# fmt_chains <count>
# Same colouring as fmt_findings, label is "compound chains".
fmt_chains() {
    fmt_findings "$1" "compound chains"
}

# fmt_kv "<label>" "<value>"
# Two-column key-value line, dim label.
fmt_kv() {
    printf '  %s%-22s%s %s\n' "$FMT_DIM" "$1" "$FMT_RESET" "$2"
}

# fmt_list "<color>" <items...>
# Print one item per line indented under a bullet.
fmt_list() {
    local color=$1
    shift
    if [[ $# -eq 0 ]]; then
        printf '  %s(none)%s\n' "$FMT_DIM" "$FMT_RESET"
        return
    fi
    local item
    for item in "$@"; do
        printf '    %s•%s %s\n' "$color" "$FMT_RESET" "$item"
    done
}

# fmt_violations <items...>
# Red bullets — used for fired controls / unsafe states.
fmt_violations() {
    fmt_list "$FMT_RED" "$@"
}

# fmt_chain_list <chain-names...>
# Yellow bullets — compound chains that fired (severity-aware
# reporting could recolour by chain.severity in a future
# refinement).
fmt_chain_list() {
    fmt_list "$FMT_YELLOW" "$@"
}

# fmt_safe_list <items...>
# Green bullets — used for confirmations / improvements.
fmt_safe_list() {
    fmt_list "$FMT_GREEN" "$@"
}

# fmt_finding_detail <color> <id> <name> <description>
# Render a single finding row with three lines:
#   • <id>            (bullet + bold colored id)
#     <name>          (one-line title from the YAML)
#     <description>   (multi-line description, soft-wrapped to ~80 cols)
# All four args required; pass "" for missing pieces and the row
# omits that line. The description is wrapped via `fold -s -w`
# so long YAML descriptions don't blow out the terminal.
fmt_finding_detail() {
    local color=$1
    local id=$2
    local name=$3
    local description=$4
    local width=${FMT_WIDTH:-${COLUMNS:-100}}
    local body_width=$((width - 6))
    if [[ $body_width -lt 40 ]]; then
        body_width=72
    fi

    printf '    %s•%s %s%s%s%s\n' "$color" "$FMT_RESET" "$FMT_BOLD" "$color" "$id" "$FMT_RESET"
    if [[ -n "$name" ]]; then
        printf '      %s%s%s\n' "$FMT_BOLD" "$name" "$FMT_RESET"
    fi
    if [[ -n "$description" ]]; then
        # Collapse internal newlines to spaces so fold sees one
        # paragraph per finding; preserve double-newlines as
        # paragraph breaks.
        printf '%s\n' "$description" \
            | awk 'BEGIN{RS=""; ORS="\n\n"} {gsub(/\n/, " "); print}' \
            | fold -s -w "$body_width" \
            | sed -e 's/^/      /' -e '/^[[:space:]]*$/d'
    fi
}

# fmt_findings_with_descriptions <color> <findings-json>
# Read a JSON array of {id, name, description} from $2 and render
# each as a fmt_finding_detail row. Empty array prints "(none)".
fmt_findings_with_descriptions() {
    local color=$1
    local json=$2
    local count
    count=$(jq 'length' <<<"$json")
    if [[ "$count" -eq 0 ]]; then
        printf '    %s(none)%s\n' "$FMT_DIM" "$FMT_RESET"
        return
    fi
    local i
    for ((i = 0; i < count; i++)); do
        local id name description fix
        id=$(jq -r ".[$i].id // \"\"" <<<"$json")
        name=$(jq -r ".[$i].name // \"\"" <<<"$json")
        description=$(jq -r ".[$i].description // \"\"" <<<"$json")
        fix=$(jq -r ".[$i].fix // \"\"" <<<"$json")
        fmt_finding_detail "$color" "$id" "$name" "$description"
        if [[ -n "$fix" && "$fix" != "null" ]]; then
            fmt_fix "$fix"
        fi
    done
}

# fmt_fix "<remediation prose>"
# One-line "Fix:" callout in cyan. Used after a violation
# block to surface the YAML's remediation.action — the
# cloud-domain answer to "what should the operator do?".
# A leading [ID] tag is preserved so multi-finding outputs
# can attribute each fix to the control that needs it.
fmt_fix() {
    local action=$1
    if [[ -z "$action" ]]; then
        return
    fi
    printf '      %sFix:%s %s\n' "$FMT_BOLD$FMT_CYAN" "$FMT_RESET" "$action"
}

# fmt_verdict <"sat"|"unsat"|"unknown"> [extra...]
# Render an SMT verdict with the right colour and a plain-
# language gloss. Extra args are appended as the gloss line.
fmt_verdict() {
    local verdict=$1
    shift
    local color label gloss
    case "$verdict" in
        sat)
            color=$FMT_RED
            label="SAT (reachable)"
            gloss="${*:-The forbidden state is reachable in the current configuration.}"
            ;;
        unsat)
            color=$FMT_GREEN
            label="UNSAT (unreachable)"
            gloss="${*:-The forbidden state cannot be reached given the constraints.}"
            ;;
        *)
            color=$FMT_YELLOW
            label="$verdict"
            gloss="${*:-The solver could not decide.}"
            ;;
    esac
    printf '  %s%s%s — %s\n' "$color" "$label" "$FMT_RESET" "$gloss"
}
