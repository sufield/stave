#!/usr/bin/env bash
# Shadow Admin Detection Demo — IAM role privilege creep that
# compounds into two CRITICAL chains. A role tagged role-type=readonly
# can retrieve any secret, invoke any Lambda, and enumerate IAM —
# no admin policy attached.
#
# stave apply exits 3 when violations are found (expected here).
# Use `set -uo pipefail` (no -e) and explicit exit-code handling.
set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
STAVE=${STAVE_BIN:-$stave_root/stave}
WRITEUP="$script_dir/fixtures/writeup-config/observations"
REMEDIATED="$script_dir/fixtures/remediated-config/observations"
NOW="2026-05-10T00:00:00Z"

# Chains auto-discover from ./chains relative to cwd; demos invoke
# from the project root so the catalog and chain definitions both
# resolve.
cd "$stave_root"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; NC=""
fi

divider() { printf '\n%s%s%s\n\n' "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "$NC"; }

apply_json() {
    local out rc
    out=$("$STAVE" apply \
        --observations "$1" \
        --controls "$stave_root/controls/iam/entropy" \
        --now "$NOW" --max-unsafe 168h --allow-unknown-input \
        --format json 2>/dev/null) || rc=$?
    rc=${rc:-0}
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
        printf 'stave apply exited %s (unexpected)\n' "$rc" >&2
        return "$rc"
    fi
    printf '%s' "$out"
}

printf '%sShadow Admin Detection Demo%s\n' "$BOLD" "$NC"
divider

printf '%s▼ Before — Role: S3-ReadOnly (tagged readonly, 2 years old)%s\n\n' "$BOLD" "$NC"

BEFORE=$(apply_json "$WRITEUP")
TOTAL=$(echo "$BEFORE" | jq '.findings | length')
printf 'Individual findings: %s%s%s\n' "$RED" "$TOTAL" "$NC"
echo "$BEFORE" | jq -r '.findings[] | "  [\(.control_severity | ascii_upcase)] \(.control_id)"'
echo ""

CHAINS=$(echo "$BEFORE" | jq '.chain_findings | length')
printf 'Compound chains:     %s%s%s\n' "$RED" "$CHAINS" "$NC"
echo "$BEFORE" | jq -r '.chain_findings[] | "  [\(.severity | ascii_upcase)] \(.chain)\n         members fired: \(.controls_failing | join(", "))"'
echo ""

printf '%sThis role is named S3-ReadOnly and tagged role-type=readonly.\n' "$YELLOW"
printf 'It can retrieve any secret in the account, invoke any Lambda,\n'
printf 'and enumerate the full IAM role inventory.\n'
printf 'No admin policy attached. No scanner flags it.%s\n' "$NC"

divider

printf '%s▼ After — Remediated (unused services removed, categories split, tag aligned)%s\n\n' "$BOLD" "$NC"

AFTER=$(apply_json "$REMEDIATED")
REM_TOTAL=$(echo "$AFTER" | jq '.findings | length')
REM_CHAINS=$(echo "$AFTER" | jq '.chain_findings | length')

printf 'Individual findings: %s%s%s\n' "$GREEN" "$REM_TOTAL" "$NC"
printf 'Compound chains:     %s%s%s\n' "$GREEN" "$REM_CHAINS" "$NC"

if [ "$REM_TOTAL" -eq 0 ] && [ "$REM_CHAINS" -eq 0 ]; then
    printf '\n%s%sClean. No shadow admin. No privilege creep.%s\n' "$GREEN" "$BOLD" "$NC"
fi

divider

printf '%sDemo complete.%s\n' "$BOLD" "$NC"
printf '  The role was not an admin. It became one by accumulation.\n'
printf '  No single permission was alarming. The combination was catastrophic.\n'
