#!/usr/bin/env bash
# scripts/check-coverage.sh
# Search the Stave control catalog for coverage of a given attack pattern.
#
# Usage: check-coverage.sh "QUERY" CONTROLS_DIR CHAINS_DIR
# Example: check-coverage.sh "subdomain takeover s3 cloudfront" ./controls ./chains

set -euo pipefail

QUERY="${1:-}"
CONTROLS_DIR="${2:-./controls}"
CHAINS_DIR="${3:-./chains}"

if [[ -z "$QUERY" ]]; then
    echo "Usage: check-coverage.sh \"QUERY\" [CONTROLS_DIR] [CHAINS_DIR]"
    exit 1
fi

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STAVE CATALOG COVERAGE CHECK${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  Query:    ${CYAN}${QUERY}${RESET}"
echo -e "  Controls: ${CONTROLS_DIR}"
echo -e "  Chains:   ${CHAINS_DIR}"
echo ""

# ── Extract individual keywords ──────────────────────────────────────────────
IFS=' ' read -ra KEYWORDS <<< "$QUERY"

# ── Build grep pattern from keywords ────────────────────────────────────────
PATTERN=$(printf "%s\n" "${KEYWORDS[@]}" | paste -sd '|')

# ── Search 1: Direct keyword match in control YAML files ────────────────────
echo -e "${BOLD}DIRECT MATCHES — controls referencing these terms:${RESET}"
echo -e "  (searching: id, name, rationale, predicate, attack_stage)"
echo ""

MATCHED_CONTROLS=()
while IFS= read -r -d '' yaml_file; do
    if grep -qiE "$PATTERN" "$yaml_file" 2>/dev/null; then
        CONTROL_ID=$(grep "^id:" "$yaml_file" | head -1 | sed 's/id: *//')
        CONTROL_NAME=$(grep "^name:" "$yaml_file" | head -1 | sed 's/name: *//')
        SEVERITY=$(grep "^severity:" "$yaml_file" | head -1 | sed 's/severity: *//')
        ATTACK_STAGE=$(grep "attack_stage:" "$yaml_file" | head -1 | sed 's/.*attack_stage: *//')

        # Show which keyword triggered the match
        MATCHED_BY=""
        for kw in "${KEYWORDS[@]}"; do
            if grep -qiE "$kw" "$yaml_file" 2>/dev/null; then
                MATCHED_BY="${MATCHED_BY} ${kw}"
            fi
        done

        echo -e "  ${GREEN}✓${RESET} ${BOLD}${CONTROL_ID}${RESET}"
        echo -e "    Name:         ${CONTROL_NAME}"
        echo -e "    Severity:     ${SEVERITY}"
        echo -e "    Attack stage: ${ATTACK_STAGE}"
        echo -e "    Matched by:  ${CYAN}${MATCHED_BY}${RESET}"
        echo -e "    File:         ${yaml_file}"
        echo ""
        MATCHED_CONTROLS+=("$CONTROL_ID")
    fi
done < <(find "$CONTROLS_DIR" -name "*.yaml" -print0 2>/dev/null)

if [[ ${#MATCHED_CONTROLS[@]} -eq 0 ]]; then
    echo -e "  ${YELLOW}No direct matches found in controls.${RESET}"
    echo ""
fi

# ── Search 2: Chain definitions ──────────────────────────────────────────────
echo -e "${BOLD}COMPOUND CHAIN MATCHES — chains referencing these terms:${RESET}"
echo ""

MATCHED_CHAINS=()
while IFS= read -r -d '' chain_file; do
    if grep -qiE "$PATTERN" "$chain_file" 2>/dev/null; then
        CHAIN_ID=$(grep "^id:" "$chain_file" | head -1 | sed 's/id: *//')

        echo -e "  ${GREEN}✓${RESET} ${BOLD}${CHAIN_ID}${RESET}"
        echo -e "    File: ${chain_file}"
        echo ""
        MATCHED_CHAINS+=("$CHAIN_ID")
    fi
done < <(find "$CHAINS_DIR" -name "*.yaml" -print0 2>/dev/null)

if [[ ${#MATCHED_CHAINS[@]} -eq 0 ]]; then
    echo -e "  ${YELLOW}No compound chains match these terms.${RESET}"
    echo ""
fi

# ── Search 3: Attack stage coverage ─────────────────────────────────────────
echo -e "${BOLD}ATTACK STAGE COVERAGE — controls by relevant ATT&CK stage:${RESET}"
echo ""

declare -A STAGE_MAP
STAGE_MAP["takeover"]="initial_access"
STAGE_MAP["subdomain"]="initial_access"
STAGE_MAP["public"]="initial_access exfiltration"
STAGE_MAP["bucket"]="initial_access exfiltration"
STAGE_MAP["xss"]="initial_access"
STAGE_MAP["supply.chain"]="persistence"
STAGE_MAP["privilege"]="privilege_escalation"
STAGE_MAP["credential"]="credential_access"
STAGE_MAP["exfil"]="exfiltration"
STAGE_MAP["lateral"]="lateral_movement"
STAGE_MAP["persist"]="persistence"
STAGE_MAP["evasion"]="detection_evasion"

RELEVANT_STAGES=()
for kw in "${KEYWORDS[@]}"; do
    for stage_kw in "${!STAGE_MAP[@]}"; do
        if echo "$kw" | grep -qiE "$stage_kw"; then
            IFS=' ' read -ra stages <<< "${STAGE_MAP[$stage_kw]}"
            RELEVANT_STAGES+=("${stages[@]}")
        fi
    done
done

# Deduplicate stages
if [[ ${#RELEVANT_STAGES[@]} -gt 0 ]]; then
    UNIQUE_STAGES=($(echo "${RELEVANT_STAGES[@]}" | tr ' ' '\n' | sort -u))
    for stage in "${UNIQUE_STAGES[@]}"; do
        count=$(grep -rl "attack_stage: *${stage}" "$CONTROLS_DIR" 2>/dev/null | wc -l | tr -d ' ')
        echo -e "  ${BLUE}${stage}${RESET}: ${count} controls"
    done
    echo ""
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}SUMMARY${RESET}"
echo ""

TOTAL_CONTROLS=${#MATCHED_CONTROLS[@]}
TOTAL_CHAINS=${#MATCHED_CHAINS[@]}

if [[ $TOTAL_CONTROLS -gt 0 || $TOTAL_CHAINS -gt 0 ]]; then
    echo -e "  ${GREEN}COVERED${RESET} — ${TOTAL_CONTROLS} control(s) and ${TOTAL_CHAINS} chain(s) match"
    echo ""
    echo -e "  Matching controls: ${BOLD}${MATCHED_CONTROLS[*]:-none}${RESET}"
    echo -e "  Matching chains:   ${BOLD}${MATCHED_CHAINS[*]:-none}${RESET}"
    echo ""
    echo -e "  ${GREEN}This attack pattern appears to be covered by the catalog.${RESET}"
    echo -e "  Verify by running:"
    echo -e "    ${CYAN}stave apply --controls ${CONTROLS_DIR} --snapshot <fixture>${RESET}"
else
    echo -e "  ${RED}GAP DETECTED${RESET} — no controls or chains match this query"
    echo ""
    echo -e "  ${YELLOW}This attack pattern may not be covered. Consider:${RESET}"
    echo -e "  1. Expanding the query with different terms"
    echo -e "  2. Checking the attack stage directly:"
    echo -e "     ${CYAN}grep -rl \"attack_stage\" ${CONTROLS_DIR} | xargs grep -l \"initial_access\"${RESET}"
    echo -e "  3. Writing a new control if the gap is confirmed"
    echo -e "     ${CYAN}stave forge new${RESET}"
fi

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
