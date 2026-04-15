#!/usr/bin/env bash
# scripts/coverage-summary.sh
# Show a summary of all attack categories covered by the current catalog.
#
# Usage: coverage-summary.sh [CONTROLS_DIR] [CHAINS_DIR]

set -euo pipefail

CONTROLS_DIR="${1:-./controls}"
CHAINS_DIR="${2:-./chains}"

BOLD='\033[1m'
CYAN='\033[0;36m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  STAVE CATALOG COVERAGE SUMMARY${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Total control count
TOTAL=$(find "$CONTROLS_DIR" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_CHAINS=$(find "$CHAINS_DIR" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
echo -e "  Total controls: ${BOLD}${TOTAL}${RESET}"
echo -e "  Total chains:   ${BOLD}${TOTAL_CHAINS}${RESET}"
echo ""

# ── By domain (directory) ────────────────────────────────────────────────────
echo -e "${BOLD}BY DOMAIN:${RESET}"
find "$CONTROLS_DIR" -name "*.yaml" 2>/dev/null \
    | sed "s|${CONTROLS_DIR}/||" \
    | cut -d'/' -f1 \
    | sort \
    | uniq -c \
    | sort -rn \
    | while read -r count domain; do
        printf "  %-30s %s controls\n" "${domain}" "${count}"
    done
echo ""

# ── By attack stage ──────────────────────────────────────────────────────────
echo -e "${BOLD}BY ATT&CK STAGE:${RESET}"
grep -rh "attack_stage:" "$CONTROLS_DIR" 2>/dev/null \
    | sed 's/.*attack_stage: *//' \
    | sort \
    | uniq -c \
    | sort -rn \
    | while read -r count stage; do
        printf "  %-35s %s controls\n" "${stage}" "${count}"
    done
echo ""

# ── By severity ──────────────────────────────────────────────────────────────
echo -e "${BOLD}BY SEVERITY:${RESET}"
grep -rh "^severity:" "$CONTROLS_DIR" 2>/dev/null \
    | sed 's/severity: *//' \
    | sort \
    | uniq -c \
    | sort -rn \
    | while read -r count sev; do
        printf "  %-15s %s controls\n" "${sev}" "${count}"
    done
echo ""

# ── Takeover / supply chain controls ────────────────────────────────────────
echo -e "${BOLD}TAKEOVER AND SUPPLY CHAIN CONTROLS:${RESET}"
TAKEOVER_COUNT=0
while IFS= read -r f; do
    id=$(grep "^id:" "$f" | head -1 | sed 's/id: *//')
    echo "  ${id}"
    TAKEOVER_COUNT=$((TAKEOVER_COUNT + 1))
done < <(grep -rl "takeover\|dangling\|unclaimed\|supply.chain\|ghost" "$CONTROLS_DIR" 2>/dev/null)
if [[ $TAKEOVER_COUNT -eq 0 ]]; then
    echo "  (none)"
fi
echo ""

# ── Active compound chains ───────────────────────────────────────────────────
echo -e "${BOLD}COMPOUND CHAINS:${RESET}"
find "$CHAINS_DIR" -name "*.yaml" 2>/dev/null \
    | sort \
    | while read -r f; do
        id=$(grep "^id:" "$f" | head -1 | sed 's/id: *//')
        echo "  ${id}"
    done
echo ""

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  To check coverage for a specific attack:"
echo -e "  ${CYAN}make check-coverage QUERY=\"subdomain takeover s3\"${RESET}"
echo ""
