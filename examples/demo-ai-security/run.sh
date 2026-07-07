#!/usr/bin/env bash
# AI Security Demo — five-act showcase of Stave's AI agent identity
# detection. Runs in the Codespaces devcontainer with zero setup;
# all analysis is local against fixture JSON.
#
# stave apply exits 3 when violations are found (expected here).
# Use `set -uo pipefail` (no -e) and explicit exit-code handling
# in apply_json so the runner doesn't abort on the writeup pass.
set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
STAVE=${STAVE_BIN:-$stave_root/stave}
# Workspace fallback: when the script lives outside a built
# repo (e.g. the Coder image installs the binary at
# /usr/local/bin/stave), fall back to the one on PATH.
[ -x "${STAVE}" ] || STAVE="$(command -v stave || echo "${STAVE}")"
WRITEUP="$script_dir/fixtures/writeup-config/observations"
REMEDIATED="$script_dir/fixtures/remediated-config/observations"
NOW="2026-05-10T00:00:00Z"

# Projector-readable colors. Respect NO_COLOR.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'
    BOLD=$'\033[1m'
    NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; NC=""
fi

divider() {
    printf '\n%s%s%s\n\n' "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "$NC"
}

apply_json() {
    local out rc
    out=$("$STAVE" apply --observations "$1" \
        --eval-time "$NOW" --max-unsafe 168h \
        --format json 2>/dev/null) || rc=$?
    rc=${rc:-0}
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
        echo "stave apply exited $rc (unexpected)" >&2
        return "$rc"
    fi
    printf '%s' "$out"
}

# ═══════════════════════════════════════════════════════════
# ACT 1 — Detection
# ═══════════════════════════════════════════════════════════

printf '%sACT 1: What does Stave find?%s\n' "$BOLD" "$NC"
divider

printf '%sRunning:%s stave apply on a Bedrock agent + Lambda + KB + S3 PHI bucket\n\n' \
    "$YELLOW" "$NC"

FINDINGS=$(apply_json "$WRITEUP")

# Filter to AI-relevant controls so the demo focuses on the AI surface.
AI_FILTER='[.findings[] | select(.control_id | startswith("CTL.BEDROCK") or startswith("CTL.LAMBDA"))]'

CRITICAL=$(jq "$AI_FILTER"' | map(select(.control_severity == "critical")) | length' <<<"$FINDINGS")
HIGH=$(jq "$AI_FILTER"' | map(select(.control_severity == "high")) | length' <<<"$FINDINGS")
MEDIUM=$(jq "$AI_FILTER"' | map(select(.control_severity == "medium")) | length' <<<"$FINDINGS")
LOW=$(jq "$AI_FILTER"' | map(select(.control_severity == "low")) | length' <<<"$FINDINGS")
AI_TOTAL=$(jq "$AI_FILTER"' | length' <<<"$FINDINGS")

printf 'AI findings: %s%s critical%s, %s%s high%s, %s medium, %s low — %s total\n\n' \
    "$RED" "$CRITICAL" "$NC" "$YELLOW" "$HIGH" "$NC" "$MEDIUM" "$LOW" "$AI_TOTAL"

jq -r "$AI_FILTER"'[] | "  [\(.control_severity | ascii_upcase)] \(.control_id)\n      \(.control_name)\n"' <<<"$FINDINGS"

divider

# ═══════════════════════════════════════════════════════════
# ACT 2 — Compound chains
# ═══════════════════════════════════════════════════════════

printf '%sACT 2: Those aren'\''t separate findings. They'\''re attack chains.%s\n' "$BOLD" "$NC"
divider

CHAIN_COUNT=$(jq '(.chain_findings // []) | length' <<<"$FINDINGS")
printf 'Compound chains: %s%s%s\n\n' "$RED" "$CHAIN_COUNT" "$NC"

jq -r '(.chain_findings // [])[] | "  [\(.severity | ascii_upcase)] \(.chain_id // .chain)\n      \(.description // .narrative // "")\n"' <<<"$FINDINGS"

divider

# ═══════════════════════════════════════════════════════════
# ACT 3 — Formal verification + encoding
# ═══════════════════════════════════════════════════════════

printf '%sACT 3: Engines independently confirm the encoding.%s\n' "$BOLD" "$NC"
divider

"$STAVE" export-sir --format jsonl --observations "$WRITEUP" --eval-time "$NOW" 2>/dev/null > /tmp/demo-ai-facts.jsonl
FACT_COUNT=$(wc -l < /tmp/demo-ai-facts.jsonl | tr -d ' ')
printf 'Facts exported: %s\n\n' "$FACT_COUNT"

# Encoding verification — every emitted fact traces to an observation property
printf 'Encoding verification:\n'
VERIFY=$(python3 "$stave_root/examples/explain/verify_encoding.py" --strict \
    /tmp/demo-ai-facts.jsonl "$WRITEUP" 2>&1 | tail -1)
printf '  %s%s%s\n\n' "$GREEN" "$VERIFY" "$NC"

# Z3 availability check
if command -v z3 >/dev/null 2>&1; then
    Z3_VERSION=$(z3 --version 2>&1 | head -1)
    printf 'SMT solver available:\n'
    printf '  Z3:    %s\n' "$Z3_VERSION"
    if command -v cvc5 >/dev/null 2>&1; then
        printf '  cvc5:  %s\n' "$(cvc5 --version 2>&1 | head -1)"
    fi
    printf '\n'
    printf '  Stave exports SMT-LIB v2 facts ready for these solvers.\n'
    printf '  Per-control forbidden_state queries live under\n'
    printf '  examples/z3-forbidden-state/ — for controls that define them,\n'
    printf '  Z3 + cvc5 + Yices independently verify the unsafe state is\n'
    printf '  reachable or impossible. The Iteration 2–6 AI controls do not\n'
    printf '  yet declare forbidden_state (they are CEL predicates on\n'
    printf '  pre-computed collector facts) — the SMT layer is the natural\n'
    printf '  Iteration 7 extension.\n'
else
    printf 'SMT solvers (Z3 + cvc5) ship in the Codespaces devcontainer\n'
    printf '— available for examples/z3-forbidden-state/ controls.\n'
fi

divider

# ═══════════════════════════════════════════════════════════
# ACT 4 — Remediation
# ═══════════════════════════════════════════════════════════

printf '%sACT 4: The fix — and proof it works.%s\n' "$BOLD" "$NC"
divider

printf 'Remediations applied to the four assets:\n'
printf '  1. Scoped agent execution role to specific Lambda ARNs\n'
printf '  2. Attached a Bedrock guardrail (sensitive-info filter on)\n'
printf '  3. Enabled per-agent invocation logging\n'
printf '  4. Changed KB data source from PHI bucket → product-docs bucket\n'
printf '  5. Scoped Lambda tool role to non-PHI bucket only\n\n'

printf '%sRunning:%s stave apply on the remediated configuration\n\n' "$YELLOW" "$NC"

REM_FINDINGS=$(apply_json "$REMEDIATED")
REM_AI=$(jq "$AI_FILTER"' | length' <<<"$REM_FINDINGS")
REM_CHAINS=$(jq '(.chain_findings // []) | length' <<<"$REM_FINDINGS")

printf 'AI findings: %s%s%s\n' "$GREEN" "$REM_AI" "$NC"
printf 'Chains:      %s%s%s\n\n' "$GREEN" "$REM_CHAINS" "$NC"

if [ "$REM_AI" -eq 0 ] && [ "$REM_CHAINS" -eq 0 ]; then
    printf '%s%sAll AI controls pass. The compound chains are silent.%s\n\n' "$GREEN" "$BOLD" "$NC"
    printf '  Cost of remediation:  $0 (role scoping)  +  $0.050/MAU (guardrail)\n'
    printf '  Time:                 ~30 minutes across the four config changes\n'
    printf '  Risk:                 0 — the attack path is gone, not just suppressed\n'
fi

divider

# ═══════════════════════════════════════════════════════════
# ACT 5 — What component scanners report (illustrative)
# ═══════════════════════════════════════════════════════════

printf '%sACT 5: What a component scanner reports on the same writeup.%s\n' "$BOLD" "$NC"
divider

printf '  (Illustrative — these are the checks a component-level\n'
printf '   scanner would run; not actual output from any vendor.)\n\n'

printf '    Bedrock encryption:        %s✅ PASS%s — invocation logs use KMS\n' "$GREEN" "$NC"
printf '    Bedrock VPC endpoint:      %s✅ PASS%s — VPC endpoint configured\n' "$GREEN" "$NC"
printf '    Bedrock model allowlist:   %s✅ PASS%s — foundation models scoped\n' "$GREEN" "$NC"
printf '    S3 encryption at rest:     %s✅ PASS%s — SSE-KMS enabled\n' "$GREEN" "$NC"
printf '    S3 public access block:    %s✅ PASS%s — public access blocked\n' "$GREEN" "$NC"
printf '    Lambda env encryption:     %s✅ PASS%s — at-rest encryption on\n' "$GREEN" "$NC"
printf '\n'
printf '  6 checks. 6 passes. Component scanner: %sCOMPLIANT%s.\n\n' "$GREEN" "$NC"
printf '  Stave on the same configuration: %s%s%s CRITICAL compound chains%s.\n' "$RED" "$BOLD" "$CHAIN_COUNT" "$NC"
printf '  Agent → Lambda → S3 PHI. No guardrail. No audit trail.\n\n'
printf '  The scanner checked components. Stave checked interactions.\n'

divider

# Cleanup
rm -f /tmp/demo-ai-facts.jsonl

printf '%sDemo complete.%s\n\n' "$BOLD" "$NC"
TOTAL=$(jq '.findings | length' <<<"$FINDINGS")
printf '  Findings:    %s on writeup  →  %s on remediated\n' "$TOTAL" "$(jq '.findings | length' <<<"$REM_FINDINGS")"
printf '  AI findings: %s on writeup  →  %s on remediated\n' "$AI_TOTAL" "$REM_AI"
printf '  Chains:      %s on writeup  →  %s on remediated\n' "$CHAIN_COUNT" "$REM_CHAINS"
printf '  Catalog:     %s controls across 74 AWS service domains\n' "$(jq 'length' <<<"$("$STAVE" controls list --format json 2>/dev/null)")"
printf '  Source:      github.com/sufield/stave\n'

exit 0
