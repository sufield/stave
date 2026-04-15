#!/usr/bin/env bash
# scripts/check-coverage-file.sh
# Extract keywords from a saved HackerOne report file and run coverage check.
#
# Usage: check-coverage-file.sh REPORT_FILE [CONTROLS_DIR] [CHAINS_DIR]
# Example: check-coverage-file.sh ./reports/h1-2256740.txt ./controls ./chains

set -euo pipefail

REPORT_FILE="${1:-}"
CONTROLS_DIR="${2:-./controls}"
CHAINS_DIR="${3:-./chains}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "$REPORT_FILE" || ! -f "$REPORT_FILE" ]]; then
    echo "Usage: check-coverage-file.sh REPORT_FILE [CONTROLS_DIR] [CHAINS_DIR]"
    echo "Report file not found: ${REPORT_FILE}"
    exit 1
fi

echo ""
echo "Extracting keywords from: ${REPORT_FILE}"
echo ""

# ── Extract AWS resource types mentioned in the report ───────────────────────
AWS_RESOURCES=$(grep -oiE '\b(s3|cloudfront|lambda|iam|rds|ec2|ecs|eks|kms|sqs|sns|cognito|api.?gateway|route53|acm|ecr|efs|waf)\b' \
    "$REPORT_FILE" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u | tr '\n' ' ')

# ── Extract attack pattern keywords ─────────────────────────────────────────
ATTACK_TERMS=$(grep -oiE '\b(takeover|hijack|injection|traversal|escalation|exfiltration|bypass|leak|exposure|misconfiguration|public|anonymous|unauthenticated|subdomain|dangling|unclaimed|supply.chain|xss|ssrf|sqli|rce|idor|open.redirect|xxe|deserializ)\b' \
    "$REPORT_FILE" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u | tr '\n' ' ')

# ── Extract CVE or CWE references ───────────────────────────────────────────
CVE_REFS=$(grep -oiE '\bCVE-[0-9]{4}-[0-9]+\b' "$REPORT_FILE" 2>/dev/null | sort -u | tr '\n' ' ')
CWE_REFS=$(grep -oiE '\bCWE-[0-9]+\b' "$REPORT_FILE" 2>/dev/null | sort -u | tr '\n' ' ')

# ── Extract AWS error codes that indicate specific misconfigs ────────────────
ERROR_CODES=$(grep -oiE '\b(NoSuchBucket|AccessDenied|NoSuchKey|AllAccessDisabled|InvalidBucketName|PermanentRedirect|TemporaryRedirect)\b' \
    "$REPORT_FILE" 2>/dev/null | sort -u | tr '\n' ' ')

# ── Build combined query ─────────────────────────────────────────────────────
COMBINED="${AWS_RESOURCES} ${ATTACK_TERMS} ${ERROR_CODES} ${CVE_REFS}"
COMBINED=$(echo "$COMBINED" | tr -s ' ' | sed 's/^ //;s/ $//')

echo "Extracted terms:"
[[ -n "$AWS_RESOURCES" ]]  && echo "  AWS resources:  ${AWS_RESOURCES}"
[[ -n "$ATTACK_TERMS" ]]   && echo "  Attack terms:   ${ATTACK_TERMS}"
[[ -n "$ERROR_CODES" ]]    && echo "  AWS errors:     ${ERROR_CODES}"
[[ -n "$CVE_REFS" ]]       && echo "  CVE refs:       ${CVE_REFS}"
[[ -n "$CWE_REFS" ]]       && echo "  CWE refs:       ${CWE_REFS}"
echo ""

if [[ -z "$COMBINED" ]]; then
    echo "No recognizable security terms found in report."
    echo "Try: make check-coverage QUERY=\"your terms here\""
    exit 1
fi

# ── Run the core coverage check with extracted terms ────────────────────────
exec "${SCRIPT_DIR}/check-coverage.sh" "$COMBINED" "$CONTROLS_DIR" "$CHAINS_DIR"
