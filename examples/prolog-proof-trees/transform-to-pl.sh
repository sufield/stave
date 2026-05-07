#!/usr/bin/env bash
# Convert Stave JSONL triples to a Prolog facts file.
#
# Each triple becomes `predicate("subject", "object").` with
# the subject and object kept as atoms (double-quoted strings)
# so colons / slashes / asterisks in ARNs survive verbatim.
# Predicate names already match Prolog atom syntax (lowercase,
# underscore-separated) — Stave does not emit hyphenated
# predicates, so no name sanitization is needed.

set -euo pipefail

JSONL_FILE=$1
OUTPUT_FILE=$2

{
    echo "% Stave facts — auto-generated from export-sir --format jsonl"
    echo ":- discontiguous has_severity/2."
    echo ":- discontiguous has_type/2."
    echo ":- discontiguous has_intent_rationale/2."
    echo ":- discontiguous has_forbidden_state/2."
    echo ":- discontiguous has_vendor/2."
    echo ":- discontiguous has_action/2."
    echo ":- discontiguous has_resource/2."
    echo ":- discontiguous has_tag/2."
    echo ":- discontiguous has_exposure_window/2."
    echo ":- discontiguous first_seen_at/2."
    echo ":- discontiguous last_seen_at/2."
    echo ":- discontiguous can_assume/2."
    echo ":- discontiguous trusts_service/2."
    echo ":- discontiguous contributed_by/2."
    echo ":- discontiguous maps_unauth_to/2."
    echo ":- discontiguous maps_auth_to/2."
    echo ":- discontiguous allows_unauthenticated/2."
    echo ":- discontiguous self_registration_unrestricted/2."
    echo ":- discontiguous is_provisioned/2."
    echo ":- discontiguous is_decommissioned/2."
    echo ""
    jq -r '"\(.predicate)(\"\(.subject | gsub("\\\\"; "\\\\\\\\") | gsub("\""; "\\\""))\", \"\(.object | gsub("\\\\"; "\\\\\\\\") | gsub("\""; "\\\""))\")."' \
        "$JSONL_FILE"
} > "$OUTPUT_FILE"
