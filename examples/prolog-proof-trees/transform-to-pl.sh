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
    # Per-asset boolean projectors used by the expansion rules in
    # reasoning.pl. Discontiguous declarations keep the SWI-Prolog
    # warning channel clean when a fixture's JSONL only mentions a
    # subset of these predicates.
    echo ":- discontiguous has_public_read/2."
    echo ":- discontiguous has_public_list/2."
    echo ":- discontiguous has_public_access_blocked/2."
    echo ":- discontiguous has_mfa_enforced/2."
    echo ":- discontiguous has_advanced_security_enabled/2."
    echo ":- discontiguous has_logging_enabled/2."
    echo ":- discontiguous has_data_event_logging/2."
    echo ":- discontiguous has_bucket_exists/2."
    echo ":- discontiguous has_bucket_owned/2."
    echo ":- discontiguous has_exposed_repo_artifacts/2."
    echo ":- discontiguous has_webhook_config_access/2."
    echo ":- discontiguous has_uses_access_key_id/2."
    echo ":- discontiguous has_upload_key_mode/2."
    echo ":- discontiguous resource_policy_principal/2."
    echo ":- discontiguous resource_policy_action/2."
    echo ":- discontiguous has_condition/2."
    echo ":- discontiguous has_condition_value/2."
    echo ":- discontiguous has_deny_action/2."
    echo ":- discontiguous has_deny_resource/2."
    echo ":- discontiguous has_purpose_flag/2."
    echo ""
    jq -r '"\(.predicate)(\"\(.subject | gsub("\\\\"; "\\\\\\\\") | gsub("\""; "\\\""))\", \"\(.object | gsub("\\\\"; "\\\\\\\\") | gsub("\""; "\\\""))\")."' \
        "$JSONL_FILE"
} > "$OUTPUT_FILE"
