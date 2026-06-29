#!/usr/bin/env bash
# Split JSONL facts into per-predicate .facts files (TSV) for Soufflé.
# lambda_invoke_grant is 5-arity; lambda_invoke_deny is 4-arity;
# all others are binary (2 columns).

set -euo pipefail

JSONL=$1
OUT=$2
mkdir -p "$OUT"

for pred in $(jq -r '.predicate' "$JSONL" | sort -u); do
    case "$pred" in
        lambda_invoke_grant)
            jq -r --arg P "$pred" \
                'select(.predicate == $P) | [.subject, .field_1, .field_2, .field_3, .field_4] | @tsv' \
                "$JSONL" > "$OUT/${pred}.facts"
            ;;
        lambda_invoke_deny)
            jq -r --arg P "$pred" \
                'select(.predicate == $P) | [.subject, .field_1, .field_2, .field_3] | @tsv' \
                "$JSONL" > "$OUT/${pred}.facts"
            ;;
        *)
            jq -r --arg P "$pred" \
                'select(.predicate == $P) | [.subject, .object] | @tsv' \
                "$JSONL" > "$OUT/${pred}.facts"
            ;;
    esac
done

# Pre-create empty .facts for every declared input relation.
for pred in \
    has_type lambda_role account_id \
    esm_maps esm_state esm_type esm_has_filter dynamodb_stream_table \
    lambda_invoke_grant lambda_invoke_deny \
    s3_notifies_lambda sns_subscribes_lambda \
    eventbridge_targets_lambda eventbridge_rule_pattern_breadth \
    apigw_integrates_lambda apigw_auth_type \
    alb_targets_lambda cognito_triggers_lambda stepfunctions_invokes_lambda \
    source_trust_level \
    lambda_blast_radius lambda_reach_target lambda_sensitive_reach \
    triggers_lambda account_id_from_principal; do
    touch "$OUT/${pred}.facts"
done
