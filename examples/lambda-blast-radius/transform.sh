#!/usr/bin/env bash
# Split JSONL facts into per-predicate .facts files (TSV) for Soufflé.
# All predicates are binary (subject, object).

set -euo pipefail

JSONL=$1
OUT=$2
mkdir -p "$OUT"

for pred in $(jq -r '.predicate' "$JSONL" | sort -u); do
    jq -r --arg P "$pred" \
        'select(.predicate == $P) | [.subject, .object] | @tsv' \
        "$JSONL" > "$OUT/${pred}.facts"
done

# Pre-create empty .facts for every declared input relation.
for pred in \
    has_type has_action has_resource has_deny_action has_deny_resource \
    can_assume has_tag has_privilege_level \
    lambda_role resource_exists sensitive_resource \
    policy_matches_resource deny_matches_resource \
    read_action write_action admin_action \
    triggers_lambda account_id; do
    touch "$OUT/${pred}.facts"
done
