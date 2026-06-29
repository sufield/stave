#!/usr/bin/env bash
# Split JSONL facts into per-predicate .facts files (TSV) for Soufflé.
# function_criticality and throttle_behavior are 3-arity;
# lambda_invocation_path is 4-arity; all others are binary.

set -euo pipefail

JSONL=$1
OUT=$2
mkdir -p "$OUT"

for pred in $(jq -r '.predicate' "$JSONL" | sort -u); do
    case "$pred" in
        function_criticality|throttle_behavior)
            jq -r --arg P "$pred" \
                'select(.predicate == $P) | [.subject, .field_1, .field_2] | @tsv' \
                "$JSONL" > "$OUT/${pred}.facts"
            ;;
        lambda_invocation_path)
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
    has_type account_concurrency_limit \
    function_reserved function_provisioned function_region function_timeout \
    function_criticality throttle_behavior \
    lambda_invocation_path; do
    touch "$OUT/${pred}.facts"
done
