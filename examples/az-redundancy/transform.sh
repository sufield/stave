#!/usr/bin/env bash
# Split JSONL facts into per-predicate .facts files (TSV) for Soufflé.
# dep_type is ternary (3 columns); all others are binary (2 columns).

set -euo pipefail

JSONL=$1
OUT=$2
mkdir -p "$OUT"

# Split each predicate into its own TSV.
for pred in $(jq -r '.predicate' "$JSONL" | sort -u); do
    if [[ "$pred" == "dep_type" ]]; then
        # Ternary: subject, object, extra (third field via .extra or
        # encoded in the object as "target\ttype" — the projector
        # emits a proper .extra field).
        jq -r --arg P "$pred" \
            'select(.predicate == $P) | [.subject, .object, .extra // ""] | @tsv' \
            "$JSONL" > "$OUT/${pred}.facts"
    else
        jq -r --arg P "$pred" \
            'select(.predicate == $P) | [.subject, .object] | @tsv' \
            "$JSONL" > "$OUT/${pred}.facts"
    fi
done

# Pre-create empty .facts for every declared relation.
for pred in \
    has_type resource_az az_scoped depends_on dep_type; do
    touch "$OUT/${pred}.facts"
done
