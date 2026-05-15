#!/usr/bin/env bash
#
# JSONL → Soufflé .facts converter.
#
# Soufflé's `.input` directives read one TSV file per declared
# relation: `has_type.facts` for the `has_type` relation, etc.
# Splitting Stave's JSONL stream by predicate produces exactly
# that shape.
#
# Usage:
#   bash convert.sh <facts.jsonl> [output-dir]
#
# The output-dir defaults to ./facts. After running, you'll see
# one `.facts` file per distinct predicate plus pre-created empty
# files for every relation the bundled rules declare — a fixture
# that doesn't emit (say) `can_assume` just gets an empty
# `can_assume.facts` and the relation evaluates to empty, no
# Soufflé warnings.
set -euo pipefail

JSONL_FILE="${1:?Usage: convert.sh <facts.jsonl> [output-dir]}"
OUTPUT_DIR="${2:-./facts}"

if ! command -v jq >/dev/null 2>&1; then
  echo "Install jq first: brew install jq (macOS) or apt install jq (Ubuntu)." >&2
  exit 127
fi

mkdir -p "$OUTPUT_DIR"

# Split the JSONL stream into per-predicate TSV files.
for pred in $(jq -r '.predicate' "$JSONL_FILE" | sort -u); do
  jq -r --arg P "$pred" \
    'select(.predicate == $P) | [.subject, .object] | @tsv' \
    "$JSONL_FILE" > "$OUTPUT_DIR/${pred}.facts"
done

# Pre-create empty .facts for relations the bundled .dl programs
# declare but a given fixture might not emit. Soufflé treats
# missing input files as a warning; empty files evaluate as the
# empty relation, which is the correct semantic.
for pred in \
  has_type has_action has_resource has_tag \
  can_assume trusts_service contributed_by \
  maps_unauth_to maps_auth_to \
  allows_unauthenticated self_registration_unrestricted; do
  [ -e "$OUTPUT_DIR/${pred}.facts" ] || touch "$OUTPUT_DIR/${pred}.facts"
done

echo "Converted $(wc -l < "$JSONL_FILE") JSONL lines into:"
ls "$OUTPUT_DIR"/*.facts | wc -l | xargs -I{} echo "  {} per-predicate .facts files in $OUTPUT_DIR"
