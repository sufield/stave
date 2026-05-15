#!/usr/bin/env bash
#
# JSONL → Clingo .lp facts converter.
#
# Lifts each JSONL triple `{subject, predicate, object}` into a
# Clingo binary atom: `<predicate>("<subject>", "<object>").`
#
# The bundled rules in this directory query per-predicate atoms
# (e.g., `has_agent_lambda_scope_broad(A, "true")`) — same shape
# as what Stave's predicate names produce, so the conversion is
# verbatim: predicate becomes the functor, subject + object
# become its two string arguments.
#
# Usage:
#   bash convert.sh <facts.jsonl> [output.lp]
set -euo pipefail

JSONL_FILE="${1:?Usage: convert.sh <facts.jsonl> [output.lp]}"
OUTPUT="${2:-facts.lp}"

if ! command -v jq >/dev/null 2>&1; then
  echo "Install jq first: brew install jq (macOS) or apt install jq (Ubuntu)." >&2
  exit 127
fi

# Lift each triple. Backslash-escape any embedded quotes in
# subject / object so the emitted .lp parses cleanly.
jq -r '
  "\(.predicate)(\"\(.subject | gsub("\""; "\\\""))\", \"\(.object | gsub("\""; "\\\""))\")."
' "$JSONL_FILE" > "$OUTPUT"

echo "Converted $(wc -l < "$JSONL_FILE") JSONL lines into $(wc -l < "$OUTPUT") Clingo atoms in $OUTPUT"
