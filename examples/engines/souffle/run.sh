#!/usr/bin/env bash
#
# Soufflé runner over Stave's JSONL fact export.
#
# Computes the complete transitive closure of the relations the
# bundled .dl rules define, then prints counts and selected
# outputs. Soufflé's unique value over Z3 / Clingo is "how WIDE
# is the blast radius?" — it enumerates every reachable tuple
# rather than finding a single witness.
#
# Usage:
#   bash run.sh <facts.jsonl> [rule-file.dl]
set -uo pipefail

JSONL_FILE="${1:?Usage: run.sh <facts.jsonl> [rule-file.dl]}"
RULE_FILE="${2:-reachability.dl}"
WORK_DIR="${WORK_DIR:-./.work}"

if ! command -v souffle >/dev/null 2>&1; then
  echo "Install Soufflé first:" >&2
  echo "  brew install souffle      # macOS" >&2
  echo "  apt install souffle       # Ubuntu" >&2
  exit 127
fi

# Resolve the rule file relative to the script directory so
# `bash run.sh ../facts.jsonl` Just Works without cd-ing first.
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ ! -f "$RULE_FILE" ] && [ -f "$HERE/$RULE_FILE" ]; then
  RULE_FILE="$HERE/$RULE_FILE"
fi

mkdir -p "$WORK_DIR"
echo "==> Converting JSONL → per-predicate .facts in $WORK_DIR ..."
bash "$HERE/convert.sh" "$JSONL_FILE" "$WORK_DIR"

echo ""
echo "==> Running Soufflé with rules: $RULE_FILE"
echo "----------------------------------------"
# -F = facts directory; -D = output (relation .csv) directory.
souffle -F "$WORK_DIR" -D "$WORK_DIR" "$RULE_FILE"
echo "----------------------------------------"

echo ""
echo "==> Output relations:"
for csv in "$WORK_DIR"/*.csv; do
  [ -e "$csv" ] || continue
  rel=$(basename "$csv" .csv)
  n=$(wc -l < "$csv")
  echo "  $rel: $n tuple(s)"
done

echo ""
echo "Sample output (first 5 rows of each relation):"
for csv in "$WORK_DIR"/*.csv; do
  [ -e "$csv" ] || continue
  rel=$(basename "$csv" .csv)
  echo ""
  echo "  --- $rel ---"
  head -5 "$csv" | sed 's/^/    /'
done
