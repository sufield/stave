#!/usr/bin/env bash
#
# Clingo runner over Stave's JSONL fact export.
#
# Enumerates every grounded `violation/2` and `violation/3` atom
# the bundled rule files derive from the fact set. Where Z3
# returns one witness, Clingo's stable-model semantics returns
# the COMPLETE set of violations — the answer shape Soufflé and
# Z3 can't match in one query.
#
# Usage:
#   bash run.sh <facts.jsonl> [rule-file.lp]
set -euo pipefail

JSONL_FILE="${1:?Usage: run.sh <facts.jsonl> [rule-file.lp]}"
RULE_FILE="${2:-ai-delegation-shadow.lp}"
WORK_DIR="${WORK_DIR:-./.work}"

if ! command -v clingo >/dev/null 2>&1; then
  echo "Install Clingo first:" >&2
  echo "  brew install clingo                # macOS" >&2
  echo "  conda install -c potassco clingo   # cross-platform" >&2
  echo "  pip install clingo                 # Python bindings only" >&2
  exit 127
fi

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ ! -f "$RULE_FILE" ] && [ -f "$HERE/$RULE_FILE" ]; then
  RULE_FILE="$HERE/$RULE_FILE"
fi
# constraints.lp ships shared helper predicates; always include it.
CONSTRAINTS="$HERE/constraints.lp"

mkdir -p "$WORK_DIR"
echo "==> Converting JSONL → Clingo atoms in $WORK_DIR/facts.lp ..."
bash "$HERE/convert.sh" "$JSONL_FILE" "$WORK_DIR/facts.lp"

echo ""
echo "==> Running Clingo: facts.lp + constraints.lp + $RULE_FILE"
echo "----------------------------------------"
# `0` requests all answer sets (Clingo defaults to one). Each
# answer set is a stable model — a self-consistent set of
# derived violations. For purely additive rule sets (every rule
# derives a positive atom from facts), there's exactly one
# stable model and Clingo prints it.
clingo 0 "$WORK_DIR/facts.lp" "$CONSTRAINTS" "$RULE_FILE" || true
echo "----------------------------------------"
echo ""
echo "Every violation atom above is a grounded rule firing on the exported facts."
