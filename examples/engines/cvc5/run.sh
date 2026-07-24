#!/usr/bin/env bash
#
# cvc5 cross-check over Stave's SMT-LIB export.
#
# Same input file as Z3; independent solver. Two solvers agreeing on
# UNSAT for the same SMT-LIB bundle is the strongest confidence signal
# this multi-engine setup can produce.
#
# Usage:
#   bash run.sh <facts.smt2>
set -uo pipefail

SMT2_FILE="${1:?Usage: run.sh <facts.smt2>}"

if ! command -v cvc5 >/dev/null 2>&1; then
  echo "Install cvc5 first:" >&2
  echo "  brew install cvc5             # macOS" >&2
  echo "  https://cvc5.github.io/       # Linux / source" >&2
  exit 127
fi

echo "cvc5: cross-checking satisfiability of $SMT2_FILE..."
echo "----------------------------------------"
# Stave's smt2 export emits FACTS ONLY — no (check-sat). Append
# one if the file doesn't already have it (matching the Z3 runner;
# both solvers must process the same exact bytes for a meaningful
# cross-check).
QUERY_FILE=$(mktemp)
trap 'rm -f "$QUERY_FILE"' EXIT
if grep -q '^\s*(check-sat' "$SMT2_FILE"; then
  cp "$SMT2_FILE" "$QUERY_FILE"
else
  cat "$SMT2_FILE" > "$QUERY_FILE"
  echo "(check-sat)" >> "$QUERY_FILE"
fi
# --lang smt2 forces SMT-LIB v2 parsing (cvc5's default is auto-detect;
# explicit avoids surprises when the input file lacks a shebang).
# --tlimit caps wall time in milliseconds; 30000 = 30s, matching the Z3
# runner so a single fact file gets the same fairness budget on both
# solvers when you're cross-checking.
RESULT=$(cvc5 --lang smt2 --tlimit 30000 "$QUERY_FILE" 2>&1 || true)
echo "$RESULT"
echo "----------------------------------------"

# Match the sat/unsat verdict line itself; cvc5 may emit warnings
# or notes ahead of the verdict, so anchoring "sat*" / "unsat*" on
# the whole $RESULT misses those runs.
VERDICT=$(echo "$RESULT" | grep -E '^(sat|unsat|unknown|timeout)$' | tail -n1)
case "$VERDICT" in
  sat)
    echo ""
    echo "RESULT: SAT — cvc5 confirms a forbidden state is reachable."
    echo "If Z3 also returns SAT on the same file, the reachability is independently verified."
    ;;
  unsat)
    echo ""
    echo "RESULT: UNSAT — cvc5 confirms the forbidden state is unreachable."
    echo "If Z3 also returns UNSAT on the same file, the proof is independently verified."
    ;;
  *)
    echo ""
    echo "RESULT: solver did not return sat/unsat — see output above."
    echo "Raise --tlimit if the timeout was hit, or check the SMT-LIB file for issues."
    ;;
esac
