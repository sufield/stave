#!/usr/bin/env bash
#
# Z3 runner over Stave's SMT-LIB export.
#
# Usage:
#   bash run.sh <facts.smt2>
#
# SAT     → a forbidden state is reachable; Z3 returns a model showing how.
# UNSAT   → the forbidden state is provably unreachable from the exported facts.
# unknown → solver gave up (rare with our schema; investigate timeouts).
set -uo pipefail

SMT2_FILE="${1:?Usage: run.sh <facts.smt2>}"

if ! command -v z3 >/dev/null 2>&1; then
  echo "Install Z3 first: brew install z3 (macOS) or apt install z3 (Ubuntu)." >&2
  exit 127
fi

echo "Z3: checking satisfiability of $SMT2_FILE..."
echo "----------------------------------------"
# Stave's smt2 export emits FACTS ONLY — no (check-sat). The file
# comment says explicitly: "Append your query (check-sat /
# get-model / etc.) before invoking the solver." For a generic
# "is the encoded world consistent?" run, we append (check-sat)
# ourselves. Production users feeding a custom query should
# concat their query file ahead of this script.
QUERY_FILE=$(mktemp)
trap 'rm -f "$QUERY_FILE"' EXIT
if grep -q '^\s*(check-sat' "$SMT2_FILE"; then
  cp "$SMT2_FILE" "$QUERY_FILE"
else
  cat "$SMT2_FILE" > "$QUERY_FILE"
  echo "(check-sat)" >> "$QUERY_FILE"
fi
# -smt2 forces SMT-LIB v2; the export is v2 but being explicit helps when
# users feed in concatenated files. -T:30 caps wall time so a runaway
# benchmark doesn't wedge a CI run.
RESULT=$(z3 -smt2 -T:30 "$QUERY_FILE" 2>&1 || true)
echo "$RESULT"
echo "----------------------------------------"

# Match the sat/unsat verdict line itself; Z3 may emit warnings or
# error lines ahead of the verdict, so anchoring to a leading
# "sat*" / "unsat*" on $RESULT misses those runs.
VERDICT=$(echo "$RESULT" | grep -E '^(sat|unsat|unknown|timeout)$' | tail -n1)
case "$VERDICT" in
  sat)
    echo ""
    echo "RESULT: SAT — a forbidden state is reachable."
    echo "The model above shows the specific variable assignment that reaches it."
    ;;
  unsat)
    echo ""
    echo "RESULT: UNSAT — the forbidden state is provably unreachable."
    echo "No combination of the exported facts can reach the forbidden state."
    ;;
  *)
    echo ""
    echo "RESULT: solver did not return sat/unsat — see output above."
    echo "Common causes: timeout (raise -T:N), syntax error in the SMT-LIB file."
    ;;
esac
