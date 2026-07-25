#!/usr/bin/env bash
set -uo pipefail

BASELINE="${BASELINE:-docs-internal/baselines/catalog.json}"

if [ ! -f "$BASELINE" ]; then
  echo "No baseline found at $BASELINE — skipping monotonicity check"
  exit 0
fi

baseline_controls=$(jq -r '.control_count' "$BASELINE")
baseline_chains=$(jq -r '.chain_count' "$BASELINE")

current_controls=$(find controls -name '*.yaml' -type f | wc -l)
current_chains=$(find chains -name '*.yaml' -type f 2>/dev/null | wc -l)

failed=0

if [ "$current_controls" -lt "$baseline_controls" ]; then
  echo "FAIL: Control count dropped ($current_controls < baseline $baseline_controls)"
  echo "  If intentional (duplicate removed, control merged),"
  echo "  update $BASELINE before committing."
  failed=1
fi

if [ "$current_chains" -lt "$baseline_chains" ]; then
  echo "FAIL: Chain count dropped ($current_chains < baseline $baseline_chains)"
  echo "  If intentional, update $BASELINE before committing."
  failed=1
fi

if [ "$failed" -eq 0 ]; then
  echo "PASS: Coverage monotonicity (controls: $current_controls >= $baseline_controls, chains: $current_chains >= $baseline_chains)"
fi

exit $failed
