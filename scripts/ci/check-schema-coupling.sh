#!/usr/bin/env bash
set -uo pipefail

echo "=== Schema-Control Coupling ==="

contract="data/collector-contract.yaml"
if [ ! -f "$contract" ]; then
  echo "SKIP: No collector contract at $contract"
  exit 0
fi

# Extract consumer control IDs from the contract
consumer_ids=$(grep -E '^\s+- CTL\.' "$contract" | sed 's/.*- //' | sort -u)

# Check each consumer ID references an existing control
orphan_count=0
while IFS= read -r id; do
  [ -z "$id" ] && continue
  if ! find controls -name "${id}.yaml" -type f 2>/dev/null | grep -q .; then
    if ! find internal/controldata/embedded -name "${id}.yaml" -type f 2>/dev/null | grep -q .; then
      echo "WARN: Contract consumer $id has no matching control YAML"
      orphan_count=$((orphan_count + 1))
    fi
  fi
done <<< "$consumer_ids"

total=$(echo "$consumer_ids" | grep -c 'CTL\.' || true)
echo "Contract consumers checked: $total"
echo "Missing controls: $orphan_count"

if [ "$orphan_count" -gt 0 ]; then
  echo "INFO: $orphan_count contract consumer(s) reference controls not yet in the catalog"
  echo "  This is a warning — controls may be planned but not yet authored."
fi

echo "PASS: Schema-control coupling check complete"
exit 0
