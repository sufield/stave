#!/usr/bin/env bash
# add-parallel.sh — adds t.Parallel() as first line of each Test function
# that doesn't already have it
set -euo pipefail

dir="${1:-.}"

find "$dir" -name '*_test.go' -print0 | while IFS= read -r -d '' f; do
  # Skip files that test process-wide state
  if grep -qE 't\.Setenv|os\.Setenv|os\.Chdir' "$f"; then
    echo "SKIP (env/chdir): $f"
    continue
  fi

  sed -i.bak -E '
    /^func Test[A-Z][a-zA-Z0-9_]*\(t \*testing\.T\) \{/ {
      n
      /t\.Parallel\(\)/! {
        i\
\tt.Parallel()
      }
    }
  ' "$f"
done

find "$dir" -name '*.bak' -delete
echo "done — run: go test -count=1 ./..."
