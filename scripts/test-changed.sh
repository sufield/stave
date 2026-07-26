#!/usr/bin/env bash
set -euo pipefail

# Test only Go packages containing changed .go files.
# Usage:
#   ./scripts/test-changed.sh          # changes vs HEAD
#   ./scripts/test-changed.sh main     # changes vs main branch

base="${1:-HEAD}"

changed_packages=$(
  git diff --name-only "$base" -- '*.go' 2>/dev/null | \
    xargs -n1 dirname 2>/dev/null | \
    sort -u | \
    sed 's|^|./|'
)

if [ -z "$changed_packages" ]; then
  echo "No changed Go files vs $base. Nothing to test."
  exit 0
fi

echo "Testing changed packages (vs $base):"
echo "$changed_packages" | while read -r pkg; do
  echo "  $pkg"
done
echo ""

# shellcheck disable=SC2086
go test -count=1 -v -failfast $changed_packages
