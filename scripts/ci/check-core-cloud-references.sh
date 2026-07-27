#!/usr/bin/env bash
set -uo pipefail

# Ratchet: cloud-provider references in internal/core/ must not increase.
# The baseline is the count after the Fix 1+2 cleanups (derive, remediation,
# kernel). Remaining references are LOW-priority deferrals (sirfacts, risk,
# translation, comments). Fix those and lower the baseline.

BASELINE=98

current=$(grep -r "aws_\|gcp_\|azure_\|arn:\|amazonaws\|googleapi\|azure\.com" \
  --include="*.go" \
  internal/core/ \
  | grep -v "_test.go\|testdata" \
  | wc -l)

if [ "$current" -gt "$BASELINE" ]; then
  echo "FAIL: Cloud-provider references in core increased ($current > baseline $BASELINE)"
  echo ""
  echo "New violations:"
  grep -rn "aws_\|gcp_\|azure_\|arn:\|amazonaws\|googleapi\|azure\.com" \
    --include="*.go" internal/core/ \
    | grep -v "_test.go\|testdata"
  exit 1
fi

echo "PASS: Core cloud references ($current <= baseline $BASELINE)"

if [ "$current" -lt "$BASELINE" ]; then
  echo "INFO: Count decreased ($current < $BASELINE) — update baseline in this script"
fi
