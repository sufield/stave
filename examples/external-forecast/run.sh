#!/usr/bin/env bash
# Runs external-forecast and verifies it matches core.
# Prerequisites: python3, go.

set -uo pipefail
cd "$(dirname "$0")"

# 1. Python computes the forecast.
python3 forecast.py input.json external.json

# 2. Go core computes the same forecast (via the
#    build-ignored verify_against_core.go helper).
go run verify_against_core.go input.json core.json

# 3. Semantic JSON equality via Python — handles the
#    int-vs-float-with-zero formatting difference between
#    Python's json (24.0) and Go's encoding/json (24)
#    that would mislead a textual diff.
python3 - <<'PY'
import json
import sys

with open("external.json") as f:
    external = json.load(f)
with open("core.json") as f:
    core = json.load(f)

def normalize(obj):
    """Recursively coerce whole-number floats to ints so the
    semantic equality is insensitive to Python's 24.0 vs Go's
    24 serialization quirk. Real floats (with non-zero
    fractional part) stay as floats and compare bit-for-bit."""
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize(v) for v in obj]
    return obj

a = normalize(external)
b = normalize(core)
if a == b:
    print("external matches core — semantic equality on normalized JSON")
    sys.exit(0)

import difflib
sys.stderr.write("external and core diverge:\n")
da = json.dumps(a, indent=2, sort_keys=True).splitlines()
db = json.dumps(b, indent=2, sort_keys=True).splitlines()
for line in difflib.unified_diff(da, db, fromfile="external", tofile="core", lineterm=""):
    sys.stderr.write(line + "\n")
sys.exit(1)
PY
