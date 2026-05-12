#!/usr/bin/env bash
# Gap B: surface observation property paths that no projector reads.
#
# Cross-checks every observation property path that appears in
# fixtures (examples/ + testdata/) against the propertyAllowlist
# entries in cmd/exportsir/facts.go. Properties that exist in
# observations but no projector projects show up as "orphaned" —
# either:
#   • a property added for future use (legitimate orphan)
#   • a property a control evaluates but no projector emits a
#     fact for (encoding gap, but `--validate` already catches
#     this when controls actually evaluate the path)
#   • a property whose projector entry was removed during a
#     refactor (genuine drift)
#
# Output is three lists:
#   1. Property paths in observations that no projector handles
#   2. Projector entries whose property path doesn't appear in
#      any observation (catches stale projector entries)
#   3. Predicate names the projectors emit that no .facts.jsonl
#      fixture exercises (catches specialized-projector blind
#      spots that the property-path audit cannot see)
#
# This is a development-time script, not a CI gate. Run it after
# adding a new control or projector to see what shifted.
#
# Usage:
#   bash examples/explain/audit_projector_coverage.sh
#
# The output is informational; the script always exits 0. Reading
# the orphan list is a triage step, not a fail-fast check.

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
explain_dir="$script_dir"
stave_root=$(cd "$explain_dir/../.." && pwd)

# --- Collect property paths used in observations ---------------
# Walk every *.obs.json under examples/ and testdata/. Strip the
# top-level "assets[i].properties." prefix so we get the same
# shape the propertyAllowlist uses (block-key + nested keys).
obs_paths=$(mktemp)
proj_paths=$(mktemp)
pred_names=$(mktemp)
pred_seen=$(mktemp)
trap 'rm -f "$obs_paths" "$proj_paths" "$pred_names" "$pred_seen"' EXIT

# observation files live under observations/ dirs throughout
# examples/ and testdata/. Match any .json file inside a path
# component named "observations" — the convention is
# stable across the repo.
while IFS= read -r f; do
    jq -r '
        (.assets // [])[]
        | .properties
        | paths(scalars or arrays)
        | join(".")
    ' "$f" 2>/dev/null
done < <(find "$stave_root/examples" "$stave_root/testdata" -type f -name '*.json' \
    | grep '/observations/') \
    | sort -u > "$obs_paths"

obs_count=$(wc -l < "$obs_paths")

# --- Collect property paths the projector allowlist reads ------
# Each propertyAllowlist entry has a blockKey + keys list. We
# rebuild the dotted path the projector navigates so the diff is
# apples-to-apples with the observation paths above.
python3 - "$stave_root/cmd/exportsir/facts.go" > "$proj_paths" <<'PY'
import re
import sys

text = open(sys.argv[1]).read()
# Match: {blockKey: "x", keys: []string{"a", "b"}, ...}
pattern = re.compile(
    r'blockKey:\s*"([^"]+)"\s*,\s*keys:\s*\[\]string\{([^}]*)\}',
    re.S,
)
for m in pattern.finditer(text):
    block = m.group(1)
    keys_raw = m.group(2)
    keys = re.findall(r'"([^"]*)"', keys_raw)
    if keys:
        print(block + "." + ".".join(keys))
    else:
        print(block)
PY
proj_count=$(sort -u "$proj_paths" | wc -l)

# --- Diff -----------------------------------------------------
echo "Projector coverage audit"
echo "  observation paths catalogued: $obs_count"
echo "  projector allowlist entries:  $proj_count"
echo ""

# Orphaned observation properties — exist in fixtures but no
# allowlist entry projects them.
echo "Observation properties no projector reads:"
orphans=$(comm -23 <(sort -u "$obs_paths") <(sort -u "$proj_paths") | head -40)
if [ -z "$orphans" ]; then
    echo "  (none)"
else
    echo "$orphans" | sed 's/^/  /'
fi
echo ""

# Stale projector entries — paths the allowlist names but no
# fixture exercises. May indicate a removed property or simply
# a control that's tested via inline asset blocks.
echo "Projector allowlist entries no fixture exercises:"
stale=$(comm -13 <(sort -u "$obs_paths") <(sort -u "$proj_paths"))
if [ -z "$stale" ]; then
    echo "  (none)"
else
    echo "$stale" | sed 's/^/  /'
fi
echo ""

# --- Predicate-side audit -------------------------------------
# The propertyAllowlist audit above only sees property-driven
# projectors. Specialized projectors (denyPolicyFacts,
# conditionFacts, stringifiedPolicyFacts, dataEventLoggingFacts,
# tagFacts, trustPolicyFacts, assumeEdgeFacts, iamPolicyFacts,
# cognitoMappingFacts, cognitoUserPoolFacts, identityFacts,
# exposureFacts, assetFacts, controlFacts) emit predicates that
# never appear in the allowlist. To surface them, enumerate the
# string-literal predicate names emitted anywhere in facts.go
# and check each against the .facts.jsonl goldens.
grep -oP 'Predicate:\s*"\K[a-z_][a-z_0-9]*' \
    "$stave_root/cmd/exportsir/facts.go" \
    | sort -u > "$pred_names"
pred_count=$(wc -l < "$pred_names")

# Collect every predicate name observed in .facts.jsonl fixtures.
while IFS= read -r f; do
    jq -r '.predicate // empty' "$f" 2>/dev/null
done < <(find "$stave_root/examples" "$stave_root/testdata" -type f -name '*.facts.jsonl') \
    | sort -u > "$pred_seen"
seen_count=$(wc -l < "$pred_seen")

echo "Projector predicate audit"
echo "  predicate names emitted by facts.go: $pred_count"
echo "  predicate names seen in fixtures:    $seen_count"
echo ""

# Predicates the projectors emit but no .facts.jsonl golden
# exercises. These are blind spots — if a projector regresses
# on one of these, no test catches it.
echo "Projector predicates no fixture exercises:"
unexercised=$(comm -23 "$pred_names" "$pred_seen")
if [ -z "$unexercised" ]; then
    echo "  (none)"
else
    echo "$unexercised" | sed 's/^/  /'
fi
