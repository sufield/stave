#!/usr/bin/env bash
# Split the JSONL fact stream into per-predicate `.facts` files
# (TSV, two columns) for Soufflé. Soufflé's `.input` directives
# read one file per declared relation; missing files trigger a
# warning but the relation is treated as empty, so this script
# also pre-creates empty .facts for the relations the program
# declares but the fixture happens not to populate (e.g.,
# `can_assume` on a fixture without role-trust chains).

set -euo pipefail

JSONL=$1
OUT=$2
mkdir -p "$OUT"

# Split each predicate into its own TSV.
for pred in $(jq -r '.predicate' "$JSONL" | sort -u); do
    jq -r --arg P "$pred" \
        'select(.predicate == $P) | [.subject, .object] | @tsv' \
        "$JSONL" > "$OUT/${pred}.facts"
done

# Pre-create empty .facts files for every relation the
# reachability.dl program declares, so a fixture that doesn't
# emit (say) `can_assume` simply runs that relation as empty
# instead of causing Soufflé to print a warning to stderr.
for pred in \
    has_type has_action has_resource has_tag \
    can_assume trusts_service contributed_by \
    maps_unauth_to maps_auth_to \
    allows_unauthenticated self_registration_unrestricted; do
    touch "$OUT/${pred}.facts"
done
