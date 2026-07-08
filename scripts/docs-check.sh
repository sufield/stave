#!/usr/bin/env bash
# Detect stale documentation: hardcoded counts, deprecated flags,
# phantom make targets. Complements consistency-check (which catches
# generated-file drift); this catches prose drift in non-generated docs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

ERRORS=0
err() { echo "STALE: $*"; ERRORS=$((ERRORS + 1)); }

EXCLUDE='vendor/|node_modules/|\.tmp/|CHANGELOG|\.tmpl:|site/build/|docs-check\.sh'

# ── Hardcoded chain count ────────────────────────
ACTUAL_CHAINS=$(find chains/ -name '*.yaml' | wc -l)
while IFS= read -r match; do
  err "stale chain count (actual $ACTUAL_CHAINS): $match"
done < <(
  grep -rn -I '\b[0-9]\{3\} \(compound \)\?chain\(s\| definition\)' \
    --include='*.md' . \
    | grep -Ev "$EXCLUDE" \
    | grep -Ev "\\b${ACTUAL_CHAINS}\\b" \
  || true
)

# ── Hardcoded control count ──────────────────────
ACTUAL_CONTROLS=$(grep -oP '\d+(?= controls)' <(make readme 2>/dev/null) || echo "")
if [ -n "$ACTUAL_CONTROLS" ]; then
  while IFS= read -r match; do
    err "stale control count (actual $ACTUAL_CONTROLS): $match"
  done < <(
    grep -rn -I '\b[0-9]\{4\} controls\b' --include='*.md' . \
      | grep -Ev "$EXCLUDE" \
      | grep -Ev "\\b${ACTUAL_CONTROLS} controls\\b" \
    || true
  )
fi

# ── Deprecated/removed CLI flags ─────────────────
DEPRECATED_FLAGS=(
  "allow-unknown-input"
)
for FLAG in "${DEPRECATED_FLAGS[@]}"; do
  while IFS= read -r match; do
    err "deprecated flag --$FLAG: $match"
  done < <(
    grep -rn -I -- "--${FLAG}" . \
      | grep -E '\.(md|sh|txt|yaml):' \
      | grep -Ev "$EXCLUDE" \
    || true
  )
done

# ── Phantom make targets ─────────────────────────
REAL_TARGETS=$({
  grep -oP '^[a-z][a-z0-9_-]*(?=:)' Makefile
  grep -oP '\.PHONY:\s*\K.*' Makefile | tr ' ' '\n' | grep -v '^$'
} | sort -u)
while IFS= read -r target_str; do
  cmd="${target_str#make }"
  if ! grep -qxF "$cmd" <<< "$REAL_TARGETS"; then
    hit=$(grep -rn -I "\`make ${cmd}\`" --include='*.md' . \
      | grep -Ev "$EXCLUDE" | head -1 || true)
    if [ -n "$hit" ]; then
      err "make target '$cmd' not in Makefile: $hit"
    fi
  fi
done < <(
  grep -roh -I '`make [a-z][a-z0-9_-]*`' --include='*.md' . \
    | sed 's/`//g' \
    | sort -u \
  || true
)

# ── Summary ──────────────────────────────────────
if [ "$ERRORS" -eq 0 ]; then
  echo "OK: documentation checks passed"
else
  echo ""
  echo "FAIL: $ERRORS staleness issues found"
  exit 1
fi
