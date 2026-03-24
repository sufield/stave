#!/usr/bin/env bash
set -euo pipefail

SCENARIOS_DIR="/scenarios"
WORK_DIR="/work"
ALL_CONTROLS="/scenarios/all_controls.txt"
INIT_DONE="$WORK_DIR/.init_done"

usage() {
  cat <<'HELP'
Stave Tutorial Demo — 44 S3 security scenarios

Usage:
  docker run stave-tutorials --list                  List all scenarios
  docker run stave-tutorials --scenario 1            Run bad config (shows violations)
  docker run stave-tutorials --scenario 1 --fixed    Run fixed config (shows remediation)
  docker run stave-tutorials -- stave <args>         Pass-through to stave

Each scenario uses the same project structure. Observations are swapped
per scenario, then stave apply runs against the observations/ directory.

Examples:
  docker run stave-tutorials --scenario 10           # CTL.S3.PUBLIC.007 violation
  docker run stave-tutorials --scenario 10 --fixed   # CTL.S3.PUBLIC.007 remediated
  docker run stave-tutorials --list                  # Show all 44 scenarios
HELP
}

list_scenarios() {
  printf "%-4s %-32s %-10s %s\n" "#" "Control" "Severity" "Name"
  printf "%-4s %-32s %-10s %s\n" "---" "------" "--------" "----"
  for dir in "$SCENARIOS_DIR"/[0-9]*/; do
    [ -f "$dir/meta.txt" ] || continue
    num="$(basename "$dir")"
    IFS='|' read -r ctl sev name < "$dir/meta.txt"
    printf "%-4s %-32s %-10s %s\n" "$num" "$ctl" "$sev" "$name"
  done
}

# Initialize project once.
ensure_init() {
  if [ -f "$INIT_DONE" ]; then
    return
  fi
  cd "$WORK_DIR"
  stave init --profile aws-s3 >/dev/null 2>&1 || true
  touch "$INIT_DONE"
}

# Write stave.yaml excluding all controls except the target.
write_focused_config() {
  local target_ctl="$1"
  local yaml="$WORK_DIR/stave.yaml"

  cat > "$yaml" <<'HEADER'
enabled_control_packs:
  - s3
HEADER

  if [ "$target_ctl" = "-" ]; then
    return
  fi

  printf "exclude_controls:\n" >> "$yaml"
  while IFS= read -r line; do
    [ "$line" = "$target_ctl" ] && continue
    printf "  - %s\n" "$line" >> "$yaml"
  done < "$ALL_CONTROLS"
}

run_scenario() {
  local num="$1"
  local mode="${2:-bad}"
  local padded
  padded=$(printf "%02d" "$num")

  local dir="$SCENARIOS_DIR/$padded"
  if [ ! -d "$dir" ]; then
    echo "Error: scenario $num not found" >&2
    exit 2
  fi

  IFS='|' read -r ctl sev name < "$dir/meta.txt"
  local flags=""
  [ -f "$dir/flags.txt" ] && flags="$(cat "$dir/flags.txt")"

  local src_dir now_time
  if [ "$mode" = "fixed" ]; then
    src_dir="$dir/fixed"
    now_time="2026-03-22T12:00:00Z"
    if [ ! -d "$src_dir" ] || ! ls "$src_dir"/*.json >/dev/null 2>&1; then
      echo "Error: scenario $num has no fixed observations" >&2
      exit 2
    fi
  else
    src_dir="$dir/bad"
    now_time="2026-03-21T12:00:00Z"
  fi

  ensure_init
  cd "$WORK_DIR"

  # Swap observations
  rm -f "$WORK_DIR"/observations/*.json
  cp "$src_dir"/*.json "$WORK_DIR/observations/"

  # Focus on target control
  write_focused_config "$ctl"

  # ── Display ─────────────────────────────────────────────
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Scenario $num: $name"
  echo "Control:  $ctl ($sev)"
  echo "Mode:     $mode"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # Show observation files
  echo ""
  echo "  \$ ls observations/"
  for f in "$WORK_DIR"/observations/*.json; do
    echo "    $(basename "$f")"
  done

  # Show observation content
  echo ""
  echo "── observations/$(basename "$(ls "$WORK_DIR"/observations/*.json | head -1)") ──"
  echo ""
  cat "$(ls "$WORK_DIR"/observations/*.json | head -1)"

  # Show command
  echo ""
  local cmd="  \$ stave apply --observations observations --max-unsafe 12h --now $now_time"
  if [ -n "$flags" ]; then
    cmd="$cmd $flags"
  fi
  echo "$cmd"

  # Run evaluation
  echo ""
  echo "── output ────────────────────────────────────────────"
  echo ""

  rc=0
  stave apply \
    --observations observations \
    --max-unsafe 12h \
    --now "$now_time" \
    --format text \
    $flags \
    || rc=$?

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ "$mode" = "bad" ]; then
    if [ "$rc" -eq 3 ]; then
      echo "Result: VIOLATION DETECTED (exit 3)"
      echo ""
      echo "To see the fix:"
      echo "  docker run --rm stave-tutorials --scenario $num --fixed"
    else
      echo "Result: exit $rc"
    fi
  else
    if [ "$rc" -eq 0 ]; then
      echo "Result: NO VIOLATIONS (exit 0) — remediation confirmed"
    else
      echo "Result: exit $rc"
    fi
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit "$rc"
}

case "${1:-}" in
  --list|-l)
    list_scenarios
    ;;
  --scenario|-s)
    num="${2:-}"
    if [ -z "$num" ]; then
      echo "Error: --scenario requires a number (1-44)" >&2
      exit 2
    fi
    mode="bad"
    if [ "${3:-}" = "--fixed" ] || [ "${3:-}" = "-f" ]; then
      mode="fixed"
    fi
    run_scenario "$num" "$mode"
    ;;
  --help|-h|"")
    usage
    ;;
  --)
    shift
    exec "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
