#!/usr/bin/env bash
set -euo pipefail

SCENARIOS_DIR="/scenarios"
WORK_DIR="/work"
ALL_CONTROLS="/scenarios/all_controls.txt"
INIT_DONE="$WORK_DIR/.init_done"

# Trusted Advisor blind spot scenarios
BLIND_SPOT_SCENARIOS=(8 23 18)

# HIPAA compliance scenario directory
HIPAA_DIR="$SCENARIOS_DIR/hipaa-compliance"

usage() {
  cat <<'HELP'
Stave Tutorial Demo — 44 S3 security scenarios + HIPAA compliance profile

Usage:
  docker run stave-tutorials --list                  List all scenarios
  docker run stave-tutorials --scenario 1            Run bad config (shows violations)
  docker run stave-tutorials --scenario 1 --fixed    Run fixed config (shows remediation)
  docker run stave-tutorials --blind-spots           Run the 3 Trusted Advisor blind spots
  docker run stave-tutorials --hipaa                 Run HIPAA compliance profile (violations)
  docker run stave-tutorials --hipaa --fixed         Run HIPAA profile (fully remediated)
  docker run stave-tutorials --hipaa --json          Run HIPAA profile with JSON output
  docker run stave-tutorials -- stave <args>         Pass-through to stave

Examples:
  docker run stave-tutorials --scenario 10           # CTL.S3.PUBLIC.007 violation
  docker run stave-tutorials --hipaa                 # HIPAA: 14 controls + compound risks
  docker run stave-tutorials --hipaa --fixed         # HIPAA: all controls passing
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

  return "$rc"
}

run_blind_spots() {
  local mode="${1:-bad}"

  cat <<'INTRO'
================================================================
  AWS Trusted Advisor Blind Spots
================================================================

AWS Trusted Advisor checks whether S3 buckets are publicly
accessible. These three scenarios demonstrate risks that
Trusted Advisor cannot see.

  #8   Policy-Denied Scanning (Fog Security Bypass)
       An attacker denies the scanning role access to bucket
       policy, ACL, and Public Access Block APIs. Trusted
       Advisor reports green. The bucket is fully public.
       Stave flags missing data as unsafe.

  #23  Latent Public Exposure Behind Public Access Block
       A bucket has Public Access Block enabled but an
       underlying policy grants Principal: "*". Trusted
       Advisor reports safe. Removing PAB — one toggle —
       makes the bucket instantly public.

  #18  ACL Escalation (WRITE_ACP)
       A bucket ACL grants WRITE_ACP to AllUsers. Anyone
       can call PutBucketAcl, grant themselves FULL_CONTROL,
       then read every object. Trusted Advisor does not
       check whether the public can modify the ACL itself.

INTRO

  if [ "$mode" = "fixed" ]; then
    echo "Running all three with FIXED observations..."
  else
    echo "Running all three with BAD observations..."
  fi
  echo ""

  local any_failed=0
  for num in "${BLIND_SPOT_SCENARIOS[@]}"; do
    rc=0
    run_scenario "$num" "$mode" || rc=$?
    echo ""
    if [ "$rc" -ne 0 ] && [ "$mode" = "fixed" ]; then
      any_failed=1
    fi
  done

  echo "================================================================"
  echo "  Blind Spot Summary"
  echo "================================================================"
  echo ""
  printf "  %-4s %-28s %-10s %s\n" "#" "Blind Spot" "Control" "Trusted Advisor"
  printf "  %-4s %-28s %-10s %s\n" "---" "----------" "-------" "---------------"
  printf "  %-4s %-28s %-10s %s\n" "8"  "Policy-denied scanning"     "INCOMPLETE.001"  "Reports green"
  printf "  %-4s %-28s %-10s %s\n" "23" "Latent exposure behind PAB" "PUBLIC.005"      "Reports safe"
  printf "  %-4s %-28s %-10s %s\n" "18" "ACL escalation (WRITE_ACP)" "ESCALATION.001" "Not checked"
  echo ""

  if [ "$mode" = "bad" ]; then
    echo "Stave detected all three. Trusted Advisor missed all three."
    echo ""
    echo "To see the fixes:"
    echo "  docker run --rm stave-tutorials --blind-spots --fixed"
  else
    echo "All three blind spots remediated."
  fi
  echo "================================================================"
}

run_hipaa() {
  local mode="bad"
  local format="text"
  shift  # consume --hipaa
  while [ $# -gt 0 ]; do
    case "$1" in
      --fixed|-f) mode="fixed" ;;
      --json) format="json" ;;
    esac
    shift
  done

  local snap_file
  if [ "$mode" = "fixed" ]; then
    snap_file="$HIPAA_DIR/fixed/snapshot.json"
  else
    snap_file="$HIPAA_DIR/bad/snapshot.json"
  fi

  if [ ! -f "$snap_file" ]; then
    echo "Error: HIPAA scenario snapshot not found at $snap_file" >&2
    exit 2
  fi

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "HIPAA Security Rule — S3 Compliance Profile"
  echo "Mode:     $mode"
  echo "Format:   $format"
  echo "Controls: 14 invariants + 3 compound risk detectors"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  echo ""
  echo "  \$ stave evaluate --snapshot snapshot.json --profile hipaa --format $format"
  echo ""
  echo "── observation snapshot ──────────────────────────────"
  echo ""
  echo "  Bucket: phi-patient-records"
  echo "  Tags:   data-classification=phi, compliance=hipaa"
  echo ""

  if [ "$mode" = "bad" ]; then
    echo "  Config:  Public Access Block OFF, AWS-managed KMS key,"
    echo "           no logging, no versioning, no Object Lock,"
    echo "           wildcard policy (s3:*), no VPC restriction"
  else
    echo "  Config:  Public Access Block ON, customer-managed CMK,"
    echo "           server + object-level logging, versioning ON,"
    echo "           Object Lock COMPLIANCE 6yr, VPC-only access,"
    echo "           presigned URL restriction, ACLs disabled"
  fi

  echo ""
  echo "── output ────────────────────────────────────────────"
  echo ""

  rc=0
  stave evaluate \
    --snapshot "$snap_file" \
    --profile hipaa \
    --format "$format" \
    || rc=$?

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ "$mode" = "bad" ]; then
    if [ "$rc" -ne 0 ]; then
      echo "Result: CRITICAL VIOLATIONS (exit $rc)"
      echo ""
      echo "This PHI bucket fails multiple HIPAA Security Rule"
      echo "requirements. Compound risks amplify the severity."
      echo ""
      echo "To see the fully remediated configuration:"
      echo "  docker run --rm stave-tutorials --hipaa --fixed"
    else
      echo "Result: exit $rc (unexpected — bad config should fail)"
    fi
  else
    if [ "$rc" -eq 0 ]; then
      echo "Result: ALL CONTROLS PASSING (exit 0)"
      echo ""
      echo "The PHI bucket meets all 14 HIPAA technical safeguard"
      echo "requirements evaluated by Stave."
    else
      echo "Result: exit $rc"
    fi
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  return "$rc"
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
    exit $?
    ;;
  --blind-spots)
    mode="bad"
    if [ "${2:-}" = "--fixed" ] || [ "${2:-}" = "-f" ]; then
      mode="fixed"
    fi
    run_blind_spots "$mode"
    ;;
  --hipaa)
    run_hipaa "$@"
    exit $?
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
