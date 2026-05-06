#!/usr/bin/env bash
set -euo pipefail

SCENARIOS_DIR="/scenarios"
WORK_DIR="/work"
ALL_CONTROLS="/scenarios/all_controls.txt"
INIT_DONE="$WORK_DIR/.init_done"
export STAVE_DEMO=1

# Trusted Advisor blind spot scenarios
BLIND_SPOT_SCENARIOS=(8 23 18)

# HIPAA compliance scenario directory
HIPAA_DIR="$SCENARIOS_DIR/hipaa-compliance"

usage() {
  cat <<'HELP'
Stave Risk Reasoning Engine — 243 controls across 29 domains

Usage:
  docker run stave-tutorials --list                  List all scenarios
  docker run stave-tutorials --scenario 1            Run bad config (shows violations)
  docker run stave-tutorials --scenario 1 --fixed    Run fixed config (shows remediation)
  docker run stave-tutorials --blind-spots           Run the 3 Trusted Advisor blind spots
  docker run stave-tutorials --hipaa                 Run HIPAA compliance profile (violations)
  docker run stave-tutorials --hipaa --fixed         Run HIPAA profile (fully remediated)
  docker run stave-tutorials --hipaa --json          Run HIPAA profile with JSON output
  docker run stave-tutorials --risk-chains           Show the 3 built-in safety chains
  docker run stave-tutorials --z3-walkthrough        Run the canned Z3 solver demo (S3 public exposure)
  docker run stave-tutorials --solver                Read SIR JSON from stdin and emit findings (raw solver)
  docker run stave-tutorials --try-your-own           Run stave on your own AWS bucket
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

  # ── 1. What control is being checked ────────────────────
  echo ""
  echo "[$sev] $ctl"
  echo "$name"
  echo ""

  # ── 2. The observation (what the bucket looks like) ────
  echo "Observation:"
  echo ""
  cat "$(ls "$WORK_DIR"/observations/*.json | head -1)"
  echo ""

  # ── 3. The command (what you would run) ────────────────
  local cmd="stave apply --observations observations --max-unsafe 12h --now $now_time"
  if [ -n "$flags" ]; then
    cmd="$cmd $flags"
  fi
  echo "\$ $cmd"
  echo ""

  # ── 4. The result (what stave found) ───────────────────
  rc=0
  stave apply \
    --observations observations \
    --max-unsafe 12h \
    --now "$now_time" \
    --format text \
    $flags \
    2>/dev/null \
    || rc=$?

  echo ""
  if [ "$mode" = "bad" ]; then
    if [ "$rc" -eq 3 ]; then
      echo "Exit code 3 — violation detected."
    else
      echo "Exit code $rc"
    fi
  else
    if [ "$rc" -eq 0 ]; then
      echo "Exit code 0 — no violations."
    else
      echo "Exit code $rc"
    fi
  fi

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

  # ── 1. What profile is being evaluated ──────────────────
  echo ""
  echo "HIPAA Security Rule — S3 Compliance Profile"
  echo "14 invariants + 3 compound risk detectors"
  echo ""

  # ── 2. The command ─────────────────────────────────────
  echo "\$ stave evaluate --snapshot snapshot.json --profile hipaa --format $format"
  echo ""

  # ── 3. The result ──────────────────────────────────────
  rc=0
  stave evaluate \
    --snapshot "$snap_file" \
    --profile hipaa \
    --format "$format" \
    2>/dev/null \
    || rc=$?

  echo ""
  if [ "$mode" = "bad" ]; then
    if [ "$rc" -ne 0 ]; then
      echo "Exit code $rc — critical violations detected."
    else
      echo "Exit code $rc"
    fi
  else
    if [ "$rc" -eq 0 ]; then
      echo "Exit code 0 — all controls passing."
    else
      echo "Exit code $rc"
    fi
  fi

  return "$rc"
}

# --z3-walkthrough: a canned end-to-end demo of the Z3 solver
# pipeline. Builds a SIR document from scenario 1's bad
# observations, pipes it through stave-solver, and renders the
# resulting findings — all inside the running container.
run_z3_walkthrough() {
  local dir="$SCENARIOS_DIR/01"
  IFS='|' read -r ctl sev name < "$dir/meta.txt"

  ensure_init
  cd "$WORK_DIR"
  rm -f "$WORK_DIR"/observations/*.json
  cp "$dir/bad"/*.json "$WORK_DIR/observations/"
  write_focused_config "$ctl"

  cat <<INTRO
================================================================
  Stave Z3 Solver — End-to-End Walkthrough
================================================================

This walkthrough exercises the full pipeline:

  observations + controls
    -> stave export-sir
    -> SIR JSON document
    -> stave-solver (Z3)
    -> findings with model-extracted suggested fixes

Scenario: $name ($ctl, $sev)

Step 1. Produce a SIR document from the scenario:

  \$ stave export-sir --observations observations \\
                     --now 2026-03-21T12:00:00Z \\
                     > /tmp/sir.json

Step 2. Sanity-check the SIR shape:

INTRO

  stave export-sir --observations observations \
                   --now 2026-03-21T12:00:00Z \
                   > /tmp/sir.json 2>/dev/null

  echo "  Controls in SIR: $(jq '.controls | length' /tmp/sir.json)"
  echo "  Assets in SIR:   $(jq '.assets | length' /tmp/sir.json)"
  echo ""

  cat <<MID
Step 3. Pipe the SIR through the Z3 solver:

  \$ stave-solver < /tmp/sir.json | jq .

Findings:

MID

  stave-solver < /tmp/sir.json | jq .

  cat <<OUTRO

Step 4. (For interactive use) compose the pipeline directly:

  \$ stave export-sir --observations observations \\
                     --now 2026-03-21T12:00:00Z \\
  | stave-solver | jq .

The 'suggested_fix' block on each finding is the Z3 backend's
distinctive output — a model-extracted minimal change that
flips the unsafe predicate to safe.
================================================================
OUTRO
}

# --solver: raw solver entrypoint. Reads SIR JSON from stdin and
# writes Stave findings to stdout. Useful when piping output
# from a separate \`docker compose run\` of stave export-sir.
run_solver() {
  exec stave-solver "$@"
}

show_try_your_own() {
  cat <<'OWN'
Try with your own AWS data
==========================

1. Pick a bucket:

   BUCKET=my-bucket-name

2. Capture two snapshots (at least a day apart for duration tracking):

   aws s3api get-public-access-block --bucket $BUCKET > pab.json
   aws s3api get-bucket-encryption --bucket $BUCKET > enc.json
   aws s3api get-bucket-versioning --bucket $BUCKET > ver.json
   aws s3api get-bucket-logging --bucket $BUCKET > log.json
   aws s3api get-bucket-policy --bucket $BUCKET > pol.json 2>/dev/null || echo '{}' > pol.json

3. Build the observation JSON:

   cat <<EOF > snap1.json
   {
     "schema_version": "obs.v0.1",
     "generated_by": {"source_type": "aws-s3-snapshot", "tool": "aws-cli"},
     "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
     "assets": [{
       "id": "$BUCKET",
       "type": "aws_s3_bucket",
       "vendor": "aws",
       "properties": {
         "storage": {
           "kind": "bucket",
           "name": "$BUCKET",
           "controls": {
             "public_access_block": $(cat pab.json | jq '.PublicAccessBlockConfiguration // {}')
           },
           "encryption": {
             "at_rest_enabled": $(cat enc.json | jq 'has("ServerSideEncryptionConfiguration")'),
             "algorithm": $(cat enc.json | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // ""' | jq -R .)
           },
           "versioning": {
             "enabled": $(cat ver.json | jq '.Status == "Enabled"')
           },
           "logging": {
             "enabled": $(cat log.json | jq 'has("LoggingEnabled")'),
             "target_bucket": $(cat log.json | jq -r '.LoggingEnabled.TargetBucket // ""' | jq -R .)
           }
         },
         "policy_json": $(cat pol.json | jq -r '.Policy // ""' | jq -R .)
       }
     }]
   }
   EOF

4. Copy the snapshot and run stave:

   mkdir -p mydata
   cp snap1.json mydata/
   docker compose run --rm -T -v $(pwd)/mydata:/work/observations \
     stave stave apply --observations observations --max-unsafe 0s --format json

OWN
}

run_risk_chains() {
  cat <<'CHAINS'
================================================================
  Stave Risk Reasoning Engine — Safety Chains
================================================================

Stave reasons across co-failing controls to detect compound risks
that individual checks miss. Three built-in safety chains:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Chain: public_phi_exposure
  PHI data reachable from public internet with no encryption
  or audit trail — total safety envelope failure.

  Controls: CTL.S3.PUBLIC.001 + CTL.S3.ENCRYPT.001
            + CTL.S3.LOG.001 + CTL.CLOUDTRAIL.DATAREAD.001
  Threshold: 2 co-failing → CRITICAL compound finding
  Attack stages: initial_access + exfiltration + detection_evasion

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Chain: root_compromise_path
  Root account lacks fundamental protections. Without MFA,
  with active access keys, and admin policies — single
  credential theft gives unrestricted account control.

  Controls: CTL.IAM.ROOT.MFA.001 + CTL.IAM.ROOT.ACCESSKEY.001
            + CTL.IAM.POLICY.ADMIN.001 + CTL.IAM.ROOT.HWMFA.001
  Threshold: 2 co-failing → CRITICAL compound finding
  Attack stages: credential_access + persistence

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Chain: detection_blindness
  Multiple detection controls disabled simultaneously.
  Every other violation becomes invisible — the blast radius
  of any misconfiguration becomes unbounded.

  Controls: CTL.CLOUDTRAIL.ENABLED.001 + CTL.GUARDDUTY.ENABLED.001
            + CTL.CONFIG.ENABLED.001 + CTL.VPC.FLOWLOG.001
  Threshold: 2 co-failing → CRITICAL compound finding
  Blast radius: 2.5x multiplier on all co-occurring findings

================================================================

How risk scoring works:

  Environmental = base_impact × asset_sensitivity × exposure_vector
  Compound      = environmental × chain_escalation × blast_multiplier

  Chain escalation: 1 control=1.0x, 2=1.8x, 3+=2.5x (bounded)

  Asset sensitivity: phi=3.0, production=2.0, dev=0.5
  Exposure vector:   public=2.0, cross_account=1.5, vpc=1.0

The output is not a list of findings — it is a structured argument
about compound risk.

================================================================
CHAINS
}

case "${1:-}" in
  --list|-l)
    list_scenarios
    ;;
  --scenario|-s)
    num="${2:-}"
    if [ -z "$num" ]; then
      echo "Error: --scenario requires a number" >&2
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
  --risk-chains)
    run_risk_chains
    ;;
  --hipaa)
    run_hipaa "$@"
    exit $?
    ;;
  --z3-walkthrough)
    run_z3_walkthrough
    ;;
  --solver)
    shift
    run_solver "$@"
    ;;
  --try-your-own)
    show_try_your_own
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
