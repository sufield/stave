#!/usr/bin/env bash
# extract-observations.sh — Extract pre-built observation JSON from tutorial articles.
# Requires: bash, jq
# Usage: ./extract-observations.sh [article-dir] [output-dir]
set -euo pipefail

ARTICLE_DIR="${1:-$(cd "$(dirname "$0")/../../../docs-content" && pwd)}"
OUTPUT_DIR="${2:-$(cd "$(dirname "$0")" && pwd)/scenarios}"

# Control metadata: number|control_id|severity|name|extra_flags
declare -a META=(
  "01|CTL.S3.PUBLIC.001|critical|No Public S3 Bucket Read|"
  "02|CTL.S3.CONTROLS.001|high|Public Access Block Must Be Enabled|"
  "03|CTL.S3.ENCRYPT.001|high|Encryption at Rest Required|"
  "04|CTL.S3.LOG.001|medium|Access Logging Required|"
  "05|CTL.S3.VERSION.001|medium|Versioning Required|"
  "06|CTL.S3.VERSION.002|medium|Backup Buckets Must Have MFA Delete Enabled|"
  "07|CTL.S3.GOVERNANCE.001|low|Data Classification Tag Required|"
  "08|CTL.S3.INCOMPLETE.001|low|Complete Data Required for Safety Assessment|"
  "09|CTL.S3.ENCRYPT.002|high|Transport Encryption Required|"
  "10|CTL.S3.PUBLIC.007|critical|No Public Read via Policy|"
  "11|CTL.S3.PUBLIC.003|critical|No Public Write Access|"
  "12|CTL.S3.ACCESS.002|high|No Wildcard Action Policies|"
  "13|CTL.S3.ACCESS.003|high|No External Write Access|"
  "14|CTL.S3.NETWORK.001|high|Public-Principal Policies Must Have Network Conditions|"
  "15|CTL.S3.PUBLIC.004|medium|No Public Read via ACL|"
  "16|CTL.S3.ACL.FULLCONTROL.001|critical|No FULL_CONTROL ACL Grants to Public|"
  "17|CTL.S3.ACL.RECON.001|high|No Public ACL Readability|"
  "18|CTL.S3.ACL.ESCALATION.001|high|No Public ACL Modification|"
  "19|CTL.S3.AUTH.READ.001|high|No Authenticated-Users Read Access|"
  "20|CTL.S3.AUTH.WRITE.001|high|No Authenticated-Users Write Access|"
  "21|CTL.S3.PUBLIC.LIST.001|high|No Public S3 Bucket Listing|"
  "22|CTL.S3.PUBLIC.LIST.002|high|Anonymous S3 Listing Must Be Explicitly Intended|"
  "23|CTL.S3.PUBLIC.005|medium|No Latent Public Read Exposure|"
  "24|CTL.S3.PUBLIC.006|critical|No Latent Public Bucket Listing|"
  "25|CTL.S3.ACCESS.001|high|No Unauthorized Cross-Account Access|"
  "26|CTL.S3.PUBLIC.002|critical|No Public S3 Buckets With Sensitive Data|"
  "27|CTL.S3.PUBLIC.PREFIX.001|high|Protected Prefixes Must Not Be Publicly Readable|"
  "28|CTL.S3.ENCRYPT.003|high|PHI Buckets Must Use SSE-KMS with Customer-Managed Key|"
  "29|CTL.S3.ENCRYPT.004|high|Sensitive Data Requires KMS Encryption|"
  "30|CTL.S3.LIFECYCLE.001|medium|Retention-Tagged Buckets Must Have Lifecycle Rules|"
  "31|CTL.S3.LIFECYCLE.002|medium|PHI Buckets Must Not Expire Data Before Minimum Retention|"
  "32|CTL.S3.LOCK.001|medium|Compliance-Tagged Buckets Must Have Object Lock Enabled|"
  "33|CTL.S3.LOCK.003|medium|PHI Object Lock Retention Must Meet Minimum Period|"
  "34|CTL.S3.LOCK.002|medium|PHI Buckets Must Use COMPLIANCE Mode Object Lock|"
  "35|CTL.S3.PUBLIC.008|critical|No Public List via Policy|"
  "36|CTL.S3.WEBSITE.PUBLIC.001|critical|No Public Website Hosting with Public Read|"
  "37|CTL.S3.REPO.ARTIFACT.001|medium|Public Buckets Must Not Expose VCS Artifacts|"
  "38|CTL.S3.WRITE.SCOPE.001|high|S3 Signed Upload Must Bind To Exact Object Key|--allow-unknown-input"
  "39|CTL.S3.WRITE.CONTENT.001|high|S3 Signed Upload Must Restrict Content Types|--allow-unknown-input"
  "40|CTL.S3.TENANT.ISOLATION.001|high|Shared-Bucket Tenant Isolation Must Enforce Prefix|"
  "41|CTL.S3.BUCKET.TAKEOVER.001|critical|Referenced S3 Buckets Must Exist And Be Owned|"
  "42|CTL.S3.DANGLING.ORIGIN.001|high|CDN S3 Origins Must Not Be Dangling|--allow-unknown-input"
  "43|CTL.S3.ACL.WRITE.001|critical|No Public Write via ACL|"
  "44|-|all|Full Hardening Audit|"
)

# Extract bash code blocks from markdown, run each block that contains
# shell commands (cat, jq, mkdir), skip blocks with only stave commands.
extract_article() {
  local num="$1"
  local md="$ARTICLE_DIR/${num}.md"
  local tmpdir
  tmpdir="$(mktemp -d)"

  if [ ! -f "$md" ]; then
    echo "SKIP: $md not found" >&2
    rm -rf "$tmpdir"
    return 1
  fi

  # Extract each bash code block into a separate numbered script
  awk '
    /^```bash$/ { in_block=1; block++; next }
    /^```$/     { in_block=0; next }
    in_block    { print > sprintf("'"$tmpdir"'/block_%03d.sh", block) }
  ' "$md"

  # Run each block that has shell commands, skip stave-only blocks
  for block in "$tmpdir"/block_*.sh; do
    [ -f "$block" ] || continue

    # Skip blocks that only contain stave commands
    if ! grep -qvE '^\s*(stave |$)' "$block"; then
      continue
    fi

    # Filter out stave lines, keep everything else
    grep -vE '^\s*stave ' "$block" > "$block.filtered" || true

    (cd "$tmpdir" && mkdir -p observations observations-after && bash "$block.filtered") >/dev/null 2>&1 || true
  done

  echo "$tmpdir"
}

echo "Extracting observations from $ARTICLE_DIR into $OUTPUT_DIR"
echo ""

for entry in "${META[@]}"; do
  IFS='|' read -r num ctl_id severity name flags <<< "$entry"
  article_num="${num#0}"  # strip leading zero for file lookup

  printf "  %s %-30s ... " "$num" "$ctl_id"

  tmpdir=$(extract_article "$article_num") || { echo "SKIP"; continue; }

  # Create scenario directory
  scenario_dir="$OUTPUT_DIR/$num"
  rm -rf "$scenario_dir"
  mkdir -p "$scenario_dir/bad" "$scenario_dir/fixed"

  # Write metadata
  echo "${ctl_id}|${severity}|${name}" > "$scenario_dir/meta.txt"
  if [ -n "$flags" ]; then
    echo "$flags" > "$scenario_dir/flags.txt"
  fi

  # Copy bad observations
  bad_count=0
  if ls "$tmpdir/observations"/*.json >/dev/null 2>&1; then
    cp "$tmpdir/observations"/*.json "$scenario_dir/bad/"
    bad_count=$(ls "$scenario_dir/bad/"*.json 2>/dev/null | wc -l)
  fi

  # Copy fixed observations
  fixed_count=0
  if ls "$tmpdir/observations-after"/*.json >/dev/null 2>&1; then
    cp "$tmpdir/observations-after"/*.json "$scenario_dir/fixed/"
    fixed_count=$(ls "$scenario_dir/fixed/"*.json 2>/dev/null | wc -l)
  fi
  # Clean up empty fixed dir
  if [ "$fixed_count" -eq 0 ]; then
    rmdir "$scenario_dir/fixed" 2>/dev/null || true
  fi

  rm -rf "$tmpdir"
  echo "bad=$bad_count fixed=$fixed_count"
done

echo ""
echo "Done. Scenarios in $OUTPUT_DIR"
