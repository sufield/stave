---
title: "Recipes"
sidebar_label: "Recipes"
sidebar_position: 10
description: "Multi-command workflow recipes for common Stave tasks."
---

# Recipes

Reusable multi-command workflows. Each recipe shows the exact commands, expected exit codes, and when to use it.

## 1. Validate, Evaluate, Diagnose — Standard Safety Check

**When to use:** You have observation snapshots and controls and want a complete safety assessment with troubleshooting.

1. **Validate inputs** — catch schema errors before evaluation:

   ```bash
   stave validate \
     --controls controls/s3 \
     --observations observations/
   ```

   Exit 0 means inputs are well-formed. Exit 2 means fix your inputs before continuing.

2. **Evaluate** — detect assets that have been unsafe too long:

   ```bash
   stave apply \
     --controls controls/s3 \
     --observations observations/ \
     --max-unsafe 168h \
     --now 2026-02-22T00:00:00Z
   ```

   Exit 0 = no violations. Exit 3 = violations found (review stdout JSON).

3. **Diagnose** — if results are unexpected, understand why:

   ```bash
   stave diagnose \
     --controls controls/s3 \
     --observations observations/ \
     --format text
   ```

   Diagnose explains missing or unexpected findings (threshold too high, time span too short, no predicate matches, etc.).

---

## 2. Terraform Snapshot to Evaluation

**When to use:** You have AWS CLI JSON exports from a Terraform-managed environment and want to evaluate them with Stave.

1. **Extract** — use an extractor (any language) to produce `obs.v0.1` JSON from your AWS snapshot directory. The input directory should contain files like `list-buckets.json`, `get-bucket-acl/<bucket>.json`, etc. See [Building an Extractor](extractor-prompt.md) for a jumpstart template.

2. **Validate** — confirm the extracted observation is well-formed:

   ```bash
   stave validate --in ./observations/snap-2026-02-22.json
   ```

3. **Evaluate** — run controls against the observations:

   ```bash
   stave apply \
     --controls controls/s3 \
     --observations ./observations/ \
     --max-unsafe 168h \
     --now 2026-02-22T00:00:00Z
   ```

   Remember: you need at least 2 observation snapshots (two points in time) for duration-based controls to detect violations.

---

## 3. CI Gate with Fix-Loop

**When to use:** In CI/CD, you want to verify that a remediation actually fixed the violations found in a before-state snapshot.

1. **Capture before-state observations** (pre-remediation) — use an extractor to produce `obs.v0.1` JSON from your AWS snapshot. See [Building an Extractor](extractor-prompt.md).

2. **Apply remediation** (your Terraform apply, script, etc.)

3. **Capture after-state observations** (post-remediation) — re-run your extractor against the post-remediation snapshot.

4. **Run fix-loop** — evaluate both states and produce a remediation report:

   ```bash
   stave ci fix-loop \
     --before ./obs-before \
     --after ./obs-after \
     --controls controls/s3 \
     --out ./ci-output \
     --now 2026-02-22T00:00:00Z
   ```

   Exit 0 = all violations resolved, none introduced. Exit 3 = remaining or new violations exist.

   Output files in `./ci-output/`:
   - `evaluation.before.json` — findings from before-state
   - `evaluation.after.json` — findings from after-state
   - `verification.json` — before/after comparison
   - `remediation-report.json` — summary for CI dashboards

---

## 4. Coverage Visualization

**When to use:** You want to see which controls apply to which assets and find coverage gaps before running a full evaluation.

1. **Generate DOT graph** — pipe to graphviz for rendering:

   ```bash
   stave graph coverage \
     --controls controls/s3 \
     --observations observations/ \
     --allow-unknown-input \
   | dot -Tpng > coverage.png
   ```

   Uncovered assets are highlighted in yellow. Control nodes appear in blue.

2. **JSON output** — for programmatic analysis:

   ```bash
   stave graph coverage \
     --controls controls/s3 \
     --observations observations/ \
     --format json \
   | jq '.uncovered_assets'
   ```

3. **Sanitized output** — for sharing without exposing asset names:

   ```bash
   stave graph coverage \
     --controls controls/s3 \
     --observations observations/ \
     --sanitize
   ```

---

## 5. Filter Findings with jq

**When to use:** You want to extract specific fields from Stave's JSON output for reporting or alerting.

**List violated control IDs:**

```bash
stave apply \
  --controls controls/s3 \
  --observations observations/ \
  --max-unsafe 168h \
  --now 2026-02-22T00:00:00Z \
| jq -r '.findings[].control_id'
```

**Count findings by severity:**

```bash
stave apply \
  --controls controls/s3 \
  --observations observations/ \
  --max-unsafe 168h \
  --now 2026-02-22T00:00:00Z \
| jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'
```

**Extract asset IDs with unsafe durations over 24h:**

```bash
stave apply \
  --controls controls/s3 \
  --observations observations/ \
  --max-unsafe 168h \
  --now 2026-02-22T00:00:00Z \
| jq '[.findings[] | select(.unsafe_duration_hours > 24) | {asset: .asset_id, hours: .unsafe_duration_hours}]'
```

---

## 6. Generate Report and Filter with Unix Tools

**When to use:** You want a human-readable report from evaluation output, or need to extract specific findings using unix text-processing tools.

1. **Evaluate** and save output:

   ```bash
   stave apply \
     --controls controls/s3 \
     --observations observations/ \
     --max-unsafe 168h \
     --now 2026-02-22T00:00:00Z \
     --out output
   ```

2. **Generate report**:

   ```bash
   stave report --in output/evaluation.json --out output/report.md
   ```

3. **Filter findings** with unix tools:

   ```bash
   # Find all public-exposure violations
   stave report --in output/evaluation.json | grep '^CTL.S3.PUBLIC'

   # Sort by duration (longest first)
   stave report --in output/evaluation.json | awk '/^CTL\./' | sort -t$'\t' -k5 -nr

   # Count violations per control
   stave report --in output/evaluation.json | awk -F'\t' '/^CTL\./{print $1}' | sort | uniq -c | sort -rn
   ```

---

## 7. Custom Output with --template

**When to use:** You want to extract specific fields from diagnose or validate output without jq.

**Validate summary as JSON:**

```bash
stave validate \
  --controls controls/s3 \
  --observations observations/ \
  --template '{{json .Summary}}'
```

**Diagnose summary:**

```bash
stave diagnose \
  --controls controls/s3 \
  --observations observations/ \
  --template '{{.Report.Summary.Snapshots}} snapshots, {{.Report.Summary.Diagnostics}} diagnostics'
```

---

## 8. Command Aliases for Repeated Workflows

**When to use:** You run the same stave commands frequently and want shortcuts.

```bash
# Create aliases for your project's common commands
stave alias set ev "apply --controls controls/s3 --observations observations --max-unsafe 24h"
stave alias set val "validate --controls controls/s3 --observations observations"
stave alias set diag "diagnose --controls controls/s3 --observations observations"

# Use them (extra flags are appended)
stave ev --now 2026-02-22T00:00:00Z
stave val --strict
stave diag --format json

# List all aliases
stave alias list

# Clean up
stave alias delete ev
```

---

## 9. Pipeline Composition (stdin chaining)

**When to use:** You want to chain Stave commands together using Unix pipes, or feed output into downstream tools without intermediate files.

1. **Evaluate and extract control IDs in one shot:**

   ```bash
   stave apply \
     --controls controls/s3 \
     --observations observations/ \
     --max-unsafe 168h \
     --now 2026-02-22T00:00:00Z \
   | jq -r '.findings[].control_id'
   ```

2. **Evaluate and feed into diagnose via stdin:**

   ```bash
   stave apply \
     --controls controls/s3 \
     --observations observations/ \
     --max-unsafe 168h \
     --now 2026-02-22T00:00:00Z \
   | stave diagnose \
     --previous-output - \
     --controls controls/s3 \
     --observations observations/
   ```

3. **Validate a control from stdin:**

   ```bash
   cat controls/s3/CTL.S3.PUBLIC.001.yaml | stave validate --in -
   ```

4. **File-mediated pipeline for CI:**

   ```bash
   # Step 1: Evaluate and save
   stave apply \
     --controls controls/s3 \
     --observations observations/ \
     --max-unsafe 168h \
     --format json \
     --out output

   # Step 2: CI gate
   stave ci gate --in output/evaluation.json

   # Step 3: Report
   stave report --in output/evaluation.json --out output/report.md

   # Step 4: Remediation guidance for a specific finding
   stave fix --input output/evaluation.json --finding CTL.S3.PUBLIC.001@my-bucket

   # Step 5: Generate enforcement artifacts
   stave enforce --in output/evaluation.json --mode pab --out output/enforcement
   ```

5. **Render coverage graph as PNG:**

   ```bash
   stave graph coverage \
     --controls controls/s3 \
     --observations observations/ \
   | dot -Tpng > coverage.png
   ```
