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

## 5. Chain Visualization

**When to use:** You want to see which compound attack paths are currently active — which controls are co-failing within each chain, and what attacker capability each active chain produces.

`stave graph chains` reads `chain_findings` from `stave apply` output and produces DOT text showing active chains.

1. **Generate chain graph** — from assessment output:

   ```bash
   stave graph chains --output ./output.json | dot -Tpng > chains.png
   ```

2. **Pipe from stave apply** — single pipeline:

   ```bash
   stave apply --controls controls/ --observations obs/ \
     | stave graph chains --output - | dot -Tsvg > chains.svg
   ```

3. **Include inactive chains** — show all defined chains for context:

   ```bash
   stave graph chains --output ./output.json --all | dot -Tpng > all-chains.png
   ```

**Reading the output:**
- **Clusters** are chains. Active chains have dashed borders colored by severity.
- **Nodes** inside clusters are co-failing controls.
- **Diamond terminus nodes** represent the attacker capability the chain produces, with the compound risk score.
- **Dotted clusters** (with `--all`) are inactive chains — defined but not currently triggered.

**Difference from coverage:** `stave graph coverage` shows which controls match which assets (a static coverage map). `stave graph chains` shows which compound threats are active right now (a dynamic risk view).

---

## 6. Filter Findings with jq

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

## 7. Generate Report and Filter with Unix Tools

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

## 8. Custom Output with --template

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

## 9. Command Aliases for Repeated Workflows

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

## 10. Pipeline Composition (stdin chaining)

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

## 12. Logic Audit Trace — Proof of Pass

**When to use:** You need to demonstrate to an auditor *why* every resource was marked compliant or non-compliant, with a verifiable reasoning chain.

1. **Run evaluation with trace enabled:**

   ```bash
   stave apply \
     --controls controls/s3 \
     --observations observations/ \
     --max-unsafe 7d \
     --format json \
     --trace audit_trace.json \
     > evaluation.json
   ```

2. **In CI/CD (via environment variable):**

   ```bash
   STAVE_TRACE=1 stave apply \
     --controls controls/s3 \
     --observations observations/ \
     --max-unsafe 7d \
     --format json > evaluation.json
   # audit_trace.json is written to the current directory
   ```

3. **Inspect the trace with jq:**

   ```bash
   # Show all PASS verdicts with their reasoning
   jq '.assessments[] | select(.verdict == "PASS") | {resource_id, steps}' audit_trace.json

   # Show all VIOLATION verdicts with finding links
   jq '.assessments[] | select(.verdict == "VIOLATION") | {resource_id, finding_id, steps}' audit_trace.json

   # Summary counts
   jq '.summary' audit_trace.json
   ```

---

## 13. PHI Access Governance

**When to use:** You need to know who has effective access to resources tagged `data-classification: phi` and whether any non-designated principals have access.

`stave nep resource` resolves all access paths (resource policies + identity-based policies) and classifies each principal as designated or non-designated.

1. **Show non-designated access to a PHI resource:**

   ```bash
   stave nep resource --snapshot obs.json \
     --resource arn:aws:s3:::phi-patient-records
   ```

2. **Show all principals including designated:**

   ```bash
   stave nep resource --snapshot obs.json \
     --resource arn:aws:s3:::phi-patient-records --all
   ```

3. **Use a different classification tag:**

   ```bash
   stave nep resource --snapshot obs.json \
     --resource arn:aws:s3:::pii-data --classification pii
   ```

4. **Graph visualization:**

   ```bash
   stave nep resource --snapshot obs.json \
     --resource arn:aws:s3:::phi-patient-records \
     --format dot | dot -Tpng > phi-access.png
   ```

5. **Exit codes:**
   - Exit 0: only designated principals have access
   - Exit 1: one or more non-designated principals have access

6. **Designated principal tags:**

   Mark a principal as authorized for PHI access with any of these tags:
   - `stave/phi-authorized: "true"`
   - `stave/role-type: "phi-processor"`
   - `stave/role-type: "administrative"`

**Relationship to CTL.IAM.NEP.PHI.001:** The control fires only when non-designated access exists. `stave nep resource` shows the complete access picture including designated principals (with `--all`), giving full visibility for audit.

---

## 14. Snapshot Cleanup

**When to use:** You have accumulated snapshot files and need to decide which to keep, archive, or delete. Stave provides per-file intelligence. Your external script executes the action.

1. **Generate inventory:**

   ```bash
   stave snapshot inventory --observations-dir ./observations/ --format json > inventory.json
   ```

2. **Review recommendations:**

   ```bash
   stave snapshot inventory --observations-dir ./observations/
   ```

3. **Sample cleanup script** (consumes JSON, executes actions):

   ```bash
   #!/bin/bash
   INVENTORY=$(stave snapshot inventory --observations-dir ./observations/ --format json)

   # Archive snapshots Stave recommends archiving
   echo "$INVENTORY" | jq -r \
     '.snapshots[] | select(.recommended_action == "archive") | .path' | \
     while read path; do
       aws s3 mv "$path" s3://my-archive-bucket/stave-snapshots/
       echo "Archived: $path"
     done

   # Delete snapshots Stave recommends deleting
   echo "$INVENTORY" | jq -r \
     '.snapshots[] | select(.recommended_action == "delete") | .path' | \
     while read path; do
       rm "$path"
       echo "Deleted: $path"
     done
   ```

4. **OpenMetrics for monitoring:**

   ```bash
   stave snapshot inventory --observations-dir ./observations/ \
     --format openmetrics --out /var/lib/node_exporter/textfile_collector/stave_inventory.prom
   ```

Stave never deletes or moves files. The external script owns the execution.
