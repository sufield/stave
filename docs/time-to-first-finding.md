# Time To First Finding

Goal: get your first finding in under 60 seconds with one command.

## Prerequisites

- `stave` installed and on `PATH`
- writable working directory

Optional (recommended):

- `jq` for quick JSON inspection

## Step 1: Run the Demo

```bash
stave demo
```

Expected terminal output:

```
Found 1 violation: CTL.S3.PUBLIC.001
Asset: s3://demo-public-bucket
Evidence: BlockPublicAccess=false, ACL=public-read
Fix: enable account/bucket Block Public Access + deny public principals

Example (Terraform):

  resource "aws_s3_bucket_public_access_block" "example" {
    bucket                  = aws_s3_bucket.example.id
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
Report: ./stave-report.json
```

## Step 2: View the Report

The demo saves a JSON report to `./stave-report.json` in your current directory. View it:

```bash
cat stave-report.json              # view the full JSON report
jq . stave-report.json             # pretty-print with jq (recommended)
jq '.summary' stave-report.json    # just the summary
```

## Step 3: Compare Safe vs Unsafe

Run the demo with a properly secured bucket to see what zero violations looks like:

```bash
stave demo --fixture known-good
```

Expected output:

```
Found 0 violations.
Report: ./stave-report.json
```

Compare the two reports:

```bash
stave demo --fixture known-bad     # default — one violation
cat stave-report.json              # see the finding details

stave demo --fixture known-good    # no violations
cat stave-report.json              # empty findings array
```

## Fast Path On Your Data

```bash
stave quickstart
```

`quickstart` auto-detects snapshots in your current directory and `./stave.snapshot/`:

- If a snapshot is found, it runs evaluation against it immediately.
- If no snapshot is found, it falls back to the built-in demo fixture.
- The report is always saved to `./stave-report.json`.

```bash
# View results
cat stave-report.json

# Deterministic variant (for CI or reproducible output):
stave quickstart --now 2026-01-15T00:00:00Z --report ./output/report.json
```

Output shape:

```
Source: <detected-path-or-built-in-demo-fixture>
Top finding: CTL.S3.PUBLIC.001
Asset: s3://demo-public-bucket
Fix: enable account/bucket Block Public Access + deny public principals (BlockPublicAccess=false, ACL=public-read)

Example (Terraform):

  resource "aws_s3_bucket_public_access_block" "example" {
    bucket                  = aws_s3_bucket.example.id
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
Report: stave-report.json
Next: run `stave demo --fixture known-good` to compare safe output.
```

## What Next? Check Status

After your first finding, run `stave status` to see where you are and what to do next:

```bash
stave status
```

This prints a summary of your project state (controls, snapshots, observations, last evaluation) and recommends the next command to run.

## Full Workflow After First Finding

```bash
# 1) Create a new project with built-in S3 pack enabled
mkdir -p ./stave-first-finding
cd ./stave-first-finding
stave init --profile aws-s3

# 2) Confirm readiness
stave plan

# 3) Run control engine and save findings
stave apply --format json > output/evaluation.json
```

Quick check:

```bash
cat output/evaluation.json                              # view the full output
jq '.summary.violations, .findings[0].control_id' output/evaluation.json  # summary
```

If `stave plan` is not ready, run exactly the `Next:` command shown in its output.

## If Apply Returns No Findings

Run:

```bash
stave diagnose --controls ./controls --observations ./observations
```

This explains why findings did not trigger (threshold too high, time span too short, no predicate matches, or data shape issues).
