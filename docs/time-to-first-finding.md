# Time To First Finding

Get your first real finding against your own AWS environment in under 10 minutes.

No agents, no credentials stored by Stave, no network calls during evaluation. You extract the data yourself with the AWS CLI, then Stave evaluates it offline.

## Prerequisites

- `stave` installed and on `PATH`
- AWS CLI configured with read access to the target account
- `jq` installed (for extracting observation data)

## Step 1: Extract a snapshot from your AWS account

Use the AWS CLI to pull S3 bucket configuration into a local directory. This is your extractor — a few shell commands you control.

```bash
mkdir -p snapshot-raw
aws s3api list-buckets > snapshot-raw/list-buckets.json
for bucket in $(jq -r '.Buckets[].Name' snapshot-raw/list-buckets.json); do
  aws s3api get-public-access-block --bucket "$bucket" > "snapshot-raw/${bucket}-pab.json" 2>/dev/null || true
  aws s3api get-bucket-acl --bucket "$bucket" > "snapshot-raw/${bucket}-acl.json" 2>/dev/null || true
  aws s3api get-bucket-policy --bucket "$bucket" > "snapshot-raw/${bucket}-policy.json" 2>/dev/null || true
  aws s3api get-bucket-encryption --bucket "$bucket" > "snapshot-raw/${bucket}-encryption.json" 2>/dev/null || true
  aws s3api get-bucket-logging --bucket "$bucket" > "snapshot-raw/${bucket}-logging.json" 2>/dev/null || true
  aws s3api get-bucket-versioning --bucket "$bucket" > "snapshot-raw/${bucket}-versioning.json" 2>/dev/null || true
done
```

This runs entirely in your terminal. Stave never sees your credentials.

## Step 2: Ingest the snapshot into observations

Convert the raw AWS CLI output into Stave's normalized observation format.

```bash
stave ingest --source-dir ./snapshot-raw --output-dir ./observations
```

## Step 3: Validate the observations

Check that the ingested data is well-formed before evaluation.

```bash
stave validate --controls controls/s3 --observations ./observations
```

If validation fails, the error message tells you exactly which field is missing or malformed. Fix your extractor script (Step 1) and re-run ingest.

## Step 4: Apply built-in controls

Run all 43 built-in S3 controls against your observations. This is where findings appear.

```bash
stave apply --controls controls/s3 --observations ./observations \
  --max-unsafe 168h --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format text
```

Example output:

```
Evaluation Results
==================

Summary
-------
  Controls evaluated:  43
  Assets evaluated:    12
  Attack surface:      2
  Violations:          3

Violations
----------
  1. CTL.S3.CONTROLS.001
     Public Access Block Must Be Enabled
     Asset: res:aws:s3:bucket:staging-uploads
     Remediation: Enable BlockPublicAccess on this bucket.

  2. CTL.S3.ENCRYPT.002
     Transport Encryption Required
     Asset: res:aws:s3:bucket:staging-uploads
     Remediation: Add a bucket policy requiring ssl-only access.

  3. CTL.S3.LOG.001
     Access Logging Required
     Asset: res:aws:s3:bucket:staging-uploads
     Remediation: Enable server access logging.
```

You now have your first findings with specific remediation guidance.

## Step 5: Fix and verify

Fix the issues in your AWS account, then take a second snapshot and re-evaluate.

```bash
# Fix the cloud config (e.g., enable BlockPublicAccess in AWS console or Terraform)

# Take a second snapshot
aws s3api get-public-access-block --bucket staging-uploads > snapshot-raw/staging-uploads-pab.json

# Re-ingest and re-evaluate
stave ingest --source-dir ./snapshot-raw --output-dir ./observations
stave apply --controls controls/s3 --observations ./observations \
  --max-unsafe 168h --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format text
```

If the fix worked, the finding disappears from the output. To formally verify:

```bash
# Save both evaluations
stave apply ... -f json > before.json   # (from Step 4)
stave apply ... -f json > after.json    # (after fix)
stave verify --before before.json --after after.json
```

## Step 6: Check status

See where you are in the workflow and what to do next:

```bash
stave status
```

## What if apply returns no findings?

Your infrastructure might be clean, or the threshold might be too high. Run:

```bash
stave diagnose --controls controls/s3 --observations ./observations
```

This explains why findings did not trigger — threshold too high, time span too short, no predicate matches, or data shape issues.

## What if validate fails?

The error tells you which field is missing or malformed. Common fixes:

- **Missing `source_type`**: add `"source_type": "aws-s3-snapshot"` to your observation JSON, or pass `--allow-unknown-input`
- **Missing `captured_at`**: add a timestamp to your observation: `"captured_at": "2026-03-15T00:00:00Z"`
- **Schema mismatch**: ensure observations use `obs.v0.1` format — flat JSON, no `"snapshots"` wrapper

Fix your extractor script, re-run `stave ingest`, and validate again.

## Summary

| Step | Command | What happens |
|---|---|---|
| 1 | AWS CLI + jq | Extract bucket config from your account |
| 2 | `stave ingest` | Normalize raw exports to observations |
| 3 | `stave validate` | Check observations are well-formed |
| 4 | `stave apply` | Evaluate 43 S3 controls, get findings |
| 5 | Fix + re-snapshot | Remediate, retake snapshot, re-evaluate |
| 6 | `stave verify` | Confirm the fix resolved the finding |
