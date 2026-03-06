# HackerOne 1835133: Brave S3 Bucket Takeover

**Program:** Brave
**Report:** 1835133
**Title:** S3 Bucket Takeover "brave-browser-rpm-staging-release-test"

## Pattern

Stale install URL references an unclaimed S3 bucket. An attacker can claim the bucket and host malicious artifacts (keyrings, packages) served to users following the official install guide.

## Modeling

Uses `s3_bucket_reference` resource with `bucket_exists`/`bucket_owned` booleans provided by the snapshot (no live checks). Same approach as IBM/Apptio 2498255.

## Test Case

**T1 (2023-01-14, Unsafe):** `bucket_exists: false`, `bucket_owned: false`
- CTL.S3.BUCKET.TAKEOVER.001 fires

**T2 (2023-01-21, Fixed):** `bucket_exists: true`, `bucket_owned: true`
- CTL.S3.BUCKET.TAKEOVER.001 clears
