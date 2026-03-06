# HackerOne 1791558: Brave S3 Bucket Takeover

**Program:** Brave
**Report:** 1791558
**Title:** S3 Bucket Takeover : brave-apt

## Pattern

Stale apt install reference points to an unclaimed S3 bucket. An attacker can claim the bucket and host malicious repo artifacts served to users following public install threads.

## Modeling

Uses `s3_bucket_reference` resource with `bucket_exists`/`bucket_owned` booleans provided by the snapshot (no live checks). Same approach as e2e-h1-brave-1835133.

## Test Case

**T1 (2022-12-03, Unsafe):** `bucket_exists: false`, `bucket_owned: false`
- CTL.S3.BUCKET.TAKEOVER.001 fires

**T2 (2022-12-10, Fixed):** `bucket_exists: true`, `bucket_owned: true`
- CTL.S3.BUCKET.TAKEOVER.001 clears
