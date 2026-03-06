# HackerOne 2498255: IBM/Apptio S3 Bucket Takeover

**Program:** IBM/Apptio
**Report:** HackerOne 2498255
**Type:** S3 Bucket Takeover via Dangling Reference

## Pattern

Dangling or unclaimed S3 bucket references that are no longer owned by the organization enable bucket takeover attacks. An attacker can claim the unclaimed bucket and serve attacker-controlled content.

## Modeling

The test case models this risk as an `s3_bucket_reference` resource with two boolean properties:
- `bucket_exists`: Whether the referenced bucket still exists in AWS
- `bucket_owned`: Whether the bucket is owned by the organization

## Test Case

**T1 (2024-05-09, Unsafe):** Bucket reference with `bucket_exists: false` and `bucket_owned: false`

**T2 (2024-05-17, Still Unsafe):** Same bucket reference, still dangling after 8 days (192h > 168h threshold)

**Expected:** Exit 3 (violation), 1 finding for CTL.S3.BUCKET.TAKEOVER.001
