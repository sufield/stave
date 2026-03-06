# IBB/RubyGems 2262939: CloudFront Dangling S3 Origin

**Program:** Internet Bug Bounty (RubyGems)
**Report:** 2262939
**Title:** CloudFront served content from unclaimed S3 bucket

## Pattern

CloudFront distribution references an S3 origin bucket that does not exist. An attacker can claim the bucket and serve poisoned content via the CDN.

## Modeling

Uses `properties.cdn.origins_has_dangling_s3` boolean on the CloudFront distribution resource. Derived from `s3_bucket_exists` per origin entry in the snapshot.

## Test Case

**T1 (2023-11-24, Unsafe):** `origins_has_dangling_s3: true`, `s3_bucket_exists: false`
- CTL.S3.DANGLING.ORIGIN.001 fires

**T2 (2023-12-05, Fixed):** `origins_has_dangling_s3: false`, `s3_bucket_exists: true`
- CTL.S3.DANGLING.ORIGIN.001 clears
