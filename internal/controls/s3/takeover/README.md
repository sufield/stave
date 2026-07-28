# S3 Bucket Takeover Controls

Controls in this directory detect dangling S3 references that enable bucket takeover attacks.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.BUCKET.TAKEOVER.001 | Referenced S3 Buckets Must Exist And Be Owned | External reference points to a bucket that does not exist or is not owned by your account |
| CTL.S3.DANGLING.ORIGIN.001 | CDN S3 Origins Must Not Be Dangling | CloudFront distribution references an S3 origin bucket that does not exist |

## Attack Pattern

Bucket takeover occurs when a DNS CNAME, CloudFront origin, or application config references an S3 bucket that does not exist. An attacker creates a bucket with that name in their own account and serves malicious content through your infrastructure.

1. **Generic references (BUCKET.TAKEOVER.001):** Covers DNS records, CDN origins, and application configs. Uses an `any` predicate -- fires if the bucket does not exist OR is not owned. These are different observation source types (`s3_ref`).

2. **CDN-specific (DANGLING.ORIGIN.001):** Specifically targets CloudFront distributions with dangling S3 origins. These are CDN observation types (`cdn.kind == "distribution"`). A dangling origin enables CDN content poisoning -- the attacker's content is cached and served at scale.

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.s3_ref.bucket_exists` | bool | BUCKET.TAKEOVER.001 |
| `properties.s3_ref.bucket_owned` | bool | BUCKET.TAKEOVER.001 |
| `properties.cdn.kind` | string | DANGLING.ORIGIN.001 |
| `properties.cdn.origins_has_dangling_s3` | bool | DANGLING.ORIGIN.001 |

BUCKET.TAKEOVER.001 fires on `any` (either missing or unowned). DANGLING.ORIGIN.001 gates on `cdn.kind == "distribution"`.
