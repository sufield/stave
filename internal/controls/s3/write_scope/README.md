# S3 Write Scope Controls

Controls in this directory enforce restrictions on S3 signed upload policies to prevent arbitrary overwrite and content-type abuse.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.WRITE.SCOPE.001 | S3 Signed Upload Must Bind To Exact Object Key | Signed upload uses prefix-wide key permissions instead of exact key binding |
| CTL.S3.WRITE.CONTENT.001 | S3 Signed Upload Must Restrict Content Types | Signed upload does not restrict allowed content types |

## Attack Patterns

Signed upload policies are a common S3 integration pattern where the backend generates a presigned POST policy for the client. Two misconfiguration classes:

1. **Prefix-wide keys (WRITE.SCOPE.001):** Using `starts-with $key files/` instead of `eq $key files/uuid.jpg` allows the uploader to write to any path under the prefix. This enables arbitrary overwrite of other users' objects and cross-tenant tampering in shared buckets.

2. **Unrestricted content types (WRITE.CONTENT.001):** Without an exact `Content-Type` condition, an attacker can upload `image/svg+xml` or `text/html` files. When the bucket serves these directly (via S3 website hosting or CloudFront), the SVG/HTML executes JavaScript in the browser -- stored XSS.

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `type` | string | WRITE.SCOPE.001, WRITE.CONTENT.001 |
| `properties.s3_upload.operation` | string | WRITE.SCOPE.001, WRITE.CONTENT.001 |
| `properties.s3_upload.allowed_key_mode` | string | WRITE.SCOPE.001 |
| `properties.s3_upload.content_type_restricted` | bool | WRITE.CONTENT.001 |

Both controls gate on `type == "s3_upload_policy"` and `operation == "write"`. These are not bucket observations -- they evaluate upload policy configurations.
