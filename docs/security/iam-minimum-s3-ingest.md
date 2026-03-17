# Minimum IAM Permissions for S3 Ingest

This document is generated from the source-of-truth mapping in:
`internal/domain/s3/policy/manifest_iam.go`

The actions below are the minimum IAM permissions required for Stave S3 ingest workflows.

| Operation | IAM Action |
| :--- | :--- |
| `list-buckets` | `s3:ListAllMyBuckets` |
| `get-bucket-tagging` | `s3:GetBucketTagging` |
| `get-bucket-policy` | `s3:GetBucketPolicy` |
| `get-bucket-acl` | `s3:GetBucketAcl` |
| `get-public-access-block` | `s3:GetBucketPublicAccessBlock` |
