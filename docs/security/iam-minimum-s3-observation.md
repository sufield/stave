# Minimum IAM Permissions for S3 Observation Collection

Stave evaluates local observation files. Users collect these observations
using the AWS CLI (or equivalent tools) before running Stave.

The table below lists the minimum IAM permissions required to run the
AWS CLI commands that produce S3 observation data.

| AWS CLI Command | IAM Action |
| :--- | :--- |
| `aws s3api list-buckets` | `s3:ListAllMyBuckets` |
| `aws s3api get-bucket-tagging` | `s3:GetBucketTagging` |
| `aws s3api get-bucket-policy` | `s3:GetBucketPolicy` |
| `aws s3api get-bucket-acl` | `s3:GetBucketAcl` |
| `aws s3api get-public-access-block` | `s3:GetBucketPublicAccessBlock` |
| `aws s3api get-bucket-encryption` | `s3:GetEncryptionConfiguration` |
| `aws s3api get-bucket-versioning` | `s3:GetBucketVersioning` |
| `aws s3api get-object-lock-configuration` | `s3:GetBucketObjectLockConfiguration` |
| `aws s3api get-bucket-logging` | `s3:GetBucketLogging` |
| `aws s3api get-bucket-lifecycle-configuration` | `s3:GetLifecycleConfiguration` |

## Example: Minimal IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketTagging",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketLogging",
        "s3:GetLifecycleConfiguration"
      ],
      "Resource": "*"
    }
  ]
}
```

These are **read-only** permissions. No write, delete, or administrative
access is required.

After collecting the AWS CLI output, use `jq` or a custom script to
transform it into observation files conforming to the `obs.v0.1` schema.
See [S3 Assessment Workflow](../s3-assessment.md) for the end-to-end process.
