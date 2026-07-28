# S3 Logging Controls

Controls in this directory enforce audit logging at both the bucket level (server access logs) and object level (CloudTrail data events).

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.LOG.001 | Access Logging Required | Server access logging is disabled on the bucket |
| CTL.S3.AUDIT.OBJECTLEVEL.001 | CloudTrail Object-Level Logging Required | CloudTrail S3 data event logging is not enabled |

## Why Two Controls

S3 has two independent logging mechanisms that serve different purposes:

1. **Server access logging (LOG.001):** Records bucket-level operations (ListBucket, GetBucketPolicy, etc.) to a target bucket. This is the baseline audit trail for all S3 buckets.

2. **CloudTrail object-level logging (AUDIT.OBJECTLEVEL.001):** Records individual object operations (GetObject, PutObject, DeleteObject) via CloudTrail data events. Required for HIPAA audit controls where per-object access forensics are needed. Severity is high because without it, there is no evidence of individual PHI access.

## Compliance Mapping

| Control | HIPAA | CIS AWS 1.4.0 | PCI DSS 3.2.1 | SOC 2 |
|---------|-------|---------------|---------------|-------|
| LOG.001 | 164.312(b) | 2.1.3 | 10.2.1 | CC7.2 |
| AUDIT.OBJECTLEVEL.001 | 164.312(b) | -- | -- | -- |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | LOG.001, AUDIT.OBJECTLEVEL.001 |
| `properties.storage.logging.enabled` | bool | LOG.001 |
| `properties.storage.logging.object_level_logging.enabled` | bool | AUDIT.OBJECTLEVEL.001 |

Both controls gate on `kind == "bucket"`.
