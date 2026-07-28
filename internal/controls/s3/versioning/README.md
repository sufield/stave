# S3 Versioning Controls

Controls in this directory enforce object versioning and MFA delete protection for S3 buckets.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.VERSION.001 | Versioning Required | Bucket does not have versioning enabled |
| CTL.S3.VERSION.002 | Backup Buckets Must Have MFA Delete Enabled | Backup-tagged bucket does not have MFA delete enabled |

## Why Two Controls

Versioning and MFA delete are independent protections:

1. **Versioning (VERSION.001):** The baseline. Without versioning, deleted or overwritten objects are gone permanently. Versioning preserves prior versions for recovery.

2. **MFA delete (VERSION.002):** Versioning alone does not prevent deletion of versions. Any principal with `s3:DeleteObject` can permanently destroy backup data. MFA delete requires multi-factor authentication to delete object versions, protecting against ransomware and accidental mass deletion. Gates on `backup == "true"` tag because MFA delete is operationally expensive (requires root credentials) and is only enforced for backup buckets.

## Compliance Mapping

| Control | HIPAA | CIS AWS 1.4.0 | SOC 2 |
|---------|-------|---------------|-------|
| VERSION.001 | 164.312(c)(1) | 2.1.3 | CC6.1 |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | VERSION.001 |
| `properties.storage.versioning.enabled` | bool | VERSION.001 |
| `properties.storage.tags.backup` | string | VERSION.002 |
| `properties.storage.versioning.mfa_delete_enabled` | bool | VERSION.002 |

VERSION.001 gates on `kind == "bucket"`. VERSION.002 gates on `backup == "true"`.
