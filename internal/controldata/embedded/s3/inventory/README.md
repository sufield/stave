# S3 Inventory Controls

Controls in this directory enforce S3 Inventory configuration for bucket content visibility.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.INVENTORY.001 | S3 Inventory Must Be Enabled for Visibility | Bucket does not have S3 Inventory configured |

## Why This Control

S3 Inventory provides a complete manifest of all objects in a bucket, including metadata like encryption status, storage class, and optionally ACL grants. This is essential for:

1. **Detecting misplaced data:** Without Inventory, there is no way to systematically identify sensitive files accidentally placed in public or unprotected buckets. Research has shown that 21% of publicly exposed S3 buckets contain sensitive data, often due to misplaced files.

2. **Verifying encryption coverage:** Inventory reports include encryption status for every object, enabling detection of unencrypted objects that bucket-level default encryption missed (e.g., objects uploaded before encryption was enabled).

3. **Auditing object-level ACLs:** With the optional ACL field, Inventory reveals which individual objects have public or overly permissive ACL grants — critical for buckets where BucketOwnerEnforced is not yet set.

4. **Macie alternative:** When Amazon Macie is not deployed or not available, S3 Inventory is the primary mechanism for systematic bucket content auditing at scale.

## Compliance Mapping

| Control | HIPAA | SOC 2 | NIST 800-53 | FedRAMP |
|---------|-------|-------|-------------|---------|
| INVENTORY.001 | 164.312(b) | CC7.2 | CM-8 | CM-8 |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | INVENTORY.001 |
| `properties.storage.inventory.enabled` | bool | INVENTORY.001 |
| `properties.storage.inventory.frequency` | string | INVENTORY.001 (remediation) |
| `properties.storage.inventory.optional_fields` | list | INVENTORY.001 (remediation) |

INVENTORY.001 fires when `inventory.enabled` is `false`.
