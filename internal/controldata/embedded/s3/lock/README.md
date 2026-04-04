# S3 Object Lock Controls

Controls in this directory enforce S3 Object Lock (WORM) requirements for compliance-tagged and PHI buckets.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.LOCK.001 | Compliance-Tagged Buckets Must Have Object Lock Enabled | Bucket tagged with a compliance framework has Object Lock disabled |
| CTL.S3.LOCK.002 | PHI Buckets Must Use COMPLIANCE Mode Object Lock | PHI bucket with Object Lock uses GOVERNANCE mode instead of COMPLIANCE |
| CTL.S3.LOCK.003 | PHI Object Lock Retention Must Meet Minimum Period | PHI bucket Object Lock retention is shorter than 2190 days (6 years) |

## Why Three Controls

Object Lock has three independent failure modes:

1. **Not enabled (LOCK.001):** Compliance-tagged buckets (SOC2, GDPR, HIPAA, PCI-DSS) need WORM protection. Without Object Lock, objects can be deleted or overwritten at any time. Note: Object Lock can only be enabled at bucket creation.

2. **Wrong mode (LOCK.002):** GOVERNANCE mode allows privileged users to override retention. For PHI data, COMPLIANCE mode is required -- no user, including root, can delete protected objects during the retention period.

3. **Too short (LOCK.003):** Even in COMPLIANCE mode, a retention period shorter than 6 years means WORM protection expires before the HIPAA minimum retention period.

## Compliance Mapping

| Control | HIPAA | SOC 2 |
|---------|-------|-------|
| LOCK.001 | 164.316(b)(2) | CC6.1 |

LOCK.002 and LOCK.003 are organization-specific controls not mapped to external frameworks.

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | LOCK.001 |
| `properties.storage.tags.compliance` | string | LOCK.001 |
| `properties.storage.object_lock.enabled` | bool | LOCK.001, LOCK.002, LOCK.003 |
| `properties.storage.tags.data-classification` | string | LOCK.002, LOCK.003 |
| `properties.storage.object_lock.mode` | string | LOCK.002 |
| `properties.storage.object_lock.retention_days` | int | LOCK.003 |

LOCK.001 gates on `compliance` tag being present. LOCK.002 and LOCK.003 gate on `data-classification == "phi"` and `object_lock.enabled == true`.
