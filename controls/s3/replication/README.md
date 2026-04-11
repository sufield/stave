# S3 Replication Controls

Controls in this directory enforce S3 replication requirements for compliance-tagged and PHI buckets.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.REPLICATION.001 | Compliance-Tagged Buckets Must Have Replication Enabled | Compliance-tagged bucket has no replication configured |
| CTL.S3.REPLICATION.002 | PHI Replication Must Be Cross-Region | PHI bucket replication destination is in the same region as source |
| CTL.S3.REPLICATION.003 | Replication Destination Must Be Encrypted | Replication destination bucket does not have encryption configured |

## Why Three Controls

Replication has three independent failure modes:

1. **Not enabled (REPLICATION.001):** Compliance-tagged buckets need an independent copy for disaster recovery. Without replication, a regional outage or accidental deletion causes permanent data loss. Gates on `compliance` tag being present.

2. **Same-region only (REPLICATION.002):** Same-region replication (SRR) protects against accidental deletion but not regional outages. PHI data requires cross-region replication (CRR) to meet HIPAA contingency planning requirements. Gates on `data-classification == "phi"`.

3. **Destination unencrypted (REPLICATION.003):** Replication creates a shadow copy. If the destination is unencrypted, replicated data bypasses the source bucket's encryption controls. Gates on `replication.enabled == true`.

## Compliance Mapping

| Control | HIPAA | SOC 2 | NIST 800-53 | FedRAMP | ISO 27001 | PCI-DSS v4.0 | GDPR |
|---------|-------|-------|-------------|---------|-----------|--------------|------|
| REPLICATION.001 | 164.308(a)(7) | A1.1 | CP-9 | CP-9 | A.8.13 | | |
| REPLICATION.002 | 164.308(a)(7)(ii)(A) | A1.2 | CP-6(1) | CP-6(1) | | | |
| REPLICATION.003 | 164.312(a)(2)(iv) | CC6.1 | SC-28 | SC-28 | | 3.4.1 | Art.32 |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | REPLICATION.001, REPLICATION.002, REPLICATION.003 |
| `properties.storage.tags.compliance` | string | REPLICATION.001 |
| `properties.storage.tags.data-classification` | string | REPLICATION.002 |
| `properties.storage.replication.enabled` | bool | REPLICATION.001, REPLICATION.002, REPLICATION.003 |
| `properties.storage.replication.destination_region` | string | REPLICATION.002 |
| `properties.storage.replication.destination_encrypted` | bool | REPLICATION.003 |
| `properties.storage.replication.destination_kms_key_id` | string | REPLICATION.003 (remediation) |
| `properties.storage.replication.source_region` | string | REPLICATION.002 (remediation) |

REPLICATION.001 gates on `compliance` tag being present. REPLICATION.002 gates on `data-classification == "phi"` and `replication.enabled == true`. REPLICATION.003 gates on `replication.enabled == true`.
