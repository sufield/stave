# S3 Encryption Controls

Controls in this directory enforce encryption at rest and in transit for S3 buckets, with stricter requirements for buckets containing classified or regulated data.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.ENCRYPT.001 | Encryption at Rest Required | Server-side encryption (SSE-S3 or SSE-KMS) must be enabled |
| CTL.S3.ENCRYPT.002 | Transport Encryption Required | Bucket policy must deny plaintext HTTP via `aws:SecureTransport=false` |
| CTL.S3.ENCRYPT.003 | PHI Buckets Must Use SSE-KMS with CMK | Buckets tagged `data-classification=phi` must use SSE-KMS with a customer-managed key |
| CTL.S3.ENCRYPT.004 | Sensitive Data Requires KMS Encryption | Any classified bucket (not `public` or `non-sensitive`) must use SSE-KMS, not SSE-S3 (AES256) |

## Why Four Controls

S3 encryption has two axes -- storage and transport -- and two tiers of key management:

1. **At rest (ENCRYPT.001):** The baseline. Any encryption is better than none. SSE-S3 (AES256) is the minimum acceptable configuration.

2. **In transit (ENCRYPT.002):** Without a `Deny` policy on `aws:SecureTransport=false`, S3 accepts plaintext HTTP requests. Data in flight is exposed to network-level interception.

3. **PHI data (ENCRYPT.003):** HIPAA requires organizations to control encryption keys for protected health information. SSE-S3 uses AWS-managed keys with no customer control over rotation, access policies, or audit logging. SSE-KMS with a customer-managed key (CMK) closes this gap.

4. **All classified data (ENCRYPT.004):** Extends the CMK requirement beyond PHI to any bucket tagged with a non-public data classification. Fires when `data-classification` is present and is not `public` or `non-sensitive`, and the algorithm is not `aws:kms`.

## Compliance Mapping

| Control | HIPAA | CIS AWS 1.4.0 | PCI DSS 3.2.1 | SOC 2 |
|---------|-------|---------------|---------------|-------|
| ENCRYPT.001 | 164.312(a)(2)(iv) | 2.1.1 | 3.4 | CC6.1 |
| ENCRYPT.002 | 164.312(e)(2)(ii) | 2.1.2 | 4.1 | CC6.1 |
| ENCRYPT.003 | -- | -- | -- | -- |
| ENCRYPT.004 | -- | -- | -- | -- |

ENCRYPT.003 and ENCRYPT.004 are organization-specific controls not mapped to external frameworks. They enforce key management posture based on data classification tags.

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.encryption.at_rest_enabled` | bool | ENCRYPT.001 |
| `properties.storage.encryption.in_transit_enforced` | bool | ENCRYPT.002 |
| `properties.storage.encryption.algorithm` | string | ENCRYPT.003, ENCRYPT.004 |
| `properties.storage.encryption.kms_key_id` | string | ENCRYPT.003 |
| `properties.storage.tags.data-classification` | string | ENCRYPT.003, ENCRYPT.004 |

ENCRYPT.001 and ENCRYPT.002 gate on `properties.storage.kind == "bucket"`. ENCRYPT.003 gates on `data-classification == "phi"`. ENCRYPT.004 gates on `data-classification` being present and not `public` or `non-sensitive`.
