# S3 Macie Controls

Controls in this directory enforce Amazon Macie sensitive data discovery requirements for S3 buckets.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.DETECT.MACIE.001 | Sensitive Data Buckets Must Have Macie Enabled | Bucket with sensitive data classification is not monitored by Macie |
| CTL.S3.DETECT.MACIE.002 | Macie Automated Sensitive Data Discovery Must Be Active | Macie is enabled but automated discovery is not running |

## Why Two Controls

Macie monitoring has two independent failure modes:

1. **Not enabled (DETECT.MACIE.001):** Buckets with sensitive data classifications (phi, pii, confidential, internal) need Macie to detect sensitive data that arrives outside normal workflows. Without Macie, PII or credentials uploaded accidentally go undetected. Gates on `data-classification` being one of the sensitive values.

2. **Discovery not active (DETECT.MACIE.002):** Macie can be enabled but have no active classification job. A paused or cancelled job means new data uploaded after the last scan is never inspected. Automated discovery continuously samples bucket contents to catch sensitive data as it arrives. Gates on `macie.enabled == true`.

## Compliance Mapping

| Control | HIPAA | SOC 2 | NIST 800-53 | FedRAMP | PCI-DSS v4.0 | GDPR | ISO 27001 |
|---------|-------|-------|-------------|---------|--------------|------|-----------|
| DETECT.MACIE.001 | 164.312(b) | CC7.2 | RA-5 | RA-5 | 11.5.1 | Art.30 | A.8.12 |
| DETECT.MACIE.002 | 164.308(a)(1)(ii)(D) | CC7.2 | SI-4 | SI-4 | | | |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | DETECT.MACIE.001, DETECT.MACIE.002 |
| `properties.storage.tags.data-classification` | string | DETECT.MACIE.001 |
| `properties.storage.macie.enabled` | bool | DETECT.MACIE.001, DETECT.MACIE.002 |
| `properties.storage.macie.classification_job_active` | bool | DETECT.MACIE.001 (remediation) |
| `properties.storage.macie.automated_discovery` | bool | DETECT.MACIE.002 |

DETECT.MACIE.001 gates on `data-classification` being a sensitive value. DETECT.MACIE.002 gates on `macie.enabled == true`.
