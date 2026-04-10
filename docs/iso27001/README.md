# ISO 27001:2022 — Control Catalog

ISO/IEC 27001:2022 Annex A controls mapped to Stave. Organized by
the four ISO 27001:2022 themes plus compliance requirements.

## Coverage

| File | Theme | Total | Mapped | Manual |
|---|---|---|---|---|
| iso27001-theme8-technological.yaml | Theme 8 — Technological | 20 | 20 | 0 |
| iso27001-theme5-organizational.yaml | Theme 5 — Organizational | 10 | 2 | 8 |
| iso27001-theme67-people-physical.yaml | Theme 6+7 — People & Physical | 6 | 0 | 6 |
| iso27001-compliance.yaml | A.8.10-12 + Compliance | 5 | 2 | 3 |
| **Total** | | **41** | **24** | **17** |

## Key Mapping

Theme 8 (Technological) maps almost entirely to existing Stave
controls through HIPAA, CIS, SOC 2, PCI-DSS, and NIST:

| Annex A | Title | Stave Controls |
|---|---|---|
| A.8.3 | Access Restriction | S3.CONTROLS, S3.PUBLIC, RDS.PUBLIC, IAM.POLICY.ADMIN |
| A.8.5 | Authentication | IAM.ROOT.MFA, IAM.CONSOLE.MFA, IAM.PASSWORD.* |
| A.8.24 | Cryptography | S3.ENCRYPT.*, RDS.ENCRYPT, EC2.EBS.ENCRYPT, KMS.* |
| A.8.9 | Config Management | CONFIG.ENABLED, CONFIG.RULES |
| A.8.15 | Logging | CLOUDTRAIL.*, S3.LOG, VPC.FLOWLOG |
| A.8.16 | Monitoring | GUARDDUTY, SECURITYHUB, CLOUDWATCH.MONITOR.* |
