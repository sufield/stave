# SOC 2 Trust Service Criteria — Control Catalog

Complete mapping of SOC 2 Trust Service Criteria to Stave control
definitions. One YAML file per criteria section.

## Coverage

| File | Criteria | Total | Mapped | New | Manual |
|---|---|---|---|---|---|
| soc2-cc6.yaml | CC6 — Logical & Physical Access | 18 | 14 | 2 | 2 |
| soc2-cc7.yaml | CC7 — System Operations | 12 | 8 | 2 | 2 |
| soc2-cc8.yaml | CC8 — Change Management | 6 | 3 | 1 | 2 |
| soc2-cc9.yaml | CC9 — Risk Mitigation | 5 | 2 | 0 | 3 |
| soc2-a1.yaml | A1 — Availability | 8 | 5 | 2 | 1 |
| soc2-c1.yaml | C1 — Confidentiality | 8 | 7 | 0 | 1 |
| soc2-pi1.yaml | PI1 — Processing Integrity | 5 | 2 | 1 | 2 |
| **Total** | | **62** | **41** | **8** | **13** |

## Classification

- **MAPPED (41)**: Already covered by existing HIPAA or CIS v3.0
  controls. These controls need `soc2:` compliance tags added to
  existing ctrl.v1 YAML files.

- **NEW (8)**: Genuinely new controls not covered by HIPAA or CIS.
  These require new ctrl.v1 controls and potentially new service domains.

- **MANUAL (13)**: Cannot be verified from a static configuration
  snapshot. These are organizational processes (access reviews, risk
  assessments, vendor management, BCP/DR testing).

## New Controls Required

| SOC 2 ID | Control | Service | New Domain? |
|---|---|---|---|
| SOC2.CC6.15 | Access Analyzer no unresolved findings | IAM | No |
| SOC2.CC6.16 | S3 no wildcard principal | S3 | No (CTL.S3.ACCESS.002 exists) |
| SOC2.CC7.9 | GuardDuty enabled | GuardDuty | Yes |
| SOC2.CC7.10 | Security Hub enabled | Security Hub | Yes |
| SOC2.CC8.4 | CloudFormation drift detection | CloudFormation | Yes |
| SOC2.A1.6 | Auto Scaling multi-AZ | Auto Scaling | Yes |
| SOC2.A1.7 | Route 53 health checks | Route 53 | Yes |
| SOC2.PI1.3 | SQS dead-letter queue | SQS | No |

## New Domains Required

| Domain | Asset Type | Namespace | SOC 2 Control |
|---|---|---|---|
| guardduty | `aws_guardduty_detector` | `threat_detection.*` | CC7.9 |
| securityhub | `aws_securityhub` | `security_hub.*` | CC7.10 |
| cloudformation | `aws_cloudformation_stack` | `infrastructure.*` | CC8.4 |
| autoscaling | `aws_autoscaling_group` | `scaling.*` | A1.6 |
| route53 | `aws_route53_zone` | `dns_service.*` | A1.7 |

## Existing Framework Overlap

Most SOC 2 controls are already implemented through HIPAA and CIS:

- **CC6 (Access)**: 78% mapped to CIS IAM/VPC + HIPAA access controls
- **CC7 (Operations)**: 67% mapped to CIS CloudTrail/CloudWatch/Config
- **CC8 (Change Mgmt)**: 50% mapped to CIS monitoring controls
- **CC9 (Risk)**: 40% mapped — mostly organizational/manual
- **A1 (Availability)**: 63% mapped to HIPAA backup/availability
- **C1 (Confidentiality)**: 88% mapped to HIPAA encryption controls
- **PI1 (Processing)**: 40% mapped to CIS CloudTrail data events
