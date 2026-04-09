# CIS AWS Foundations Benchmark v3.0 — Invariant Catalog

Complete mapping of CIS AWS Foundations Benchmark v3.0.0 to Stave
invariant definitions. One YAML file per AWS service.

## Coverage

| File | Service | Controls | Automatable | Manual |
|---|---|---|---|---|
| cis-iam.yaml | IAM | 22 | 18 | 3 (+1 partial) |
| cis-iam-access-analyzer.yaml | IAM Access Analyzer | 1 | 1 | 0 |
| cis-config.yaml | AWS Config | 1 | 1 | 0 |
| cis-cloudtrail.yaml | CloudTrail | 6 | 6 | 0 |
| cis-cloudwatch.yaml | CloudWatch | 15 | 15 | 0 |
| cis-sns.yaml | SNS | 0 | 0 | 0 |
| cis-s3.yaml | S3 | 4 | 3 | 1 |
| cis-ec2.yaml | EC2 | 3 | 3 | 0 |
| cis-rds.yaml | RDS | 3 | 3 | 0 |
| cis-vpc.yaml | VPC | 7 | 6 | 1 |
| **Total** | | **60** | **54** | **6** |

2 CIS v3.0 controls are outside the requested service scope:
- 2.4.1 (EFS encryption) — EFS is not in scope
- 4.16 (Security Hub enabled) — Security Hub is not in scope

## Manual Controls

6 controls cannot be evaluated from a static configuration snapshot:

| CIS ID | Title | Reason |
|---|---|---|
| 1.1 | Current contact details | Human verification required |
| 1.2 | Security contact registered | Contact monitoring not verifiable |
| 1.3 | Security questions set | Console-only, no API |
| 1.21 | Identity federation | Organizational design decision |
| 2.1.3 | Data classification | Requires Macie discovery results |
| 5.5 | VPC peering least access | Requires business intent context |

## Existing Stave Control Mappings

31 of 62 CIS v3.0 controls map to existing Stave controls:

| CIS ID | Stave Control |
|---|---|
| 1.4 | CTL.IAM.ROOT.ACCESSKEY.001 |
| 1.5 | CTL.IAM.ROOT.MFA.001 |
| 1.8 | CTL.IAM.PASSWORD.LENGTH.001 |
| 1.9 | CTL.IAM.PASSWORD.REUSE.001 |
| 1.10 | CTL.IAM.CONSOLE.MFA.001 |
| 1.12 | CTL.IAM.CRED.UNUSED.001 |
| 1.14 | CTL.IAM.CRED.ROTATION.001 |
| 1.15 | CTL.IAM.POLICY.INLINE.001 + DIRECT.001 |
| 2.1.1 | CTL.S3.ENCRYPT.002 |
| 2.1.4 | CTL.S3.CONTROLS.001 |
| 2.2.1 | CTL.EC2.EBS.ENCRYPT.001 |
| 2.3.1 | CTL.RDS.ENCRYPT.001 |
| 2.3.3 | CTL.RDS.PUBLIC.001 |
| 3.1 | CTL.CLOUDTRAIL.ENABLED.001 |
| 3.2 | CTL.CLOUDTRAIL.VALIDATION.001 |
| 3.3 | CTL.CONFIG.ENABLED.001 |
| 3.5 | CTL.CLOUDTRAIL.ENCRYPT.001 |
| 3.7 | CTL.VPC.FLOWLOG.001 |
| 5.2 | CTL.VPC.SG.UNRESTRICTED.001 |
| 5.4 | CTL.VPC.SG.DEFAULT.001 |
| 5.6 | CTL.EC2.IMDSV2.001 |

## New Observation Properties Required

Properties not yet in the observation contract:

| Property | CIS Controls | Domain |
|---|---|---|
| `identity.root.hardware_mfa` | 1.6 | IAM |
| `identity.root.last_used_days` | 1.7 | IAM |
| `identity.access_keys.active_count` | 1.13 | IAM |
| `identity.access_keys.created_at_setup` | 1.11 | IAM |
| `identity.policies.has_admin_access` | 1.16 | IAM |
| `identity.support_role.exists` | 1.17 | IAM |
| `identity.certificates.has_expired` | 1.19 | IAM |
| `identity.policies.cloudshell_unrestricted` | 1.22 | IAM |
| `access_analyzer.enabled` | 1.20 | IAM Access Analyzer |
| `compute.iam_profile_attached` | 1.18 | EC2 |
| `database.auto_minor_version_upgrade` | 2.3.2 | RDS |
| `audit_trail.s3_bucket_logging_enabled` | 3.4 | CloudTrail |
| `audit_trail.s3_data_events.write_enabled` | 3.8 | CloudTrail |
| `audit_trail.s3_data_events.read_enabled` | 3.9 | CloudTrail |
| `cryptography.key_rotation_enabled` | 3.6 | KMS |
| `monitoring.metric_filters.*` | 4.1–4.15 | CloudWatch |
| `monitoring.alarms.*` | 4.1–4.15 | CloudWatch |
| `network.nacl.*` | 5.1 | VPC |
| `network.has_unrestricted_ipv6_ingress` | 5.3 | VPC |
