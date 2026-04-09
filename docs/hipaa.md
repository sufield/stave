# HIPAA Compliance Evaluation

Stave evaluates infrastructure configurations against HIPAA Security Rule
technical safeguards (§164.312, §164.316) across 20 service domains. The
HIPAA profile loads all built-in controls and filters to the 64 controls
with HIPAA compliance mappings — covering 100% of §164.312 technical
safeguard checks.

## Quick Start

```bash
# Evaluate observations against the HIPAA profile
stave apply --profile hipaa --input observations.json --include-all

# JSON output for automation
stave apply --profile hipaa --input observations.json --include-all --format json

# CI gating — fail if any violation
stave apply --profile hipaa --input observations.json --include-all --quiet
```

Exit codes:
- `0` — compliant
- `2` — input or configuration error
- `3` — violations found

## HIPAA Profile

The `--profile hipaa` flag loads controls from every domain, then filters
by `hipaa` compliance tag. Unlike domain-specific profiles (aws-s3,
aws-iam, gcp-gcs) that load a single directory, the HIPAA profile is
cross-domain.

**Scope filtering**: By default, the profile applies PHI boundary
filtering (assets tagged `containsPHI: true` or `DataDomain: health`).
Use `--include-all` to evaluate all assets regardless of tags.

## Coverage Summary

| §164 Section | Description | Controls | Services |
|---|---|---|---|
| §164.312(a)(1) | Access Control | 12 | IAM, KMS, RDS, S3, VPC, Secrets Manager |
| §164.312(a)(2)(i) | Unique User Identification | 5 | IAM |
| §164.312(a)(2)(iv) | Encryption at Rest | 12 | S3, RDS, EC2, DynamoDB, SQS, SNS, Secrets Manager, Backup, CloudTrail, K8s |
| §164.312(b) | Audit Controls | 10 | CloudTrail, CloudWatch, AWS Config, S3, RDS, ELB, VPC, K8s |
| §164.312(c)(1) | Integrity | 2 | S3, AWS Config |
| §164.312(d) | Authentication | 4 | IAM, Cognito, RDS |
| §164.312(e)(1) | Transmission Security | 5 | S3, EC2, VPC, K8s |
| §164.312(e)(2)(ii) | Encryption in Transit | 6 | S3, RDS, ELB, API Gateway, ElastiCache |
| §164.316(b)(2) | Documentation Retention | 1 | S3 |
| **Total** | | **64** | **20 domains** |

## Controls by §164 Section

### §164.312(a)(1) — Access Control

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.IAM.POLICY.DIRECT.001 | No Direct Policy Attachment on IAM Users | IAM | low |
| CTL.IAM.POLICY.INLINE.001 | No Inline Policies on IAM Users | IAM | medium |
| CTL.IAM.ROOT.ACCESSKEY.001 | Root Account Must Not Have Access Keys | IAM | critical |
| CTL.KMS.POLICY.001 | KMS Key Policy Must Restrict Access | KMS | high |
| CTL.RDS.PUBLIC.001 | RDS Must Not Be Publicly Accessible | RDS | critical |
| CTL.S3.ACCESS.GRANTS.001 | S3 Access Grants Must Not Grant Broad Permissions | S3 | high |
| CTL.S3.CDN.EXPOSURE.001 | Private Bucket Must Not Be Publicly Exposed Via CloudFront | S3 | high |
| CTL.S3.MRAP.PAB.001 | Multi-Region Access Point Must Have Block Public Access | S3 | high |
| CTL.S3.PRESIGNED.001 | Presigned URL Access Must Be Restricted | S3 | medium |
| CTL.S3.PUBLIC.001 | No Public S3 Bucket Read | S3 | critical |
| CTL.SECRETSMANAGER.ACCESS.001 | Secrets Must Have Rotation Enabled | Secrets Manager | medium |
| CTL.VPC.SG.DEFAULT.001 | Default Security Group Must Restrict All Traffic | VPC | medium |

### §164.312(a)(2)(i) — Unique User Identification

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.IAM.CRED.ROTATION.001 | Access Keys Must Be Rotated Within 90 Days | IAM | medium |
| CTL.IAM.CRED.UNUSED.001 | Disable Unused Credentials | IAM | medium |
| CTL.IAM.PASSWORD.COMPLEXITY.001 | Password Must Require All Character Types | IAM | medium |
| CTL.IAM.PASSWORD.LENGTH.001 | Password Minimum Length Must Be At Least 14 | IAM | medium |
| CTL.IAM.PASSWORD.REUSE.001 | Password Reuse Prevention Must Be At Least 24 | IAM | medium |

### §164.312(a)(2)(iv) — Encryption at Rest

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.BACKUP.ENCRYPT.001 | Backups Must Be Encrypted | Backup | high |
| CTL.CLOUDTRAIL.ENCRYPT.001 | CloudTrail Logs Must Be Encrypted with KMS | CloudTrail | high |
| CTL.DYNAMODB.ENCRYPT.001 | DynamoDB Must Use Customer-Managed KMS Encryption | DynamoDB | high |
| CTL.EC2.EBS.ENCRYPT.001 | EBS Volumes Must Be Encrypted | EC2 | high |
| CTL.EC2.SNAPSHOT.ENCRYPT.001 | EBS Snapshots Must Be Encrypted | EC2 | high |
| CTL.K8S.SECRETS.ENCRYPT.001 | K8s Secrets Must Be Encrypted at Rest in etcd | K8s | high |
| CTL.RDS.ENCRYPT.001 | RDS Storage Encryption Must Be Enabled | RDS | high |
| CTL.S3.ENCRYPT.001 | Encryption at Rest Required | S3 | high |
| CTL.SECRETSMANAGER.ENCRYPT.001 | Secrets Must Be Encrypted with Customer-Managed KMS Key | Secrets Manager | high |
| CTL.SNS.ENCRYPT.001 | SNS Topics Must Be Encrypted with KMS | SNS | high |
| CTL.SQS.ENCRYPT.001 | SQS Queues Must Be Encrypted with KMS | SQS | high |
| CTL.VPC.FLOWLOG.ENCRYPT.001 | VPC Flow Logs Must Be Encrypted | VPC | medium |

### §164.312(b) — Audit Controls

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.CLOUDTRAIL.ENABLED.001 | CloudTrail Must Be Enabled in All Regions | CloudTrail | critical |
| CTL.CLOUDTRAIL.VALIDATION.001 | CloudTrail Log File Validation Must Be Enabled | CloudTrail | high |
| CTL.CLOUDWATCH.RETENTION.001 | CloudWatch Log Groups Must Have Retention Policy | CloudWatch | medium |
| CTL.CONFIG.ENABLED.001 | AWS Config Must Be Recording All Resource Types | AWS Config | high |
| CTL.ELB.LOG.001 | Load Balancer Access Logging Must Be Enabled | ELB | medium |
| CTL.K8S.AUDIT.001 | Kubernetes Audit Logging Must Be Enabled | K8s | high |
| CTL.RDS.LOG.001 | RDS Audit Logging Must Be Enabled | RDS | medium |
| CTL.S3.AUDIT.OBJECTLEVEL.001 | CloudTrail Object-Level Logging Required | S3 | high |
| CTL.S3.LOG.001 | Access Logging Required | S3 | high |
| CTL.VPC.FLOWLOG.001 | VPC Flow Logging Must Be Enabled | VPC | high |

### §164.312(c)(1) — Integrity

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.CONFIG.RULES.001 | AWS Config Must Have Active Rules | AWS Config | medium |
| CTL.S3.VERSION.001 | Versioning Required | S3 | medium |

### §164.312(d) — Person or Entity Authentication

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.COGNITO.MFA.001 | Cognito User Pool Must Enforce MFA | Cognito | high |
| CTL.IAM.CONSOLE.MFA.001 | Console Users Must Have MFA Enabled | IAM | high |
| CTL.IAM.ROOT.MFA.001 | Root Account Must Have MFA Enabled | IAM | critical |
| CTL.RDS.IAMAUTH.001 | RDS Must Enable IAM Authentication | RDS | medium |

### §164.312(e)(1) — Transmission Security

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.EC2.PUBLIC.001 | EC2 Must Not Have Public IP Addresses | EC2 | high |
| CTL.K8S.NETPOL.001 | Namespaces Must Have Network Policies | K8s | high |
| CTL.S3.NETWORK.POLICY.001 | VPC Endpoint Policy Must Restrict Access | S3 | medium |
| CTL.S3.NETWORK.VPC.001 | VPC Endpoint or IP Condition Required | S3 | medium |
| CTL.VPC.SG.UNRESTRICTED.001 | Security Groups Must Not Allow Unrestricted Ingress | VPC | high |

### §164.312(e)(2)(ii) — Encryption in Transit

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.APIGATEWAY.TLS.001 | API Gateway Must Enforce TLS 1.2 | API Gateway | high |
| CTL.ELASTICACHE.TRANSIT.001 | ElastiCache Must Have In-Transit Encryption | ElastiCache | high |
| CTL.ELB.HTTPS.001 | Load Balancer Must Redirect HTTP to HTTPS | ELB | high |
| CTL.ELB.TLS.001 | Load Balancer Must Use TLS 1.2 or Higher | ELB | high |
| CTL.RDS.SSL.001 | RDS Must Require SSL Connections | RDS | high |
| CTL.S3.ENCRYPT.002 | Transport Encryption Required | S3 | high |

### §164.316(b)(2) — Documentation Retention

| Control ID | Name | Service | Severity |
|---|---|---|---|
| CTL.S3.LOCK.001 | Compliance-Tagged Buckets Must Have Object Lock | S3 | high |

## Service Domains

The HIPAA profile evaluates assets from 20 service domains. Each domain
has its own property namespace in the observation contract.

| Domain | Asset Type | Property Namespace | HIPAA Controls |
|---|---|---|---|
| S3 | `aws_s3_bucket` | `storage.*` | 12 |
| IAM | `aws_iam_account`, `aws_iam_user` | `identity.*` | 12 |
| RDS | `aws_rds_instance` | `database.*` | 7 |
| VPC | `aws_vpc`, `aws_security_group` | `network.*` | 4 |
| EC2 | `aws_instance`, `aws_ebs_snapshot` | `compute.*` | 3 |
| ELB | `aws_load_balancer` | `loadbalancer.*` | 4 |
| K8s | `k8s_cluster`, `k8s_namespace` | `audit.*`, `secrets.*`, `network_policy.*` | 3 |
| Backup | `aws_backup_resource` | `backup.*`, `availability.*`, `replication.*` | 5 |
| CloudTrail | `aws_cloudtrail_trail` | `audit_trail.*` | 3 |
| KMS | `aws_kms_key` | `cryptography.*` | 1 |
| DynamoDB | `aws_dynamodb_table` | `database.*` | 1 |
| SQS | `aws_sqs_queue` | `messaging.*` | 1 |
| SNS | `aws_sns_topic` | `messaging.*` | 1 |
| Secrets Manager | `aws_secretsmanager_secret` | `secret.*` | 2 |
| CloudWatch | `aws_cloudwatch_log_group` | `log_group.*` | 1 |
| AWS Config | `aws_config_recorder` | `compliance.*` | 2 |
| API Gateway | `aws_apigateway_stage` | `api.*` | 1 |
| ElastiCache | `aws_elasticache_cluster` | `cache.*` | 1 |
| Cognito | `aws_cognito_user_pool` | `identity.*` | 1 |
| DNS | `dns_record` | `dns.*` | 0 (no HIPAA mapping) |

Shared namespaces: DynamoDB uses `database.*` with `kind: "table"`
alongside RDS `kind: "instance"`. Cognito uses `identity.*` with
`kind: "user_pool"` alongside IAM `kind: "account"` / `kind: "user"`.

## Compound Risk Detection

After individual control evaluation, the compound risk detector
identifies known dangerous combinations that represent higher risk than
any individual finding alone.

| Compound | Triggers | Severity | Risk |
|---|---|---|---|
| COMPOUND.001 | Public access + wildcard policy | critical | S3 + IAM lateral movement |
| COMPOUND.002 | Encrypted but publicly accessible | high | Encryption provides no benefit |
| COMPOUND.003 | VPC endpoint without endpoint policy | high | VPC wormhole to any S3 bucket |

## Acknowledged Exceptions

Legitimate configurations that intentionally fail controls can be
declared as acknowledged exceptions:

```yaml
exceptions:
  - control_id: CTL.S3.PUBLIC.001
    bucket: my-public-assets-bucket
    rationale: "CloudFront + OAI pattern — bucket is private to CloudFront"
    acknowledged_by: bala@example.com
    acknowledged_date: 2026-03-28
    requires_passing:
      - CTL.S3.ENCRYPT.001
      - CTL.S3.ENCRYPT.002
      - CTL.S3.LOG.001
```

Exceptions require compensating controls. If any compensating control
fails, the original violation stands.

## Severity Levels

| Level | Meaning | SLA |
|---|---|---|
| CRITICAL | Immediate risk of ePHI exposure | Remediate before production use |
| HIGH | Significant compliance gap | Remediate within the current sprint |
| MEDIUM | Defense-in-depth gap | Remediate within the current quarter |
| LOW | Informational finding | Remediate when convenient |

## Architecture

### How the HIPAA Profile Works

```
stave apply --profile hipaa --input observations.json --include-all
```

1. Load all controls from every embedded domain (20 directories)
2. Filter to controls with `hipaa` compliance tag (64 controls)
3. Load observation bundle (multi-domain asset snapshots)
4. Evaluate each asset against matching controls (by property namespace)
5. Detect compound risks across findings
6. Generate output (text, JSON, or SARIF)

### Profile Routing (cmd/apply/profile.go)

```go
func profileControlDomain(prof Profile) string {
    case ProfileHIPAA:
        return "" // Cross-domain: loads all directories
}

func profileComplianceFramework(prof Profile) policy.ComplianceFramework {
    case ProfileHIPAA:
        return "hipaa" // Filters by compliance tag
}
```

Domain-specific profiles (aws-s3, aws-iam, gcp-gcs) return a single
directory. HIPAA returns empty string (root), loading all domains, then
`filterByCompliance` keeps only controls with `hipaa:` in their
compliance mapping.

### Observation Bundle Format

The HIPAA profile uses bundled observations containing assets from
multiple domains:

```json
{
  "schema_version": "obs.v0.1",
  "snapshots": [
    {
      "captured_at": "2026-01-10T00:00:00Z",
      "assets": [
        {"id": "phi-bucket", "type": "aws_s3_bucket", "vendor": "aws", "properties": {"storage": {"kind": "bucket", ...}}},
        {"id": "phi-database", "type": "aws_rds_instance", "vendor": "aws", "properties": {"database": {"kind": "instance", ...}}},
        {"id": "main-trail", "type": "aws_cloudtrail_trail", "vendor": "aws", "properties": {"audit_trail": {"kind": "trail", ...}}}
      ]
    }
  ]
}
```

Each asset type uses its own property namespace. Controls match assets
by checking the `kind` discriminator within their namespace.

## BAA Disclaimer

Every report includes:

> Stave evaluates technical controls only. A BAA with AWS is a
> contractual prerequisite for HIPAA compliance that Stave cannot verify.

This appears in both text and JSON output formats.

## What HIPAA Does Not Cover

Stave evaluates **technical safeguards** (§164.312) and retention
requirements (§164.316). The following are outside Stave's scope:

- **Administrative safeguards** (§164.308) — workforce training, security
  management processes, contingency planning procedures
- **Physical safeguards** (§164.310) — facility access controls, workstation
  security, device and media controls
- **Breach notification** (§164.400-414) — incident response workflows,
  notification timelines
- **Business Associate Agreements** — contractual requirements between
  covered entities and business associates

These require organizational policies and procedures, not infrastructure
configuration checks.
