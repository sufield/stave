# Scope and support

## In scope
- 228 controls across 26 AWS/GCP/K8s service domains
- Offline analysis of local configuration snapshots (obs.v0.1)
- Deterministic findings and reports
- 10 compliance framework profiles: HIPAA, CIS AWS v3.0, SOC 2, PCI-DSS v4.0, NIST 800-53, FedRAMP, GDPR, FFIEC, ISO 27001, NIST CSF 2.0

## Service domains
S3, IAM, VPC, EC2, RDS, ELB, Kubernetes, Backup, CloudTrail,
CloudWatch, KMS, Config, Secrets Manager, DynamoDB, SQS, SNS,
CloudFormation, GuardDuty, Security Hub, Auto Scaling, Route 53,
Cognito, ElastiCache, API Gateway, GCS, DNS

## Out of scope
- Runtime behavior monitoring or agents
- Application-specific logic (CMS, e-commerce, etc.)
- Organizational processes (training, incident response plans, vendor management)
- Live API call history or metric alarm trigger state

## Supported commands
- `stave apply` — control evaluation (default and profile modes)
- `stave validate` — input validation
- `stave diagnose` — per-control analysis
- `stave ci` — CI/CD baseline and gating
- Tests: `make test`, `make e2e`, `make lint`
