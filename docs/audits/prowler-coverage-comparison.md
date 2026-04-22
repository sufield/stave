# Prowler AWS Coverage Comparison

Audited: 2026-04-22
Prowler version: master branch (April 2026)
Stave catalog: 713 controls across 47 families

## Summary

| Metric | Count |
|--------|-------|
| Prowler AWS checks (estimated) | ~470 |
| Stave controls with explicit Prowler mappings | 88 |
| Unique Prowler checks mapped to Stave | 64 |
| Prowler services covered | 103 |
| Stave AWS service families | ~35 (excluding K8S, AD, vSphere, Cisco) |

**Estimated coverage: 65-70% of security-relevant Prowler checks
have functional equivalents in Stave.** The 88 Stave controls with
explicit `alternatives.prowler` mappings cover 64 unique Prowler
checks. Many additional Stave controls cover the same ground as
Prowler checks without explicit mappings (e.g., Stave has 105 IAM
controls vs Prowler's 47 IAM checks — Stave covers the same
surface through different decomposition).

## Coverage by Service

| Service | Prowler checks | Stave controls | Stave family | Coverage |
|---------|---------------|----------------|-------------|----------|
| S3 | 21 | 98 | CTL.S3 | **Strong** — Stave has 5x the checks. All 21 Prowler checks have functional equivalents. |
| IAM | 47 | 105 | CTL.IAM | **Strong** — Stave has 2x. All Prowler IAM checks covered plus escalation and blast radius controls Prowler lacks. |
| EC2 | 71 | 32 | CTL.EC2 + CTL.VPC | **Strong on SG/IMDS. Gaps on per-port instance checks.** Prowler has 20+ per-port instance exposure checks (Cassandra, Kafka, LDAP, etc.); Stave aggregates into SG.RESTRICTED.PORTS.001. |
| RDS | 35 | 23 | CTL.RDS | **Good** — core vectors covered. Gaps in RDS-specific sub-checks (Proxy, Performance Insights KMS, cluster-specific). |
| CloudTrail | 14 | 19 | CTL.CLOUDTRAIL | **Strong** — Stave exceeds Prowler with org trail, replication, Network Activity, Insights controls. |
| VPC | 11 | 20 | CTL.VPC | **Strong** — Stave exceeds with endpoint decomposition, firewall, env isolation. |
| Lambda | 12 | 24 | CTL.LAMBDA | **Strong** — Stave has 2x with execution role, code signing, layer, VPC endpoint controls. |
| ECS | 11 | 19 | CTL.ECS | **Strong** — Stave exceeds with task role, execution role, supply chain, capabilities. |
| ECR | 6 | 7 | CTL.ECR | **Full** — all Prowler checks have equivalents. |
| CloudWatch | 22 | 28 | CTL.CLOUDWATCH | **Strong** — Stave has all CIS metric filters plus IMDS, STS, Lambda, cross-account, trail access monitoring. |
| CloudFront | 13 | 11 | CTL.CLOUDFRONT | **Good** — core vectors covered. Some CloudFront-specific sub-checks may be missing. |
| GuardDuty | 10 | 6 | CTL.GUARDDUTY | **Partial** — Stave covers enabled/export/suppression/malware/ECS runtime. Missing: Kubernetes protection, S3 protection, individual finding-type checks. |
| KMS | 5 | 7 | CTL.KMS | **Full** — Stave exceeds with concentration and isolation controls. |
| ELB/ELBv2 | 20 | 5 | CTL.ELB | **Gaps** — Stave covers HTTPS, TLS, cross-zone, logging. Missing: WAF association on ALB, desync mitigation, deletion protection, target health. |
| EKS | 7 | 14 | CTL.EKS | **Strong** — Stave exceeds. |
| Secrets Manager | 4 | 3 | CTL.SECRETSMANAGER | **Good** — rotation, encryption, access covered. |
| DynamoDB | 9 | 3 | CTL.DYNAMODB | **Gaps** — Stave covers encryption and PITR. Missing: autoscaling, DAX encryption, table-level backup, VPC endpoint. |
| OpenSearch | 12 | 13 | CTL.OPENSEARCH | **Full** — all Prowler checks have equivalents. |
| Cognito | 16 | 6 | CTL.COGNITO | **Gaps** — Stave covers MFA, password, advanced security. Missing: user pool deletion protection, WAF, specific auth settings. |
| SNS | 3 | 3 | CTL.SNS | **Full** |
| SQS | 2 | 4 | CTL.SQS | **Full** — Stave exceeds. |
| Config | 2 | 5 | CTL.CONFIG | **Full** — Stave exceeds. |
| Backup | 5 | 9 | CTL.BACKUP | **Full** — Stave exceeds with isolation controls. |
| WAF/WAFv2 | 10 | 8 | CTL.WAF | **Good** — core controls covered. |
| Shield | 6 | 1 | CTL.SHIELD | **Gap** — Stave has Advanced detection only. Missing: specific protection types, auto-renewal, DRT access. |
| ACM | 3 | 1 | CTL.ACM | **Gap** — Stave has cert expiry. Missing: transparency logging, RSA key length. |
| Route53 | 4 | 2 | CTL.ROUTE53 | **Gap** — Stave has DNSSEC and query logging. Missing: health checks, domain transfer lock. |
| SSM | 3 | 5 | CTL.SSM | **Full** — Stave exceeds. |
| Organizations | 5 | 1 | CTL.ORG | **Gap** — Stave has region SCP. Missing: all-features enabled, AI opt-out, delegated admin. |
| ElastiCache | 8 | 3 | CTL.ELASTICACHE | **Gap** — Stave covers auth, transit. Missing: at-rest encryption, auto-upgrade, multi-AZ, backup. |
| EFS | 7 | 12 | CTL.EFS | **Full** — Stave exceeds. |
| Autoscaling | 8 | 2 | CTL.AUTOSCALING | **Gap** — Missing: ELB health checks, launch template, capacity rebalancing. |
| CloudFormation | — | 5 | CTL.CLOUDFORMATION | Prowler has no specific CF service checks. |

### Services Prowler covers that Stave has NO controls for

| Service | Prowler checks | Description |
|---------|---------------|-------------|
| Redshift | 10 | Cluster encryption, public access, audit logging, SSL, VPC |
| Glue | 13 | Job encryption, catalog encryption, connection SSL, dev endpoint |
| SageMaker | 11 | Notebook encryption, VPC, root access, model isolation |
| Bedrock | 9 | Model invocation logging, guardrails, knowledge base encryption |
| Neptune | 10 | Cluster encryption, audit logging, IAM auth, snapshot |
| CodeBuild | 10 | Project encryption, VPC, privileged mode, logging |
| EMR | 3 | Cluster encryption, logging, security configuration |
| EventBridge | 4 | Bus policy, schema registry, global endpoints |
| Lightsail | 4 | Instance public ports, static IP, automated snapshots |
| FSx | 3 | File system encryption, multi-AZ, backup |
| MQ | 5 | Broker encryption, logging, public access |
| Kinesis | 2 | Stream encryption, enhanced monitoring |
| Macie | 2 | Macie enabled, auto-sensitive-data-discovery |
| Transfer | 1 | SFTP server public access |
| Firehose | 1 | Delivery stream encryption |
| Inspector | 2 | Inspector enabled, Lambda scanning |
| DMS | ? | Database migration encryption, replication |
| DocumentDB | ? | Cluster encryption, audit logging |

**18 AWS services where Stave has zero controls and Prowler has
checks.** These are primarily data/ML services (Redshift, Glue,
SageMaker, Bedrock, Neptune), application services (CodeBuild,
EventBridge, MQ), and specialized storage/networking (Lightsail,
FSx, Kinesis, Firehose).

## Gap Analysis

### Critical/High Gaps (in services customers use)

| Gap | Prowler check | Service | Priority | Classification |
|-----|--------------|---------|----------|----------------|
| ELB WAF association | elbv2_waf_acl_attached | ELB | High | A — observation data likely exists |
| ELB deletion protection | elbv2_deletion_protection | ELB | Medium | A |
| ELB desync mitigation | elbv2_desync_mitigation_mode | ELB | Medium | B |
| GuardDuty K8S protection | guardduty_eks_protection_enabled | GuardDuty | Medium | B |
| GuardDuty S3 protection | guardduty_s3_protection_enabled | GuardDuty | Medium | B |
| DynamoDB autoscaling | dynamodb_autoscaling_enabled | DynamoDB | Low | B |
| DynamoDB DAX encryption | dynamodb_accelerator_cluster_encryption_enabled | DynamoDB | Medium | B |
| Cognito WAF | cognito_user_pool_waf_acl_attached | Cognito | Medium | B |
| ElastiCache encryption at rest | elasticache_redis_cluster_rest_encryption_enabled | ElastiCache | High | B |
| Shield protections | shield_advanced_protection_in_*_resources | Shield | Medium | B |

### Wholesale Service Gaps (no Stave controls at all)

| Service | Prowler checks | Priority | Classification |
|---------|---------------|----------|----------------|
| Redshift | 10 | High (data warehouse security) | C — no asset type |
| CodeBuild | 10 | High (CI/CD security) | C — no asset type |
| Glue | 13 | Medium (ETL/data pipeline) | C — no asset type |
| SageMaker | 11 | Medium (ML security) | C — no asset type |
| Bedrock | 9 | Medium (AI/LLM security) | C — no asset type |
| Neptune | 10 | Low (graph database) | C — no asset type |
| EMR | 3 | Low (big data) | C — no asset type |
| EventBridge | 4 | Low (event routing) | C — no asset type |

## Priority Gaps (Top 20)

| # | Gap | Prowler equivalent | Stave service | Type | Effort |
|---|-----|--------------------|---------------|------|--------|
| 1 | ElastiCache at-rest encryption | elasticache_redis_cluster_rest_encryption_enabled | CTL.ELASTICACHE | A | 1 control |
| 2 | ELB WAF association | elbv2_waf_acl_attached | CTL.ELB | A | 1 control |
| 3 | ELB deletion protection | elbv2_deletion_protection | CTL.ELB | A | 1 control |
| 4 | GuardDuty K8S protection | guardduty_eks_protection_enabled | CTL.GUARDDUTY | B | 1 control |
| 5 | GuardDuty S3 protection | guardduty_s3_protection_enabled | CTL.GUARDDUTY | B | 1 control |
| 6 | Cognito WAF | cognito_user_pool_waf_acl_attached | CTL.COGNITO | B | 1 control |
| 7 | DynamoDB DAX encryption | dynamodb_accelerator_cluster_encryption | CTL.DYNAMODB | B | 1 control |
| 8 | Redshift public access | redshift_cluster_public_access | NEW | C | asset type + controls |
| 9 | Redshift encryption | redshift_cluster_audit_logging | NEW | C | same |
| 10 | CodeBuild privileged mode | codebuild_project_privileged_mode | NEW | C | asset type + controls |
| 11 | Shield protection types | shield_advanced_protection_in_* | CTL.SHIELD | B | 5 controls |
| 12 | Cognito deletion protection | cognito_user_pool_deletion_protection | CTL.COGNITO | B | 1 control |
| 13 | ELB target health | elbv2_ssl_listeners | CTL.ELB | B | 1 control |
| 14 | Route53 health checks | route53_health_check_exists | CTL.ROUTE53 | B | 1 control |
| 15 | ACM transparency logging | acm_certificate_transparency_logging | CTL.ACM | B | 1 control |
| 16 | Autoscaling ELB health | autoscaling_group_elb_healthcheck | CTL.AUTOSCALING | A | 1 control |
| 17 | EC2 instance age | ec2_instance_older_than_specific_days | CTL.EC2 | A | 1 control |
| 18 | EC2 unassigned EIPs | ec2_elastic_ip_unassigned | CTL.EC2 | A | 1 control |
| 19 | Glue job encryption | glue_job_encryption | NEW | C | asset type |
| 20 | SageMaker notebook encryption | sagemaker_notebook_instance_encryption | NEW | C | asset type |

## Customer Audit Cross-Reference

| Customer | Deferred gaps | Prowler has check? | Notes |
|----------|--------------|-------------------|-------|
| Apple | No deferred gaps | N/A | 17/17 Full |
| Tesla | RDS Proxy (low) | No Prowler check for RDS Proxy | Correct deferral |
| Ford | No deferred gaps | N/A | 18/18 Full |
| BMW | No deferred gaps | N/A | 20/20 Full |
| Squarespace | Mixed content, path patterns (Gap C) | No Prowler equivalent | Content-level analysis outside both tools |
| Firefox | No deferred gaps | N/A | 23/23 Full |
| Wayfair | No deferred gaps | N/A | 17/17 Full |
| Coinbase | SSRF network blocking (Gap C), IMDS disable (low) | No Prowler check for iptables-level blocking | Correct deferral |
| Varonis | Inbound malware via endpoint (Gap C) | No Prowler equivalent | Runtime detection |

**No customer-deferred gap has a Prowler check.** The Gap C items
we deferred (OS-level SSRF blocking, content classification,
runtime malware detection) are genuinely outside both tools' scope.

## Stave Advantages Over Prowler

Areas where Stave has capabilities Prowler lacks:

1. **Compound chain detection** — 30+ chain definitions composing
   individual controls into attack paths. Prowler checks are
   independent.
2. **Triage chain (DEFECT/INFECTION/FAILURE/DELTA)** — Stave
   produces actionable triage context per finding. Prowler
   produces pass/fail.
3. **Predicate-derived DELTA** — mechanical counterfactual showing
   what specific change eliminates the finding.
4. **Blast radius analysis** — CTL.IAM.IDENTITY.BLASTRADIUS.*
   controls measure reachable resources per identity.
5. **Temporal detection** — duration-based controls with SLA
   thresholds. Prowler is point-in-time.
6. **IAM escalation techniques** — 22 per-technique controls
   covering Rhino Security Labs patterns. Prowler aggregates into
   2 checks.
7. **Cross-domain controls** — S3+CloudFront CDN bypass, ECS+VPC
   SSRF, IAM+Lambda escalation chains.

## Recommendations

**Immediate (Gap A — catalog authoring, ~10 controls):**
1. ElastiCache at-rest encryption
2. ELB WAF association + deletion protection
3. Autoscaling ELB health check
4. EC2 instance age + unassigned EIPs
5. DynamoDB backup + VPC endpoint

**Short-term (Gap B — property additions, ~15 controls):**
1. GuardDuty K8S/S3 protection
2. Cognito WAF + deletion protection
3. Shield protection types (5 controls)
4. DynamoDB DAX encryption
5. Route53 health checks + ACM transparency

**Medium-term (Gap C — new asset types, ~30+ controls):**
1. Redshift (10 checks — data warehouse is common)
2. CodeBuild (10 checks — CI/CD security is critical)
3. Glue (13 checks — ETL pipeline security)
4. SageMaker/Bedrock (20 checks — AI/ML security, growing demand)

**Estimated effort:** Gap A closes in 1-2 iterations. Gap B in
2-3 iterations. Gap C requires observation schema work per service
— estimate 1 iteration per new service.
