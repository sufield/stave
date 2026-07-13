# Control Reference — ORG

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ORG.ALLFEATURES.001

**AWS Organizations Must Be in All Features Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; scs_c02: 1.1; soc2: CC6.1;

AWS Organizations must operate in ALL_FEATURES mode, not CONSOLIDATED_BILLING. Consolidated-billing-only mode disables SCPs, tag policies, AI opt-out policies, and backup policies — the entire organizational governance layer is unavailable. Without ALL_FEATURES mode, the management account cannot enforce guardrails on member accounts. Migrating from consolidated-billing to all-features requires consent from every member account.

**Remediation:** Enable all features in the organization via the AWS Organizations console or EnableAllFeatures API. This sends an invitation to each member account that must be accepted.

---

### CTL.ORG.CONTROLTOWER.DRIFT.001

**Control Tower Landing Zone Has Configuration Drift**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3, CM-6; scs_c02: 1.4; soc2: CC8.1;

The Control Tower landing zone has detected configuration drift from its baseline. Drift occurs when guardrails, OUs, or account configurations are modified outside Control Tower, creating gaps between intended and actual governance state. Drifted guardrails may not enforce intended restrictions.

**Remediation:** Resolve drift by re-registering the affected OU or resetting the landing zone. Review CloudTrail for the change that caused drift.

---

### CTL.ORG.CONTROLTOWER.ENABLED.001

**AWS Control Tower Must Be Enabled for Landing Zone Governance**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-3, CM-2; scs_c02: 1.4; soc2: CC6.1, CC8.1;

AWS Control Tower is not enabled. Control Tower provides a governed landing zone with preventive and detective guardrails across member accounts. Without it, account provisioning and baseline security configuration must be managed manually, leading to configuration drift and inconsistent security posture across the organization.

**Remediation:** Enable Control Tower from the management account. Select a home region, configure the log archive and audit accounts, and enable the default guardrails.

---

### CTL.ORG.REGION.SCP.001

**AWS Organizations Must Have an SCP Restricting Resource Creation to Approved Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; gdpr: Art.32; hipaa: 164.312(b); nist_800_53_r5: CM-7; pci_dss_v4.0: 12.5.2; soc2: CC7.1;

AWS Organizations must have a Service Control Policy that restricts resource creation to an approved set of AWS regions. Without a region restriction SCP, any IAM principal can create resources in any of 30+ regions — including regions where the organization has no CloudTrail, no GuardDuty, no Config recording, and no monitoring infrastructure. MITRE ATT&CK T1535 documents this as a defense evasion technique: attackers deliberately operate in unused regions to bypass cloud monitoring. A region restriction SCP closes all unmonitored regions simultaneously with a single organizational policy rather than requiring monitoring deployment to every region. This is the architectural complement to per-region monitoring controls — it eliminates the regions where monitoring is not deployed.

**Remediation:** Attach an SCP to the organization root with a Deny statement conditioned on aws:RequestedRegion that restricts resource creation to the organization's approved operating regions. Example condition: StringNotEquals aws:RequestedRegion [us-east-1, us-west-2, eu-west-1]. Exclude global services (IAM, CloudFront, Route 53) from the restriction using a NotAction list.

---

### CTL.ORG.SCP.AMPLIFY.DENY.001

**SCP Does Not Deny Amplify Usage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny Amplify service usage in member accounts. Amplify provisions CloudFront distributions, S3 buckets, Lambda@Edge functions, and IAM roles behind a separate API surface. These resources are invisible to the standard CloudFront, S3, and Lambda management APIs and run outside the organization's network security monitoring. Without an SCP denying amplify:*, any IAM principal can deploy internet-facing web applications with their own CDN, storage, and compute layer.

**Remediation:** Add an SCP denying amplify:* for all principals. Exclude specific accounts if Amplify is intentionally used.

---

### CTL.ORG.SCP.APPRUNNER.DENY.001

**SCP Does Not Deny App Runner Usage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny App Runner service usage in member accounts. App Runner creates fully managed container compute with public HTTPS endpoints and IAM execution roles outside the standard EC2/ECS API surface. Resources are invisible to ec2:DescribeInstances, not recorded by AWS Config resource types for EC2, and run in an AWS-managed VPC. Without an SCP denying apprunner:*, any IAM principal can provision internet-facing compute invisible to the organization's network security monitoring.

**Remediation:** Add an SCP denying apprunner:* for all principals. Exclude specific accounts if App Runner is intentionally used.

---

### CTL.ORG.SCP.BATCH.DENY.001

**SCP Does Not Deny AWS Batch Usage**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny AWS Batch service usage in member accounts. Batch provisions EC2 instances or Fargate compute with IAM execution roles behind the Batch API surface. Batch jobs can run arbitrary container images with the job role's permissions, and compute environments may use IMDSv1 by default. Without an SCP denying batch:*, any IAM principal can provision compute with broad permissions outside standard EC2/ECS governance.

**Remediation:** Add an SCP denying batch:* for all principals. Exclude specific accounts if Batch is intentionally used.

---

### CTL.ORG.SCP.BEANSTALK.DENY.001

**SCP Does Not Deny Elastic Beanstalk Usage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny Elastic Beanstalk service usage in member accounts. Beanstalk provisions EC2 instances, Auto Scaling groups, Elastic Load Balancers, security groups, S3 buckets, and optionally RDS databases behind the Beanstalk API surface. These resources are created with Beanstalk-managed defaults that may not match organizational security baselines — including overpermissioned security groups and public-facing load balancers. Without an SCP denying elasticbeanstalk:*, any IAM principal can provision internet-facing infrastructure outside the standard IaC governance pipeline.

**Remediation:** Add an SCP denying elasticbeanstalk:* for all principals. Exclude specific accounts if Beanstalk is intentionally used.

---

### CTL.ORG.SCP.CLOUD9.DENY.001

**SCP Does Not Deny Cloud9 Usage**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny Cloud9 service usage in member accounts. Cloud9 creates EC2 instances with security groups and IAM credentials behind the Cloud9 API surface. Environments can have direct SSH access from the internet and run with the credentials of the creating IAM principal. Without an SCP denying cloud9:*, any IAM principal can provision compute with network exposure and credential access outside normal EC2 governance.

**Remediation:** Add an SCP denying cloud9:* for all principals. Exclude specific accounts if Cloud9 is intentionally used.

---

### CTL.ORG.SCP.DEPUTYPREVENTION.001

**AWS Organizations Must Have an SCP Preventing Confused Deputy Attacks**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.1;

AWS Organizations must have a Service Control Policy that prevents confused deputy attacks by requiring sts:AssumeRole calls to include the aws:SourceAccount condition. Without this SCP, cross-account role assumption can be exploited by confused deputy attacks where a trusted service is tricked into acting on behalf of an unauthorized principal. This is a foundational cross-account trust boundary control.

**Remediation:** Attach an SCP to the organization root that denies sts:AssumeRole when the aws:SourceAccount condition key is not present. This forces all cross-account role assumptions to declare the source account, preventing confused deputy attacks.

---

### CTL.ORG.SCP.EMR.DENY.001

**SCP Does Not Deny EMR Usage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny EMR service usage in member accounts. EMR provisions EC2 instances with overpermissioned default security groups (ElasticMapReduce-master and ElasticMapReduce-slave) that allow broad inbound access. EMR clusters run with IAM roles that may have S3 and KMS access, and the default security groups are created automatically if none are specified. Without an SCP denying elasticmapreduce:*, any IAM principal can provision compute clusters with network exposure and broad data access.

**Remediation:** Add an SCP denying elasticmapreduce:* for all principals. Exclude specific accounts if EMR is intentionally used.

---

### CTL.ORG.SCP.LIGHTSAIL.DENY.001

**SCP Does Not Deny Lightsail Usage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny Lightsail service usage in member accounts. Lightsail operates outside the standard AWS governance boundary — it runs in an AWS-managed VPC, creates its own credential namespace, and is not recorded by AWS Config. Without an SCP denying lightsail:*, any IAM principal can provision shadow infrastructure invisible to the organization's CSPM, SIEM, and credential inventory.

**Remediation:** Add an SCP denying lightsail:* for all principals. Exclude specific accounts if Lightsail is intentionally used.

---

### CTL.ORG.SCP.MWAA.DENY.001

**SCP Does Not Deny MWAA Usage**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny MWAA (Managed Workflows for Apache Airflow) service usage in member accounts. MWAA provisions Fargate compute, S3 buckets for DAG storage, and CloudWatch log groups behind the Airflow API surface. The web server can be configured for public access, and DAGs execute arbitrary Python code with the MWAA execution role's permissions. Without an SCP denying airflow:*, any IAM principal can provision workflow orchestration compute with potentially broad permissions.

**Remediation:** Add an SCP denying airflow:* for all principals. Exclude specific accounts if MWAA is intentionally used.

---

### CTL.ORG.SCP.OBJECTLOCK.DOW.001

**SCP Must Restrict S3 Object Lock Retention Duration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

AWS Organizations must have a Service Control Policy that restricts S3 Object Lock retention duration. Without this SCP, any identity with s3:PutObjectRetention can lock objects for up to 100 years — locked objects cannot be deleted even by AWS, creating an irrecoverable denial-of-wallet condition. The SCP should deny s3:PutObjectRetention when s3:object-lock-remaining-retention-days exceeds the organization's maximum (e.g. 2555 days / 7 years). External principals invited via bucket policy bypass SCPs entirely, making this a necessary-but-not-sufficient control.

**Remediation:** Attach an SCP to the organization root that denies s3:PutObjectRetention when the condition key s3:object-lock-remaining-retention-days exceeds your maximum retention period. Also consider denying s3:PutBucketObjectLockConfiguration to prevent new Object Lock-enabled buckets without approval.

---

### CTL.ORG.SCP.S3NAMESPACE.001

**SCP Does Not Enforce S3 Account-Regional Namespace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not enforce the S3 account-regional namespace for new bucket creation. Without this enforcement, services that auto-create buckets with predictable names (Glue, SageMaker, CDK, Athena, Beanstalk, EMR Studio, CodeStar) use the global namespace, where an attacker who knows the account ID can pre-create the bucket in an unused region. The account-regional namespace (buckets in the format {prefix}-{account-id}-{region}-an) prevents cross-account name squatting by construction. An SCP requiring the s3:x-amz-bucket-namespace condition on s3:CreateBucket is the structural fix for the entire Bucket Monopoly attack class.

**Remediation:** Add an SCP denying s3:CreateBucket unless s3:x-amz-bucket-namespace matches the account-regional format. This prevents all future buckets from using the global namespace, eliminating the Bucket Monopoly attack surface for Glue, SageMaker, CDK, Athena, Beanstalk, and other services that auto-create predictable-name buckets.

---

### CTL.ORG.SCP.SAGEMAKER.DENY.001

**SCP Does Not Deny SageMaker Usage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny SageMaker service usage in member accounts. SageMaker provisions EC2 instances, EBS volumes, EFS file systems, and IAM execution roles behind the SageMaker API surface. Notebook instances can have direct internet access, and execution roles may have broad S3 and KMS permissions for training data access. Without an SCP denying sagemaker:*, any IAM principal can provision compute with data access and potential internet exposure outside the standard EC2 governance pipeline.

**Remediation:** Add an SCP denying sagemaker:* for all principals. Exclude specific accounts if SageMaker is intentionally used.

---

### CTL.ORG.TRUSTEDACCESS.001

**AWS Organizations Trusted Access Must Be Reviewed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

AWS Organizations trusted access allows AWS services to perform operations across all accounts in the organization. Each enabled trusted access service (CloudTrail, GuardDuty, Config, etc.) gains cross-account permissions. Unreviewed trusted access means services may have organization-wide permissions that were enabled for a project and never revoked.

**Remediation:** Review all enabled trusted access services. Disable any that are no longer needed. Use aws organizations list-aws-service-access-for-organization to list enabled services and disable-aws-service-access to revoke.

---

