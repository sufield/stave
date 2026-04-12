# Control Reference

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`

**Total controls:** 253
**Pack hash:** `2f1cad2a3a173125012c61f2a0cdc05f9aad4990150465fdeb40a5d9506c4530`

## Summary

| Severity | Count |
|----------|-------|
| critical | 34 |
| high | 107 |
| info | 16 |
| low | 15 |
| medium | 81 |

| Domain | Count |
|--------|-------|
| exposure | 198 |
| governance | 2 |
| identity | 49 |
| storage | 4 |

## Controls

### CTL.APIGATEWAY.AUTH.001

**API Routes Must Have Authorization Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

API Gateway routes and methods must have an authorizer configured (Cognito, Lambda, IAM, or JWT). Routes with authorization set to NONE are publicly accessible without any identity verification. The Trello breach (2024) exposed 15 million accounts through an unauthenticated API endpoint. The Spoutible breach (2024) leaked user data through an API without proper auth checks.

**Remediation:** Configure an authorizer on all non-health-check routes. Use Cognito user pools, Lambda authorizers, IAM authorization, or JWT authorizers depending on the client type.

---

### CTL.APIGATEWAY.INCOMPLETE.001

**Complete Data Required for API Gateway Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required API Gateway properties.

**Remediation:** Ensure the extractor calls aws apigateway get-rest-apis and aws apigateway get-domain-names and maps security policy to the api observation properties.

---

### CTL.APIGATEWAY.TLS.001

**API Gateway Must Enforce TLS 1.2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

API Gateway stages must enforce TLS 1.2 or higher. Allowing older TLS versions exposes API traffic to known cryptographic attacks (BEAST, POODLE, etc).

**Remediation:** Set the minimum TLS version on the custom domain or API stage. For REST APIs, configure a security policy of TLS_1_2 on the custom domain name.

---

### CTL.AUTOSCALING.INCOMPLETE.001

**Complete Data Required for Auto Scaling Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Auto Scaling properties.

**Remediation:** Ensure the extractor calls aws autoscaling describe-auto-scaling-groups.

---

### CTL.AUTOSCALING.MULTIAZ.001

**Auto Scaling Groups Must Span Multiple Availability Zones**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: A1.1;

Auto Scaling groups must be configured across multiple AZs. A single-AZ ASG has a single point of failure during AZ outages.

**Remediation:** Update the ASG: aws autoscaling update-auto-scaling-group --auto-scaling-group-name <name> --availability-zones us-east-1a us-east-1b

---

### CTL.BACKUP.ENCRYPT.001

**Backups Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; ffiec: BCP; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

All backups must be encrypted at rest. Unencrypted backups expose data if the backup storage is compromised or the backup is shared across accounts.

**Remediation:** Enable encryption on the backup vault or copy the backup with encryption enabled. For AWS Backup, set the vault encryption key to a customer-managed KMS key.

---

### CTL.BACKUP.EXISTS.001

**Critical Resources Must Have Backups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Resources tagged as critical or containing PHI must have at least one backup configured. Without backups, data loss from accidental deletion, corruption, or ransomware is permanent and unrecoverable.

**Remediation:** Configure automated backups via AWS Backup, RDS automated snapshots, or S3 cross-region replication depending on the resource type.

---

### CTL.BACKUP.INCOMPLETE.001

**Complete Data Required for Backup Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Backup safety cannot be assessed when backup status is missing from the snapshot. The extractor must populate backup.has_backup.

**Remediation:** Re-run the extractor with backup permissions: backup:ListBackupJobs, backup:DescribeBackupVault, rds:DescribeDBSnapshots, s3:GetBucketReplication.

---

### CTL.BACKUP.MULTIAZ.001

**Critical Resources Must Be Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Resources tagged as critical must be deployed across multiple Availability Zones. Single-AZ deployment has a single point of failure that causes unavailability during AZ outages.

**Remediation:** Enable Multi-AZ deployment or configure cross-AZ replication depending on the resource type (RDS Multi-AZ, S3 cross-region replication, ELB multi-AZ targets).

---

### CTL.BACKUP.RECENT.001

**Backups Must Be Recent**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** ffiec: BCP; hipaa: 164.308(a)(7); soc2: A1.1;

The most recent backup must be within the defined recovery point objective (RPO). Stale backups indicate a broken backup process and increase data loss exposure.

**Remediation:** Verify the backup schedule is active and producing successful backups. Check AWS Backup job history or RDS automated snapshot timestamps.

---

### CTL.BACKUP.REPLICATION.001

**Critical Data Must Have Cross-Region Replication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Data classified as critical or PHI must have cross-region replication configured for disaster recovery. Single-region data is vulnerable to regional outages and cannot meet recovery time objectives (RTO) for multi-region failover.

**Remediation:** Configure cross-region replication: S3 CRR, RDS cross-region read replica, or AWS Backup cross-region copy rule.

---

### CTL.CLOUDFORMATION.DRIFT.001

**CloudFormation Stack Drift Detection Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

CloudFormation stacks managing production infrastructure must have drift detection enabled. Drift indicates out-of-band changes bypassing IaC.

**Remediation:** Detect drift: aws cloudformation detect-stack-drift --stack-name <name>. Configure periodic detection via EventBridge.

---

### CTL.CLOUDFORMATION.INCOMPLETE.001

**Complete Data Required for CloudFormation Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudFormation properties.

**Remediation:** Ensure the extractor calls aws cloudformation describe-stacks.

---

### CTL.CLOUDFORMATION.ROLLBACK.001

**CloudFormation Stacks Must Have Rollback Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

CloudFormation stacks must not have DisableRollback set to true. With rollback disabled, a failed deployment leaves resources in a partially created state that may be insecure. Rollback ensures failed changes are reverted to the last known-good state.

**Remediation:** Remove DisableRollback from stack creation/update parameters. Ensure all stacks use the default rollback behavior.

---

### CTL.CLOUDFORMATION.STATE.001

**Terraform State Must Be Versioned**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

Terraform state files must be stored in a versioned backend (S3 with versioning, Terraform Cloud, or equivalent). Unversioned state means a corrupted or accidentally deleted state file cannot be recovered, leaving infrastructure in an unmanaged state with no rollback path.

**Remediation:** Configure an S3 backend with versioning enabled and DynamoDB state locking. Alternatively, use Terraform Cloud or an equivalent managed backend with built-in versioning.

---

### CTL.CLOUDTRAIL.DATAREAD.001

**S3 Object Read Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-3; gdpr: Art.30; nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.1.7; soc2: CC6.2;

CloudTrail must log S3 data read events (GetObject). Read logging provides evidence of data access for PHI audit trails and breach investigation.

**Remediation:** Add S3 data read event selectors to the trail using advanced event selectors with readOnly=true.

---

### CTL.CLOUDTRAIL.DATAWRITE.001

**S3 Object Write Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.8; fedramp_moderate: AU-3; gdpr: Art.30; nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.1.7; soc2: CC6.2;

CloudTrail must log S3 data write events (PutObject, DeleteObject). Without object-level write logging, individual object mutations are invisible to the audit trail.

**Remediation:** Add S3 data write event selectors to the trail using advanced event selectors with readOnly=false.

---

### CTL.CLOUDTRAIL.ENABLED.001

**CloudTrail Must Be Enabled in All Regions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.1; cis_aws_v3.0: 3.1; fedramp_moderate: AU-2; ffiec: ISH-4; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-2; nist_csf_2.0: DE.CM; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

CloudTrail must be configured as a multi-region trail. A single-region trail misses API activity in other regions, leaving gaps in the audit record that prevent forensic investigation of unauthorized access.

**Remediation:** Update the trail to enable multi-region logging. Run: aws cloudtrail update-trail --name xxx --is-multi-region-trail

---

### CTL.CLOUDTRAIL.ENCRYPT.001

**CloudTrail Logs Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.7; cis_aws_v3.0: 3.5; fedramp_moderate: AU-9; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC6.7;

CloudTrail logs must be encrypted at rest using a KMS customer-managed key. Default S3 encryption (SSE-S3) does not provide key revocation capability needed for breach response.

**Remediation:** Configure the trail to use a KMS key for log encryption. Run: aws cloudtrail update-trail --name xxx --kms-key-id arn:aws:kms:...

---

### CTL.CLOUDTRAIL.INCOMPLETE.001

**Complete Data Required for CloudTrail Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudTrail properties. A safety assessment cannot be completed without trail configuration data.

**Remediation:** Ensure the extractor calls aws cloudtrail describe-trails and aws cloudtrail get-trail-status and maps the response to the audit_trail observation properties.

---

### CTL.CLOUDTRAIL.RETENTION.001

**CloudTrail Logs Must Be Retained Beyond 90 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.3; fedramp_moderate: AU-11; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-11; nist_csf_2.0: DE.AE; pci_dss_v4.0: 10.7.1; soc2: CC7.1;

CloudTrail trail must deliver logs to an S3 bucket or CloudWatch Logs group with a retention policy that preserves logs beyond the 90-day CloudTrail Events History window. Without long-term retention, forensic investigation of incidents older than 90 days is impossible.

**Remediation:** Configure the trail to deliver logs to an S3 bucket with a lifecycle policy that retains objects for at least 365 days. Alternatively, deliver logs to a CloudWatch Logs group with a retention policy of 365 days or more.

---

### CTL.CLOUDTRAIL.S3LOG.001

**CloudTrail S3 Bucket Must Have Access Logging**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-9; nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC7.1;

The S3 bucket receiving CloudTrail logs must have server access logging enabled. Without it, access to the audit logs themselves is not auditable.

**Remediation:** Enable access logging on the trail S3 bucket: aws s3api put-bucket-logging --bucket <trail-bucket> --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-bucket>"}}'

---

### CTL.CLOUDTRAIL.VALIDATION.001

**CloudTrail Log File Validation Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.2; cis_aws_v3.0: 3.2; fedramp_moderate: AU-9; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-9; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

CloudTrail must have log file integrity validation enabled. Without validation, an attacker who gains access to the log bucket can modify or delete log entries to cover their tracks.

**Remediation:** Enable log file validation on the trail. Run: aws cloudtrail update-trail --name xxx --enable-log-file-validation

---

### CTL.CLOUDWATCH.INCOMPLETE.001

**Complete Data Required for CloudWatch Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudWatch log group properties.

**Remediation:** Ensure the extractor calls aws logs describe-log-groups and maps the retentionInDays to the log_group observation properties.

---

### CTL.CLOUDWATCH.LOG.RETENTION365.001

**CloudWatch Log Retention Must Be At Least 365 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-11; gdpr: Art.30; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.7;

CloudWatch log groups for cardholder data environment audit logs must retain logs for at least 365 days. PCI-DSS v4.0 requires 12 months of audit trail with at least 3 months immediately available.

**Remediation:** Set retention to at least 365 days: aws logs put-retention-policy --log-group-name <name> --retention-in-days 365

---

### CTL.CLOUDWATCH.MONITOR.AUTHFAIL.001

**Console Authentication Failures Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.6; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor console authentication failures. Failed console authentication attempts indicate brute force attacks against IAM user passwords.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for console authentication failures, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CMK.001

**CMK Disable or Deletion Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.7; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor cmk disable or deletion. KMS key disabling or scheduled deletion renders encrypted data permanently inaccessible — a ransomware vector.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for cmk disable or deletion, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CONFIG.001

**AWS Config Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.9; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor aws config changes. Changes to AWS Config (StopConfigurationRecorder) remove drift detection.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for aws config changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.GW.001

**Network Gateway Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.12; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor network gateway changes. Gateway attachment is the boundary between a VPC and the internet.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for network gateway changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.IAMPOLICY.001

**IAM Policy Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor iam policy changes. IAM policy modifications (CreatePolicy, DeletePolicy, AttachRolePolicy) are a primary persistence mechanism for attackers.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for iam policy changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.MFADEVICE.001

**MFA Device Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor MFA device enrollment and deactivation events. MFA device changes (CreateVirtualMFADevice, EnableMFADevice, DeactivateMFADevice, DeleteVirtualMFADevice) are a persistence mechanism — an attacker who gains temporary access can enroll their own MFA device to maintain access after the victim resets their password.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching CreateVirtualMFADevice, EnableMFADevice, DeactivateMFADevice, and DeleteVirtualMFADevice events. Create an alarm with an SNS notification action to alert on any MFA device change.

---

### CTL.CLOUDWATCH.MONITOR.NACL.001

**NACL Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.11; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor nacl changes. Network ACL changes can open or close network paths.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for nacl changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.NOMFA.001

**Console Sign-In Without MFA Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.2; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor console sign-in without mfa. Console sign-ins without MFA indicate either MFA is not enforced or credentials were used from a context that bypassed MFA.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for console sign-in without mfa, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ORG.001

**AWS Organizations Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.15; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor aws organizations changes. Organizations changes affect account-level governance and SCP enforcement.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for aws organizations changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ROOT.001

**Root Account Usage Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.3; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor root account usage. Root account API activity should be near-zero. Any activity may indicate compromise or unauthorized administrative action.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for root account usage, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ROUTE.001

**Route Table Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.13; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor route table changes. Route table modifications can redirect traffic through attacker-controlled paths.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for route table changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.S3POLICY.001

**S3 Bucket Policy Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor s3 bucket policy changes. S3 bucket policy changes (PutBucketPolicy, PutBucketAcl) can make private buckets public.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for s3 bucket policy changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.SG.001

**Security Group Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.10; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor security group changes. Security group changes directly affect network access to resources.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for security group changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.TRAIL.001

**CloudTrail Configuration Changes Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.5; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor cloudtrail configuration changes. Changes to CloudTrail (CreateTrail, UpdateTrail, DeleteTrail, StopLogging) are the first action in covering tracks after compromise.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for cloudtrail configuration changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.UNAUTH.001

**Unauthorized API Calls Must Be Monitored**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.1; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor unauthorized api calls. Unauthorized API calls (AccessDenied, UnauthorizedAccess) indicate credential probing or misconfigured IAM policies.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for unauthorized api calls, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.VPC.001

**VPC Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.14; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor vpc changes. VPC lifecycle changes affect the entire network boundary.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for vpc changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.RETENTION.001

**CloudWatch Log Groups Must Have Retention Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

CloudWatch Logs log groups must have a retention policy configured. Without a retention policy, logs are kept indefinitely (incurring cost) or may be deleted manually without audit trail.

**Remediation:** Set a retention policy on the log group. Run: aws logs put-retention-policy --log-group-name xxx --retention-in-days 365

---

### CTL.COGNITO.INCOMPLETE.001

**Complete Data Required for Cognito Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** identity

The observation snapshot is missing required Cognito user pool properties.

**Remediation:** Ensure the extractor calls aws cognito-idp describe-user-pool and maps MfaConfiguration to the identity observation properties.

---

### CTL.COGNITO.MFA.001

**Cognito User Pool Must Enforce MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); pci_dss_v4.0: 8.3.1; soc2: CC6.1;

Cognito user pools handling PHI must enforce multi-factor authentication. Without MFA, a compromised password grants full access to the application and any PHI it serves.

**Remediation:** Set MfaConfiguration to ON (required) on the user pool. Run: aws cognito-idp set-user-pool-mfa-config --user-pool-id xxx --mfa-configuration ON --software-token-mfa-configuration Enabled=true

---

### CTL.CONFIG.ENABLED.001

**AWS Config Must Be Recording All Resource Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.5; cis_aws_v3.0: 3.3; fedramp_moderate: CM-2; ffiec: CAT-D3; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.9; nist_800_53_r5: CM-2; nist_csf_2.0: PR.PS; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

AWS Config must be enabled and recording all supported resource types. Without Config, configuration changes are not tracked and drift from the desired security baseline cannot be detected.

**Remediation:** Enable the Config recorder with all resource types. Run: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:...,recordingGroup={allSupported=true}

---

### CTL.CONFIG.INCOMPLETE.001

**Complete Data Required for AWS Config Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required AWS Config properties.

**Remediation:** Ensure the extractor calls aws configservice describe-configuration-recorders and aws configservice describe-config-rules.

---

### CTL.CONFIG.RULES.001

**AWS Config Must Have Active Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; hipaa: 164.312(c)(1); nist_800_53_r5: CM-3; pci_dss_v4.0: 6.3.2; soc2: CC6.3;

AWS Config must have active Config Rules to evaluate resource compliance. Recording without rules provides change history but no automated drift detection.

**Remediation:** Deploy Config Rules for your compliance requirements. Start with AWS managed rules for common checks (encrypted-volumes, restricted-common-ports, etc).

---

### CTL.DNS.DANGLING.001

**DNS Records Must Not Point to Unclaimed Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records (CNAME, ALIAS, A) that reference external cloud resources must resolve to resources that exist and are owned by the organization. A dangling DNS record pointing to a deleted or unclaimed resource enables subdomain takeover — the attacker claims the resource and serves content under the organization's domain.

**Remediation:** Either claim the target resource in your cloud account to block takeover, or delete the DNS record that points to the unclaimed resource. Audit all DNS zones for records pointing to decommissioned infrastructure.

---

### CTL.DNS.DANGLING.002

**DNS Records to Cloud Storage Must Resolve to Owned Buckets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records that reference cloud storage endpoints (S3, GCS, Azure Blob) must resolve to buckets that exist and are owned by the organization. Storage bucket names are globally unique — a deleted bucket's name can be claimed by any account, enabling content injection under a trusted domain.

**Remediation:** Create the bucket in your cloud account to claim the name, or remove the DNS record. For software distribution URLs, update documentation to point to the current distribution endpoint.

---

### CTL.DNS.DANGLING.003

**DNS Records to Software Distribution Must Resolve to Owned Endpoints**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records or URLs that reference software distribution endpoints (package repositories, binary downloads, update servers) must resolve to resources owned by the organization. Supply chain takeover through dangling distribution references delivers executable code to systems that trust the source.

**Remediation:** Claim the resource to block takeover. Update all documentation, install guides, and CI pipelines to reference the current distribution URL. Search community forums and cached tutorials for outdated references.

---

### CTL.DYNAMODB.ENCRYPT.001

**DynamoDB Must Use Customer-Managed KMS Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

DynamoDB tables must use a customer-managed KMS key for encryption at rest. The default AWS-owned key does not support key revocation, audit of key usage, or cross-account key policies.

**Remediation:** Update the table encryption to use a customer-managed KMS key. Run: aws dynamodb update-table --table-name xxx --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=arn:...

---

### CTL.DYNAMODB.INCOMPLETE.001

**Complete Data Required for DynamoDB Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required DynamoDB properties.

**Remediation:** Ensure the extractor calls aws dynamodb describe-table and maps the SSEDescription to the database.encryption observation properties.

---

### CTL.DYNAMODB.PITR.001

**Point-in-Time Recovery Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7); nist_800_53_r5: CP-9; soc2: A1.1;

DynamoDB tables must have point-in-time recovery (PITR) enabled. Without PITR, accidental deletes, application bugs, or ransomware that corrupts table data cannot be recovered. PITR provides continuous backups with per-second granularity for the last 35 days.

**Remediation:** Enable PITR using aws dynamodb update-continuous-backups --table-name TABLE --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true.

---

### CTL.EC2.EBS.ENCRYPT.001

**EBS Volumes Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; cis_aws_v3.0: 2.2.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

EBS volumes attached to EC2 instances must have encryption enabled. Unencrypted volumes storing PHI or sensitive data violate encryption at rest requirements.

**Remediation:** Enable EBS encryption by default for the account. For existing volumes, create an encrypted snapshot and restore to a new encrypted volume. Run: aws ec2 enable-ebs-encryption-by-default

---

### CTL.EC2.IAMROLE.001

**EC2 Instances Must Use IAM Instance Roles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.18; soc2: CC6.8;

EC2 instances that access AWS services must use IAM instance profiles (roles) instead of embedded access keys. Instance roles provide temporary credentials that are automatically rotated.

**Remediation:** Create an IAM role and attach it to the instance: aws ec2 associate-iam-instance-profile --iam-instance-profile Name=<role> --instance-id <id>

---

### CTL.EC2.IMDSV2.001

**EC2 Instances Must Require IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.6; cis_aws_v3.0: 5.6; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

EC2 instances must enforce Instance Metadata Service Version 2 (IMDSv2). IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials from the metadata endpoint.

**Remediation:** Set HttpTokens to required on the instance metadata options. Run: aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required --http-endpoint enabled

---

### CTL.EC2.INCOMPLETE.001

**Complete Data Required for EC2 Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

EC2 instance safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate compute.encryption.ebs_encrypted.

**Remediation:** Re-run the extractor with EC2 permissions: ec2:DescribeInstances, ec2:DescribeVolumes, ec2:DescribeSnapshots.

---

### CTL.EC2.PUBLIC.001

**EC2 Instances Must Not Have Public IP Addresses**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.1; fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(e)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

EC2 instances should not have public IP addresses unless explicitly required. Public IP assignment exposes the instance to direct internet access, bypassing network perimeter controls.

**Remediation:** Launch instances in private subnets without public IP assignment. Use NAT Gateway or VPC endpoints for outbound internet access. Use ALB or NLB for inbound traffic that requires internet access.

---

### CTL.EC2.SNAPSHOT.ENCRYPT.001

**EBS Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

EBS snapshots must be encrypted. Unencrypted snapshots can be shared across accounts or made public, exposing data at rest.

**Remediation:** Copy the snapshot with encryption enabled. Delete the unencrypted snapshot. Enable EBS encryption by default for future snapshots.

---

### CTL.ECR.INCOMPLETE.001

**Complete Data Required for ECR Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

ECR repository safety cannot be proven when access control data is missing from the snapshot. The extractor must populate container_registry.access.public to evaluate exposure controls.

**Remediation:** Re-run the extractor with ECR permissions: ecr:DescribeRepositories, ecr:GetRepositoryPolicy.

---

### CTL.ECR.PUBLIC.001

**ECR Repository Must Not Be Public**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

ECR repositories must not be publicly accessible. A public ECR repository allows anyone to pull container images, potentially exposing proprietary code, embedded credentials, internal architecture details, and software supply chain artifacts. Public repositories should use ECR Public Gallery only for intentionally open-source images.

**Remediation:** Set the repository policy to restrict access to specific IAM principals. If the repository was created as ECR Public, migrate images to a private ECR repository and update deployment configs.

---

### CTL.ECR.SCAN.001

**Image Scanning Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: RA-5; nist_800_53_r5: RA-5; soc2: CC7.1;

ECR repositories must have image scanning enabled (basic or enhanced). Without scanning, container images with known vulnerabilities are deployed to production undetected.

**Remediation:** Enable scan-on-push in the repository configuration. For enhanced scanning, enable Amazon Inspector ECR integration.

---

### CTL.EFS.ENCRYPT.001

**EFS File System Must Be Encrypted at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.4.1; fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

EFS file systems must have encryption at rest enabled. Data stored on unencrypted file systems is readable if the underlying storage is compromised. EFS encryption uses AWS KMS and must be enabled at creation time — it cannot be enabled on existing file systems.

**Remediation:** Create a new encrypted EFS file system and migrate data. Encryption cannot be enabled on existing file systems. Run: aws efs create-file-system --encrypted --kms-key-id alias/aws/elasticfilesystem

---

### CTL.EFS.ENCRYPT.TRANSIT.001

**EFS File System Must Enforce Encryption in Transit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.4.1; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.1;

EFS file systems must enforce encryption in transit via a file system policy that denies unencrypted connections. Without this policy, NFS clients can mount the file system without TLS, exposing data to network-level interception.

**Remediation:** Apply a file system policy that denies unencrypted transport. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'

---

### CTL.EFS.INCOMPLETE.001

**Complete Data Required for EFS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

EFS file system safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate filesystem.encryption.at_rest_enabled.

**Remediation:** Re-run the extractor with EFS permissions: elasticfilesystem:DescribeFileSystems, elasticfilesystem:DescribeFileSystemPolicy.

---

### CTL.ELASTICACHE.AUTH.001

**Redis AUTH Token Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ElastiCache Redis clusters must have an AUTH token configured. Without AUTH, any client with network access can read and write data. Combined with a missing VPC or open security group, this creates an unauthenticated database exposure — the same pattern as the Darkbeam Elasticsearch breach.

**Remediation:** Set an AUTH token using aws elasticache modify-replication-group --auth-token. Ensure transit encryption is also enabled (required for AUTH). Rotate the token periodically.

---

### CTL.ELASTICACHE.INCOMPLETE.001

**Complete Data Required for ElastiCache Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required ElastiCache properties.

**Remediation:** Ensure the extractor calls aws elasticache describe-replication-groups and maps TransitEncryptionEnabled to the cache observation properties.

---

### CTL.ELASTICACHE.TRANSIT.001

**ElastiCache Must Have In-Transit Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

ElastiCache clusters must have in-transit encryption enabled. Without TLS, cache traffic travels in plaintext between the application and the cache nodes, exposing cached PHI data.

**Remediation:** In-transit encryption can only be enabled at cluster creation. Create a new replication group with TransitEncryptionEnabled=true and migrate data from the existing cluster.

---

### CTL.ELB.CROSSZONE.001

**Load Balancer Must Have Cross-Zone Load Balancing Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** ffiec: BCP; hipaa: 164.308(a)(7); soc2: A1.1;

Load balancers must distribute traffic across all registered targets in all enabled Availability Zones. Without cross-zone balancing, uneven distribution can cause availability issues during AZ failures.

**Remediation:** Enable cross-zone load balancing. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=load_balancing.cross_zone.enabled,Value=true

---

### CTL.ELB.HTTPS.001

**Load Balancer Must Redirect HTTP to HTTPS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

Load balancers serving PHI must redirect all HTTP traffic to HTTPS. Allowing plaintext HTTP exposes data in transit to interception.

**Remediation:** Add a listener rule on port 80 that redirects to HTTPS (443) with status code 301.

---

### CTL.ELB.INCOMPLETE.001

**Complete Data Required for ELB Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Load balancer safety cannot be assessed when TLS configuration is missing from the snapshot. The extractor must populate loadbalancer.encryption.tls_1_2_or_higher.

**Remediation:** Re-run the extractor with ELB permissions: elasticloadbalancing:DescribeLoadBalancers, elasticloadbalancing:DescribeLoadBalancerAttributes, elasticloadbalancing:DescribeListeners.

---

### CTL.ELB.LOG.001

**Load Balancer Access Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

Load balancer access logging must be enabled for audit and forensic analysis. Without access logs, request patterns and potential unauthorized access cannot be investigated after an incident.

**Remediation:** Enable access logging to an S3 bucket. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=my-elb-logs

---

### CTL.ELB.TLS.001

**Load Balancer Must Use TLS 1.2 or Higher**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

Application and Network Load Balancers must use TLS 1.2 or higher for HTTPS listeners. Older TLS versions have known vulnerabilities.

**Remediation:** Update the HTTPS listener to use an ELBSecurityPolicy that enforces TLS 1.2 minimum (e.g., ELBSecurityPolicy-TLS-1-2-2017-01).

---

### CTL.GCS.ENCRYPT.001

**Customer-Managed Encryption Key Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets containing sensitive data must use a customer-managed encryption key (CMEK) via Cloud KMS, not the default Google-managed key. CMEK provides key rotation control, access policies, and audit trails that Google-managed keys do not.

**Remediation:** Set a default CMEK on the bucket. Run: gcloud storage buckets update gs://BUCKET --default-encryption-key=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY

---

### CTL.GCS.INCOMPLETE.001

**Complete Data Required for GCS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** storage

GCS bucket safety cannot be proven when access control data is missing from the snapshot. The extractor must populate storage.access.public_read to evaluate public exposure controls.

**Remediation:** Re-run the extractor with storage permissions: storage.buckets.getIamPolicy, storage.buckets.get.

---

### CTL.GCS.LOG.001

**Access Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets must have access logging enabled. Without logging, access patterns cannot be audited and unauthorized access goes undetected.

**Remediation:** Enable access logging for the bucket. Run: gcloud storage buckets update gs://BUCKET --log-bucket=LOG_BUCKET --log-object-prefix=PREFIX

---

### CTL.GCS.PUBLIC.001

**No Public GCS Bucket Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.1;

GCS buckets must not allow public read access. Detects buckets where IAM bindings include allUsers or allAuthenticatedUsers with read permissions, or where uniform bucket-level access is disabled and object ACLs may grant public access.

**Remediation:** Remove allUsers and allAuthenticatedUsers from bucket IAM bindings. Run: gcloud storage buckets remove-iam-policy-binding gs://BUCKET --member=allUsers --role=roles/storage.objectViewer

---

### CTL.GCS.PUBLIC.002

**No Public GCS Bucket Listing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.1;

GCS buckets must not allow public listing. Anonymous bucket listing exposes the full object inventory, enabling bulk data discovery.

**Remediation:** Remove allUsers from bucket IAM bindings for storage.objects.list. Enable uniform bucket-level access to prevent object ACL overrides.

---

### CTL.GCS.UNIFORM.001

**Uniform Bucket-Level Access Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.2;

GCS buckets must use uniform bucket-level access. When disabled, both IAM policies and object ACLs control access, creating a dual-path exposure risk that is harder to audit and more prone to misconfiguration.

**Remediation:** Enable uniform bucket-level access. Run: gcloud storage buckets update gs://BUCKET --uniform-bucket-level-access

---

### CTL.GCS.VERSION.001

**Object Versioning Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets must have object versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and ransomware attacks that encrypt objects are irreversible.

**Remediation:** Enable versioning. Run: gcloud storage buckets update gs://BUCKET --versioning

---

### CTL.GUARDDUTY.ENABLED.001

**Amazon GuardDuty Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.16; nist_800_53_r5: SI-3; nist_csf_2.0: DE.CM; pci_dss_v4.0: 5.2; soc2: CC7.1;

GuardDuty must be enabled to provide continuous threat detection. It analyzes CloudTrail, VPC Flow Logs, and DNS logs to detect reconnaissance, instance compromise, and account compromise.

**Remediation:** Enable GuardDuty: aws guardduty create-detector --enable

---

### CTL.GUARDDUTY.INCOMPLETE.001

**Complete Data Required for GuardDuty Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required GuardDuty properties.

**Remediation:** Ensure the extractor calls aws guardduty list-detectors and get-detector.

---

### CTL.IAM.ACCOUNT.INACTIVE.001

**Inactive Accounts Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.2;

IAM accounts with no login or API activity for 90 days or more must be disabled. Dormant accounts are high-value targets — they have permissions but no active user monitoring their usage. Legacy accounts, test accounts, and accounts from departed employees accumulate over time and provide persistent, unmonitored access paths for attackers.

**Remediation:** Disable or delete the IAM user. If the account is still needed, review and renew its access with a documented justification and an updated expiry date.

---

### CTL.IAM.ADMIN.COUNT.001

**Admin User Count Must Not Exceed Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

AWS accounts must have no more than 2 users with full administrator access. Excessive admin accounts expand the credential compromise surface and violate least privilege. Use IAM roles with temporary elevation (break-glass) instead of permanent admin access.

**Remediation:** Reduce admin users to 2 or fewer. Convert permanent admin access to IAM roles with temporary elevation via sts:AssumeRole. Use IAM Access Analyzer to identify unused admin permissions.

---

### CTL.IAM.ANALYZER.001

**IAM Access Analyzer Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC6.1;

IAM Access Analyzer must be enabled in every region. Access Analyzer identifies resources shared with external entities and generates findings for unintended exposure.

**Remediation:** Create an Access Analyzer in each region: aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT --region <region>

---

### CTL.IAM.BOUNDARY.001

**IAM Roles Must Have Permissions Boundary**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles must have a permissions boundary attached. A permissions boundary sets a ceiling on the effective permissions of a role, regardless of what identity policies are attached. Without a boundary, a developer who can create or modify roles has no ceiling preventing the provisioned role from granting full admin access.

**Remediation:** Attach a permissions boundary policy to the role using aws iam put-role-permissions-boundary. Define a boundary that caps permissions to the services and actions required for the role's documented function.

---

### CTL.IAM.CERT.EXPIRED.001

**Remove Expired IAM Server Certificates**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.19;

Expired SSL/TLS server certificates must be removed from IAM. Expired certificates cannot serve TLS but create confusion during audits and may mask missing certificate rotation.

**Remediation:** Delete expired certificates and migrate active ones to ACM: aws iam delete-server-certificate --server-certificate-name <name>

---

### CTL.IAM.CONSOLE.MFA.001

**Console Users Must Have MFA Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.10; cis_aws_v3.0: 1.10; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.3; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

IAM users with console access must have multi-factor authentication enabled. Console access without MFA allows credential-only login, making accounts vulnerable to password compromise.

**Remediation:** Enable MFA for the user via IAM > Users > Security credentials > MFA. Alternatively, disable console access if the user only needs programmatic access.

---

### CTL.IAM.CRED.EXPIRY.001

**Credentials Must Have Defined Expiry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.8.5; nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.1;

IAM credentials must have a defined maximum lifetime. Credentials without expiry — access keys created for QA, debugging, or temporary integrations — persist indefinitely and become permanent attack surfaces. Time transforms temporary mistakes into permanent breaches. Every credential must have a TTL enforced at creation time or through automated lifecycle policies.

**Remediation:** Replace long-lived access keys with STS temporary credentials that expire automatically. If access keys are required, enforce a maximum age policy and automate rotation via Secrets Manager. Tag credentials with creation date and intended expiry.

---

### CTL.IAM.CRED.ROTATION.001

**Access Keys Must Be Rotated Within 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.14; cis_aws_v3.0: 1.14; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); pci_dss_v3.2.1: 8.2.4; pci_dss_v4.0: 8.3.9; soc2: CC6.1;

IAM user access keys older than 90 days must be rotated. Long-lived access keys accumulate exposure risk and may have been leaked in code repositories, logs, or configuration files.

**Remediation:** Create a new access key, update all systems using the old key, then deactivate and delete the old key.

---

### CTL.IAM.CRED.SETUPKEY.001

**No Access Keys Created at User Setup**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.11; soc2: CC6.2;

Access keys should not be created at user creation time. Keys created during setup are often distributed insecurely and may not be needed. Create keys only for specific programmatic access.

**Remediation:** Delete the setup-time access key and create a new one only if programmatic access is specifically required.

---

### CTL.IAM.CRED.SINGLEKEY.001

**Single Active Access Key per User**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.13; fedramp_moderate: IA-5; nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

Each IAM user must have at most one active access key. Multiple active keys increase the attack surface and complicate key rotation.

**Remediation:** Deactivate and delete the extra access key: aws iam update-access-key --status Inactive --access-key-id AKIA... aws iam delete-access-key --access-key-id AKIA...

---

### CTL.IAM.CRED.UNUSED.001

**Disable Unused Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.12; cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.2;

IAM credentials unused for 90 days or more must be disabled. Dormant credentials are a persistent attack surface that provides access without triggering normal usage patterns.

**Remediation:** Disable or delete unused credentials. Review the user's need for access and remove the IAM user if no longer required.

---

### CTL.IAM.CRED.UNUSED45.001

**Disable Credentials Unused for 45 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12;

IAM credentials (passwords and access keys) unused for 45 or more days must be disabled. CIS v3.0 requires a 45-day threshold, which is stricter than the 90-day HIPAA threshold.

**Remediation:** Disable inactive access keys and console passwords: aws iam update-access-key --status Inactive --access-key-id AKIA...

---

### CTL.IAM.CROSS.ENV.001

**Non-Production Must Not Access Production Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-4; iso_27001_2022: A.8.22; nist_800_53_r5: AC-4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles in non-production environments (test, staging, QA) must not have access to production resources. Cross-environment access collapses security boundaries — a compromised test account becomes a path to production data. The Microsoft breach (2024) demonstrated this exact failure: a test tenant with production-scope grants enabled a nation-state actor to pivot from test to production.

**Remediation:** Remove production resource ARNs from non-production role policies. Use separate AWS accounts for prod and non-prod with no cross- account trust. Enforce environment boundaries via SCPs that deny non-prod accounts from accessing prod resources. Tag all accounts and roles with their environment classification.

---

### CTL.IAM.CROSSCLOUD.ADMIN.001

**No Full Admin Policies Across Any Cloud Provider**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No IAM policy on any cloud provider should grant unrestricted administrative access (Action: *, Resource: * or equivalent). This control extends CTL.IAM.POLICY.ADMIN.001 beyond AWS to Azure (Contributor/Owner at subscription scope) and GCP (roles/owner, roles/editor at project scope). The same least-privilege principle applies regardless of cloud provider.

**Remediation:** Replace admin policies with scoped policies granting only required permissions. Use cloud-specific access analyzers to identify unused permissions.

---

### CTL.IAM.CROSSCLOUD.MFA.001

**MFA Must Be Enforced Across All Cloud Providers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2(1); soc2: CC6.1;

All privileged accounts across all cloud providers must have MFA enforced. This control extends AWS MFA controls to Azure AD (Conditional Access requiring MFA) and GCP (2-Step Verification enforcement). A single cloud account without MFA is a breach vector regardless of how well other clouds are protected.

**Remediation:** Enforce MFA at the identity provider level. AWS: IAM MFA policy conditions. Azure: Conditional Access policies. GCP: 2-Step Verification enforcement in Workspace/Cloud Identity.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.001

**Role Blast Radius Must Not Exceed Resource Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM roles must not be able to reach more than 50 resources through direct permissions and transitive role assumption chains. A role with wide blast radius means a single credential compromise gives an attacker access to a large surface area. The extractor computes reachable resources by traversing sts:AssumeRole edges and collecting data access permissions per reachable role.

**Remediation:** Reduce the role's permissions to the minimum set of resources required. Split broad roles into per-service roles with scoped Resource ARNs. Use IAM Access Analyzer to identify unused permissions for removal.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.002

**Cross-Account Role Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account blast radius (can reach resources in other AWS accounts) must require an external ID condition on the trust policy. Without an external ID, any principal in the trusted account can assume the role — including compromised service accounts and test tenants. Combined with cross-account reach, this is the maximum blast radius configuration.

**Remediation:** Add an sts:ExternalId condition to the role trust policy. Restrict the trust to specific role ARNs rather than account-wide principals. Review cross-account access grants for least privilege.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.003

**Role Assume Chain Must Not Exceed Depth Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM role assumption chains must not exceed 2 hops. Deep chains (Role A assumes Role B which assumes Role C) create hidden transitive access that is difficult to audit and often exceeds the intended permissions of the originating principal. Each hop in the chain potentially widens the blast radius.

**Remediation:** Flatten the role assumption chain. Grant permissions directly to the role that needs them rather than chaining through intermediate roles. Use service-linked roles where possible to avoid manual chain construction.

---

### CTL.IAM.INCOMPLETE.001

**Complete Data Required for IAM Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

IAM account safety cannot be proven when root account MFA status or access key data is missing from the snapshot. The extractor must populate identity.root.mfa_enabled and identity.root.has_access_keys.

**Remediation:** Re-run the extractor with IAM permissions: iam:GetAccountSummary, iam:GenerateCredentialReport, iam:ListMFADevices.

---

### CTL.IAM.MFA.HWKEY.001

**Privileged Accounts Must Use Hardware MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.6; fedramp_moderate: IA-2(1); gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

IAM users with admin access must use a hardware MFA device (FIDO2, YubiKey, Gemalto), not a virtual MFA app or SMS. Virtual MFA can be compromised through device theft, seed extraction, or SIM swap attacks. Hardware tokens cannot be cloned or phished via device compromise, providing stronger protection for the most privileged identities.

**Remediation:** Replace virtual MFA with a hardware FIDO2 or TOTP device. Remove the existing virtual MFA device and enroll a hardware token via IAM > Users > Security credentials > MFA.

---

### CTL.IAM.PASSWORD.COMPLEXITY.001

**Password Policy Must Require All Character Types**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); pci_dss_v3.2.1: 8.2.3; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

The IAM account password policy must require uppercase, lowercase, numbers, and symbols. Missing any character type requirement reduces the keyspace and makes passwords easier to crack.

**Remediation:** Update the IAM password policy to require all four character types.

---

### CTL.IAM.PASSWORD.LENGTH.001

**Password Minimum Length Must Be At Least 14**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; cis_aws_v3.0: 1.8; fedramp_moderate: IA-5(1); ffiec: CAT-D3; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.5; nist_800_53_r5: IA-5(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.2.3; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

The IAM account password policy must require a minimum password length of 14 characters. Shorter passwords are vulnerable to brute-force and dictionary attacks.

**Remediation:** Update the IAM account password policy to require at least 14 characters. Run: aws iam update-account-password-policy --minimum-password-length 14

---

### CTL.IAM.PASSWORD.REUSE.001

**Password Reuse Prevention Must Be At Least 24**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.9; cis_aws_v3.0: 1.9; fedramp_moderate: IA-5(1); ffiec: ISH-4; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.5; nist_800_53_r5: IA-5(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.2.5; pci_dss_v4.0: 8.3.7; soc2: CC6.1;

The IAM account password policy must prevent reuse of the last 24 passwords. Without reuse prevention, users cycle between a small set of passwords, negating the value of password rotation.

**Remediation:** Update the IAM password policy to prevent reuse of the last 24 passwords. Run: aws iam update-account-password-policy --password-reuse-prevention 24

---

### CTL.IAM.PASSWORD.ROTATION.001

**User Passwords Must Be Rotated Within Policy Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); pci_dss_v4.0: 8.3.9; soc2: CC6.1;

IAM user console passwords must be rotated per organizational policy (typically 90 days). The credential report tracks password_last_changed; passwords older than the policy period have accumulated exposure risk and may have been shared, phished, or brute-forced. This complements access key rotation (CTL.IAM.CRED.ROTATION.001) to cover the full credential lifecycle.

**Remediation:** Require the user to change their password. Enforce a maximum password age via the account password policy. Run: aws iam update-account-password-policy --max-password-age 90

---

### CTL.IAM.POLICY.ADMIN.001

**No Full Admin Policies Attached**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

No IAM policy with Effect Allow on Action "*" and Resource "*" should be attached to any IAM entity. Full admin policies violate least privilege and grant unrestricted access to all services.

**Remediation:** Replace wildcard admin policies with scoped policies granting only the specific permissions required. Use AWS Access Analyzer to generate least-privilege policies from CloudTrail activity.

---

### CTL.IAM.POLICY.ASSUMEROLE.001

**AssumeRole Must Be Scoped to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

sts:AssumeRole permissions must be scoped to specific role ARNs, not wildcard Resource *. With unrestricted AssumeRole, a compromised identity can assume any role in the account — including admin roles, cross-account trust roles, and service roles with elevated permissions. This is a direct privilege escalation path.

**Remediation:** Restrict sts:AssumeRole to specific role ARNs in the Resource field. Use IAM conditions like aws:PrincipalTag to further limit which roles can be assumed.

---

### CTL.IAM.POLICY.CLOUDSHELL.001

**Restrict AWSCloudShellFullAccess**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.22; soc2: CC6.3;

The AWSCloudShellFullAccess managed policy should not be attached to any IAM entity unless specifically required. CloudShell provides a browser-based shell that can bypass network-level controls.

**Remediation:** Detach AWSCloudShellFullAccess from all IAM users, groups, and roles that do not require it.

---

### CTL.IAM.POLICY.COMPLEXITY.001

**IAM Policy Complexity Must Be Bounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM policies with more than 25 statements indicate excessive complexity that increases misconfiguration risk. Complex policies are harder to audit, more likely to contain shadowed statements or contradictory rules, and resist review. Policy complexity is itself a risk factor — it obscures the effective permissions and makes least-privilege verification impractical.

**Remediation:** Refactor complex policies into smaller, focused policies scoped to specific services. Use policy conditions and resource-scoped statements instead of many broad statements. Consider using AWS managed policies where appropriate.

---

### CTL.IAM.POLICY.DIRECT.001

**No Direct Policy Attachment on IAM Users**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; cis_aws_v3.0: 1.15; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM users must not have managed policies attached directly. Policies should be attached to groups or roles, not individual users. Direct attachment creates unmanageable per-user permission sprawl.

**Remediation:** Create IAM groups with the required policies and add the user to the appropriate groups. Remove directly attached policies from the user.

---

### CTL.IAM.POLICY.ESCALATION.001

**IAM Policies Must Not Grant Self-Modification**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policies must not grant the ability to modify, create, or attach policies to the principal's own role or user. Permissions like iam:CreatePolicyVersion, iam:AttachRolePolicy, and iam:PutRolePolicy scoped to self enable privilege escalation — a compromised identity can grant itself full admin access without needing any other vulnerability.

**Remediation:** Remove iam:CreatePolicyVersion, iam:AttachRolePolicy, and iam:PutRolePolicy permissions from non-admin roles. Use SCPs to deny self-modification at the organization level.

---

### CTL.IAM.POLICY.INLINE.001

**No Inline Policies on IAM Users**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; cis_aws_v3.0: 1.15; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM users must not have inline policies attached directly. Inline policies are harder to audit, cannot be reused, and create per-user policy sprawl that resists central governance.

**Remediation:** Convert inline policies to managed policies and attach via groups or roles. Delete the inline policies from the user.

---

### CTL.IAM.POLICY.MFA.001

**Destructive Actions Must Require MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.4; fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); pci_dss_v4.0: 8.4.1; soc2: CC6.1;

IAM policies governing destructive operations (s3:DeleteBucket, iam:CreateUser, ec2:TerminateInstances, etc.) must include an aws:MultiFactorAuthPresent condition. Without policy-level MFA enforcement, a compromised access key alone is sufficient to execute destructive actions — the credential becomes the only barrier between an attacker and data loss.

**Remediation:** Add an aws:MultiFactorAuthPresent condition to IAM policies that permit destructive actions. Example condition block: "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}} Apply to policies covering s3:Delete*, iam:Create*, iam:Delete*, ec2:Terminate*, rds:Delete*, and similar destructive API calls.

---

### CTL.IAM.POLICY.PASSROLE.001

**PassRole Must Be Scoped to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

iam:PassRole permissions must be scoped to specific role ARNs, not wildcard resource *. PassRole allows a principal to assign an IAM role to an AWS service (Lambda, EC2, ECS). With a wildcard resource, an attacker can pass any role — including highly privileged ones — to a service they control, achieving privilege escalation without directly modifying IAM policies.

**Remediation:** Restrict iam:PassRole to specific role ARNs in the Resource field. Example: arn:aws:iam::123456789012:role/my-lambda-role. Use IAM conditions like iam:PassedToService to further limit which services can receive the role.

---

### CTL.IAM.POLICY.SOD.001

**IAM Roles Must Not Combine Data Access and IAM Management**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-5; iso_27001_2022: A.8.3; nist_800_53_r5: AC-5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

No single IAM role should have both data access permissions (s3:GetObject, dynamodb:GetItem, rds:*, secretsmanager:GetSecretValue) and IAM management permissions (iam:CreateRole, iam:AttachPolicy, iam:CreateUser, iam:PutRolePolicy). Combining these creates a privilege escalation path — a compromised role with data access can grant itself additional permissions. Separation of privileged access is required by IAM-09 in CCM v4.1.

**Remediation:** Split into two roles: one for data access (application role) and one for IAM management (admin role). Use separate assume-role policies for each. Apply the principle of least privilege — data-path roles should never modify IAM.

---

### CTL.IAM.ROLE.BREAKGLASS.001

**Break-Glass Elevated Roles Must Not Persist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; nist_800_53_r5: AC-2; soc2: CC6.1;

IAM roles granted elevated permissions for incident response (break-glass access) must be revoked within 7 days. Elevated roles that persist beyond the incident become permanent backdoors — they carry admin-level permissions with no active justification. Debug rules, elevated roles, and emergency access must have mandatory time-bounding.

**Remediation:** Revoke the elevated role or revert its permissions to the pre-incident baseline. Implement automated expiry via STS session policies or Lambda-based role revocation. Tag elevated roles with grant timestamp and incident ID for tracking.

---

### CTL.IAM.ROOT.ACCESSKEY.001

**Root Account Must Not Have Access Keys**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.4; cis_aws_v3.0: 1.4; fedramp_moderate: IA-2; hipaa: 164.312(a)(1); nist_800_53_r5: IA-2; pci_dss_v3.2.1: 2.1; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

The AWS root account must not have active access keys. Root access keys provide unrestricted programmatic access. Use IAM users or roles for programmatic access instead.

**Remediation:** Delete the root access keys. Create IAM users or roles with least-privilege policies for programmatic access.

---

### CTL.IAM.ROOT.HWMFA.001

**Root Account Must Use Hardware MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.6; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

The root account must use a hardware MFA device, not a virtual one. Hardware tokens cannot be cloned or phished via device compromise, providing stronger protection for the most privileged identity.

**Remediation:** Replace the virtual MFA with a hardware TOTP device (YubiKey, Gemalto) in the IAM console under Security Credentials.

---

### CTL.IAM.ROOT.MFA.001

**Root Account Must Have MFA Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.5; cis_aws_v3.0: 1.5; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.3; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

The AWS root account must have multi-factor authentication enabled. Root has unrestricted access to all resources. Compromise without MFA is the highest-severity identity risk.

**Remediation:** Enable MFA on the root account using a hardware MFA device or virtual MFA app. Navigate to IAM > Security credentials > MFA.

---

### CTL.IAM.ROOT.USAGE.001

**Root Account Must Not Be Used for Daily Tasks**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.7; fedramp_moderate: AC-2; nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.1; soc2: CC6.2;

The root account must not be used for day-to-day operations. Root activity should be limited to account setup tasks. Recent root usage indicates operational reliance on root credentials.

**Remediation:** Create IAM admin users or roles for daily operations. Lock root credentials and use them only for account-level tasks.

---

### CTL.IAM.SCP.FULLACCESS.001

**Organizations Must Not Rely Solely on FullAWSAccess SCP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

AWS Organizations must have restrictive Service Control Policies beyond the default FullAWSAccess SCP. An organization that only has FullAWSAccess applied has no organizational guardrails — any IAM permission granted within a member account is allowed, including access to unused services that expand the attack surface.

**Remediation:** Create restrictive SCPs that deny unused services and dangerous actions. Apply them to organizational units. Keep FullAWSAccess on the root but add deny-based SCPs to OUs that restrict the effective permissions.

---

### CTL.IAM.SUPPORT.001

**AWS Support Role Must Exist**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.17;

At least one IAM entity must have the AWSSupportAccess managed policy attached. This ensures someone can open support cases during security incidents without using root.

**Remediation:** Create an IAM role with the AWSSupportAccess policy: aws iam attach-role-policy --role-name SupportRole --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess

---

### CTL.IAM.TRUST.EXTERNALID.001

**Cross-Account Trust Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account trust policies must include an sts:ExternalId condition. Without an external ID, any principal in the trusted account can assume the role — including compromised service accounts, OAuth applications, or test tenants. The Microsoft Midnight Blizzard 2024 breach exploited a legacy test OAuth app to assume a role with full_access_as_app permissions, pivoting from a test tenant to production Exchange mailboxes.

**Remediation:** Add an sts:ExternalId condition to the role trust policy. Generate a unique external ID per trust relationship. Verify the assuming application passes the correct external ID.

---

### CTL.IAM.ZT.PERIMETER.001

**Sensitive Resources Must Use Identity-Based Access Not Network Perimeter**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.AA;

Access to sensitive resources must be governed by identity-based controls (IAM policies, conditions, session tags) rather than relying solely on network perimeter (VPC, security groups, NACLs). Network-only access control fails when the perimeter is bypassed — via VPN compromise, lateral movement, or insider threat. Zero Trust requires every access decision to verify identity, device, and context.

**Remediation:** Add IAM-based access controls (resource policies with principal constraints, IAM conditions for aws:PrincipalTag, VPC endpoint policies with principal scoping). Use AWS Verified Access or IAM Roles Anywhere for workload identity.

---

### CTL.IAM.ZT.SHORTLIVED.001

**Service Access Must Use Short-Lived Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5; nist_800_53_r5: IA-5; nist_csf_2.0: PR.AA;

Service-to-service access must use short-lived credentials (STS temporary tokens, IAM Roles Anywhere certificates, OIDC federation) rather than long-lived access keys. Short-lived credentials limit the blast radius of compromise — a stolen token expires automatically. This is a core Zero Trust principle: never trust a credential longer than necessary.

**Remediation:** Replace long-lived access keys with IAM roles (for EC2, ECS, Lambda), IAM Roles Anywhere (for on-premises), or OIDC federation (for CI/CD). Use STS AssumeRole with session duration limits.

---

### CTL.K8S.AUDIT.001

**Kubernetes Audit Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 3.2.1; hipaa: 164.312(b); soc2: CC7.1;

The Kubernetes API server must have audit logging enabled. Without audit logs, API calls (including unauthorized access attempts) are not recorded for forensic analysis.

**Remediation:** Configure the API server with --audit-policy-file and --audit-log-path. For managed clusters (EKS, GKE), enable control plane logging via the cloud provider console.

---

### CTL.K8S.AUTH.ACCESSKEYMAP.001

**K8s Clusters Must Not Map Identity via AccessKeyID**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_k8s_v1.8.0: 3.1.1; nist_800_53_r5: IA-2; soc2: CC6.1;

Kubernetes clusters using AWS IAM Authenticator must not use {{AccessKeyID}} in identity mapping templates. The AccessKeyID is extracted from client-supplied presigned URL query parameters, not from the STS response, making it vulnerable to parameter injection via case-variant duplication.

**Remediation:** Replace {{AccessKeyID}} with {{SessionName}} or use ARN-based mapping (userARN matching) without template substitution. ARN and SessionName come from the STS GetCallerIdentity response and cannot be manipulated by the client.

---

### CTL.K8S.INCOMPLETE.001

**Complete Data Required for Kubernetes Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Kubernetes cluster safety cannot be assessed when audit logging status is missing from the snapshot. The extractor must populate audit.audit_logging_enabled.

**Remediation:** Re-run the extractor with Kubernetes API access to describe cluster configuration, RBAC, network policies, and secrets.

---

### CTL.K8S.NETPOL.001

**Namespaces Must Have Network Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.3.2; hipaa: 164.312(e)(1);

Kubernetes namespaces containing workloads must have at least one NetworkPolicy defined. Without network policies, all pod-to-pod traffic is allowed by default, enabling lateral movement.

**Remediation:** Create a default-deny NetworkPolicy for the namespace, then add explicit allow rules for required traffic flows.

---

### CTL.K8S.NETPOL.DENY.001

**Namespaces Must Have Default-Deny Network Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.3.2;

Namespaces with network policies must include a default-deny ingress policy. Without default-deny, network policies only add allow rules on top of the implicit allow-all default.

**Remediation:** Add a default-deny ingress NetworkPolicy that selects all pods and has no ingress rules.

---

### CTL.K8S.RBAC.SERVICEACCOUNT.001

**Default Service Account Must Not Have Active Tokens**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.1.5;

The default service account in each namespace should not have auto-mounted tokens. Pods using the default service account inherit permissions that may allow unintended API access.

**Remediation:** Set automountServiceAccountToken to false on the default service account in every namespace. Create dedicated service accounts with minimal permissions for workloads that need API access.

---

### CTL.K8S.RBAC.WILDCARD.001

**ClusterRoles Must Not Use Wildcard Resources or Verbs**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.1.3;

Kubernetes ClusterRoles must not grant wildcard (*) access to resources or verbs. Wildcard grants provide cluster-wide permissions that bypass the principle of least privilege.

**Remediation:** Replace wildcard entries with explicit resource names and verbs. Use Roles (namespace-scoped) instead of ClusterRoles where possible.

---

### CTL.K8S.SECRETS.ENCRYPT.001

**Kubernetes Secrets Must Be Encrypted at Rest in etcd**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 1.2.29; hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

Kubernetes Secrets stored in etcd must be encrypted at rest. By default, Secrets are stored as base64-encoded plaintext in etcd, readable by anyone with etcd access or etcd backup access.

**Remediation:** Configure the API server with --encryption-provider-config pointing to an EncryptionConfiguration that uses aescbc, aesgcm, or kms provider. For EKS, enable envelope encryption with a KMS key.

---

### CTL.K8S.SECRETS.PLAINTEXT.001

**Pods Must Not Mount Secrets as Environment Variables**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.4.1;

Secrets should be mounted as files, not environment variables. Environment variables are visible in process listings, crash dumps, and container inspection output, increasing the risk of credential exposure.

**Remediation:** Mount Secrets as volumes instead of environment variables. Use projected volumes with restrictive file permissions (0400).

---

### CTL.KMS.FIPS.001

**KMS Keys Must Use FIPS 140-2 Validated HSM Origin**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-13;

KMS keys must have AWS_KMS origin, confirming they are generated and stored in FIPS 140-2 Level 2 validated hardware security modules. Keys with EXTERNAL or CUSTOM_KEY_STORE origin may not meet FedRAMP FIPS 140 cryptography requirements.

**Remediation:** Create a new key with AWS_KMS origin (default). Rotate data encrypted with the non-compliant key to the new key.

---

### CTL.KMS.INCOMPLETE.001

**Complete Data Required for KMS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required KMS key properties. A safety assessment cannot be completed without key policy data.

**Remediation:** Ensure the extractor calls aws kms get-key-policy and maps the response to the cryptography observation properties.

---

### CTL.KMS.POLICY.001

**KMS Key Policy Must Restrict Access to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key policies must not grant wildcard principal access. A key policy with Principal "*" allows any IAM entity in the account (or any account if conditions are missing) to use the key, defeating the purpose of customer-managed encryption.

**Remediation:** Update the key policy to restrict Principal to specific IAM roles or accounts. Remove any statements with Principal "*".

---

### CTL.KMS.ROTATION.001

**KMS Customer-Managed Key Rotation Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.6; fedramp_moderate: SC-12; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Customer-created symmetric KMS keys must have automatic key rotation enabled. Key rotation limits the amount of data encrypted with a single key version, reducing the blast radius of key compromise.

**Remediation:** Enable key rotation: aws kms enable-key-rotation --key-id <key-id>

---

### CTL.OPENSEARCH.ACCESS.POLICY.001

**Access Policy Must Not Allow Wildcard Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

OpenSearch domain access policies must not grant access to wildcard principals (Principal: *). A wildcard principal in the resource-based policy allows any AWS account or unauthenticated user to access the cluster, depending on whether the domain is public or VPC-only. Combined with a public endpoint, this enables completely anonymous access.

**Remediation:** Replace wildcard principals with specific IAM role ARNs or account IDs. Use condition keys (aws:SourceIp, aws:SourceVpc) to further restrict access.

---

### CTL.OPENSEARCH.AUTH.001

**Authentication Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.5; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

OpenSearch domains must have authentication enabled. A domain without authentication allows anyone with network access to query, index, delete, and enumerate all data. The Darkbeam breach (2023) exposed 3.8 billion credentials because the Elasticsearch cluster required zero authentication. The Wyze breach (2019) exposed 2.4 million user records via the same pattern. Authentication is the single most critical OpenSearch security control.

**Remediation:** Enable fine-grained access control with an internal user database or IAM authentication. At minimum, enable the security plugin with a master user. For production, use IAM-based authentication via SAML or Cognito for OpenSearch Dashboards.

---

### CTL.OPENSEARCH.ENCRYPT.001

**Encryption at Rest Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

OpenSearch domains must have encryption at rest enabled using AWS KMS. Unencrypted data at rest is exposed if the underlying storage is compromised or if snapshots are shared.

**Remediation:** Enable encryption at rest in the domain configuration. Note: encryption at rest can only be enabled at domain creation time for some versions. If needed, create a new domain with encryption enabled and migrate data.

---

### CTL.OPENSEARCH.ENCRYPT.002

**Node-to-Node Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; soc2: CC6.7;

OpenSearch domains must have node-to-node encryption enabled. Without it, data transmitted between nodes within the cluster travels unencrypted, exposing it to interception on the internal network. Node-to-node encryption is a prerequisite for fine-grained access control.

**Remediation:** Enable node-to-node encryption in the domain configuration. This is required for fine-grained access control.

---

### CTL.OPENSEARCH.FGAC.001

**Fine-Grained Access Control Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

OpenSearch domains must have fine-grained access control (FGAC) enabled. Without FGAC, access is controlled only by resource-based policies which cannot restrict access at the index, document, or field level. FGAC enables role-based access control within the cluster, authentication via IAM or internal users, and audit logging of all access decisions.

**Remediation:** Enable fine-grained access control in the domain security configuration. This requires enabling node-to-node encryption and encryption at rest as prerequisites.

---

### CTL.OPENSEARCH.HTTPS.001

**HTTPS Must Be Enforced**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

OpenSearch domains must enforce HTTPS for all connections. Without HTTPS enforcement, clients can connect over unencrypted HTTP, exposing queries, results, and credentials in transit.

**Remediation:** Enable HTTPS enforcement in the domain endpoint options. Set the TLS security policy to Policy-Min-TLS-1-2-PFS-2023-10 for current best practice.

---

### CTL.OPENSEARCH.INCOMPLETE.001

**Complete Data Required for OpenSearch Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

OpenSearch domain safety cannot be proven when access control data is missing from the snapshot. The extractor must populate search_service.access.publicly_accessible to evaluate public exposure controls.

**Remediation:** Re-run the extractor with OpenSearch permissions: es:DescribeDomain, es:DescribeDomainConfig.

---

### CTL.OPENSEARCH.KIBANA.001

**OpenSearch Dashboards Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

OpenSearch Dashboards (Kibana) endpoints must not be publicly accessible without authentication. Dashboards provide a query interface to the entire cluster — a public, unauthenticated dashboard is functionally equivalent to giving attackers a SQL client connected to your database. The Darkbeam breach exposed both the Elasticsearch API and the Kibana dashboard to the public internet.

**Remediation:** Restrict Dashboards access via VPC, Cognito authentication, or SAML federation. Enable fine-grained access control to enforce role-based access within Dashboards.

---

### CTL.OPENSEARCH.LOG.001

**Audit Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; soc2: CC7.1;

OpenSearch domains must have audit logging enabled to track authentication attempts, access decisions, and data operations. Without audit logging, unauthorized access to the cluster cannot be detected or investigated after the fact.

**Remediation:** Enable audit logging in the domain configuration. Configure a CloudWatch log group as the destination. Fine-grained access control must be enabled as a prerequisite for audit logging.

---

### CTL.OPENSEARCH.PUBLIC.001

**OpenSearch Domain Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20; nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

OpenSearch domains must not have public endpoints accessible from the internet. A publicly accessible domain allows anyone to query, index, or enumerate data without network-level restrictions. The Darkbeam breach (2023) exposed 3.8 billion records from an Elasticsearch instance left unprotected on the public internet. Domains must be deployed within a VPC.

**Remediation:** Migrate the domain to a VPC. Create a new domain with VPC configuration specifying private subnets and security groups. Use VPN, bastion, or AWS PrivateLink for authorized access.

---

### CTL.OPENSEARCH.SNAPSHOT.001

**Snapshots Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

OpenSearch domain snapshots must be stored in encrypted repositories. Unencrypted snapshots expose the same data as the live cluster but are often stored with weaker access controls. Snapshot repositories in S3 must use server-side encryption.

**Remediation:** Configure the snapshot repository S3 bucket with default encryption (SSE-S3 or SSE-KMS). Verify the IAM role used for snapshots has minimum required permissions.

---

### CTL.OPENSEARCH.VPC.001

**Domain Must Be Deployed in VPC**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

OpenSearch domains must be deployed within a VPC, not on public endpoints. A domain outside a VPC is directly reachable from the internet, bypassing all network-level controls. Even with authentication enabled, a public endpoint exposes the cluster to brute-force, credential stuffing, and zero-day exploits. VPC deployment restricts access to authorized networks only.

**Remediation:** Create a new domain with VPC configuration specifying private subnets and security groups. Migrate data from the public domain. Use VPN, bastion host, or AWS PrivateLink for authorized access. Note: existing domains cannot be migrated to VPC in-place.

---

### CTL.RDS.AUTOUPGRADE.001

**RDS Auto Minor Version Upgrade Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.3.2; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: A1.1;

RDS instances must have automatic minor version upgrades enabled. Minor versions include security patches. Without auto-upgrade, instances run known-vulnerable database engine versions.

**Remediation:** Enable auto minor version upgrade: aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately

---

### CTL.RDS.BACKUP.001

**RDS Automated Backups Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); hipaa_retention: 164.316(b)(2); soc2: A1.1;

RDS instances must have automated backups enabled with a retention period of at least 7 days. Without backups, data loss from accidental deletion, corruption, or ransomware is permanent.

**Remediation:** Enable automated backups with at least 7 days retention. Run: aws rds modify-db-instance --db-instance-identifier xxx --backup-retention-period 7 --apply-immediately

---

### CTL.RDS.ENCRYPT.001

**RDS Storage Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.1; cis_aws_v3.0: 2.3.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

RDS instances must have storage encryption enabled. Unencrypted database storage exposes data at rest to unauthorized access if the underlying storage is compromised.

**Remediation:** Storage encryption can only be enabled at creation time. Create a snapshot, copy it with encryption enabled, then restore to a new encrypted instance. Enable encryption by default for new instances.

---

### CTL.RDS.IAMAUTH.001

**RDS Must Enable IAM Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(d);

RDS instances should enable IAM database authentication. IAM auth eliminates long-lived database passwords and integrates with AWS identity governance for centralized access control and audit.

**Remediation:** Enable IAM authentication on the instance. Run: aws rds modify-db-instance --db-instance-identifier xxx --enable-iam-database-authentication --apply-immediately

---

### CTL.RDS.INCOMPLETE.001

**Complete Data Required for RDS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

RDS instance safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate database.encryption.storage_encrypted.

**Remediation:** Re-run the extractor with RDS permissions: rds:DescribeDBInstances, rds:DescribeDBClusters.

---

### CTL.RDS.LOG.001

**RDS Audit Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

RDS instances must export audit logs to CloudWatch. Without audit logging, database access patterns cannot be monitored and unauthorized queries are undetectable.

**Remediation:** Enable CloudWatch log exports for the database engine. Run: aws rds modify-db-instance --db-instance-identifier xxx --cloudwatch-logs-export-configuration '{"EnableLogTypes":["audit","error","slowquery"]}'

---

### CTL.RDS.MONITORING.001

**RDS Enhanced Monitoring Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; hipaa: 164.312(b); nist_800_53_r5: SI-4; soc2: CC7.1;

RDS instances must have Enhanced Monitoring enabled. Enhanced Monitoring provides real-time OS-level metrics (CPU, memory, disk I/O, network) that standard CloudWatch metrics do not capture. Without it, performance degradation and resource exhaustion attacks are harder to detect and investigate.

**Remediation:** Enable Enhanced Monitoring with a 60-second granularity. Run: aws rds modify-db-instance --db-instance-identifier xxx --monitoring-interval 60 --monitoring-role-arn arn:aws:iam::ACCOUNT:role/rds-monitoring-role --apply-immediately

---

### CTL.RDS.MULTIAZ.001

**RDS Instances Must Use Multi-AZ Deployment**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Production RDS instances must use Multi-AZ deployment for high availability. Single-AZ instances have a single point of failure that can cause data unavailability during AZ outages.

**Remediation:** Modify the instance to enable Multi-AZ. Run: aws rds modify-db-instance --db-instance-identifier xxx --multi-az --apply-immediately

---

### CTL.RDS.PUBLIC.001

**RDS Instances Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.2; cis_aws_v3.0: 2.3.3; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

RDS instances must not have public accessibility enabled. A publicly accessible database is reachable from the internet, exposing it to brute force attacks, SQL injection, and unauthorized data access.

**Remediation:** Modify the instance to disable public accessibility. Run: aws rds modify-db-instance --db-instance-identifier xxx --no-publicly-accessible --apply-immediately

---

### CTL.RDS.SSL.001

**RDS Must Require SSL Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.3; fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

RDS instances must enforce SSL/TLS for all client connections. Without require_ssl, database traffic travels unencrypted over the network, exposing query data and credentials to interception.

**Remediation:** Set the rds.force_ssl parameter to 1 in the parameter group (PostgreSQL) or require_secure_transport to ON (MySQL). For Aurora, use the cluster parameter group.

---

### CTL.ROUTE53.HEALTHCHECK.001

**Route 53 Health Checks Must Be Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: A1.1;

Route 53 health checks must be configured for DNS records pointing to critical endpoints. Without health checks, DNS routes to failed endpoints.

**Remediation:** Create health checks: aws route53 create-health-check and associate with failover routing.

---

### CTL.ROUTE53.INCOMPLETE.001

**Complete Data Required for Route 53 Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Route 53 properties.

**Remediation:** Ensure the extractor calls aws route53 list-hosted-zones and list-health-checks.

---

### CTL.S3.ACCESS.001

**No Unauthorized Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 1.16; pci_dss_v3.2.1: 7.1; soc2: CC6.3;

S3 bucket policies must not grant access to external AWS accounts. `allowed_accounts` contains trusted external AWS account IDs (12-digit). Access from accounts outside this allowlist is unsafe.

**Remediation:** Review bucket policy Principal elements for external account IDs. Remove statements granting access to accounts not in your organization. Use aws:PrincipalOrgID condition to restrict access to your AWS Organization.

---

### CTL.S3.ACCESS.002

**No Wildcard Action Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not use wildcard actions (s3:* or *). Wildcard policies grant more permissions than intended and violate the principle of least privilege.

**Remediation:** Replace wildcard actions with specific S3 actions required by the use case (e.g., s3:GetObject, s3:PutObject). Audit which principals use this policy and scope actions to their actual needs.

---

### CTL.S3.ACCESS.003

**No External Write Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant write or delete permissions to external AWS accounts. Cross-account read access may be acceptable for analytics or auditing, but write access from external accounts creates data integrity and supply chain risks.

**Remediation:** Remove bucket policy statements granting s3:PutObject, s3:DeleteObject, or s3:PutBucketPolicy to external accounts. If cross-account write is required, restrict to specific account IDs with condition keys.

---

### CTL.S3.ACCESS.GRANTS.001

**S3 Access Grants Must Not Grant Broad Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1);

S3 Access Grants provide temporary credentials scoped to a bucket or prefix. An Access Grant with READWRITE permission on a broad scope (entire bucket or wildcard prefix) bypasses bucket policy restrictions.

**Remediation:** Restrict grant scope to specific prefixes. Use READ not READWRITE.

---

### CTL.S3.ACCESS.GRANTS.002

**S3 Access Grants Identity Center Must Be Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance

When S3 Access Grants are enabled, IAM Identity Center should be attached to the Access Grants instance. Without Identity Center, grants can only target IAM principals — losing the benefit of centralized identity governance and SSO-based access control.

**Remediation:** Associate IAM Identity Center with the Access Grants instance using aws s3control associate-access-grants-identity-center. This enables directory-based grantee resolution.

---

### CTL.S3.ACCESS.PHI.001

**PHI Bucket Access Must Be Scoped to Specific Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.502(b); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

S3 buckets tagged with data-classification=phi must have access restricted to explicitly named principals and prefixes. Broad bucket-level access (wildcard principals, unrestricted actions) on PHI data violates the HIPAA minimum necessary standard (§164.502(b)). Access must be narrowed to the exact IAM roles, account IDs, and object prefixes required for each authorized workflow.

**Remediation:** Restrict bucket policy to named IAM role ARNs and specific object prefixes. Remove wildcard principals and broad s3:* actions. Use IAM Access Analyzer to identify unused permissions and generate least-privilege policies from CloudTrail activity.

---

### CTL.S3.ACCOUNT.PAB.001

**Account-Level Block Public Access Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; soc2: CC6.1;

The AWS account must have S3 Block Public Access enabled at the account level. Account-level PAB overrides all bucket and object settings, providing a hard ceiling that prevents any S3 resource in the account from being made public regardless of bucket policies, ACLs, or access point policies. Without account-level PAB, each bucket's public access depends on its own settings, and a single misconfigured bucket or object ACL can expose data. Account-level PAB is the strongest single defense against accidental public exposure.

**Remediation:** Enable all four S3 Block Public Access settings at the account level using aws s3control put-public-access-block with the --account-id parameter. This blocks public access for all current and future buckets in the account. If specific buckets require public access, use CloudFront with Origin Access Control instead of making buckets directly public.

---

### CTL.S3.ACL.ESCALATION.001

**No Public ACL Modification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs must not be writable by AllUsers or AuthenticatedUsers. WRITE_ACP permission enables attackers to modify the ACL itself, granting themselves FULL_CONTROL and escalating to read, write, and delete all objects.

**Remediation:** Remove WRITE_ACP grants from the bucket ACL and remove policy statements granting s3:PutBucketAcl or s3:PutObjectAcl to public principals. Enable S3 Public Access Block with BlockPublicAcls set to true.

---

### CTL.S3.ACL.FULLCONTROL.001

**No FULL_CONTROL ACL Grants to Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs must not grant FULL_CONTROL to AllUsers or AuthenticatedUsers. FULL_CONTROL is the worst-case ACL misconfiguration — the grantee can read, write, and delete objects and modify the ACL itself.

**Remediation:** Replace the bucket ACL with "BucketOwnerFullControl" or remove the FULL_CONTROL grant to public groups. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.ACL.OBJECT.001

**Objects Must Not Be Individually Public via ACL**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; soc2: CC6.1;

S3 buckets must not contain objects that are individually made public through object-level ACL grants. When a bucket itself is not public, individual objects can still be accessible from the internet if their ACL grants read access to AllUsers or AuthenticatedUsers. This is the "Objects can be public" status in AWS — the bucket is private but objects inside it are exposed. This is a primary vector for data leakage through misplaced sensitive files, where a single object with a public ACL in an otherwise private bucket exposes data that was never intended to be public.

**Remediation:** Set Object Ownership to BucketOwnerEnforced to disable all ACLs. If that is not immediately possible, enable S3 Block Public Access with IgnorePublicAcls set to true, then audit object ACLs using S3 Inventory with the optional ACL fields. Remove public grants from individual objects using aws s3api put-object-acl.

---

### CTL.S3.ACL.RECON.001

**No Public ACL Readability**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs should not be readable by unauthenticated users. READ_ACP permission enables attackers to enumerate ACL grants, discover which principals have access, and find escalation paths.

**Remediation:** Remove READ_ACP grants from the bucket ACL and remove policy statements granting s3:GetBucketAcl or s3:GetObjectAcl to public principals. Enable S3 Public Access Block with BlockPublicAcls set to true.

---

### CTL.S3.ACL.WRITE.001

**No Public Write via ACL**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs must not grant write access to AllUsers or AuthenticatedUsers. ACL-based write access enables attackers to upload malicious objects or overwrite existing content.

**Remediation:** Replace the bucket ACL with "BucketOwnerFullControl" or remove the public write grant. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.AUDIT.OBJECTLEVEL.001

**CloudTrail Object-Level Logging Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1.3; soc2: CC7.1;

CloudTrail S3 object-level data event logging must be enabled for PHI buckets. Server access logging captures bucket-level operations but not individual object access patterns. CloudTrail data events record GetObject, PutObject, and DeleteObject calls required for HIPAA audit controls.

**Remediation:** Configure a CloudTrail trail with a data event selector for AWS::S3::Object covering this bucket. Use aws cloudtrail put-event-selectors to add the selector.

---

### CTL.S3.AUTH.READ.001

**No Authenticated-Users Read Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant read access to all authenticated AWS users. AuthenticatedUsers scope means any AWS account can read objects, which is nearly as dangerous as fully public access.

**Remediation:** Remove the ACL grant to AuthenticatedUsers. Replace with specific IAM principals or use bucket policy with explicit account IDs. Enable S3 Public Access Block with IgnorePublicAcls set to true.

---

### CTL.S3.AUTH.WRITE.001

**No Authenticated-Users Write Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant write or delete access to all authenticated AWS users. AuthenticatedUsers scope means any AWS account holder worldwide can upload, overwrite, or delete objects — enabling data injection, ransomware, and supply chain poisoning.

**Remediation:** Remove the ACL grant or policy statement granting write access to AuthenticatedUsers. Replace with specific IAM principals or use bucket policy with explicit account IDs. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.BREACH.DETECT.001

**PHI Buckets Must Have Complete Detection Infrastructure**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IR-4; hipaa: 164.400; nist_800_53_r5: IR-4; soc2: CC7.1;

S3 buckets tagged with data-classification=phi must have all four detection components active: server access logging, CloudTrail object-level logging, GuardDuty S3 protection, and AWS Config recording. Missing any one component creates a gap in breach detection and incident investigation capability. HIPAA §§164.400-414 requires the ability to detect and investigate unauthorized access to PHI.

**Remediation:** Ensure all four components are active for this bucket: 1. Server access logging (aws s3api put-bucket-logging) 2. CloudTrail object-level data events (aws cloudtrail put-event-selectors) 3. GuardDuty S3 protection (aws guardduty update-detector) 4. AWS Config recording (aws configservice put-configuration-recorder)

---

### CTL.S3.BUCKET.TAKEOVER.001

**Referenced S3 Buckets Must Exist And Be Owned**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

Any externally referenced S3 bucket must exist and be owned. Dangling references (missing or unowned buckets) enable bucket takeover and attacker-controlled content delivery.

**Remediation:** Create the S3 bucket in your AWS account, or remove the DNS record, CDN origin, or application reference pointing to the unclaimed bucket.

---

### CTL.S3.CDN.EXPOSURE.001

**Private Bucket Must Not Be Publicly Exposed Via CloudFront**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

A bucket with Block Public Access enabled can still serve objects publicly through CloudFront if the bucket policy grants access to the cloudfront.amazonaws.com service principal. This creates a false sense of security — the bucket appears private but objects are accessible via the CloudFront distribution URL.

**Remediation:** 1. Review whether public CDN access is intentional for this bucket. 2. If not intentional, remove the CloudFront distribution or restrict
   it with signed URLs/cookies.
3. If intentional, document this as an acknowledged exposure path
   and add a Stave exemption for this bucket.

---

### CTL.S3.CDN.OAC.001

**CloudFront Access Must Use OAC Not Legacy OAI**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance

When S3 objects are served via CloudFront, Origin Access Control (OAC) should be used instead of the legacy Origin Access Identity (OAI). OAC supports SSE-KMS, SigV4, and all S3 features. OAI is a legacy mechanism that does not support KMS encryption and is being deprecated.

**Remediation:** 1. Create an Origin Access Control for the distribution. 2. Update the distribution origin to use OAC instead of OAI. 3. Update the bucket policy to grant cloudfront.amazonaws.com
   with a Condition restricting to the distribution ARN.
4. Remove the legacy OAI.

---

### CTL.S3.CONTROLS.001

**Public Access Block Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; pci_dss_v3.2.1: 1.3.6; pci_dss_v4.0: 2.2.1; soc2: CC6.1;

S3 buckets must have the public access block fully enabled. When disabled, the bucket has no safety net against accidental public exposure from policy or ACL changes. This detects the enabling condition for public access, not the exposure itself.

**Remediation:** Enable all four Public Access Block settings on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.

---

### CTL.S3.DANGLING.ORIGIN.001

**CDN S3 Origins Must Not Be Dangling**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

CloudFront distributions must not reference S3 origins that do not exist. A missing/unclaimed origin bucket enables takeover and CDN content poisoning.

**Remediation:** Create the S3 bucket in your AWS account to claim the name, or remove the dangling origin from the CloudFront distribution. Update the distribution to use an Origin Access Control (OAC).

---

### CTL.S3.DETECT.MACIE.001

**Sensitive Data Buckets Must Have Macie Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: RA-5; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.12; nist_800_53_r5: RA-5; pci_dss_v4.0: 11.5.1; soc2: CC7.2;

S3 buckets tagged with a non-public data classification (phi, pii, confidential, internal) must be monitored by Amazon Macie. Macie uses machine learning and pattern matching to discover and classify sensitive data, detecting PII, PHI, and credentials that may have been stored without proper controls. Without Macie, sensitive data can accumulate undetected in buckets that were not originally intended for it.

**Remediation:** Enable Amazon Macie in the account and region, then add this bucket to a Macie classification job. Use aws macie2 create-classification-job to configure automated scanning. For organization-wide coverage, enable Macie via AWS Organizations delegated administrator.

---

### CTL.S3.DETECT.MACIE.002

**Macie Automated Sensitive Data Discovery Must Be Active**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: SI-4; soc2: CC7.2;

Buckets monitored by Macie must have automated sensitive data discovery actively running, not just enabled. A Macie classification job can exist but be paused, cancelled, or have never completed a scan. Without active discovery, new sensitive data uploaded after the last scan goes undetected. Automated discovery continuously samples bucket contents to find sensitive data as it arrives.

**Remediation:** Verify the Macie classification job for this bucket is in RUNNING status. If paused, resume it with aws macie2 update-classification-job. Enable automated sensitive data discovery at the account level with aws macie2 update-automated-discovery-configuration to ensure continuous sampling of all monitored buckets.

---

### CTL.S3.ENCRYPT.001

**Encryption at Rest Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v3.2.1: 3.4; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

S3 buckets must have server-side encryption enabled. Unencrypted storage is the top audit finding in regulated industries.

**Remediation:** Enable default bucket encryption using SSE-S3 (AES256) or SSE-KMS. Use aws s3api put-bucket-encryption to set the default encryption configuration. For sensitive data, use SSE-KMS with a customer-managed key.

---

### CTL.S3.ENCRYPT.002

**Transport Encryption Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.2; cis_aws_v3.0: 2.1.1; fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-8; nist_csf_2.0: PR.DS; pci_dss_v3.2.1: 4.1; pci_dss_v4.0: 4.2.1; soc2: CC6.1;

S3 buckets must enforce HTTPS via a deny policy on aws:SecureTransport=false. Without this, data transfers occur in plaintext.

**Remediation:** Add a bucket policy statement that denies all actions when aws:SecureTransport is false. This forces all API calls to use HTTPS.

---

### CTL.S3.ENCRYPT.003

**PHI Buckets Must Use SSE-KMS with Customer-Managed Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.5.1; soc2: CC6.7;

S3 buckets tagged with data-classification=phi must use SSE-KMS encryption with a customer-managed key (CMK), not the default AWS-managed key or SSE-S3. This ensures the organization controls key rotation, access policies, and audit logging for PHI data at rest.

**Remediation:** Change the bucket default encryption to SSE-KMS and specify a customer-managed KMS key ARN. Ensure the KMS key policy grants access only to authorized principals. Enable KMS key rotation.

---

### CTL.S3.ENCRYPT.004

**Sensitive Data Requires KMS Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets with any non-public data classification must use SSE-KMS encryption with a customer-managed key, not SSE-S3 (AES256). AES256 uses AWS-managed keys with no customer control over key rotation, access policies, or audit trails. This fires on all classified data except explicitly public or non-sensitive buckets.

**Remediation:** Change the bucket default encryption to SSE-KMS with a customer-managed key. Re-encrypt existing objects by copying them in place with the new encryption settings.

---

### CTL.S3.GOVERNANCE.001

**Data Classification Tag Required**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must have a data-classification tag. Without this tag, tag-conditional controls for PHI, PII, confidential data, backup integrity, and compliance retention cannot evaluate — the bucket silently passes all sensitivity-gated checks regardless of actual content.

**Remediation:** Add a data-classification tag to the bucket with an appropriate value (e.g., phi, pii, confidential, internal, public, non-sensitive). Update your tagging policy to require this tag on all S3 buckets.

---

### CTL.S3.INCOMPLETE.001

**Complete Data Required for Safety Assessment**

- **Severity:** low
- **Type:** unsafe_duration
- **Domain:** storage

S3 bucket safety cannot be proven when policy or ACL data is missing from the snapshot.

**Remediation:** Re-run the observation collector with full permissions to read bucket policies and ACLs. Ensure the collector IAM role has s3:GetBucketPolicy, s3:GetBucketAcl, and s3:GetBucketPolicyStatus permissions.

---

### CTL.S3.INVENTORY.001

**S3 Inventory Must Be Enabled for Visibility**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-8; hipaa: 164.312(b); nist_800_53_r5: CM-8; soc2: CC7.2;

S3 buckets must have S3 Inventory configured to provide a complete manifest of all objects, their storage classes, encryption status, and optionally their ACL grants. Without Inventory, organizations have no baseline visibility into what data exists in a bucket, making it impossible to detect misplaced sensitive files, verify encryption coverage, or audit object-level access. S3 Inventory is essential when Amazon Macie is not deployed, as it provides the only mechanism for systematic bucket content auditing at scale.

**Remediation:** Configure S3 Inventory on the bucket using aws s3api put-bucket-inventory-configuration. Include optional fields for encryption status and ACL grants. Set the inventory to report daily or weekly to a secured destination bucket. Use the inventory reports to audit for misplaced sensitive data, unencrypted objects, and objects with public ACL grants.

---

### CTL.S3.LIFECYCLE.001

**Retention-Tagged Buckets Must Have Lifecycle Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: C1.2;

S3 buckets tagged with data-retention must have at least one enabled lifecycle rule configured. HIPAA requires defined data retention policies for protected health information (PHI), audit logs, and billing records. Without lifecycle rules, data persists indefinitely, increasing exposure surface and violating retention policy requirements.

**Remediation:** Add S3 lifecycle rules to manage object expiration and transitions. Configure rules matching the retention period specified in the data-retention tag. Use lifecycle transitions to move data to cheaper storage classes before expiration.

---

### CTL.S3.LIFECYCLE.002

**PHI Buckets Must Not Expire Data Before Minimum Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi must not have lifecycle expiration rules that delete data before the minimum HIPAA retention period. HIPAA requires medical records to be retained for a minimum of 6 years (2190 days). This control detects PHI buckets with expiration rules set below this threshold, which could result in premature deletion of protected health information.

**Remediation:** Increase the lifecycle expiration period to at least the configured min_retention_days value. If the current rule is for storage class transition, ensure the expiration rule is separate and meets the minimum retention period.

---

### CTL.S3.LOCK.001

**Compliance-Tagged Buckets Must Have Object Lock Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.316(b)(2); soc2: CC6.1;

S3 buckets tagged with any compliance framework (soc2, gdpr, hipaa, pci-dss, etc.) must have S3 Object Lock enabled. Object Lock provides WORM (Write Once Read Many) protection, preventing objects from being deleted or overwritten for a specified retention period. Regulatory frameworks require immutable storage for audit logs, compliance records, and protected data.

**Remediation:** Enable S3 Object Lock on the bucket. Note: Object Lock can only be enabled at bucket creation. If the bucket already exists, create a new bucket with Object Lock enabled and migrate objects. Set a default retention period appropriate for your compliance framework.

---

### CTL.S3.LOCK.002

**PHI Buckets Must Use COMPLIANCE Mode Object Lock**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi that have Object Lock enabled must use COMPLIANCE mode, not GOVERNANCE mode. COMPLIANCE mode prevents ANY user, including the root account, from deleting or overwriting protected objects during the retention period. GOVERNANCE mode allows users with special permissions to override retention, which is insufficient for HIPAA-regulated PHI data where tamper-proof storage is required.

**Remediation:** Change the Object Lock default retention mode from GOVERNANCE to COMPLIANCE. In COMPLIANCE mode, no user (including root) can delete or modify protected objects during the retention period.

---

### CTL.S3.LOCK.003

**PHI Object Lock Retention Must Meet Minimum Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi that have Object Lock enabled must have a default retention period of at least 2190 days (6 years) to meet HIPAA minimum retention requirements. Shorter retention periods risk premature expiration of WORM protection, allowing deletion or modification of PHI data before the regulatory retention period has elapsed.

**Remediation:** Increase the Object Lock default retention period to at least 2190 days. Use aws s3api put-object-lock-configuration to update the default retention settings.

---

### CTL.S3.LOG.001

**Access Logging Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.3; fedramp_moderate: AU-2; ffiec: ISH-4; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-2; pci_dss_v3.2.1: 10.2.1; pci_dss_v4.0: 10.2.1.3; soc2: CC7.2;

S3 buckets must have server access logging enabled for audit trail and visibility into data access patterns.

**Remediation:** Enable S3 server access logging and specify a target bucket for log delivery. Ensure the target bucket has appropriate access controls and is in the same region.

---

### CTL.S3.MALWARE.001

**PHI Buckets Must Have Malware Scanning Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; hipaa: 164.308(a)(5)(ii)(B); nist_800_53_r5: SI-3; soc2: CC6.8;

S3 buckets tagged with data-classification=phi must have malware scanning enabled via GuardDuty S3 Malware Protection or an equivalent scanning pipeline. Without scanning, uploaded files containing malware can persist in PHI storage indefinitely, creating both a security risk (malware distribution) and a compliance violation (HIPAA §164.308(a)(5)(ii)(B) requires protection against malicious software).

**Remediation:** Enable GuardDuty S3 Malware Protection for the bucket. Navigate to GuardDuty > S3 Protection > Enable. Alternatively, deploy a Lambda-based AV scanning pipeline triggered by S3 PutObject events.

---

### CTL.S3.MFADELETE.001

**MFA Delete Must Be Enabled on S3 Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.2; soc2: CC6.1;

S3 buckets should have MFA Delete enabled on versioned buckets. MFA Delete requires a second factor to permanently delete object versions, preventing unauthorized or accidental data destruction.

**Remediation:** Enable MFA Delete (requires root credentials): aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "arn:aws:iam::<account>:mfa/root-account-mfa-device <code>"

---

### CTL.S3.MRAP.PAB.001

**Multi-Region Access Point Must Have Block Public Access Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

MRAPs have their own PAB settings independent of bucket PAB. A bucket can have PAB enabled while the MRAP has PAB disabled.

**Remediation:** Enable all four PAB flags on the MRAP.

---

### CTL.S3.MRAP.POLICY.001

**Multi-Region Access Point Policy Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

MRAPs can have their own resource policy evaluated independently of the bucket policy. A public MRAP policy creates a public access path.

**Remediation:** Remove public access from the MRAP policy.

---

### CTL.S3.NETWORK.001

**Public-Principal Policies Must Have Network Conditions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies that grant access to Principal * (any AWS principal) must include network-scoping conditions such as aws:SourceIp, aws:sourceVpce, aws:SourceVpc, or aws:PrincipalOrgID. Without these conditions, the bucket is accessible to anyone on the internet. This control detects policies where wildcard principals are used without network restrictions.

**Remediation:** Add network-scoping conditions to the bucket policy: aws:SourceIp for IP range restrictions, aws:SourceVpce for VPC endpoint restrictions, aws:SourceVpc for VPC restrictions, or aws:PrincipalOrgID for organization-only access.

---

### CTL.S3.NETWORK.POLICY.001

**VPC Endpoint Policy Must Restrict Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1);

VPC endpoint policy must be attached and must not be the default full-access policy (Allow * on *). The default policy allows any principal on the VPC to reach any S3 bucket in any account via the endpoint, bypassing firewall controls. A restrictive endpoint policy limits which bucket ARNs and actions are reachable.

**Remediation:** Replace the default endpoint policy with one that restricts Resource to specific bucket ARNs and Action to required S3 operations only.

---

### CTL.S3.NETWORK.VPC.001

**VPC Endpoint or IP Condition Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1);

S3 bucket access must be restricted by a VPC endpoint condition (aws:SourceVpce) or an IP address condition (aws:SourceIp) in the bucket policy. Without network-level restrictions, the bucket is reachable from any network path. This control enforces transmission security for PHI workloads.

**Remediation:** Add a VPC gateway endpoint for S3 and route bucket traffic through it, or add an IP condition (aws:SourceIp) to the bucket policy to restrict access to known CIDR ranges.

---

### CTL.S3.OWNERSHIP.001

**S3 Object Ownership Must Be Bucket Owner Enforced**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.2; fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; soc2: CC6.1;

S3 buckets must have Object Ownership set to BucketOwnerEnforced, which disables ACLs entirely. When ACLs are disabled, the bucket owner automatically owns every object regardless of who uploaded it, and access is controlled exclusively through IAM and bucket policies. This eliminates the entire class of ACL-based exposure: public grants, privilege escalation via WRITE_ACP, and object-level ACL overrides. Since April 2023 new buckets default to BucketOwnerEnforced, but buckets created before this date may still have ACLs enabled.

**Remediation:** Set Object Ownership to BucketOwnerEnforced using aws s3api put-bucket-ownership-controls. This disables all ACLs on the bucket. Before enabling, audit existing ACL grants and migrate any legitimate access to bucket policies or IAM policies. All existing ACL-based access will stop working once BucketOwnerEnforced is set.

---

### CTL.S3.PRESIGNED.001

**Presigned URL Access Must Be Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

PHI bucket policy must restrict presigned URL access using s3:signatureAge (maximum age in milliseconds) or s3:authType (require REST-HEADER to block presigned URLs). Without these guardrails, presigned URLs can provide long-lived unauthenticated access to PHI data.

**Remediation:** Add a Deny statement with Condition NumericGreaterThan s3:signatureAge (e.g., 600000 for 10 minutes) or StringNotEquals s3:authType REST-HEADER to block presigned URL access.

---

### CTL.S3.PUBLIC.001

**No Public S3 Bucket Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v3.2.1: 1.2.1; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

S3 buckets must not allow public read access. Detects buckets with anonymous read exposure via policy or ACL.

**Remediation:** Enable S3 Public Access Block (all four settings). Remove any bucket policy statements granting access to Principal "*". Remove any ACL grants to AllUsers or AuthenticatedUsers.

---

### CTL.S3.PUBLIC.002

**No Public S3 Buckets With Sensitive Data**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with sensitive data classifications (PHI, PII, confidential) must not allow any public access.

**Remediation:** Immediately enable S3 Public Access Block (all four settings). Remove bucket policy statements granting access to Principal "*". Remove ACL grants to AllUsers or AuthenticatedUsers. Audit CloudTrail logs for unauthorized access during the exposure window.

---

### CTL.S3.PUBLIC.003

**No Public Write Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not allow public write or delete access. Public write enables data injection, ransomware, and policy takeover.

**Remediation:** Remove bucket policy statements that grant s3:PutObject or s3:DeleteObject to Principal "*". Remove ACL grants that allow WRITE or FULL_CONTROL to AllUsers or AuthenticatedUsers. Enable S3 Public Access Block.

---

### CTL.S3.PUBLIC.004

**No Public Read via ACL**

- **Severity:** medium
- **Type:** unsafe_duration
- **Domain:** storage

S3 bucket ACLs must not grant read access to AllUsers or AuthenticatedUsers for PHI data.

**Remediation:** Replace the bucket ACL with "BucketOwnerFullControl" or remove the public read grant. Enable S3 Public Access Block with IgnorePublicAcls set to true to override ACL-based public access.

---

### CTL.S3.PUBLIC.005

**No Latent Public Read Exposure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** storage

S3 buckets must not have latent public read exposure where a public mechanism (policy or ACL) is masked only by Public Access Block. Removing PAB would immediately expose the bucket.

**Remediation:** Remove the underlying public-granting policy statement or ACL entry so the bucket does not depend solely on PAB for protection. Then verify PAB remains enabled as defense-in-depth.

---

### CTL.S3.PUBLIC.006

**No Latent Public Bucket Listing**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket has a policy or ACL that would allow public listing if the public access block were removed. The public access block is currently the only control preventing directory enumeration. This is a latent vulnerability — one configuration change away from exposing all object keys.

**Remediation:** Remove the underlying policy statement or ACL entry that grants s3:ListBucket to Principal "*" or AllUsers. Do not rely solely on PAB to prevent directory enumeration.

---

### CTL.S3.PUBLIC.007

**No Public Read via Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not grant public read access.

**Remediation:** Remove or constrain the public policy statement. Use restrictive principals or conditions and keep Public Access Block enabled.

---

### CTL.S3.PUBLIC.008

**No Public List via Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not grant anonymous object listing.

**Remediation:** Remove or constrain policy statements allowing s3:ListBucket to anonymous principals.

---

### CTL.S3.PUBLIC.LIST.001

**No Public S3 Bucket Listing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not allow anonymous listing of objects. Public listing exposes object keys, enabling targeted data exfiltration.

**Remediation:** Remove bucket policy statements that grant s3:ListBucket to Principal "*". Remove ACL grants that allow READ to AllUsers. Enable S3 Public Access Block.

---

### CTL.S3.PUBLIC.LIST.002

**Anonymous S3 Listing Must Be Explicitly Intended**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Anonymous bucket listing increases exposure surface even when objects are public by design. Listing must be explicitly intended via tag.

**Remediation:** If listing is intentional, add the tag public_list_intended=true to the bucket. Otherwise, remove the policy or ACL granting s3:ListBucket to Principal "*" or AllUsers.

---

### CTL.S3.PUBLIC.PREFIX.001

**Protected Prefixes Must Not Be Publicly Readable**

- **Severity:** high
- **Type:** prefix_exposure
- **Domain:** exposure

S3 bucket prefixes marked as protected must not be publicly readable. Evaluates bucket policies, ACL grants, and public access block settings to determine effective public read access for each protected prefix. Customize the prefix lists below to match your bucket layout.

**Remediation:** 1. Review the protected_prefixes and allowed_public_prefixes lists
   in this control and adjust them to match your bucket layout.
2. Enable S3 Public Access Block to restrict policy and ACL exposure. 3. Remove bucket policy statements granting s3:GetObject to Principal "*"
   for protected prefixes.
4. Remove ACL grants to AllUsers or AuthenticatedUsers.

---

### CTL.S3.REGION.001

**S3 Buckets Must Be in Approved Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** gdpr: Art.44;

S3 buckets containing personal data must be located in approved regions as determined by data residency requirements (e.g., EU/EEA regions for GDPR). Storing data outside approved regions may violate data transfer restrictions.

**Remediation:** Create a new bucket in an approved region and migrate data. Use S3 replication to move data, then delete the original bucket.

---

### CTL.S3.REPLICATION.001

**Compliance-Tagged Buckets Must Have Replication Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7); iso_27001_2022: A.8.13; nist_800_53_r5: CP-9; soc2: A1.1;

S3 buckets tagged with a compliance framework (soc2, gdpr, hipaa, pci-dss, etc.) must have replication configured. Without replication, a regional outage or accidental bucket deletion can cause permanent data loss for regulated data. Replication provides an independent copy that survives single-region failures and supports disaster recovery objectives.

**Remediation:** Configure S3 replication on the bucket using aws s3api put-bucket-replication. Use cross-region replication (CRR) for disaster recovery or same-region replication (SRR) for compliance copies. Ensure versioning is enabled on both source and destination buckets.

---

### CTL.S3.REPLICATION.002

**PHI Replication Must Be Cross-Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-6(1); hipaa: 164.308(a)(7)(ii)(A); nist_800_53_r5: CP-6(1); soc2: A1.2;

S3 buckets tagged with data-classification=phi that have replication enabled must replicate to a different AWS region. Same-region replication (SRR) does not protect against regional outages, AZ-wide failures, or region-scoped service disruptions. HIPAA contingency planning requires data to survive regional disasters.

**Remediation:** Update the replication configuration to use a destination bucket in a different AWS region. Ensure the destination bucket has versioning enabled, appropriate encryption, and a bucket policy that permits the replication role.

---

### CTL.S3.REPLICATION.003

**Replication Destination Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

When S3 replication is enabled, the destination bucket must have server-side encryption configured. Replicating data to an unencrypted destination creates a shadow copy that bypasses the source bucket's encryption controls. This is especially dangerous for sensitive data where the source meets encryption requirements but the replica does not.

**Remediation:** Configure default encryption on the destination bucket using SSE-S3 or SSE-KMS. For replication of encrypted objects, add a ReplicaKmsKeyID to the replication rule so objects are re-encrypted with a key in the destination region.

---

### CTL.S3.REPO.ARTIFACT.001

**Public Buckets Must Not Expose VCS Artifacts**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

Buckets that serve public content must not expose version control artifacts such as .git/ or .svn/. Presence of these paths enables repo reconstruction and can leak secrets.

**Remediation:** Remove .git/, .svn/, and other VCS directories from the bucket. Add a lifecycle rule or deployment script that excludes VCS artifacts from uploads. If the bucket is a static website, configure your build pipeline to strip VCS files before deployment.

---

### CTL.S3.TENANT.ISOLATION.001

**Shared-Bucket Tenant Isolation Must Enforce Prefix**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

When a shared S3 bucket uses prefix-based tenant isolation, every app-signer identity that produces presigned URLs must enforce the tenant prefix.  An identity that allows path traversal (../) or disables prefix enforcement lets one tenant read or overwrite another tenant's objects.

**Remediation:** Update the app-signer configuration to enforce tenant prefix restrictions (enforce_prefix=true) and block path traversal (allow_traversal=false) on all presigned URL signers.

---

### CTL.S3.VERSION.001

**Versioning Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.3; hipaa: 164.312(c)(1); soc2: CC6.1;

S3 buckets must have versioning enabled to protect against accidental deletion and enable recovery from negligent operations.

**Remediation:** Enable versioning on the bucket using aws s3api put-bucket-versioning. Once enabled, configure lifecycle rules to manage noncurrent versions and control storage costs.

---

### CTL.S3.VERSION.002

**Backup Buckets Must Have MFA Delete Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with backup=true must have MFA delete enabled. MFA delete requires multi-factor authentication to permanently delete object versions, protecting against ransomware attacks and accidental mass deletion of backup data. Without MFA delete, any principal with s3:DeleteObject permission can permanently destroy backup versions.

**Remediation:** Enable MFA delete on the bucket using aws s3api put-bucket-versioning with the MFA flag. This requires the root account credentials and an MFA device. Only the root account can enable or disable MFA delete.

---

### CTL.S3.WEBSITE.PUBLIC.001

**No Public Website Hosting with Public Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets with static website hosting enabled must not also have public read access. Website hosting combined with public read serves content directly to the internet.

**Remediation:** If public hosting is not intended, disable static website hosting and remove public read access. If hosting is intended, move content behind CloudFront with an Origin Access Control (OAC) and remove direct public access from the bucket.

---

### CTL.S3.WRITE.CONTENT.001

**S3 Signed Upload Must Restrict Content Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Signed upload policies must restrict allowed content types. Unrestricted content types enable attackers to upload SVGs with embedded JavaScript or HTML files, causing stored XSS when served from the bucket's domain.

**Remediation:** Add an exact content-type condition to the signed upload policy (e.g., eq $Content-Type image/jpeg). Avoid starts-with with empty prefix, which allows any content type.

---

### CTL.S3.WRITE.SCOPE.001

**S3 Signed Upload Must Bind To Exact Object Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Signed upload policies must restrict write permission to a single exact object key. Prefix-wide permissions (e.g., starts-with $key files/) enable arbitrary overwrite and cross-tenant tampering.

**Remediation:** Change the signed upload policy to use an exact key condition (eq instead of starts-with) that binds each upload to a specific object path. Generate unique object keys server-side.

---

### CTL.SECRETSMANAGER.ACCESS.001

**Secrets Must Have Rotation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

Secrets Manager secrets must have automatic rotation enabled. Long-lived secrets that are never rotated increase the blast radius of credential leaks and prevent timely revocation.

**Remediation:** Configure automatic rotation with a Lambda function. Run: aws secretsmanager rotate-secret --secret-id xxx --rotation-lambda-arn arn:aws:lambda:... --rotation-rules AutomaticallyAfterDays=90

---

### CTL.SECRETSMANAGER.ENCRYPT.001

**Secrets Must Be Encrypted with Customer-Managed KMS Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Secrets Manager secrets must be encrypted with a customer-managed KMS key. The default AWS-managed key does not support key revocation or cross-account key policies needed for breach response.

**Remediation:** Recreate the secret with a customer-managed KMS key specified. Secrets Manager does not allow changing the encryption key after creation.

---

### CTL.SECRETSMANAGER.INCOMPLETE.001

**Complete Data Required for Secrets Manager Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Secrets Manager properties. A safety assessment cannot be completed without secret configuration data.

**Remediation:** Ensure the extractor calls aws secretsmanager describe-secret and maps the response to the secret observation properties.

---

### CTL.SECURITYHUB.ENABLED.001

**AWS Security Hub Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; nist_csf_2.0: DE.CM; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

Security Hub must be enabled to aggregate security findings from GuardDuty, Inspector, Macie, and Config into a unified view.

**Remediation:** Enable Security Hub: aws securityhub enable-security-hub --enable-default-standards

---

### CTL.SECURITYHUB.INCOMPLETE.001

**Complete Data Required for Security Hub Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Security Hub properties.

**Remediation:** Ensure the extractor calls aws securityhub describe-hub.

---

### CTL.SNS.ENCRYPT.001

**SNS Topics Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

SNS topics must use server-side encryption with a KMS key. Unencrypted topics expose message payloads at rest, which may contain PHI or other sensitive notification data.

**Remediation:** Enable SSE-KMS on the topic. Run: aws sns set-topic-attributes --topic-arn xxx --attribute-name KmsMasterKeyId --attribute-value arn:aws:kms:...

---

### CTL.SNS.INCOMPLETE.001

**Complete Data Required for SNS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required SNS topic properties.

**Remediation:** Ensure the extractor calls aws sns get-topic-attributes and maps the KmsMasterKeyId to the messaging.encryption observation properties.

---

### CTL.SQS.DLQ.001

**SQS Queues Must Have Dead-Letter Queue Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: PI1.1;

SQS queues processing critical workloads must have a dead-letter queue configured. Without a DLQ, messages that fail processing are silently lost.

**Remediation:** Configure a DLQ: aws sqs set-queue-attributes --queue-url <url> --attributes RedrivePolicy='{"deadLetterTargetArn":"<dlq-arn>","maxReceiveCount":"3"}'

---

### CTL.SQS.ENCRYPT.001

**SQS Queues Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

SQS queues must use server-side encryption with a KMS key. Unencrypted queues expose message payloads at rest, which may contain PHI or other sensitive data.

**Remediation:** Enable SSE-KMS on the queue. Run: aws sqs set-queue-attributes --queue-url xxx --attributes KmsMasterKeyId=arn:aws:kms:...

---

### CTL.SQS.INCOMPLETE.001

**Complete Data Required for SQS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required SQS queue properties.

**Remediation:** Ensure the extractor calls aws sqs get-queue-attributes and maps the KmsMasterKeyId to the messaging.encryption observation properties.

---

### CTL.VPC.DEFAULT.001

**Default VPC Must Not Be Used**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

Workloads must not run in the default VPC. The default VPC is created automatically in every region with permissive settings: a public subnet in each AZ, an internet gateway, and a default security group that allows all internal traffic. These defaults create implicit public exposure that custom VPCs avoid. Production and sensitive workloads must use purpose-built VPCs with explicit network design.

**Remediation:** Create a custom VPC with private subnets, explicit route tables, and restrictive security groups. Migrate workloads from the default VPC. Consider deleting the default VPC in production accounts if no workloads require it.

---

### CTL.VPC.ENV.ISOLATION.001

**Production VPC Must Be Isolated from Non-Production**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.22; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Production VPCs must not share network boundaries with non-production environments. When production and dev/staging workloads share a VPC, a misconfiguration or compromise in a lower environment can reach production resources through security group rules, VPC peering, or shared subnets. Environment isolation requires separate VPCs with explicit, auditable cross-VPC connections.

**Remediation:** Create separate VPCs for each environment (prod, staging, dev). Tag VPCs with an environment classification tag. Use VPC peering or Transit Gateway with explicit route tables for any required cross-environment communication. Ensure security groups do not reference resources in other environments.

---

### CTL.VPC.FLOWLOG.001

**VPC Flow Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.9; cis_aws_v3.0: 3.7; fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 1.2.1; soc2: CC7.1;

VPC flow logs capture information about IP traffic going to and from network interfaces. Without flow logs, network-level access patterns cannot be audited and unauthorized traffic goes undetected.

**Remediation:** Enable VPC flow logs to CloudWatch Logs or S3. Run: aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-xxx --traffic-type ALL --log-destination-type cloud-watch-logs

---

### CTL.VPC.FLOWLOG.ENCRYPT.001

**VPC Flow Logs Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

VPC flow logs contain network metadata (source/destination IPs, ports, protocols). When stored in S3, flow logs must be encrypted with a customer-managed KMS key to protect network topology information.

**Remediation:** Configure flow log destination with SSE-KMS encryption. For S3 destinations, enable default bucket encryption with a CMK.

---

### CTL.VPC.INCOMPLETE.001

**Complete Data Required for VPC Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

VPC safety cannot be assessed when flow logging status is missing from the snapshot. The extractor must populate network.flow_log.enabled.

**Remediation:** Re-run the extractor with VPC permissions: ec2:DescribeFlowLogs, ec2:DescribeVpcs.

---

### CTL.VPC.NACL.ADMIN.001

**No NACL Ingress from 0.0.0.0/0 to Admin Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Network ACLs must not allow inbound traffic from 0.0.0.0/0 or ::/0 to SSH (22) or RDP (3389) ports. NACLs apply to entire subnets — open admin ports expose all instances.

**Remediation:** Replace the allow rule with a specific CIDR for authorized admin IP ranges using aws ec2 replace-network-acl-entry.

---

### CTL.VPC.SG.DEFAULT.001

**Default Security Group Must Restrict All Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.4; cis_aws_v3.0: 5.4; fedramp_moderate: AC-4; hipaa: 164.312(a)(1); nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

The default VPC security group should not allow any inbound or outbound traffic. Resources should use custom security groups with explicit rules instead of relying on the default group.

**Remediation:** Remove all inbound and outbound rules from the default security group. Assign custom security groups to all resources.

---

### CTL.VPC.SG.EGRESS.001

**Security Groups Must Not Allow Unrestricted Egress**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

Security groups must not allow all outbound traffic to 0.0.0.0/0 on all ports. Unrestricted egress enables data exfiltration, command-and-control communication, and lateral movement to external attacker infrastructure. While most organizations currently allow all egress by default, restricting outbound traffic to required ports and destinations is a critical APT hardening measure.

**Remediation:** Replace the default allow-all egress rule with specific outbound rules for required ports (443 for HTTPS, 53 for DNS, etc.) and destinations. Use VPC endpoints for AWS service traffic to avoid internet egress entirely.

---

### CTL.VPC.SG.IPV6.001

**No Security Group Ingress from ::/0 to Admin Ports**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.3; fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security groups must not allow inbound SSH (22) or RDP (3389) from ::/0 (IPv6 any). IPv6 open admin ports are equally dangerous as IPv4 and are often overlooked during security reviews.

**Remediation:** Revoke the IPv6 ingress rule: aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,Ipv6Ranges=[{CidrIpv6=::/0}]

---

### CTL.VPC.SG.UNRESTRICTED.001

**Security Groups Must Not Allow Unrestricted Ingress**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.2; cis_aws_v3.0: 5.2; fedramp_moderate: AC-4; hipaa: 164.312(e)(1); nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security group rules must not allow ingress from 0.0.0.0/0 on sensitive ports (SSH, RDP, database). Unrestricted ingress exposes services to the entire internet.

**Remediation:** Restrict ingress rules to specific CIDR blocks or security group references. Remove 0.0.0.0/0 and ::/0 from ingress rules on ports 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL).

---

### CTL.WAF.INCOMPLETE.001

**Complete Data Required for WAF Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

WAF assessment data is incomplete. The extractor must populate waf.rules.has_managed_rules to evaluate protection controls.

**Remediation:** Re-run the extractor with WAF permissions: wafv2:GetWebACL, wafv2:ListWebACLs, wafv2:GetLoggingConfiguration.

---

### CTL.WAF.LOGGING.001

**WAF Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; nist_800_53_r5: AU-2; soc2: CC7.1;

WAF web ACLs must have logging enabled to record blocked and allowed requests. Without logging, attacks cannot be detected, investigated, or correlated with other security events.

**Remediation:** Enable WAF logging to S3, CloudWatch Logs, or Kinesis Data Firehose via aws wafv2 put-logging-configuration.

---

### CTL.WAF.RULES.001

**WAF Must Have Managed Rule Groups Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

WAF web ACLs must include AWS managed rule groups for common attack patterns (SQLi, XSS, known bad inputs). Without managed rules, the WAF provides no baseline protection against OWASP Top 10 attacks.

**Remediation:** Add AWS managed rule groups to the web ACL: AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesKnownBadInputsRuleSet.

---

