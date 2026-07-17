# Control Reference — ORG

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ORG.ACCOUNT.ALTERNATECONTACTS.001

**Account Has No Security Alternate Contact**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: IR-6; soc2: CC7.3;

AWS account has no security alternate contact configured. AWS sends security notifications to the alternate contacts. Without a security contact, notifications go only to the root email, which may not be monitored by the security team.

**Remediation:** Configure a security alternate contact via the AWS console or account:PutAlternateContact API. Set it to a distribution list monitored by the security team.

---

### CTL.ORG.ACCOUNT.ALTERNATECONTACTS.BILLING.001

**Account Has No Billing Alternate Contact**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SA-9; soc2: CC7.3;

AWS account has no billing alternate contact configured. Without a billing contact, cost alerts and billing notifications go only to the root email.

**Remediation:** Configure a billing alternate contact via the AWS console or account:PutAlternateContact API.

---

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

### CTL.ORG.DELEGATEDADMIN.ACCESSANALYZER.001

**No Delegated Admin for IAM Access Analyzer**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No delegated administrator account is registered for IAM Access Analyzer. Without delegated admin, Access Analyzer operates per-account and cannot detect cross-account resource sharing at the org level.

**Remediation:** Register a security account as the delegated administrator for IAM Access Analyzer using organizations:RegisterDelegatedAdministrator with service principal access-analyzer.amazonaws.com.

---

### CTL.ORG.DELEGATEDADMIN.GUARDDUTY.001

**No Delegated Admin for GuardDuty**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

No delegated administrator account is registered for GuardDuty in the organization. Without delegated admin, GuardDuty must be managed per-account or from the management account. Delegated admin allows a security account to manage GuardDuty across the org without accessing the payer.

**Remediation:** Register a security account as the delegated administrator for GuardDuty using organizations:RegisterDelegatedAdministrator with service principal guardduty.amazonaws.com.

---

### CTL.ORG.DELEGATEDADMIN.SECURITYHUB.001

**No Delegated Admin for Security Hub**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

No delegated administrator account is registered for Security Hub. Without delegated admin, Security Hub cannot centrally manage findings and standards across the organization.

**Remediation:** Register a security account as the delegated administrator for Security Hub using organizations:RegisterDelegatedAdministrator with service principal securityhub.amazonaws.com.

---

### CTL.ORG.DP.AMI.BLOCKPUBLIC.001

**Declarative Policy Does Not Block Public AMI Sharing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No declarative policy blocks public AMI sharing at the organizational level. The policy type is ec2_attributes.image_block_public_access with state = "block_new_sharing". Without this, any account admin can share AMIs publicly, potentially exposing proprietary software, credentials baked into images, or internal architecture details.

**Remediation:** Create a declarative policy of type ec2_attributes.image_block_public_access with state = "block_new_sharing" at the organization root.

---

### CTL.ORG.DP.IMDSV2.001

**Declarative Policy Does Not Enforce IMDSv2**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6; soc2: CC6.1;

No declarative policy enforces IMDSv2 at the organizational level. Existing controls check individual instances for IMDSv1 (CTL.EC2.IMDS.001); this control checks whether the organizational enforcement prevents IMDSv1 instances from being launched at all. Declarative policy enforcement is stronger than per-instance checks because it is preventive, not detective. The policy type is ec2_attributes.instance_metadata_defaults with http_tokens = "required". IMDSv2 is the Capital One chain's first member control — organizational enforcement closes the gap where a single instance launched without the flag reintroduces the SSRF-to-credential path.

**Remediation:** Create a declarative policy of type ec2_attributes.instance_metadata_defaults with http_tokens = "required" at the organization root. This makes IMDSv2 the default for all new instances across all accounts and prevents overriding to IMDSv1.

---

### CTL.ORG.DP.SNAPSHOT.BLOCKPUBLIC.001

**Declarative Policy Does Not Block Public EBS Snapshot Sharing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No declarative policy blocks public EBS snapshot sharing at the organizational level. The policy type is ec2_attributes.snapshot_block_public_access with state = "block_all_sharing". Without this, any account admin can share EBS snapshots publicly, exposing disk contents including databases, log files, and credentials.

**Remediation:** Create a declarative policy of type ec2_attributes.snapshot_block_public_access with state = "block_all_sharing" at the organization root.

---

### CTL.ORG.EXISTS.001

**Account Must Be Member of an AWS Organization**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.1; nist_800_53_r5: AC-6(5); soc2: CC6.6;

AWS account is standalone — not a member of an AWS Organization. Farris traces the multi-account strategy back to the CodeSpaces incident. A standalone account has no SCPs, no RCPs, no centralized root management, no organizational CloudTrail, and no service-linked roles for cross-account governance. It is the pre-2017 security posture. The collector sets the in_organization flag on the account summary asset.

**Remediation:** Create an AWS Organization and add this account as a member, or join an existing Organization. Enable all features to get access to SCPs, consolidated billing, and centralized governance.

---

### CTL.ORG.IDENTITYCENTER.ENABLED.001

**Organization Must Use Identity Center for Human Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.1; nist_800_53_r5: AC-2; soc2: CC6.1;

Organization does not use Identity Center (or an equivalent federated identity mechanism) for human access management. Farris describes per-account IAM Users as the AWS identity anti-pattern. Identity Center provides centralized, role-based, session-credential human access across all accounts. Its absence means human access uses long-term IAM User credentials, per-account. The collector sets identity_center_enabled on the organization asset; this field is true if Identity Center is configured OR if SAML providers exist in member accounts (indicating an equivalent external IdP federation).

**Remediation:** Enable Identity Center in the management account and configure permission sets for human access. Migrate existing IAM User access to Identity Center roles. If using an external IdP (Okta, Azure AD), configure SAML federation per account.

---

### CTL.ORG.OU.STRUCTURE.001

**Organization Must Have OU Structure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

All organization member accounts are directly under the root — no Organizational Unit structure exists. Without OUs, SCPs and RCPs can only be applied to all accounts or individual accounts. OU structure enables environment separation (prod/dev/staging), policy tiering, and the cross-environment isolation controls. The collector counts OUs with member accounts and sets has_ou_structure accordingly.

**Remediation:** Create OUs for environment separation (Production, Development, Staging, Sandbox) and workload type (Security, Infrastructure, Workloads). Move accounts into appropriate OUs and attach SCPs per OU.

---

### CTL.ORG.POLICY.S3BPA.001

**S3 BPA Organizational Policy Enabled at Org Root**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

An S3 Block Public Access organizational policy must be enabled at the organization root. Unlike IAM organizational policies, S3 BPA organizational policy does not follow deny-trumps-allow — an enable at the root can be overridden on specific accounts for legacy public buckets. The policy is all-or-nothing: it enables all four S3 BPA settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) or none. This is a third enforcement mechanism alongside SCPs (CTL.ORG.SCP.PROTECTBPA.001) and per-account BPA (CTL.S3.ACCOUNT.PAB.001). The organizational policy ensures BPA is the default for all accounts without requiring per-account configuration.

**Remediation:** Enable the S3 BPA organizational policy at the organization root. This enables all four BPA settings across all member accounts by default. Use account-level overrides for legacy accounts that require public bucket access.

---

### CTL.ORG.RCP.KMSSECRETSPERIMETER.001

**RCP Does Not Restrict KMS and Secrets Manager External Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No RCP restricts KMS key usage and Secrets Manager access from principals outside the organization. Without this RCP, a KMS key policy or Secrets Manager resource policy that grants access to an external account is effective — the external principal can decrypt data or read secrets even if no identity policy in the org grants them access. RCPs are the only mechanism that overrides resource-based policies at the organizational level. The RCP should deny kms:* and secretsmanager:* when aws:PrincipalOrgID is not the organization's ID.

**Remediation:** Create an RCP that denies kms:Decrypt, kms:Encrypt, kms:GenerateDataKey, kms:ReEncryptFrom, kms:ReEncryptTo, kms:CreateGrant, secretsmanager:GetSecretValue, secretsmanager:DescribeSecret when aws:PrincipalOrgID is not the organization's ID. Exempt AWS service principals that need cross-account key usage (e.g., for cross-account S3 replication with KMS).

---

### CTL.ORG.RCP.S3.ACLDISABLED.001

**RCP Does Not Enforce S3 ACL Disabled on Bucket Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No RCP enforces BucketOwnerEnforced object ownership on new S3 buckets. S3 ACLs are a legacy access control mechanism and a persistent source of public exposure. BucketOwnerEnforced disables ACLs entirely. Without this RCP, developers can create buckets with ACLs enabled and grant public access via ACL — bypassing bucket policies and BPA. The RCP should deny s3:CreateBucket when s3:x-amz-object-ownership is not BucketOwnerEnforced.

**Remediation:** Create an RCP that denies s3:CreateBucket with condition "s3:x-amz-object-ownership" != "BucketOwnerEnforced". Attach to the organization root.

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

### CTL.ORG.SCP.AGREEMENTS.001

**SCP Does Not Restrict Marketplace and Service Agreements**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SA-4; soc2: CC6.7;

No SCP restricts marketplace subscriptions, domain registrations, or AI model agreements. Existing controls cover reserved instances (CTL.IAM.SCP.RESERVEDINSTANCE.001) and savings plans (CTL.IAM.SCP.SAVINGSPLAN.001); this control covers the remaining agreement surface: aws-marketplace:Subscribe, route53domains:RegisterDomain, route53domains:TransferDomain, and bedrock:CreateFoundationModelAgreement. Unauthorized subscriptions create recurring charges; domain registrations create assets that can be used for phishing; AI model agreements expose the organization to model-specific terms and data processing risks.

**Remediation:** Add an SCP that denies aws-marketplace:Subscribe, aws-marketplace:CreateAgreement, route53domains:RegisterDomain, route53domains:TransferDomain, and bedrock:CreateFoundationModelAgreement. Exempt a procurement or cloud engineering role.

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

### CTL.ORG.SCP.CLOUDFORMATION.MACRO.001

**SCP Must Restrict CloudFormation Macro Usage**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SA-12; soc2: CC8.1;

An SCP must restrict CloudFormation macro usage to prevent resource injection via external macros. CloudFormation macros are Lambda-backed and can transform templates at deploy time. A macro from an external account can inject arbitrary resources into a stack. Technique: Wiz "Resource injection in CloudFormation template".

**Remediation:** Add an SCP restricting cloudformation:CreateStack and cloudformation:CreateChangeSet with conditions limiting macro sources to trusted accounts.

---

### CTL.ORG.SCP.DENY.GETFEDERATIONTOKEN.001

**SCP Must Deny sts:GetFederationToken**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

An SCP must deny sts:GetFederationToken unless explicitly needed. If an attacker calls GetFederationToken before their access key is revoked, the resulting session token remains valid even after the key is deleted. SCP-denying this action prevents the persistence mechanism. Technique: hackingthe.cloud survive access key deletion with sts:GetFederationToken.

**Remediation:** Add an SCP denying sts:GetFederationToken with a role-based exception for any workloads that legitimately require it.

---

### CTL.ORG.SCP.DENY.MODIFYUSERDATA.001

**SCP Must Restrict EC2 User Data Modification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

An SCP must deny ec2:ModifyInstanceAttribute for user data modification. An attacker stops an instance, modifies its user data to include a reverse shell or credential harvester, then starts it. The cloud-init script runs with root privileges on boot. Technique: hackingthe.cloud EC2 privilege escalation through user data.

**Remediation:** Add an SCP denying ec2:ModifyInstanceAttribute with a condition on the attribute type for userData. Use a role-based exception for authorized instance management.

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

### CTL.ORG.SCP.EVS.DENY.001

**SCP Does Not Deny EVS Usage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.6;

Organization SCPs do not deny Elastic VMware Service (EVS) usage in member accounts. EVS provisions a full VMware SDDC in an AWS-managed account — the customer sees an ENI but the compute, storage, and management plane run in infrastructure outside the customer's VPC. Without an SCP denying evs:*, any IAM principal can provision shadow VMware infrastructure invisible to the organization's CSPM, SIEM, and network monitoring.

**Remediation:** Add an SCP denying evs:* for all principals. Exclude specific accounts if EVS is intentionally used.

---

### CTL.ORG.SCP.LAMBDA.PUBLIC.001

**SCP Does Not Prevent Public Lambda Invocability**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No SCP prevents Lambda functions from being made publicly invocable or using unauthenticated Function URLs. Existing controls (CTL.LAMBDA.PUBLIC.001, CTL.LAMBDA.FUNCURL.AUTH.001) detect public Lambda AFTER the fact; this SCP control prevents the configuration from being created. The SCP should deny lambda:AddPermission when lambda:Principal is "*" and deny lambda:CreateFunctionUrlConfig when lambda:FunctionUrlAuthType is not "AWS_IAM". Farris: "prevents a builder from allowing any AWS customer to invoke a function" and "prevents creating a Lambda Function URL with authentication type other than AWS_IAM."

**Remediation:** Add an SCP with two deny statements: (1) deny lambda:AddPermission with condition "lambda:Principal": "*" to prevent public resource-based policy grants; (2) deny lambda:CreateFunctionUrlConfig with condition "lambda:FunctionUrlAuthType" != "AWS_IAM" to prevent unauthenticated Function URLs.

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

### CTL.ORG.SCP.PROTECTBACKUP.001

**SCP Does Not Prevent Backup Vault Deletion**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC6.1;

No SCP prevents deletion of AWS Backup vaults and recovery points. An attacker with admin access in a member account can delete backup vaults and recovery points, eliminating the recovery path for ransomware or destructive attacks. The SCP should deny backup:DeleteBackupVault, backup:DeleteRecoveryPoint, and backup:UpdateRecoveryPointLifecycle with a role-based or tag-based exception. Farris's implementation uses tag-based conditions (aws:ResourceTag/aws_backup_bcp_tier). This is a META-INVARIANT for the ransomware kill chain.

**Remediation:** Add an SCP that denies backup:DeleteBackupVault, backup:DeleteRecoveryPoint, and backup:UpdateRecoveryPointLifecycle. Use a tag-based condition (aws:ResourceTag) or role-based exception for authorized backup management.

---

### CTL.ORG.SCP.PROTECTBPA.001

**SCP Does Not Prevent Disabling Block Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No SCP prevents disabling Block Public Access for S3, AMI sharing, or EBS snapshots. Existing controls check whether BPA is enabled; this control checks whether BPA is PROTECTED from being disabled. The distinction matters: BPA enabled without SCP protection is distance-one from BPA disabled — one API call away. This is a META-INVARIANT. The SCP should deny s3:PutBucketPublicAccessBlock, s3:PutAccountPublicAccessBlock, ec2:DisableImageBlockPublicAccess, and ec2:DisableSnapshotBlockPublicAccess with a role-based exception for cloud engineering.

**Remediation:** Add an SCP that denies s3:PutBucketPublicAccessBlock, s3:PutAccountPublicAccessBlock, ec2:DisableImageBlockPublicAccess, and ec2:DisableSnapshotBlockPublicAccess. Exempt a cloud engineering role via aws:PrincipalArn condition for legitimate BPA changes.

---

### CTL.ORG.SCP.PROTECTGUARDDUTY.001

**SCP Protects GuardDuty from Member Account Modification**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

An SCP must deny guardduty:DeleteDetector, guardduty:UpdateDetector, and guardduty:DisassociateFromMasterAccount to prevent GuardDuty from being disabled or modified from within member accounts. This is a META-INVARIANT that protects detection infrastructure. Without it, an attacker with admin access in a member account can disable GuardDuty before conducting further operations. Technique: hackingthe.cloud modify GuardDuty configuration.

**Remediation:** Add an SCP denying guardduty:DeleteDetector, guardduty:UpdateDetector, and guardduty:DisassociateFromMasterAccount across all member accounts. Use a role-based exception for the delegated admin account.

---

### CTL.ORG.SCP.PROTECTRECYCLEBIN.001

**SCP Protects Recycle Bin Rules from Deletion**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC6.1;

An SCP must deny rbin:DeleteRule and rbin:UpdateRule to prevent Recycle Bin retention rules from being deleted or shortened by an attacker. Without this meta-invariant, an attacker with admin access can disable Recycle Bin before deleting volumes or snapshots, eliminating the recovery path. The SCP should use a role-based or tag-based exception for authorized Recycle Bin management.

**Remediation:** Add an SCP denying rbin:DeleteRule and rbin:UpdateRule across all member accounts. Use a role-based or tag-based condition for authorized Recycle Bin management.

---

### CTL.ORG.SCP.PROTECTROLES.001

**SCP Does Not Protect Critical Security Roles from Modification**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No SCP prevents modification of critical security and governance IAM roles in member accounts. Without this protection, an attacker with admin access in a member account can modify CloudTrail roles, Config roles, SecurityHub roles, or GuardDuty service-linked roles — dismantling the enforcement infrastructure from within. This is a META-INVARIANT: it protects the roles that enforce all other invariants. Farris: "No one may alter the core security & governance IAM Roles." The SCP should deny iam:AttachRolePolicy, iam:DeleteRole, iam:DeleteRolePolicy, iam:DetachRolePolicy, iam:PutRolePolicy, iam:UpdateAssumeRolePolicy, and iam:UpdateRole with Resource matching critical role ARN patterns, with an exception for the governance automation role.

**Remediation:** Add an SCP that denies iam:AttachRolePolicy, iam:DeleteRole, iam:DeleteRolePolicy, iam:DetachRolePolicy, iam:PutRolePolicy, iam:UpdateAssumeRolePolicy, and iam:UpdateRole when the resource ARN matches the critical role naming pattern (e.g., *SecurityAudit*, *CloudTrail*, *ConfigRole*, *GuardDutyRole*). Exempt the governance automation role via aws:PrincipalArn condition.

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

### CTL.ORG.SCP.SES.RESTRICT.001

**SCP Must Restrict SES Send Actions to Approved Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

An SCP must restrict ses:SendEmail and ses:SendRawEmail to approved messaging roles. Compromised credentials used to send phishing emails via SES has been documented in multiple campaigns. If SES is not in use, the SCP should deny all SES actions entirely. Technique: Wiz "SES abuse for spam or phishing". Linked incidents: JavaGhost (Feb 2025), DangerDev, Attack abusing Amazon SES (Dec 2024), TruffleNet (Oct 2025), Cloud-Native Phishing via AWS WorkMail (Jan 2026).

**Remediation:** Add an SCP denying ses:SendEmail and ses:SendRawEmail with a role-based exception for approved messaging workloads. If SES is not used in the organization, deny all SES actions.

---

### CTL.ORG.SCP.SUSPENDED.001

**Suspended OU Has No Restrictive SCP**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.2;

A suspended OU exists but has no SCP that denies all actions except billing visibility. Farris's scream test pattern: accounts being decommissioned move to a suspended OU with a restrictive SCP before closure. If the OU exists without the SCP, accounts in the suspended state can still be used for compute, data access, or lateral movement. The collector identifies OU structures with a suspended/quarantine OU and checks whether a deny-all SCP is attached.

**Remediation:** Attach an SCP to the suspended OU that denies all actions ("Effect": "Deny", "Action": "*", "Resource": "*") except billing and support actions needed for account closure visibility.

---

### CTL.ORG.SCP.VPC.MANAGEMENT.001

**SCP Does Not Restrict VPC Network Mutations**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

No SCP restricts VPC networking mutations to the network engineering role. Without this restriction, any developer can create VPCs, attach internet gateways, create transit gateway attachments, modify route tables, and establish VPC peering connections — bypassing network segmentation. CTL.IAM.SCP.IGW.001 covers IGW creation specifically; this control covers the broader VPC management surface including CreateVpc, CreateTransitGateway, CreateVpcPeeringConnection, CreateRoute, and ModifyVpcAttribute. Farris: "In an enterprise setting, you typically want your network team to manage VPCs."

**Remediation:** Add an SCP that denies ec2:CreateVpc, ec2:AttachInternetGateway, ec2:CreateTransitGateway, ec2:CreateTransitGatewayVpcAttachment, ec2:CreateVpcPeeringConnection, ec2:AcceptVpcPeeringConnection, ec2:CreateRoute, ec2:ReplaceRoute, ec2:ModifyVpcAttribute, ec2:CreateVpcEndpoint with an exception for the network engineering role via aws:PrincipalArn.

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

