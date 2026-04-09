# Control Reference

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`

**Total controls:** 103
**Pack hash:** `99e6d722ab6e8828c8059074cbddf2e473511b7454e7dd8c60a15da3be152eef`

## Summary

| Severity | Count |
|----------|-------|
| critical | 22 |
| high | 41 |
| low | 10 |
| medium | 30 |

| Domain | Count |
|--------|-------|
| exposure | 86 |
| governance | 2 |
| identity | 11 |
| storage | 4 |

## Controls

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

### CTL.EC2.EBS.ENCRYPT.001

**EBS Volumes Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; hipaa: 164.312(a)(2)(iv);

EBS volumes attached to EC2 instances must have encryption enabled. Unencrypted volumes storing PHI or sensitive data violate encryption at rest requirements.

**Remediation:** Enable EBS encryption by default for the account. For existing volumes, create an encrypted snapshot and restore to a new encrypted volume. Run: aws ec2 enable-ebs-encryption-by-default

---

### CTL.EC2.IMDSV2.001

**EC2 Instances Must Require IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.6;

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
- **Compliance:** cis_aws_v1.4.0: 5.1; hipaa: 164.312(e)(1);

EC2 instances should not have public IP addresses unless explicitly required. Public IP assignment exposes the instance to direct internet access, bypassing network perimeter controls.

**Remediation:** Launch instances in private subnets without public IP assignment. Use NAT Gateway or VPC endpoints for outbound internet access. Use ALB or NLB for inbound traffic that requires internet access.

---

### CTL.EC2.SNAPSHOT.ENCRYPT.001

**EBS Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; hipaa: 164.312(a)(2)(iv);

EBS snapshots must be encrypted. Unencrypted snapshots can be shared across accounts or made public, exposing data at rest.

**Remediation:** Copy the snapshot with encryption enabled. Delete the unencrypted snapshot. Enable EBS encryption by default for future snapshots.

---

### CTL.ELB.CROSSZONE.001

**Load Balancer Must Have Cross-Zone Load Balancing Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7);

Load balancers must distribute traffic across all registered targets in all enabled Availability Zones. Without cross-zone balancing, uneven distribution can cause availability issues during AZ failures.

**Remediation:** Enable cross-zone load balancing. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=load_balancing.cross_zone.enabled,Value=true

---

### CTL.ELB.HTTPS.001

**Load Balancer Must Redirect HTTP to HTTPS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(2)(ii);

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
- **Compliance:** hipaa: 164.312(b);

Load balancer access logging must be enabled for audit and forensic analysis. Without access logs, request patterns and potential unauthorized access cannot be investigated after an incident.

**Remediation:** Enable access logging to an S3 bucket. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=my-elb-logs

---

### CTL.ELB.TLS.001

**Load Balancer Must Use TLS 1.2 or Higher**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(2)(ii);

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

### CTL.IAM.CONSOLE.MFA.001

**Console Users Must Have MFA Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.10; hipaa: 164.312(d); pci_dss_v3.2.1: 8.3; soc2: CC6.1;

IAM users with console access must have multi-factor authentication enabled. Console access without MFA allows credential-only login, making accounts vulnerable to password compromise.

**Remediation:** Enable MFA for the user via IAM > Users > Security credentials > MFA. Alternatively, disable console access if the user only needs programmatic access.

---

### CTL.IAM.CRED.ROTATION.001

**Access Keys Must Be Rotated Within 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.14; hipaa: 164.312(a)(2)(i); pci_dss_v3.2.1: 8.2.4; soc2: CC6.1;

IAM user access keys older than 90 days must be rotated. Long-lived access keys accumulate exposure risk and may have been leaked in code repositories, logs, or configuration files.

**Remediation:** Create a new access key, update all systems using the old key, then deactivate and delete the old key.

---

### CTL.IAM.CRED.UNUSED.001

**Disable Unused Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.12; hipaa: 164.312(a)(2)(i); soc2: CC6.2;

IAM credentials unused for 90 days or more must be disabled. Dormant credentials are a persistent attack surface that provides access without triggering normal usage patterns.

**Remediation:** Disable or delete unused credentials. Review the user's need for access and remove the IAM user if no longer required.

---

### CTL.IAM.INCOMPLETE.001

**Complete Data Required for IAM Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

IAM account safety cannot be proven when root account MFA status or access key data is missing from the snapshot. The extractor must populate identity.root.mfa_enabled and identity.root.has_access_keys.

**Remediation:** Re-run the extractor with IAM permissions: iam:GetAccountSummary, iam:GenerateCredentialReport, iam:ListMFADevices.

---

### CTL.IAM.PASSWORD.COMPLEXITY.001

**Password Policy Must Require All Character Types**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; hipaa: 164.312(a)(2)(i); pci_dss_v3.2.1: 8.2.3; soc2: CC6.1;

The IAM account password policy must require uppercase, lowercase, numbers, and symbols. Missing any character type requirement reduces the keyspace and makes passwords easier to crack.

**Remediation:** Update the IAM password policy to require all four character types.

---

### CTL.IAM.PASSWORD.LENGTH.001

**Password Minimum Length Must Be At Least 14**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; hipaa: 164.312(a)(2)(i); pci_dss_v3.2.1: 8.2.3; soc2: CC6.1;

The IAM account password policy must require a minimum password length of 14 characters. Shorter passwords are vulnerable to brute-force and dictionary attacks.

**Remediation:** Update the IAM account password policy to require at least 14 characters. Run: aws iam update-account-password-policy --minimum-password-length 14

---

### CTL.IAM.PASSWORD.REUSE.001

**Password Reuse Prevention Must Be At Least 24**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.9; hipaa: 164.312(a)(2)(i); pci_dss_v3.2.1: 8.2.5; soc2: CC6.1;

The IAM account password policy must prevent reuse of the last 24 passwords. Without reuse prevention, users cycle between a small set of passwords, negating the value of password rotation.

**Remediation:** Update the IAM password policy to prevent reuse of the last 24 passwords. Run: aws iam update-account-password-policy --password-reuse-prevention 24

---

### CTL.IAM.POLICY.DIRECT.001

**No Direct Policy Attachment on IAM Users**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; soc2: CC6.3;

IAM users must not have managed policies attached directly. Policies should be attached to groups or roles, not individual users. Direct attachment creates unmanageable per-user permission sprawl.

**Remediation:** Create IAM groups with the required policies and add the user to the appropriate groups. Remove directly attached policies from the user.

---

### CTL.IAM.POLICY.INLINE.001

**No Inline Policies on IAM Users**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; soc2: CC6.3;

IAM users must not have inline policies attached directly. Inline policies are harder to audit, cannot be reused, and create per-user policy sprawl that resists central governance.

**Remediation:** Convert inline policies to managed policies and attach via groups or roles. Delete the inline policies from the user.

---

### CTL.IAM.ROOT.ACCESSKEY.001

**Root Account Must Not Have Access Keys**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.4; hipaa: 164.312(a)(1); pci_dss_v3.2.1: 2.1; soc2: CC6.1;

The AWS root account must not have active access keys. Root access keys provide unrestricted programmatic access. Use IAM users or roles for programmatic access instead.

**Remediation:** Delete the root access keys. Create IAM users or roles with least-privilege policies for programmatic access.

---

### CTL.IAM.ROOT.MFA.001

**Root Account Must Have MFA Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.5; hipaa: 164.312(d); pci_dss_v3.2.1: 8.3; soc2: CC6.1;

The AWS root account must have multi-factor authentication enabled. Root has unrestricted access to all resources. Compromise without MFA is the highest-severity identity risk.

**Remediation:** Enable MFA on the root account using a hardware MFA device or virtual MFA app. Navigate to IAM > Security credentials > MFA.

---

### CTL.K8S.AUDIT.001

**Kubernetes Audit Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 3.2.1; hipaa: 164.312(b);

The Kubernetes API server must have audit logging enabled. Without audit logs, API calls (including unauthorized access attempts) are not recorded for forensic analysis.

**Remediation:** Configure the API server with --audit-policy-file and --audit-log-path. For managed clusters (EKS, GKE), enable control plane logging via the cloud provider console.

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
- **Compliance:** cis_k8s_v1.8.0: 1.2.29; hipaa: 164.312(a)(2)(iv);

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

### CTL.RDS.BACKUP.001

**RDS Automated Backups Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); hipaa_retention: 164.316(b)(2);

RDS instances must have automated backups enabled with a retention period of at least 7 days. Without backups, data loss from accidental deletion, corruption, or ransomware is permanent.

**Remediation:** Enable automated backups with at least 7 days retention. Run: aws rds modify-db-instance --db-instance-identifier xxx --backup-retention-period 7 --apply-immediately

---

### CTL.RDS.ENCRYPT.001

**RDS Storage Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.1; hipaa: 164.312(a)(2)(iv);

RDS instances must have storage encryption enabled. Unencrypted database storage exposes data at rest to unauthorized access if the underlying storage is compromised.

**Remediation:** Storage encryption can only be enabled at creation time. Create a snapshot, copy it with encryption enabled, then restore to a new encrypted instance. Enable encryption by default for new instances.

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
- **Compliance:** hipaa: 164.312(b);

RDS instances must export audit logs to CloudWatch. Without audit logging, database access patterns cannot be monitored and unauthorized queries are undetectable.

**Remediation:** Enable CloudWatch log exports for the database engine. Run: aws rds modify-db-instance --db-instance-identifier xxx --cloudwatch-logs-export-configuration '{"EnableLogTypes":["audit","error","slowquery"]}'

---

### CTL.RDS.MULTIAZ.001

**RDS Instances Must Use Multi-AZ Deployment**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7);

Production RDS instances must use Multi-AZ deployment for high availability. Single-AZ instances have a single point of failure that can cause data unavailability during AZ outages.

**Remediation:** Modify the instance to enable Multi-AZ. Run: aws rds modify-db-instance --db-instance-identifier xxx --multi-az --apply-immediately

---

### CTL.RDS.PUBLIC.001

**RDS Instances Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.2; hipaa: 164.312(a)(1);

RDS instances must not have public accessibility enabled. A publicly accessible database is reachable from the internet, exposing it to brute force attacks, SQL injection, and unauthorized data access.

**Remediation:** Modify the instance to disable public accessibility. Run: aws rds modify-db-instance --db-instance-identifier xxx --no-publicly-accessible --apply-immediately

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
- **Compliance:** hipaa: 164.312(b);

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
- **Compliance:** hipaa: 164.312(a)(1);

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
- **Compliance:** cis_aws_v1.4.0: 2.1.5; pci_dss_v3.2.1: 1.3.6; soc2: CC6.1;

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

### CTL.S3.ENCRYPT.001

**Encryption at Rest Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.1; hipaa: 164.312(a)(2)(iv); pci_dss_v3.2.1: 3.4; soc2: CC6.1;

S3 buckets must have server-side encryption enabled. Unencrypted storage is the top audit finding in regulated industries.

**Remediation:** Enable default bucket encryption using SSE-S3 (AES256) or SSE-KMS. Use aws s3api put-bucket-encryption to set the default encryption configuration. For sensitive data, use SSE-KMS with a customer-managed key.

---

### CTL.S3.ENCRYPT.002

**Transport Encryption Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.2; hipaa: 164.312(e)(2)(ii); pci_dss_v3.2.1: 4.1; soc2: CC6.1;

S3 buckets must enforce HTTPS via a deny policy on aws:SecureTransport=false. Without this, data transfers occur in plaintext.

**Remediation:** Add a bucket policy statement that denies all actions when aws:SecureTransport is false. This forces all API calls to use HTTPS.

---

### CTL.S3.ENCRYPT.003

**PHI Buckets Must Use SSE-KMS with Customer-Managed Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

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

### CTL.S3.LIFECYCLE.001

**Retention-Tagged Buckets Must Have Lifecycle Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

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
- **Compliance:** cis_aws_v1.4.0: 2.1.3; hipaa: 164.312(b); pci_dss_v3.2.1: 10.2.1; soc2: CC7.2;

S3 buckets must have server access logging enabled for audit trail and visibility into data access patterns.

**Remediation:** Enable S3 server access logging and specify a target bucket for log delivery. Ensure the target bucket has appropriate access controls and is in the same region.

---

### CTL.S3.MRAP.PAB.001

**Multi-Region Access Point Must Have Block Public Access Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1);

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

### CTL.S3.PRESIGNED.001

**Presigned URL Access Must Be Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1);

PHI bucket policy must restrict presigned URL access using s3:signatureAge (maximum age in milliseconds) or s3:authType (require REST-HEADER to block presigned URLs). Without these guardrails, presigned URLs can provide long-lived unauthenticated access to PHI data.

**Remediation:** Add a Deny statement with Condition NumericGreaterThan s3:signatureAge (e.g., 600000 for 10 minutes) or StringNotEquals s3:authType REST-HEADER to block presigned URL access.

---

### CTL.S3.PUBLIC.001

**No Public S3 Bucket Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; hipaa: 164.312(a)(1); pci_dss_v3.2.1: 1.2.1; soc2: CC6.1;

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

### CTL.VPC.FLOWLOG.001

**VPC Flow Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.9; hipaa: 164.312(b);

VPC flow logs capture information about IP traffic going to and from network interfaces. Without flow logs, network-level access patterns cannot be audited and unauthorized traffic goes undetected.

**Remediation:** Enable VPC flow logs to CloudWatch Logs or S3. Run: aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-xxx --traffic-type ALL --log-destination-type cloud-watch-logs

---

### CTL.VPC.FLOWLOG.ENCRYPT.001

**VPC Flow Logs Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv);

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

### CTL.VPC.SG.DEFAULT.001

**Default Security Group Must Restrict All Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.4; hipaa: 164.312(a)(1);

The default VPC security group should not allow any inbound or outbound traffic. Resources should use custom security groups with explicit rules instead of relying on the default group.

**Remediation:** Remove all inbound and outbound rules from the default security group. Assign custom security groups to all resources.

---

### CTL.VPC.SG.UNRESTRICTED.001

**Security Groups Must Not Allow Unrestricted Ingress**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.2; hipaa: 164.312(e)(1);

Security group rules must not allow ingress from 0.0.0.0/0 on sensitive ports (SSH, RDP, database). Unrestricted ingress exposes services to the entire internet.

**Remediation:** Restrict ingress rules to specific CIDR blocks or security group references. Remove 0.0.0.0/0 and ::/0 from ingress rules on ports 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL).

---

