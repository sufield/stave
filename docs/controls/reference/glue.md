# Control Reference — GLUE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GLUE.CATALOG.ENCRYPT.001

**Glue Data Catalog Metadata Must Be Encrypted At Rest**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

The Glue Data Catalog must use SSE-KMS encryption for metadata at rest. The catalog contains table schemas, partition information, S3 data locations, and database definitions — a complete map of the organization's data landscape. Unencrypted metadata enables reconnaissance and targeted data access.

**Remediation:** Enable SSE-KMS encryption for the Data Catalog in the Glue console or via aws glue put-data-catalog-encryption-settings.

---

### CTL.GLUE.CATALOG.ENCRYPT.CMK.001

**Glue Data Catalog Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

The Glue Data Catalog with SSE-KMS encryption must use a customer-managed KMS key, not the AWS-managed default. The catalog contains table schemas, partition information, S3 data locations, and database definitions — a complete map of the organization's data landscape. The AWS-managed key has a key policy the customer cannot edit and cannot be revoked or rotated on the customer's schedule.

**Remediation:** Update the Data Catalog encryption settings to use a customer- managed KMS key via aws glue put-data-catalog-encryption-settings with SseAwsKmsKeyId pointing to a CMK.

---

### CTL.GLUE.CATALOG.ENCRYPT.PASSWORD.001

**Glue Data Catalog Must Encrypt Connection Passwords**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

The Glue Data Catalog must encrypt connection passwords at rest using KMS. Connection properties store JDBC passwords, Redshift credentials, and other data store authentication material. Unencrypted passwords are readable by any principal with glue:GetConnection access.

**Remediation:** Enable connection password encryption in the Data Catalog encryption settings with a KMS key.

---

### CTL.GLUE.CATALOG.POLICY.001

**Glue Data Catalog Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

The Glue Data Catalog resource policy must not grant access to Principal "*" or unauthenticated principals. Public catalog access allows unauthorized actors to enumerate table schemas, S3 data locations, partition metadata, and database definitions — the complete map of the organization's data architecture.

**Remediation:** Restrict the catalog resource policy to specific accounts or roles. Remove any statements with Principal "*".

---

### CTL.GLUE.CONNECTION.SSL.001

**Glue Database Connections Must Enforce SSL**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

Glue JDBC connections must enforce TLS/SSL via the JDBC_ENFORCE_SSL connection property. Without TLS, JDBC traffic between Glue jobs and data stores — including credentials, queries, and results — can be intercepted in transit.

**Remediation:** Set the JDBC_ENFORCE_SSL connection property to true in the Glue connection configuration.

---

### CTL.GLUE.DEVENDPOINT.DEPRECATED.001

**Glue Dev Endpoint Is Deprecated**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** config
- **Compliance:** nist_800_53_r5: SA-22;

AWS Glue development endpoints are a deprecated resource type. AWS recommends migrating to Glue Studio notebooks or Glue interactive sessions, which provide better isolation, faster startup, and active feature development. Existing dev endpoints remain operational but receive no new features and may be removed in a future service update. Dev endpoints also carry a broader attack surface — they expose a network-accessible Spark environment that persists between sessions, unlike interactive sessions which are ephemeral.

**Remediation:** Migrate to Glue interactive sessions or Glue Studio notebooks. Delete the dev endpoint after confirming all development workflows have been migrated. Use aws glue delete-dev-endpoint --endpoint-name <name> to remove.

---

### CTL.GLUE.DEVENDPOINT.ENCRYPT.CMK.001

**Glue Dev Endpoint Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Glue development endpoints must encrypt S3 targets, bookmarks, and logs with a customer-managed KMS key. Dev endpoints are interactive notebook environments that process and preview data; the encryption key controls who can access intermediate data written during development sessions.

**Remediation:** Create a customer-managed KMS key and configure the Glue security configuration to use it. Dev endpoints are deprecated; prefer Glue interactive sessions with CMK encryption configured.

---

### CTL.GLUE.DEVENDPOINT.ROLE.OVERBROAD.001

**Glue Dev Endpoint Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Glue development endpoint's IAM role has permissions beyond what interactive development requires. Dev endpoints provide interactive Spark and Zeppelin sessions for ETL development. The minimum required set is S3 access for development data, Glue Data Catalog read access, and CloudWatch Logs. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets — means an interactive development session has production-level access. Dev endpoints are deprecated but still active in many accounts; if present, they often carry admin-like roles from initial setup.

**Remediation:** Scope the dev endpoint role to development-specific S3 buckets and read-only Glue Catalog access. Better yet, migrate to Glue Interactive Sessions which support per-session IAM roles. Dev endpoints are deprecated — consider removing them entirely (see CTL.GLUE.DEVENDPOINT.DEPRECATED.001).

---

### CTL.GLUE.ENDPOINT.ENCRYPT.BOOKMARKS.001

**Glue Dev Endpoint Must Encrypt Job Bookmarks**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue development endpoints must use a security configuration with job bookmark encryption enabled (CSE-KMS). Note: AWS deprecated dev endpoints in favor of interactive sessions.

**Remediation:** Attach a security configuration with job bookmark encryption to the endpoint, or migrate to Glue interactive sessions.

---

### CTL.GLUE.ENDPOINT.ENCRYPT.LOG.001

**Glue Dev Endpoint CloudWatch Logs Must Be Encrypted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue development endpoints must use a security configuration with CloudWatch Logs encryption enabled. Note: AWS deprecated dev endpoints in favor of interactive sessions. Existing endpoints remain operational.

**Remediation:** Attach a security configuration with CloudWatch Logs encryption to the endpoint, or migrate to Glue interactive sessions.

---

### CTL.GLUE.ENDPOINT.ENCRYPT.S3.001

**Glue Dev Endpoint Must Encrypt S3 Data At Rest**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue development endpoints must use a security configuration with S3 encryption enabled. Note: AWS deprecated dev endpoints in favor of interactive sessions.

**Remediation:** Attach a security configuration with S3 encryption to the endpoint, or migrate to Glue interactive sessions.

---

### CTL.GLUE.JOB.ENCRYPT.BOOKMARKS.001

**Glue ETL Jobs Must Encrypt Job Bookmarks**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue ETL jobs must use a security configuration with job bookmark encryption enabled (CSE-KMS). Unencrypted bookmarks expose dataset paths, partitions, and processing state. Tampered bookmarks can trigger data reprocessing or skipping.

**Remediation:** Create a Glue security configuration with job bookmark encryption (CSE-KMS) and attach it to the job.

---

### CTL.GLUE.JOB.ENCRYPT.CMK.001

**Glue Job Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Glue jobs must encrypt bookmarks, S3 targets, and CloudWatch Logs output with a customer-managed KMS key. The AWS-managed default key provides no key-policy control and cannot be revoked during an incident. Glue jobs process and transform data across S3, databases, and streaming sources; the encryption key controls who can access intermediate and output data at rest.

**Remediation:** Create a customer-managed KMS key and configure the Glue job security configuration to use it for S3, CloudWatch Logs, and bookmark encryption.

---

### CTL.GLUE.JOB.ENCRYPT.S3.001

**Glue ETL Jobs Must Encrypt S3 Data At Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Glue ETL jobs must use a security configuration with S3 encryption enabled (SSE-S3 or SSE-KMS). Without encryption, job outputs, temporary data, and scripts stored in S3 are readable by anyone with bucket access.

**Remediation:** Create a Glue security configuration with S3 encryption enabled (SSE-KMS recommended) and attach it to the job.

---

### CTL.GLUE.JOB.LOG.ENCRYPT.001

**Glue ETL Job CloudWatch Logs Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Glue ETL jobs must use a security configuration with CloudWatch Logs encryption enabled (SSE-KMS). Unencrypted log entries can expose credentials, PII, connection strings, and schema details.

**Remediation:** Create a Glue security configuration with CloudWatch Logs encryption (SSE-KMS) and attach it to the job.

---

### CTL.GLUE.JOB.ROLE.OVERBROAD.001

**Glue Job IAM Role Exceeds Required Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Glue job's IAM role has permissions beyond what the ETL job requires. Glue jobs process data across S3 buckets, Glue Data Catalog, and CloudWatch Logs. The minimum required set is: s3:GetObject and s3:PutObject on specific source and target buckets, glue:GetTable and glue:GetDatabase on the Data Catalog, and logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents for job logging. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets, secretsmanager:*, dynamodb:* — means a compromised or misconfigured Glue job can access data and services far beyond its ETL scope. Glue jobs run unattended on a schedule and process high-value data; an overbroad role turns every job into a lateral movement opportunity.

**Remediation:** Scope the Glue job role to only the resources the job needs: specific S3 buckets for source and target data, the Glue Data Catalog databases and tables the job reads, and CloudWatch Logs for job output. Remove wildcard actions (s3:*, glue:*, iam:PassRole) and broad Resource targets. Use separate roles for jobs with different data access requirements.

---

### CTL.GLUE.JOB.SECRETS.001

**Glue ETL Jobs Must Not Store Secrets in Job Arguments**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Glue ETL job DefaultArguments must not contain plaintext secrets (passwords, API keys, tokens). Job arguments are visible in the AWS console, CLI output, and CloudTrail logs. Use Secrets Manager or Parameter Store references instead.

**Remediation:** Move secrets to AWS Secrets Manager or SSM Parameter Store. Reference them in job scripts using boto3 at runtime instead of passing them as job arguments.

---

### CTL.GLUE.MLTRANSFORM.ENCRYPT.001

**Glue ML Transform Must Encrypt User Data At Rest**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Glue ML transforms must encrypt user data at rest using SSE-KMS. Unencrypted transform artifacts, mappings, and sample datasets may reveal schemas and data relationships.

**Remediation:** Enable SSE-KMS encryption for the ML transform's user data via the MlUserDataEncryption setting.

---

### CTL.GLUE.VERSION.OUTDATED.001

**Glue Job Must Not Run Outdated ETL Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3; soc2: CC7.1;

Glue job is configured with an outdated ETL version. AWS Glue ETL versions (2.0, 3.0, 4.0) correspond to Spark and Python runtime versions. Older versions lack security patches, performance improvements, and may use EOL dependencies. Running on deprecated versions increases vulnerability surface and blocks access to security features in newer runtimes.

**Remediation:** Upgrade the Glue job to the latest supported ETL version (currently 4.0). Test the job with the new version in a non-production environment before promoting. Review the Glue version migration guide for breaking changes.

---

