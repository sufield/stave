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

