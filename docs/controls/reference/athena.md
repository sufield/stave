# Control Reference — ATHENA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ATHENA.CONNECTOR.NOVPC.001

**Athena Federated Query Connector Not in VPC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7, AC-4; soc2: CC6.6;

Athena federated query connector Lambda function is not deployed within a VPC. The connector has unrestricted outbound network access and can reach any internet endpoint. For connectors that access internal data sources (RDS, Redshift, on-premises databases), VPC deployment provides network isolation and enables security group filtering on the connector's traffic.

**Remediation:** Deploy the connector Lambda in a VPC with security groups restricting egress to the data source endpoints only.

---

### CTL.ATHENA.CONNECTOR.VULNERABLE.001

**Athena Federated Query Connector at Vulnerable Version**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2, RA-5, SI-10; soc2: CC7.1;

Athena federated query connector is at a version with known SQL injection vulnerabilities. Crafted table names in federated queries can inject SQL into the downstream data source, enabling unauthorized data access or modification. The connector Lambda function must be updated to a version that sanitizes table name input before constructing downstream queries.

**Remediation:** Update the connector Lambda function to the latest version. If using a custom connector, audit the query construction code for parameterized query usage.

---

### CTL.ATHENA.ENCRYPT.001

**Athena Workgroups Must Encrypt Query Results**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Athena workgroups must encrypt query results at rest. Unencrypted query results in S3 expose data extracted by SQL queries.

**Remediation:** Enable encryption in the workgroup result configuration.

---

### CTL.ATHENA.GHOST.OUTPUT.S3.001

**Athena Query Results S3 Bucket Deleted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, SC-28; soc2: CC6.1;

Athena workgroup is configured to write query results to an S3 bucket that has been deleted. Queries fail or, if the bucket name is re-registered under a different account, query results — which may contain sensitive data from the queried tables — are written to attacker- controlled storage.

**Remediation:** Update the workgroup output location to an existing bucket: aws athena update-work-group --work-group <name> --configuration-updates ResultConfigurationUpdates={OutputLocation=s3://<bucket>/}.

---

### CTL.ATHENA.WORKGROUP.001

**Athena Workgroups Must Enforce Query Result Location**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

Athena workgroups must enforce a specific query result location and override client-side settings. Without this enforcement, individual users can direct query results to arbitrary S3 buckets outside the organization's control, potentially exfiltrating data or bypassing encryption and access logging.

**Remediation:** Enable enforce workgroup configuration in the workgroup settings. This forces all queries to use the workgroup's output location and encryption settings.

---

