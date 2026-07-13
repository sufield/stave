# Control Reference — MWAA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MWAA.ENV.ACTIVE.001

**MWAA Environments Are Active in Account**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active MWAA (Managed Workflows for Apache Airflow) environments. MWAA provisions Fargate compute, S3 buckets for DAG storage, and CloudWatch log groups behind the Airflow API surface. DAGs execute arbitrary Python code with the MWAA execution role's permissions.

**Remediation:** Evaluate intent; if unwanted, delete environments and SCP deny airflow:*.

---

### CTL.MWAA.ENV.PUBLIC.001

**MWAA Web Server Is Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

MWAA environment web server is configured with PUBLIC_ONLY access mode, making the Apache Airflow UI accessible from the internet. The Airflow UI provides full control over DAG execution, variable management, and connection configuration — exposing it publicly allows an attacker to trigger arbitrary DAG runs and access stored credentials. Use PRIVATE_ONLY to restrict access to the VPC.

**Remediation:** Change the MWAA environment's web server access mode to PRIVATE_ONLY. Access the Airflow UI through a VPN, bastion host, or AWS Client VPN endpoint.

---

