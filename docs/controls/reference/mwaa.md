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

### CTL.MWAA.LOG.TASK.001

**MWAA Environment Must Have Task Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

MWAA environment does not have task logging enabled. Task logs capture Airflow task execution details including DAG runs, operator outputs, and failure traces. Without task logging, unauthorized DAG modifications or data pipeline tampering cannot be detected through execution records.

**Remediation:** Enable task logging for the MWAA environment. Configure the task log level to at least INFO to capture DAG execution events in CloudWatch Logs.

---

### CTL.MWAA.ROLE.OVERBROAD.001

**MWAA Environment Execution Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

MWAA (Managed Workflows for Apache Airflow) environment's execution role has permissions beyond what the Airflow DAGs require. MWAA environments need specific S3 access for DAG storage and logs, CloudWatch Logs, SQS for Celery executor, and Secrets Manager for connection strings. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets, lambda:InvokeFunction on * — means every DAG task running in the environment can access resources far beyond its workflow scope. Airflow DAGs are code that runs on a schedule with the environment's credentials; an overbroad role turns DAG modification into lateral movement.

**Remediation:** Scope the MWAA execution role to the specific S3 bucket for DAGs and logs, Secrets Manager secrets for connection strings, and the specific AWS services the DAGs invoke. Remove wildcard actions. Consider using Airflow's connection-level credential delegation instead of a single broad environment role.

---

