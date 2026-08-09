# Control Reference — BATCH

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.BATCH.ESCALATION.CHAIN.001

**Batch EC2 Compute Environment Enables Job-to-Instance-Role Escalation**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

The full Doyensec escalation chain holds on this Batch compute environment: it uses EC2 orchestration (host networking), IMDS is reachable from job containers, a job/execution role can author and run jobs (batch:RegisterJobDefinition + batch:SubmitJob + iam:PassRole), and the EC2 instance role has sensitive access. A principal submits a malicious job, it runs on the host with network access to IMDS, retrieves the instance role credentials, and uses them against the sensitive resource — escalating from a scoped job role to the privileged instance role.
Each condition alone is a finding (CTL.BATCH.IMDS.JOBACCESS.001 catches IMDS, CTL.IAM.ESCALATE.PASSROLE.SUBMITJOB.001 catches the combo); this compound proves all hold simultaneously. Sensitive instance-role access includes direct data (S3/EFS/Secrets/KMS), ecs:* (lateral to ECS task roles), and iam:PassRole (chain extension). Computed by examples/batch-escalation-chain/ (Soufflé + Z3), composing with chains/ec2_imds_container_escalation.
Inspired by Doyensec CloudsecTidbits No. 3 — Messing Around With AWS Batch For Privilege Escalations. Lab: github.com/doyensec/cloudsec-tidbits.

**Remediation:** Break any one link: restrict IMDS (hop limit 1) on the launch template, scope iam:PassRole / remove batch:RegisterJobDefinition on the job role, or reduce the instance role to least privilege. Migrating to Fargate removes the IMDS link entirely.

---

### CTL.BATCH.IMDS.JOBACCESS.001

**Batch EC2 Compute Environment Exposes IMDS to Job Containers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.6; nist_800_53_r5: CM-6, AC-6; owasp_subtractive: S01; pci_dss_v4.0: 2.2.1; soc2: CC6.6; subtractive_tier: deletion;

An AWS Batch compute environment with EC2 (or SPOT) orchestration runs job containers with host networking, so they share the host EC2 instance's network interface and can reach the instance metadata service at 169.254.169.254. When IMDS is reachable from jobs, any job container can retrieve the EC2 instance role credentials — typically far more privileged than the job execution role (the instance role manages EFS mounts, EC2 lifecycle, networking). Fargate orchestration has no host IMDS and is out of scope.
The collector resolves batch.imds_accessible_from_jobs with the same logic as CTL.EC2.IMDSV2.002: reachable when the launch template's hop limit is > 1, the endpoint is enabled with host/bridge networking, OR the launch-template metadata options are absent (fail-loud — unknown defaults are treated as reachable). IMDSv2 enforcement WITHOUT a hop-limit restriction is still reachable: a job container completes the PUT-for-token handshake just like the host.
Inspired by Doyensec CloudsecTidbits No. 3 — Messing Around With AWS Batch For Privilege Escalations. Lab: github.com/doyensec/cloudsec-tidbits.

**Remediation:** Set the launch template metadata options to HttpPutResponseHopLimit=1 (and HttpTokens=required), or disable the IMDS endpoint, on the compute environment's launch template. Migrate to Fargate orchestration where job isolation is required. Hop-limit 1 rejects the extra hop a job container adds.

---

### CTL.BATCH.JOB.ROLE.OVERBROAD.001

**Batch Job IAM Role Exceeds Required Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

AWS Batch job definition's IAM role has permissions beyond what the compute job requires. Batch jobs need ECR pull (ecr:GetAuthorizationToken, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer), specific S3 access for input and output data, and CloudWatch Logs for job logging. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets — means a compromised container running as a Batch job can access resources far beyond its compute scope. Batch jobs run arbitrary container images; an overbroad role turns container escape or image compromise into account-wide privilege escalation.

**Remediation:** Scope the Batch job role to the specific S3 buckets, ECR repositories, and CloudWatch Logs groups the job needs. Remove wildcard actions and broad Resource targets. Use separate roles for job definitions with different data access requirements.

---

### CTL.BATCH.LOG.001

**Batch Job Definitions Must Have Log Configuration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

AWS Batch job definitions must have a log driver configured in containerProperties.logConfiguration. Without logging, job container stdout and stderr are discarded — job invocations, errors, and execution output leave no audit trail. A compromised job container generating no logs is forensically invisible. Batch defaults to no log configuration when logConfiguration is omitted from the job definition, unlike ECS Fargate which requires awslogs. EC2 and Fargate orchestration types both support logConfiguration; the absence of a log driver means job output is silently lost regardless of compute backend.

**Remediation:** Add logConfiguration to the job definition's containerProperties: aws batch register-job-definition --job-definition-name <name> --type container --container-properties '{"logConfiguration":{"logDriver":"awslogs","options":{"awslogs-group":"/aws/batch/job","awslogs-region":"us-east-1","awslogs-stream-prefix":"batch"}}}'. Use awslogs for CloudWatch integration or splunk/fluentd for third-party log aggregation.

---

### CTL.BATCH.SECRET.ENV.001

**Batch Job Definition Must Not Contain Plaintext Secrets**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

AWS Batch job definition contains plaintext secrets in environment variables. Secrets in environment variables are visible in the Batch console, API responses, and CloudTrail logs.

**Remediation:** Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them via the Batch secrets configuration.

---

