# Control Reference — APPRUNNER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APPRUNNER.ROLE.OVERBROAD.001

**App Runner Instance Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

App Runner service's instance role has permissions beyond what the containerized application requires. App Runner services need specific access to their data stores (DynamoDB tables, S3 buckets, RDS instances via Secrets Manager), ECR pull for container images, and CloudWatch Logs. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets — means a compromised web application container can access resources far beyond its service scope. App Runner services are internet-facing by default; an overbroad instance role turns web application compromise into account-wide privilege escalation.

**Remediation:** Scope the instance role to the specific DynamoDB tables, S3 buckets, and Secrets Manager secrets the application needs. Remove wildcard actions and broad Resource targets. App Runner services are internet-facing — the instance role is the first credential an attacker reaches after web application compromise.

---

### CTL.APPRUNNER.SERVICE.ACTIVE.001

**App Runner Services Are Active in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active App Runner services. App Runner provisions fully managed container compute with public HTTPS endpoints in an AWS-managed VPC outside the customer's governance boundary. Services are not visible through ec2:DescribeInstances or standard network security monitoring and run with IAM execution roles that may have broad permissions.

**Remediation:** Evaluate intent; if unwanted, delete services and SCP deny apprunner:*.

---

