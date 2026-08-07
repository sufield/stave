# Control Reference — APPRUNNER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APPRUNNER.AUTH.REQUIRED.001

**App Runner Service Must Require Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2, 8.3; soc2: CC6.1;

App Runner service exposes a public HTTPS endpoint without requiring authentication. App Runner services are internet- facing by default — any client with the URL can invoke the service. Without an authentication layer (IAM auth, Cognito, or application-level auth enforcement), the service is accessible to the entire internet. This is the compute-level equivalent of an S3 bucket with public access: the blast radius includes any data the service can reach via its instance role.

**Remediation:** Enable IAM authentication on the App Runner service to require signed requests, or deploy the service behind an API Gateway or ALB with authentication configured. If the service must be public, ensure application-level auth is enforced and document the public exposure intent.

---

### CTL.APPRUNNER.LOG.APPLICATION.001

**App Runner Service Must Have Application Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

App Runner service does not have application logging enabled. Application logs capture stdout/stderr from the containerized application, providing visibility into runtime errors, request handling, and potential exploitation attempts. App Runner services are internet-facing — without application logging, web application attacks leave no trace in CloudWatch.

**Remediation:** Enable application logging for the App Runner service to deliver container stdout/stderr to CloudWatch Logs.

---

### CTL.APPRUNNER.ROLE.OVERBROAD.001

**App Runner Instance Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

App Runner service's instance role has permissions beyond what the containerized application requires. App Runner services need specific access to their data stores (DynamoDB tables, S3 buckets, RDS instances via Secrets Manager), ECR pull for container images, and CloudWatch Logs. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets — means a compromised web application container can access resources far beyond its service scope. App Runner services are internet-facing by default; an overbroad instance role turns web application compromise into account-wide privilege escalation.

**Remediation:** Scope the instance role to the specific DynamoDB tables, S3 buckets, and Secrets Manager secrets the application needs. Remove wildcard actions and broad Resource targets. App Runner services are internet-facing — the instance role is the first credential an attacker reaches after web application compromise.

---

### CTL.APPRUNNER.SECRET.ENV.001

**App Runner Service Must Not Store Secrets in Environment Variables**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3; soc2: CC6.1;

App Runner service configuration contains plaintext secrets in environment variables. Environment variables are visible in the App Runner console, API responses, and CloudTrail logs. Secrets should be stored in Secrets Manager or SSM Parameter Store and referenced at runtime.

**Remediation:** Move secrets to Secrets Manager or SSM Parameter Store. Configure the App Runner service to reference secrets at runtime using the instance role. Remove plaintext values from the service configuration.

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

