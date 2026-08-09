# Control Reference — BEANSTALK

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.BEANSTALK.IMDS.V1.001

**Elastic Beanstalk Environment Must Enforce IMDSv2**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S01; pci_dss_v4.0: 7.2; soc2: CC6.1; subtractive_tier: deletion;

Elastic Beanstalk environment EC2 instances allow IMDSv1 access to the instance metadata service. IMDSv1 is vulnerable to SSRF attacks — a compromised web application on a Beanstalk instance can steal IAM credentials from the metadata endpoint via a simple HTTP GET. IMDSv2 requires a session token obtained via PUT, which SSRF payloads cannot forge. Beanstalk environments host web applications that are often internet-facing, making SSRF a direct threat.

**Remediation:** Set the aws:ec2:instances DisableIMDSv1 option to true in the Beanstalk environment configuration. This enforces IMDSv2 for all instances in the environment. Test applications for IMDSv2 compatibility before enforcing.

---

### CTL.BEANSTALK.LOG.001

**Elastic Beanstalk Environments Must Stream Logs to CloudWatch**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Elastic Beanstalk environments must stream instance and proxy logs to CloudWatch Logs for centralized monitoring.

**Remediation:** Enable CloudWatch Logs streaming in the environment configuration.

---

### CTL.BEANSTALK.PLATFORM.EOL.001

**Elastic Beanstalk Must Not Use a Retired Platform Version**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

Elastic Beanstalk environments must not run on retired platform versions (solution stacks). AWS retires platform versions on a published schedule — retired platforms no longer receive security patches, OS updates, or runtime fixes. This is distinct from CTL.BEANSTALK.UPDATES.001 which checks whether managed updates are enabled; a retired platform receives no updates regardless of the managed-updates toggle. Environments on retired platforms run unpatched OS images and language runtimes, accumulating known CVEs over time. The same lifecycle gap as CTL.LAMBDA.RUNTIME.EOL.001 but for the Beanstalk platform layer.

**Remediation:** Migrate the environment to a supported platform version. Use aws elasticbeanstalk update-environment --solution-stack-name to target the current platform. Test the application on the new platform in a staging environment first — platform upgrades may change OS packages, language runtime versions, or web server configuration.

---

### CTL.BEANSTALK.ROLE.OVERBROAD.001

**Elastic Beanstalk Environment Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Elastic Beanstalk environment's instance profile role has permissions beyond what the application requires. Beanstalk environments need EC2 instance management, S3 access for application versions and logs, CloudWatch Logs, and ELB health reporting. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets — means every EC2 instance in the environment can access resources far beyond the application scope. Beanstalk's default instance profile (aws-elasticbeanstalk-ec2-role) is notoriously overbroad in many deployments.

**Remediation:** Replace the default aws-elasticbeanstalk-ec2-role with a custom instance profile scoped to the application's specific S3 buckets, database endpoints, and CloudWatch Logs groups. Remove wildcard actions and broad Resource targets.

---

### CTL.BEANSTALK.UPDATES.001

**Elastic Beanstalk Must Enable Managed Platform Updates**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Elastic Beanstalk environments must enable managed platform updates to automatically apply security patches and minor updates.

**Remediation:** Enable managed platform updates in the environment.

---

