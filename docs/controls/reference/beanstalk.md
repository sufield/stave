# Control Reference — BEANSTALK

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.BEANSTALK.LOG.001

**Elastic Beanstalk Environments Must Stream Logs to CloudWatch**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Elastic Beanstalk environments must stream instance and proxy logs to CloudWatch Logs for centralized monitoring.

**Remediation:** Enable CloudWatch Logs streaming in the environment configuration.

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

