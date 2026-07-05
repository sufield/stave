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

### CTL.BEANSTALK.PLATFORM.EOL.001

**Elastic Beanstalk Must Not Use a Retired Platform Version**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

Elastic Beanstalk environments must not run on retired platform versions (solution stacks). AWS retires platform versions on a published schedule — retired platforms no longer receive security patches, OS updates, or runtime fixes. This is distinct from CTL.BEANSTALK.UPDATES.001 which checks whether managed updates are enabled; a retired platform receives no updates regardless of the managed-updates toggle. Environments on retired platforms run unpatched OS images and language runtimes, accumulating known CVEs over time. The same lifecycle gap as CTL.LAMBDA.RUNTIME.EOL.001 but for the Beanstalk platform layer.

**Remediation:** Migrate the environment to a supported platform version. Use aws elasticbeanstalk update-environment --solution-stack-name to target the current platform. Test the application on the new platform in a staging environment first — platform upgrades may change OS packages, language runtime versions, or web server configuration.

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

