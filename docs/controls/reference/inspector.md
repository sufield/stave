# Control Reference — INSPECTOR

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.INSPECTOR.COVERAGE.001

**Amazon Inspector Must Cover All Scan Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

Amazon Inspector must have all available scan types enabled — EC2 scanning, ECR container scanning, Lambda function scanning, and Lambda code scanning. Each scan type covers a different attack surface. EC2 scanning detects OS-level CVEs, ECR scanning finds container image vulnerabilities, Lambda scanning identifies dependency vulnerabilities in function code. Partial coverage leaves entire resource classes unscanned.

**Remediation:** Enable all scan types in Inspector. Use aws inspector2 enable --resource-types EC2 ECR LAMBDA LAMBDA_CODE to enable all supported scan types.

---

### CTL.INSPECTOR.DELEGATED.001

**Inspector Delegated Administrator Must Be Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; soc2: CC7.1;

Amazon Inspector must have a delegated administrator configured in AWS Organizations for centralized vulnerability management. Without delegation, each account manages Inspector independently — scan results are fragmented, no single team has visibility into organization-wide vulnerabilities, and coverage gaps go undetected.

**Remediation:** Designate a delegated administrator: aws inspector2 enable-delegated-admin-account --delegated-admin-account-id <account-id>

---

### CTL.INSPECTOR.DELIVERY.HEALTH.001

**Inspector Scanning Must Be Delivering Findings**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: RA-5; nist_800_53_r5: RA-5; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

Inspector scanning must be actively producing findings. Inspector can be enabled with full resource coverage and pass every other Inspector control while scan results silently stop flowing. When scanning stops delivering, new EC2 instances launch without vulnerability assessment, ECR images push without CVE checks, and Lambda functions deploy without code scanning. The Inspector console shows "enabled" and displays historical findings, but no new scans complete. This is the detection delivery pattern: the scanner appears functional but the scanning mechanism has degraded or stopped.

**Remediation:** Check Inspector account status and scan statistics. Common causes: SSM agent not running on EC2 instances, service-linked role permissions modified, ECR scanning set to manual, Lambda code scanning disabled, or account-level Inspector service quotas exceeded. Verify scan delivery by launching a test instance with a known CVE and confirming a finding appears.

---

### CTL.INSPECTOR.ENABLED.001

**Amazon Inspector Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; soc2: CC7.1;

Amazon Inspector 2 must be enabled for vulnerability scanning of EC2, ECR, and Lambda resources. Without Inspector, known vulnerabilities in deployed software go undetected.

**Remediation:** Enable Inspector 2 for EC2, ECR, and Lambda scanning.

---

