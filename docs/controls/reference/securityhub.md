# Control Reference — SECURITYHUB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SECURITYHUB.AUTOENABLE.001

**Security Hub Must Auto-Enable for New Organization Accounts**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

Security Hub must be configured to auto-enable for new member accounts in the organization. Without auto-enable, newly created or invited accounts have no Security Hub coverage until manually configured — a gap that can persist indefinitely if onboarding procedures are missed.

**Remediation:** Enable auto-enable: aws securityhub update-organization-configuration --auto-enable

---

### CTL.SECURITYHUB.DELIVERY.HEALTH.001

**SecurityHub Findings Aggregation Must Be Healthy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-6; nist_800_53_r5: AU-6; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

SecurityHub findings aggregation must be actively succeeding. SecurityHub can be enabled, integrated with multiple accounts and services, and pass every other SecurityHub control while findings aggregation is silently failing. When aggregation stops, the central security posture view becomes stale — member account findings, GuardDuty detections, Inspector vulnerabilities, and Config compliance results stop flowing to the administrator account. The SOC dashboard shows green because it displays cached state, not live findings. This is the detection delivery pattern: the service appears functional but the delivery mechanism has failed.

**Remediation:** Check SecurityHub administrator-member relationships and cross-region aggregation configuration. Common causes: member account disassociated, cross-region aggregation region disabled, organization integration turned off, or IAM permissions for the aggregation role revoked. Re-establish the aggregation link and verify findings flow by creating a test finding in a member account.

---

### CTL.SECURITYHUB.ENABLED.001

**AWS Security Hub Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; nist_csf_2.0: DE.CM; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

Security Hub must be enabled to aggregate security findings from GuardDuty, Inspector, Macie, and Config into a unified view.

**Remediation:** Enable Security Hub: aws securityhub enable-security-hub --enable-default-standards

---

### CTL.SECURITYHUB.EXTENDED.INCOMPLETE.001

**Security Hub Extended Must Have All Categories Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

Security Hub Extended plan is active but not all 10 security categories are enabled — gaps in coverage mean entire attack surfaces (endpoint, identity, email, network, data, browser, cloud, AI, security operations, supply chain) are not monitored through the centralized Security Hub view. Each disabled category is a blind spot where partner-detected findings do not reach the security team.

**Remediation:** Review disabled Extended categories in Security Hub → Extended → Categories. Enable all 10 for full-stack visibility: endpoint, identity, email, network, data, browser, cloud, AI, security operations, and supply chain.

---

### CTL.SECURITYHUB.INCOMPLETE.001

**Complete Data Required for Security Hub Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Security Hub properties.

**Remediation:** Ensure the extractor calls aws securityhub describe-hub.

---

### CTL.SECURITYHUB.ORG.AGGREGATION.001

**Security Hub Has No Cross-Region Finding Aggregation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; scs_c02: 4.8; soc2: CC7.1;

Security Hub does not have a finding aggregation region configured. Without cross-region aggregation, findings from each region are visible only in that region's Security Hub console. Security teams must check every active region individually, making it easy to miss findings from regions with lower operational activity. An attacker operating in a non-primary region may go undetected longer.

**Remediation:** Create a finding aggregator in your primary region: aws securityhub create-finding-aggregator --region-linking-mode ALL_REGIONS.

---

### CTL.SECURITYHUB.ORG.NODELEGATED.001

**Security Hub Has No Delegated Administrator**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6(5); scs_c02: 4.8; soc2: CC6.1;

Security Hub is managed from the management account because no delegated administrator is registered. Security Hub administration — managing standards, integrations, and member account enrollment — should run from a dedicated security account to separate operational security from organizational management.

**Remediation:** Register a security account as delegated admin: aws securityhub enable-organization-admin-account --admin-account-id <security-acct>.

---

### CTL.SECURITYHUB.STANDARDS.001

**Security Hub Must Have Relevant Standards Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.SECURITYHUB.STANDARDS.NONE.001

**Security Hub Must Have Security Standards Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

Security Hub must have at least one security standard enabled (AWS Foundational Security Best Practices, CIS Benchmarks, or PCI DSS). Security Hub without standards is a findings aggregator with no baseline — it collects third-party findings but performs no continuous posture evaluation. Standards provide automated security checks that run continuously against account resources.

**Remediation:** Enable security standards in Security Hub: aws securityhub batch-enable-standards. At minimum enable AWS Foundational Security Best Practices (FSBP).

---

### CTL.SECURITYHUB.SUPPLYCHAIN.DISABLED.001

**Security Hub Extended Must Have Supply Chain Category Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12; soc2: CC6.6;

Security Hub Extended plan does not have the supply chain security category enabled — malicious dependencies and untrusted container images are not detected before they enter build pipelines. Supply chain attacks (dependency confusion, typosquatting, compromised maintainer accounts) are a top-5 breach vector. Chainguard and Socket integrations detect these patterns and emit findings in OCSF format to Security Hub for centralized visibility.

**Remediation:** Enable the supply chain security category in Security Hub Extended. Navigate to Security Hub → Extended → Categories → Supply Chain and activate Chainguard and/or Socket.

---

