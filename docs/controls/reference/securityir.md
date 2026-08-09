# Control Reference — SECURITYIR

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SECURITYIR.ENABLED.001

**AWS Security Incident Response Not Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: IR-4, IR-5; soc2: CC7.3;

AWS Security Incident Response membership is not active. Security Incident Response provides automated triage and case management for security events. Without an active membership, security events require manual triage and coordination with no centralized case tracking.

**Remediation:** Enable Security Incident Response from the security tooling account: aws security-ir create-membership.

---

### CTL.SECURITYIR.NOTIFICATION.001

**Security Incident Response Notification Not Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: IR-6; soc2: CC7.3;

AWS Security Incident Response has an active membership but notification routing is not configured. Without notifications, new security cases and triage results are not delivered to the security team, defeating the purpose of automated triage.

**Remediation:** Configure notification routing in the Security Incident Response membership settings to deliver case updates to the security operations team.

---

