# Control Reference — SHIELD

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SHIELD.ADVANCED.001

**Shield Advanced Must Be Enabled for Internet-Facing Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(7); nist_800_53_r5: SC-5; pci_dss_v4.0: 1.3.1; soc2: A1.1;

AWS accounts with internet-facing resources must have Shield Advanced enabled with all internet-facing resources registered as protected. Shield Standard provides basic DDoS protection automatically. Shield Advanced provides volumetric DDoS mitigation at the network edge, 24/7 DDoS Response Team (DRT) access, cost protection against scaling charges during attacks, and attack diagnostics. WAF controls protect against application-layer attacks but do not protect against volumetric network-layer DDoS that exhausts bandwidth or connection capacity before WAF can evaluate requests. A 100 Gbps UDP flood cannot be mitigated by WAF rules — it requires scrubbing at the network edge. For PHI and financial services, unmitigated DDoS is both an operational and compliance risk — HIPAA and PCI-DSS require availability of regulated systems.

**Remediation:** Subscribe to AWS Shield Advanced via the Shield console or API. Register all internet-facing resources (ALBs, NLBs, CloudFront distributions, Route 53 hosted zones, Elastic IPs) as protected resources. Configure Route 53 health checks for protected resources to enable proactive engagement by the DDoS Response Team.

---

### CTL.SHIELD.CONTACTS.MISSING.001

**Shield Advanced Emergency Contacts Not Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; soc2: A1.1;

Shield Advanced has no emergency contacts configured. Proactive engagement cannot function — during a detected DDoS event, the DRT has no phone number or email to reach. The DRT detects the attack via internal telemetry but cannot notify anyone or coordinate mitigation. Without contacts, proactive engagement is effectively disabled even if Shield Advanced is subscribed and the DRT has IAM access.

**Remediation:** Configure emergency contacts via aws shield update-emergency-contact-settings --emergency-contact-list with at least one phone number and email for the on-call team.

---

### CTL.SHIELD.DRT.NOACCESS.001

**Shield DRT Has No IAM Access Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; soc2: A1.1;

Shield Advanced is active but the DDoS Response Team (DRT) has no IAM role configured for account access. During a DDoS attack, the DRT cannot create or modify WAF rules, inspect Shield protections, or adjust rate-based rules on your behalf. Manual credential provisioning during an attack delays mitigation by the time it takes to create and share an IAM role — typically 15-30 minutes of unmitigated attack traffic. The DRT role requires shield:* and wafv2:* permissions at minimum.

**Remediation:** Create an IAM role with shield:* and wafv2:* permissions and associate it via aws shield associate-drt-role --role-arn <arn>.

---

### CTL.SHIELD.DRT.NOLOGS.001

**Shield DRT Has No Access to WAF or Flow Logs**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; soc2: A1.1;

The DRT has IAM role access but no S3 log bucket access configured. During a DDoS incident, the DRT cannot analyze WAF logs, VPC flow logs, or CloudFront access logs to characterize attack traffic patterns. Without log access, the DRT must request it manually during the incident, delaying traffic analysis and targeted mitigation rule creation.

**Remediation:** Grant DRT access to log buckets via aws shield associate-drt-log-bucket --log-bucket <bucket-name> for each bucket containing WAF logs, VPC flow logs, or CloudFront access logs.

---

### CTL.SHIELD.PROTECTION.MISSING.001

**Public Resource Not Associated with Shield Advanced Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; soc2: A1.1;

A public-facing resource exists but has no Shield Advanced protection association. The resource relies on Shield Standard only, which provides basic Layer 3/4 DDoS mitigation but no enhanced detection, no DRT support, no cost protection, and no Layer 7 mitigation for the resource. Shield Advanced protections must be explicitly associated per resource — subscribing to Shield Advanced alone does not protect any resource. Applicable to CloudFront distributions, ALBs, NLBs, Elastic IPs, Global Accelerators, and Route 53 hosted zones.

**Remediation:** Associate the resource with Shield Advanced protection via aws shield create-protection --name <name> --resource-arn <arn>. Configure a Route 53 health check for the resource to enable proactive engagement.

---

### CTL.SHIELD.SUBSCRIPTION.AUTORENEW.001

**Shield Advanced Subscription Auto-Renew Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; soc2: A1.1;

Shield Advanced subscription auto-renew is disabled. When the subscription expires, all advanced protections are silently removed — DRT access, cost protection, enhanced detection, and Layer 7 mitigation revert to Shield Standard only. The subscription lapses without notice unless CloudWatch billing alarms catch the change. Re-subscribing requires a new 12-month commitment and re-registration of all protected resources.

**Remediation:** Enable auto-renew via the Shield console or aws shield update-subscription --auto-renew ENABLED.

---

