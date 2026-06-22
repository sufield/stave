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

