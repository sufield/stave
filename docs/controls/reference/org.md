# Control Reference — ORG

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ORG.REGION.SCP.001

**AWS Organizations Must Have an SCP Restricting Resource Creation to Approved Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; gdpr: Art.32; hipaa: 164.312(b); nist_800_53_r5: CM-7; pci_dss_v4.0: 12.5.2; soc2: CC7.1;

AWS Organizations must have a Service Control Policy that restricts resource creation to an approved set of AWS regions. Without a region restriction SCP, any IAM principal can create resources in any of 30+ regions — including regions where the organization has no CloudTrail, no GuardDuty, no Config recording, and no monitoring infrastructure. MITRE ATT&CK T1535 documents this as a defense evasion technique: attackers deliberately operate in unused regions to bypass cloud monitoring. A region restriction SCP closes all unmonitored regions simultaneously with a single organizational policy rather than requiring monitoring deployment to every region. This is the architectural complement to per-region monitoring controls — it eliminates the regions where monitoring is not deployed.

**Remediation:** Attach an SCP to the organization root with a Deny statement conditioned on aws:RequestedRegion that restricts resource creation to the organization's approved operating regions. Example condition: StringNotEquals aws:RequestedRegion [us-east-1, us-west-2, eu-west-1]. Exclude global services (IAM, CloudFront, Route 53) from the restriction using a NotAction list.

---

