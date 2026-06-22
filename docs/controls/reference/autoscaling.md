# Control Reference — AUTOSCALING

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.AUTOSCALING.ELB.HEALTH.001

**Auto Scaling Groups Must Use ELB Health Checks**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: CC7.1;

ASGs with load balancers must use ELB health checks.

**Remediation:** Switch to ELB health checks.

---

### CTL.AUTOSCALING.INCOMPLETE.001

**Complete Data Required for Auto Scaling Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Auto Scaling properties.

**Remediation:** Ensure the extractor calls aws autoscaling describe-auto-scaling-groups.

---

### CTL.AUTOSCALING.MULTIAZ.001

**Auto Scaling Groups Must Span Multiple Availability Zones**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: A1.1;

Auto Scaling groups must be configured across multiple AZs. A single-AZ ASG has a single point of failure during AZ outages.

**Remediation:** Update the ASG: aws autoscaling update-auto-scaling-group --auto-scaling-group-name <name> --availability-zones us-east-1a us-east-1b

---

