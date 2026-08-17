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

### CTL.AUTOSCALING.HEALTHCHECK.APPLICATIONSTATUS.001

**ASG With Application Status Checks Not Using Application Health Type**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** aws_security_hub: AutoScaling.1; nist_800_53_r5: CP-7; soc2: A1.2;

Auto Scaling group has instances with application status checks but the ASG is not configured to use application-level health check type. The application status checks are cosmetic — they report health but the ASG cannot act on them. When an instance fails the application status check, it remains in the ASG serving errors because the ASG only watches EC2 or ELB health. This is the gap between "we monitor it" and "we respond to it." Fires only on ASGs where member instances have application status checks configured.

**Remediation:** Update the ASG to use APPLICATION_STATUS health check type so that application status check failures trigger instance replacement. Set an appropriate health check grace period (300-600s) to allow instances to initialize before health checks begin.

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

