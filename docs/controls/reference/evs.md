# Control Reference — EVS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EVS.ENVIRONMENT.ACTIVE.001

**EVS Environment Is Active in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active Elastic VMware Service environments. EVS provisions a full VMware SDDC in an AWS-managed account — compute, storage, and the vCenter/NSX management plane run outside the customer's VPC. Not inventoried by AWS Config, not visible to VPC Flow Logs, not monitored by GuardDuty.

**Remediation:** Evaluate intent; if unwanted, decommission and SCP deny evs:*.

---

