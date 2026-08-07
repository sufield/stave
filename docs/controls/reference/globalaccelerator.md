# Control Reference — GLOBALACCELERATOR

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GLOBALACCELERATOR.EXISTS.001

**Global Accelerator Existence Must Be Tracked and Approved**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

Global Accelerator exists in the account without documented approval. Global Accelerators create public entry points with static anycast IP addresses that route traffic to endpoints in AWS regions. Their existence should be intentional and documented — an untracked accelerator is an unmonitored public surface. Scott Piper's aws_exposable_resources lists Global Accelerator as a resource type that creates public network exposure. API: globalaccelerator:ListAccelerators.

**Remediation:** Document the accelerator's purpose and approve it via your organization's change management process. If unneeded, delete it to reduce public surface area.

---

### CTL.GLOBALACCELERATOR.LOG.FLOW.001

**Global Accelerator Flow Logs Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

AWS Global Accelerator does not have flow logs enabled. Without flow logs, network traffic to the accelerator endpoints is not recorded, limiting visibility into connection patterns and potential abuse.

**Remediation:** Enable flow logs for the Global Accelerator to record network traffic metadata to an S3 bucket.

---

