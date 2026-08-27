# Control Reference — WORKSPACES

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.WORKSPACES.ENCRYPT.001

**WorkSpaces Must Encrypt Volumes At Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

WorkSpaces root and user EBS volumes must be encrypted at rest.

**Remediation:** Enable volume encryption on the workspace.

---

### CTL.WORKSPACES.ENCRYPT.CMK.001

**WorkSpaces Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

WorkSpaces volumes are encrypted but not with a customer-managed KMS key. The AWS-managed key provides at-rest encryption but no key-policy control and no ability to revoke access by disabling the key. If the uses_cmk field is absent the control is not-evaluable and does not fire.

**Remediation:** Launch a new WorkSpace with a customer-managed KMS key (encryption must be set at launch time). Migrate the user to the new WorkSpace.

---

