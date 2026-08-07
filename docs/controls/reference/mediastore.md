# Control Reference — MEDIASTORE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MEDIASTORE.LOG.ACCESS.001

**MediaStore Access Logging Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

AWS Elemental MediaStore container does not have access logging enabled. Without access logging, object-level operations are not recorded, limiting forensic capability after unauthorized media access.

**Remediation:** Enable access logging for the MediaStore container.

---

### CTL.MEDIASTORE.POLICY.PUBLIC.001

**MediaStore Container Policy Must Not Allow Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

MediaStore container policy grants access to Principal "*" or external accounts without aws:PrincipalOrgID condition. MediaStore containers hold streaming media assets. A public container policy lets any AWS account (or unauthenticated caller if combined with public endpoint) read, overwrite, or delete media objects. Scott Piper's aws_exposable_resources lists mediastore:PutContainerPolicy as a public exposure vector. API: mediastore:GetContainerPolicy.

**Remediation:** Restrict the container policy to specific account IDs or add an aws:PrincipalOrgID condition. For public content delivery, use CloudFront with an origin access identity instead of a public container policy.

---

