# Control Reference — APPSTREAM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APPSTREAM.IMAGE.DEPRECATED.001

**AppStream Image Must Not Use Deprecated Platform**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

AppStream 2.0 images must not use deprecated OS platforms. Windows Server 2012 R2 reached end-of-life in October 2023 and no longer receives security patches from Microsoft. AppStream images built on deprecated platforms expose streaming sessions to unpatched OS vulnerabilities. Users connect to these sessions with their corporate credentials — a compromised streaming instance is a credential-harvesting opportunity.

**Remediation:** Rebuild the AppStream image on a supported platform (Windows Server 2019 or 2022). Create a new image builder with the updated platform, install your applications, and create a new image. Update your fleet to use the new image.

---

### CTL.APPSTREAM.IMDS.V1.001

**AppStream Fleet Must Enforce IMDSv2**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S01; soc2: CC6.1; subtractive_tier: deletion;

AppStream fleet instances allow IMDSv1 access. IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials from the metadata endpoint.

**Remediation:** Enforce IMDSv2 on AppStream fleet instances by requiring token-based metadata requests.

---

### CTL.APPSTREAM.INTERNET.001

**AppStream Fleets Must Disable Default Internet Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

AppStream fleets must disable default internet access. Fleets with default internet connectivity allow streaming sessions to reach the internet directly, bypassing network controls.

**Remediation:** Disable EnableDefaultInternetAccess and use VPC with NAT.

---

