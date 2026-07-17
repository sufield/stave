# Control Reference — ACMPCA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ACMPCA.CROSSACCOUNT.001

**ACM-PCA Must Not Issue Certificates to External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

ACM Private CA resource policies must not permit acm-pca:IssueCertificate from principals outside the organization. An attacker with Route53 modification permissions plus ACM-PCA access can issue certificates for internal domains and intercept API traffic. Technique: hackingthe.cloud Route53 modification privilege escalation via ACM-PCA.

**Remediation:** Restrict the resource policy to allow acm-pca:IssueCertificate only from principals within the organization. Use aws:PrincipalOrgID conditions.

---

