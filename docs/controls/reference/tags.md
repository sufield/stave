# Control Reference — TAGS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.TAGS.CREDENTIAL.PATTERN.001

**Resource Tags Must Not Contain Credential Patterns**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

No resource tag value should match common credential patterns (AWS access key IDs, connection strings, passwords, private keys). Developers store secrets in tags for convenience. An attacker with tag:GetResources — a low-privilege, commonly granted action — can scan all tags across all services and harvest embedded credentials. This is a heuristic control with false positive risk for tags containing example data. Technique: Wiz "Extract credentials from resource tags".

**Remediation:** Move the credential to AWS Secrets Manager or Systems Manager Parameter Store (SecureString). Remove the tag value. Rotate the exposed credential.

---

