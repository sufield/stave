# Control Reference — SERVERLESSREPO

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SERVERLESSREPO.POLICY.PUBLIC.001

**Serverless Application Repository Application Must Not Be Publicly Shared**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Serverless Application Repository (SAR) application has a policy permitting public access. Public SAR applications expose Lambda deployment packages — which may contain embedded secrets, proprietary business logic, or internal API endpoints. Scott Piper's aws_exposable_resources lists serverlessrepo:PutApplicationPolicy as a public exposure vector. API: serverlessrepo:GetApplicationPolicy.

**Remediation:** Remove the public sharing statement from the application policy. To share with specific accounts, use explicit account IDs or an aws:PrincipalOrgID condition.

---

