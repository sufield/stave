# Control Reference — AMPLIFY

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.AMPLIFY.APP.ACTIVE.001

**Amplify Apps Are Active in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active Amplify apps. Amplify provisions CloudFront distributions, S3 buckets, Lambda@Edge functions, and IAM roles behind a separate API surface — invisible to the standard CloudFront, S3, and Lambda management APIs and outside the organization's network security monitoring.

**Remediation:** Evaluate intent; if unwanted, delete apps and SCP deny amplify:*.

---

### CTL.AMPLIFY.ROLE.OVERBROAD.001

**Amplify App IAM Role Exceeds Required Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Amplify app's IAM role has permissions beyond what the app requires. Amplify apps need access to specific S3 buckets for build artifacts, CloudFront for distribution management, and CloudWatch Logs for build output. Any action outside this set — iam:PassRole, sts:AssumeRole on broad targets, s3:* on Resource:* — means a compromised or misconfigured Amplify app can access resources far beyond its deployment scope. Amplify apps build and deploy continuously; an overbroad role turns every build into a lateral movement opportunity.

**Remediation:** Scope the Amplify app role to only the resources the app needs: specific S3 buckets for build artifacts, CloudFront distributions for deployment, and CloudWatch Logs for build output. Remove wildcard actions and broad Resource targets.

---

