# Control Reference — CODEARTIFACT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CODEARTIFACT.DOMAIN.POLICY.CROSSACCOUNT.001

**CodeArtifact Domain Policy Allows Unconditioned Cross-Account Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, AC-6; soc2: CC6.1;

CodeArtifact domain resource policy allows cross-account principals without aws:PrincipalOrgID or specific account conditions. An unconditioned cross-account domain policy enables confused deputy attacks and unauthorized repository creation within the domain.

**Remediation:** Add an aws:PrincipalOrgID condition to cross-account statements in the domain policy, or restrict to specific account IDs.

---

### CTL.CODEARTIFACT.EXTERNAL.UNRESTRICTED.001

**CodeArtifact Repository External Connection Without Origin Restrictions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12, SR-4; soc2: CC7.2;

CodeArtifact repository has an external connection to a public upstream (npmjs, PyPI, Maven Central) but does not enforce package origin restrictions. Without restrictions, any package published to the public upstream is automatically available in the internal registry — the exact vector exploited in dependency confusion and typosquatting attacks.

**Remediation:** Configure package origin restrictions to BLOCK upstream publish for all package formats. Use package groups to enforce origin controls at the namespace level.

---

### CTL.CODEARTIFACT.POLICY.PUBLIC.001

**CodeArtifact Repository Policy Allows Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

CodeArtifact repository resource policy allows Principal "*" or overly broad access without restrictive conditions. A public repository policy enables unauthorized package reads (information disclosure) or writes (supply chain compromise) from any AWS principal.

**Remediation:** Restrict the repository policy to specific account IDs or add an aws:PrincipalOrgID condition. Remove any Principal "*" statements.

---

### CTL.CODEARTIFACT.UPSTREAM.UNVETTED.001

**CodeArtifact Repository Has Cross-Domain Upstream**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SA-12, SR-4; soc2: CC7.2;

CodeArtifact repository upstream list includes repositories in a different domain or AWS account. Cross-domain upstreams create transitive trust — a compromise of the upstream repository propagates to all downstream consumers without additional verification.

**Remediation:** Use only same-domain upstream repositories. If cross-domain upstreams are required, document the trust relationship and add origin restrictions to block upstream publish.

---

