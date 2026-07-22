# Control Reference — LAKEFORMATION

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.LAKEFORMATION.ADMIN.COUNT.001

**Lake Formation Data Lake Admin Count Must Be Minimized**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2, AC-6(1); soc2: CC6.1, CC6.3;

More than two principals are configured as Lake Formation data lake administrators. Data lake admins have unrestricted access to all Lake Formation resources — they can grant/revoke permissions on any database, table, or column, modify the catalog, and change Lake Formation settings. Each additional admin widens the blast radius of a credential compromise and complicates audit attribution. Two admins provide operational redundancy without excessive privilege spread.

**Remediation:** Review the list of data lake admins and remove any that do not require full administrative access. Use per-database grants for team-level access instead of data lake admin.

---

### CTL.LAKEFORMATION.DEFAULTPERM.001

**Lake Formation IAMAllowedPrincipals Super-Permission Must Be Revoked**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-3, AC-6; soc2: CC6.1;

Lake Formation data lake has the default IAMAllowedPrincipals grant active. This super-permission bypasses Lake Formation's fine-grained access control entirely — any IAM principal with Glue catalog permissions can read every table in the catalog without Lake Formation evaluating grants. The default exists for backward compatibility with pre-Lake Formation setups. Leaving it active means Lake Formation grants are cosmetic: they appear to restrict access but the IAMAllowedPrincipals fallback lets everything through. Revoking this permission is the first step in any Lake Formation deployment — without it, all subsequent grant management is security theater.

**Remediation:** Revoke the IAMAllowedPrincipals super-permission for the database: aws lakeformation batch-revoke-permissions --entries '[{"Id":"1","Principal":{"DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"},"Resource":{"Database": {"Name":"<db>"}}}]'. Repeat for each database. Then revoke table-level IAMAllowedPrincipals grants. After revoking, only explicit Lake Formation grants control access.

---

