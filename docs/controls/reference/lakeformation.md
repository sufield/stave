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

### CTL.LAKEFORMATION.CROSSACCOUNT.001

**Lake Formation Grants Cross-Account Data Access Without Organizational Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.5.19; nist_800_53_r5: AC-3, AC-4, AC-6; pci_dss_v4.0: 1.2, 7.1, 7.2; soc2: CC6.1, CC6.6;

Lake Formation permission grants data access to principals in external AWS accounts without an organizational boundary condition. The external account can read or modify tables in the data lake regardless of whether it remains in the organization. Lake Formation cross-account grants are the primary mechanism for sharing data lake resources across accounts — without an org boundary, the grant persists if the account leaves the organization, and any principal in the external account with Lake Formation permissions can access the shared resources. Distinct from CTL.LAKEFORMATION.GRANT.BROAD.001 (scope of permissions) — this control fires on grants that cross account boundaries without organizational verification.

**Remediation:** Scope cross-account Lake Formation grants to the organization using tag-based access control (LF-TBAC) with organization-aware tags, or use RAM resource shares with organizational conditions for cross-account data sharing. For grants that must cross organizational boundaries, document the trust relationship and use explicit account-level grants with periodic review.

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

### CTL.LAKEFORMATION.GRANT.BROAD.001

**Lake Formation Permission Grants Broad Data Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1;

Lake Formation permission grants broad access to database or table resources. A grant with ALL_TABLES, wildcard database names, or SELECT/INSERT/DELETE on all tables in a database gives the grantee unrestricted access to the data lake. Lake Formation permissions are the primary access control layer for data lakes — they govern who can read, write, and modify tables in the Glue Data Catalog and their underlying S3 data. A broad grant bypasses the column-level and table-level access controls that Lake Formation is designed to enforce.

**Remediation:** Replace broad grants with table-specific and column-specific permissions. Use Lake Formation tag-based access control (LF-TBAC) to scope permissions to specific data classifications. Remove ALL_TABLES grants and replace with explicit table-level grants. Review grantees and remove permissions for principals that no longer need data lake access.

---

