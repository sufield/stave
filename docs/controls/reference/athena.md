# Control Reference — ATHENA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ATHENA.ENCRYPT.001

**Athena Workgroups Must Encrypt Query Results**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Athena workgroups must encrypt query results at rest. Unencrypted query results in S3 expose data extracted by SQL queries.

**Remediation:** Enable encryption in the workgroup result configuration.

---

### CTL.ATHENA.WORKGROUP.001

**Athena Workgroups Must Enforce Query Result Location**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

Athena workgroups must enforce a specific query result location and override client-side settings. Without this enforcement, individual users can direct query results to arbitrary S3 buckets outside the organization's control, potentially exfiltrating data or bypassing encryption and access logging.

**Remediation:** Enable enforce workgroup configuration in the workgroup settings. This forces all queries to use the workgroup's output location and encryption settings.

---

