# Control Reference — VERIFIEDACCESS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.VERIFIEDACCESS.ENDPOINT.NOENCRYPT.001

**Verified Access Endpoint Not Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

A Verified Access endpoint does not use encryption for the connection to the application. Unencrypted endpoints expose application traffic to interception on the internal network.

**Remediation:** Ensure the endpoint uses HTTPS for the application connection.

---

### CTL.VERIFIEDACCESS.ENDPOINT.NOLOGGING.001

**Verified Access Logging Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-2, AU-3; soc2: CC7.1;

A Verified Access instance does not have access logging enabled. Without logging, access decisions — grants, denials, and trust context — are not recorded, making incident investigation and access pattern analysis impossible.

**Remediation:** Enable logging: aws ec2 modify-verified-access-instance-logging-configuration --verified-access-instance-id <vai-id> --access-logs Enabled=true,CloudWatchLogs={Enabled=true,LogGroup=<group>}.

---

### CTL.VERIFIEDACCESS.FIPS.001

**Verified Access Instance Not Using FIPS Endpoints**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-13; soc2: CC6.7;

A Verified Access instance is not configured to use FIPS endpoints. For government and regulated workloads, FIPS-validated cryptographic modules are required for data in transit.

**Remediation:** Enable FIPS on the Verified Access instance: aws ec2 modify-verified-access-instance --verified-access-instance-id <vai-id> --fips-enabled.

---

### CTL.VERIFIEDACCESS.POLICY.PERMISSIVE.001

**Verified Access Group Policy Is Overly Permissive**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, AC-6; soc2: CC6.1;

A Verified Access group has a policy with no conditions. An unconditional allow policy grants access to all authenticated users regardless of device posture, IP, or identity attributes, negating the zero-trust intent of Verified Access.

**Remediation:** Add trust context conditions to the group policy: aws ec2 modify-verified-access-group-policy --verified-access-group-id <vag-id> --policy-document <policy-with-conditions>.

---

### CTL.VERIFIEDACCESS.TRUSTPROVIDER.NONE.001

**Verified Access Instance Has No Trust Provider**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; soc2: CC6.1;

A Verified Access instance has no trust provider attached. Without a trust provider, Verified Access endpoints have no identity verification — any network-reachable client can access the application. This defeats the purpose of zero-trust access.

**Remediation:** Attach a trust provider: aws ec2 attach-verified-access-trust-provider --verified-access-instance-id <vai-id> --verified-access-trust-provider-id <vatp-id>.

---

