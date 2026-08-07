# Control Reference — VERIFIEDPERMISSIONS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.VERIFIEDPERMISSIONS.ENCRYPT.CMK.001

**Verified Permissions Policy Store Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

Verified Permissions policy store uses AWS-owned encryption key instead of a customer-managed KMS key. Authorization decisions on sensitive data should use customer-controlled encryption for key-policy control, audit visibility via CloudTrail KMS events, and the ability to revoke access by disabling the key. Once a CMK is configured on a policy store it cannot be changed or removed — the decision is permanent.

**Remediation:** Create a new policy store with a customer-managed KMS key (CreatePolicyStore with ValidationSettings and a CMK ARN). Migrate policies, schema, and identity sources from the existing store. The CMK gives the organization key-policy control, audit visibility, and the ability to revoke access by disabling the key.

---

### CTL.VERIFIEDPERMISSIONS.IDENTITYSOURCE.GHOST.001

**Verified Permissions Identity Source References Deleted Provider**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: CM-2, CM-3, IA-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1, A1.1;

Verified Permissions policy store has an identity source configured that references a Cognito user pool or OIDC provider that no longer exists. Authorization calls using IsAuthorizedWithToken will fail because the identity source cannot validate the token against the deleted provider. This is the same ghost-reference pattern as Cognito Lambda triggers referencing deleted functions.

**Remediation:** Either recreate the identity provider (Cognito user pool or OIDC provider) that the identity source references, or delete the stale identity source and create a new one pointing to an existing provider. Verify that IsAuthorizedWithToken calls succeed after the fix.

---

### CTL.VERIFIEDPERMISSIONS.IDENTITYSOURCE.GHOST.POOL.001

**Verified Permissions Identity Source References Deleted Provider**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Verified Permissions identity source exists but the Cognito user pool or OIDC provider it references has been deleted. The identity source is configured and appears functional in the console, but token validation fails at runtime because the upstream provider is absent. This is a 2-hop ghost reference: policy store → identity source → deleted provider. The existing IDENTITYSOURCE.GHOST.001 control catches the first hop (identity source record absent). This control catches the second hop (record present, target absent).

**Remediation:** Either recreate the deleted Cognito user pool or OIDC provider, or update the identity source configuration to reference a valid provider. If the identity source is no longer needed, delete it from the policy store.

---

### CTL.VERIFIEDPERMISSIONS.LOGGING.DISABLED.001

**Verified Permissions Policy Store Authorization Logging Not Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-2, AU-12; pci_dss_v4.0: 10.2; soc2: CC7.2;

Verified Permissions policy store has no authorization decision logging configured. IsAuthorized and IsAuthorizedWithToken data events are not captured in CloudTrail unless explicitly enabled. Without logging, authorization decisions — who accessed what and when — leave no audit trail for forensics, compliance, or anomaly detection.

**Remediation:** Enable CloudTrail data events for Verified Permissions (PutEventSelectors or advanced event selectors with resource type AWS::VerifiedPermissions::PolicyStore). This captures IsAuthorized, IsAuthorizedWithToken, and BatchIsAuthorized calls with their request context and decision results.

---

### CTL.VERIFIEDPERMISSIONS.LOGGING.GHOST.001

**Verified Permissions Logging Destination Does Not Exist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-9; soc2: CC7.2;

Verified Permissions policy store has logging enabled but the log destination does not exist. The logging configuration references a CloudWatch Logs log group, S3 bucket, or Firehose delivery stream that has been deleted, moved, or is in another account that revoked access. Authorization decisions are generated but never reach the audit log. This is a ghost reference: the logging configuration appears correct but the destination is absent.

**Remediation:** Verify the logging destination exists and the policy store has permission to write to it. Recreate the log group, bucket, or delivery stream if it was deleted, or update the logging configuration to point to a valid destination.

---

### CTL.VERIFIEDPERMISSIONS.VALIDATION.OFF.001

**Verified Permissions Policy Store Schema Validation Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.8.9; nist_800_53_r5: CM-2, CM-3, SA-11; soc2: CC8.1;

Verified Permissions policy store has schema validation mode set to OFF. Cedar policies are not validated against the entity schema, allowing malformed or overpermissive policies to be accepted without type checking. Schema validation catches policy errors at authoring time — entity type mismatches, undefined actions, impossible conditions — that would otherwise silently produce wrong authorization decisions at runtime.

**Remediation:** Update the policy store validation settings to STRICT mode (UpdatePolicyStore with ValidationSettings.Mode = STRICT). Fix any existing policies that fail schema validation before enabling STRICT mode. In STRICT mode Cedar rejects policies that reference undefined entity types, actions, or attributes.

---

