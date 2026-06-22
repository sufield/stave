# Control Reference — EXPOSURE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EXPOSURE.ANON.001

**Sensitive Resources Must Not Be Reachable from Anonymous**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Resources tagged with sensitive data classifications (PHI, PII, confidential) must not be reachable from anonymous or unauthenticated principals through any composition of access grants. The extractor traces paths from anonymous through API Gateway routes, Lambda integrations, IAM role assumptions, bucket policies, VPC endpoint policies, and security group rules. This catches the API Gateway → Lambda → IAM Role → S3 Bucket pattern where every resource passes individual inspection but the composition creates an unauthenticated path to sensitive data.

**Remediation:** Add an authorization layer to the path. Configure an API Gateway authorizer (Cognito, Lambda, or IAM), attach a WAF with managed rule groups, or remove the Lambda function's permission to access the sensitive resource. Review the full path and break the chain at the most appropriate point.

---

### CTL.EXPOSURE.ANON.002

**Unauthenticated Access Path Must Not Exceed Depth Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

Unauthenticated access paths to any resource must not exceed 3 hops. Deep chains (anonymous → API Gateway → Lambda → Role A → Role B → S3) indicate unintended transitive access. Each hop is an access grant — IAM policy, resource policy, role assumption, or network rule. Shorter paths are more likely intentional and auditable. Deep paths signal accidental composition where intermediate services were granted broader permissions than their design requires.

**Remediation:** Flatten the access chain. Remove unnecessary intermediate services. Scope Lambda execution role permissions to the minimum required resources. Replace broad IAM role assumption chains with direct service-linked roles.

---

### CTL.EXPOSURE.ANON.003

**Unauthenticated Access Path Must Have Authentication Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

Any resource reachable from anonymous principals must have at least one authentication boundary in the access path — a point where identity is verified (Cognito authorizer, Lambda authorizer, IAM authorization, mTLS). An inspection boundary (WAF, API Gateway threat protection) provides defense-in-depth but does NOT establish identity — a path with only WAF is still unauthenticated. This control flags paths where no identity verification exists between the public internet and the target resource.

**Remediation:** Add an authentication boundary to the access path. Configure a Cognito user pool authorizer or Lambda authorizer on API Gateway routes. Enable IAM authorization on the API Gateway stage. If service-to-service, enable mTLS.

---

### CTL.EXPOSURE.ANON.004

**Unauthenticated Access Path Should Have Inspection Boundary**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.2;

Any resource reachable from anonymous principals should have at least one inspection boundary in the access path — a point where requests are filtered for malicious content (WAF with managed rule groups, API Gateway request validation). An authentication boundary verifies identity; an inspection boundary verifies request safety. Both are needed for defense-in-depth. This control flags paths where no request inspection exists.

**Remediation:** Attach a WAF web ACL with managed rule groups (AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet) to the API Gateway stage or ALB. Enable API Gateway request validation.

---

### CTL.EXPOSURE.ANON.INCOMPLETE.001

**Complete Data Required for Reachability Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Unauthenticated reachability cannot be assessed when the reachability kind discriminator is present but the reachable field is missing. The extractor encountered an error during graph traversal and could not determine whether the resource is reachable from anonymous principals.

**Remediation:** Re-run the reachability extractor with sufficient IAM permissions to read API Gateway configurations, Lambda function policies, IAM role trust policies, and resource-based policies for all resources in the account.

---

### CTL.EXPOSURE.ANON.PARTIAL.001

**Reachability Path Must Be Fully Resolved**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

When the extractor finds a path from anonymous to a resource but cannot fully resolve all intermediate nodes (e.g., access denied on an IAM policy lookup, missing Lambda configuration), the path is marked as partially resolved. Safety cannot be proven because the unresolved segment may contain additional access grants that widen the blast radius. This is the "unknown" state — worse than a confirmed safe path, potentially better than a confirmed unsafe path.

**Remediation:** Grant the reachability extractor read access to the unresolved resources. Required permissions include iam:GetRolePolicy, lambda:GetFunction, apigateway:GetMethod, and resource-based policy read access for all services in the path.

---

### CTL.EXPOSURE.EXFIL.001

**Sensitive Data Must Not Be Readable by Compute with Internet Egress**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(a)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Resources containing sensitive data (PHI, PII, confidential) are readable by a compute instance that has an unmonitored path to the internet. The extractor traces from the sensitive resource to compute instances that can read it, then checks if those instances have outbound internet connectivity (NAT gateway, internet gateway, VPC peering to public subnet). This is the reverse of the unauthenticated reachability check — instead of "who can get in?" it answers "how can data get out?"

**Remediation:** Remove internet egress from the compute instance's subnet. Place sensitive-data-accessing instances in private subnets with VPC endpoints only. Scope the instance role to the minimum required resources. Enable VPC Flow Logs and CloudTrail data events for audit.

---

### CTL.EXPOSURE.EXFIL.002

**Compute with Internet Egress Must Not Have Wildcard Write**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

Compute instances with internet egress paths must have scoped write permissions. An instance with s3:PutObject on Resource "*" combined with outbound internet access can write data to any S3 bucket — including attacker-controlled external buckets. The extractor checks if the instance role grants wildcard write permissions to storage services.

**Remediation:** Scope the instance role's write permissions to specific resource ARNs. Replace s3:PutObject on Resource "*" with explicit bucket ARNs. Use VPC endpoints with bucket-scoped policies to restrict write targets.

---

### CTL.EXPOSURE.EXFIL.INCOMPLETE.001

**Complete Data Required for Exfiltration Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Data exfiltration path assessment requires the exfiltration kind discriminator and the path_to_internet_exists field. The extractor could not determine whether the compute instance has internet egress.

**Remediation:** Re-run the exfiltration extractor with sufficient permissions to read VPC route tables, NAT gateways, internet gateways, and security group egress rules.

---

### CTL.EXPOSURE.SOVEREIGNTY.001

**Sensitive Data Must Not Be Accessible from Outside Its Jurisdiction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; gdpr: Art.44; nist_800_53_r5: AC-4;

Resources containing sensitive data (PHI, PII, confidential) in a specific jurisdiction must have access restricted to principals in the same jurisdiction. A bucket in eu-west-1 accessible by a US-based principal is a structural jurisdictional violation — the data is physically in the EU but logically reachable from outside the EU, defeating data residency controls.

**Remediation:** Restrict access to the resource using IAM condition keys that enforce source VPC or source IP ranges within the jurisdiction. Use SCPs to deny cross-jurisdiction access at the organization level. Review resource-based policies for cross-region grants.

---

### CTL.EXPOSURE.SOVEREIGNTY.INCOMPLETE.001

**Complete Data Required for Sovereignty Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Sovereignty assessment requires the cross_border_access_detected field. The extractor could not determine whether the resource is accessible from outside its jurisdiction.

**Remediation:** Re-run the sovereignty extractor with permissions to enumerate IAM principals, their account regions, and resource-based policies for all sensitive resources.

---

