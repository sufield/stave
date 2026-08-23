# Control Reference — IOT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.IOT.AUTH.ENDPOINT.001

**IoT Core Endpoint Must Require Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2; soc2: CC6.1;

IoT Core MQTT/HTTP endpoint does not require device authentication. Without mutual TLS, custom authorizers, or Cognito identity pools, any client with the endpoint URL can connect to the IoT message broker. Unauthenticated access allows message injection, topic subscription, and shadow manipulation across the entire IoT namespace.

**Remediation:** Configure IoT Core to require mutual TLS certificate authentication or a custom authorizer for all device connections. Disable unauthenticated access to MQTT and HTTP endpoints.

---

### CTL.IOT.LOG.AUDIT.001

**IoT Core Must Have Audit Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

IoT Core account does not have audit logging enabled. IoT audit logs capture device authentication events, policy evaluation results, and administrative actions. Without audit logging, compromised IoT devices, unauthorized MQTT connections, and policy misconfigurations cannot be detected or investigated.

**Remediation:** Enable IoT Device Defender audit logging and configure IoT Core logging at the account level to capture device activity and authentication events.

---

### CTL.IOT.POLICY.PUBLIC.001

**IoT Policy Must Not Allow Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IoT policy grants permissions to wildcard principal (*). Any AWS account or unauthenticated entity can interact with IoT resources governed by this policy. IoT policies control access to MQTT topics, device shadows, and job executions. A public policy allows unauthorized message publishing, topic subscription, device shadow manipulation, and fleet command injection. Unlike IAM policies, IoT policies are attached directly to X.509 certificates and Cognito identities — a wildcard principal bypasses the certificate-based device identity model entirely.

**Remediation:** Scope the IoT policy to specific principals using certificate- based authentication or Cognito identity pool IDs. Remove wildcard (*) from the principal field. Use IoT policy variables (iot:Connection.Thing.ThingName) to restrict actions to the authenticated device's own resources.

---

### CTL.IOT.POLICY.WILDCARD.ACTION.001

**IoT Policy Must Not Use Wildcard Action**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

IoT policy uses Action "iot:*" granting all IoT operations: iot:Connect, iot:Publish, iot:Subscribe, iot:Receive, iot:UpdateThingShadow, iot:GetThingShadow, iot:DeleteThingShadow, and every administrative action (iot:CreateThing, iot:AttachPolicy, iot:UpdateCertificate). A device certificate with this policy can register new things, attach policies to other certificates, and manage the entire fleet — not just communicate on its assigned topics. Least privilege requires scoping to specific actions: typically iot:Connect + iot:Publish/Subscribe/Receive on specific topic ARNs.

**Remediation:** Replace iot:* with the minimum required actions. Typical device policies need only iot:Connect, iot:Publish, iot:Subscribe, and iot:Receive scoped to specific topic ARNs using policy variables (e.g., iot:Connection.Thing.ThingName). Administrative actions should be restricted to IAM roles used by fleet management automation, not device certificates.

---

### CTL.IOT.ROLEALIAS.DURATION.001

**IoT Role Alias Credential Duration Exceeds Recommended Maximum**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-12; soc2: CC6.1;

IoT role alias issues temporary credentials via the IoT credential provider (X.509 → STS). Credential duration above the recommended maximum extends the blast radius of a compromised device certificate: stolen credentials remain valid longer, and detection windows shrink relative to the credential lifetime.

**Remediation:** Reduce CredentialDurationSeconds to at most 900 seconds (15 minutes). Short-lived credentials limit the blast radius of certificate compromise.

---

### CTL.IOT.ROLEALIAS.OVERBROAD.001

**IoT Role Alias Backing Role Has Wildcard Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1, CC6.3;

The IAM role backing an IoT role alias uses Resource "*" in its policy. Every device certificate mapped through this alias inherits those permissions via the IoT credential provider. A wildcard resource turns a single compromised X.509 certificate into broad AWS access — the credential provider issues STS tokens scoped to the role, not the device identity.

**Remediation:** Scope the backing role's policy to specific resource ARNs. IoT device roles should access only the S3 prefixes, DynamoDB tables, or Kinesis streams that the device class needs.

---

### CTL.IOT.RULE.NOERRORACTION.001

**IoT Topic Rule Has No Error Action**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-6; soc2: CC7.2;

IoT topic rule has no error action configured. When a rule's primary action fails (destination unreachable, throttled, role permission denied), messages are silently dropped. Without an error action routing failures to a dead-letter queue or CloudWatch log group, failed deliveries are invisible — a detection gap for both operational failures and security-relevant events.

**Remediation:** Add an error action that routes failed messages to an SQS dead-letter queue or CloudWatch Logs log group.

---

### CTL.IOT.RULE.OVERBROAD.001

**IoT Topic Rule Role Has Wildcard Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

The IAM role attached to an IoT topic rule uses Resource "*". Topic rules process device messages and route them to AWS services (S3, Kinesis, Lambda, DynamoDB). A wildcard resource on the rule's role means every matched message can trigger actions against any resource in the account — a message-driven privilege escalation path from the MQTT broker to the data plane.

**Remediation:** Scope the rule's role to the specific destination resources (S3 bucket ARNs, Kinesis stream ARNs, Lambda function ARNs) that this rule routes messages to.

---

