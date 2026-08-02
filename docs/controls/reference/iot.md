# Control Reference — IOT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

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

