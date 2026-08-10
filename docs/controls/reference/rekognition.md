# Control Reference — REKOGNITION

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.REKOGNITION.SHADOW.USAGE.001

**Rekognition Usage in Account Not Designated for AI Workloads**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-7, AC-3; soc2: CC6.1;

Rekognition usage detected in an account not designated for AI workloads. Rekognition processes images and video for face detection, content moderation, and object recognition. In an unsanctioned account, Rekognition can process biometric and visual data without privacy controls or consent management.

**Remediation:** Restrict Rekognition API access via IAM policies or authorize the account for AI workloads after security review.

---

