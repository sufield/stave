# Control Reference — REKOGNITION

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.REKOGNITION.PROJECT.ENCRYPT.CMK.001

**Rekognition Custom Labels Project Version Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Rekognition Custom Labels project version does not use a customer- managed KMS key. Project versions contain trained model artifacts that encode visual patterns from proprietary training images. Without a customer-managed key, the model artifact encryption defaults to AWS-managed with no customer key-policy control.

**Remediation:** Create a new project version with KmsKeyId set to a customer- managed KMS key via CreateProjectVersion. Existing versions cannot be re-encrypted.

---

### CTL.REKOGNITION.SHADOW.USAGE.001

**Rekognition Usage in Account Not Designated for AI Workloads**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-7, AC-3; soc2: CC6.1;

Rekognition usage detected in an account not designated for AI workloads. Rekognition processes images and video for face detection, content moderation, and object recognition. In an unsanctioned account, Rekognition can process biometric and visual data without privacy controls or consent management.

**Remediation:** Restrict Rekognition API access via IAM policies or authorize the account for AI workloads after security review.

---

### CTL.REKOGNITION.STREAM.ENCRYPT.CMK.001

**Rekognition Stream Processor Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Rekognition stream processor does not use a customer-managed KMS key. Stream processors analyze real-time video feeds for face detection and recognition. Without a customer-managed key, the processor's KmsKeyId defaults to AWS-managed encryption with no customer-controlled key policy or revocation capability.

**Remediation:** Create a new stream processor with KmsKeyId set to a customer- managed KMS key. Existing stream processors cannot be re-encrypted in place.

---

