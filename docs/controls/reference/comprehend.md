# Control Reference — COMPREHEND

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.COMPREHEND.CLASSIFIER.ENCRYPT.CMK.001

**Comprehend Document Classifier Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Comprehend custom document classifier does not use a customer- managed KMS key. Classifiers store trained model artifacts and output data that may encode patterns from sensitive training documents. Without a customer-managed key, the model artifact (ModelKmsKeyId), training volume (VolumeKmsKeyId), and output (OutputDataConfig.KmsKeyId) use AWS-managed encryption.

**Remediation:** Create a new document classifier with ModelKmsKeyId, VolumeKmsKeyId, and OutputDataConfig.KmsKeyId set to a customer-managed KMS key. Existing classifiers cannot be re-encrypted in place.

---

### CTL.COMPREHEND.FLYWHEEL.ENCRYPT.CMK.001

**Comprehend Flywheel Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Comprehend flywheel does not use a customer-managed KMS key. Flywheels orchestrate continuous training and manage data lakes, model artifacts, and training volumes. Without a customer-managed key, all three encryption surfaces (DataLakeKmsKeyId, ModelKmsKeyId, VolumeKmsKeyId) use AWS-managed encryption with no customer-controlled key policy, rotation schedule, or CloudTrail key-usage audit trail.

**Remediation:** Create a new flywheel with DataSecurityConfig specifying DataLakeKmsKeyId, ModelKmsKeyId, and VolumeKmsKeyId pointing to a customer-managed KMS key. Existing flywheels cannot be re-encrypted in place.

---

### CTL.COMPREHEND.RECOGNIZER.ENCRYPT.CMK.001

**Comprehend Entity Recognizer Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Comprehend custom entity recognizer does not use a customer- managed KMS key. Recognizers store trained model artifacts encoding domain-specific entity patterns from potentially sensitive training data. Without a customer-managed key, VolumeKmsKeyId and ModelKmsKeyId use AWS-managed encryption.

**Remediation:** Create a new entity recognizer with VolumeKmsKeyId and ModelKmsKeyId set to a customer-managed KMS key. Existing recognizers cannot be re-encrypted in place.

---

### CTL.COMPREHEND.SHADOW.ENDPOINT.001

**Comprehend Endpoint in Account Not Designated for AI Workloads**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-7, AC-3; soc2: CC6.1;

A Comprehend endpoint is deployed in an account not designated for AI workloads. Comprehend processes natural language text for sentiment, entities, and PII detection. In an unsanctioned account, Comprehend endpoints can process sensitive documents without data classification controls.

**Remediation:** Delete the endpoint or authorize the account for AI workloads after security review.

---

