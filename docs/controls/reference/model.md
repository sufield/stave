# Control Reference — MODEL

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MODEL.FORMAT.INSECURE.001

**Model Artifact Must Not Use an Insecure Serialization Format**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC7.1;

A stored model artifact must not be serialized in a pickle-based format. Pickle (and the formats that embed it — PyTorch's default .pt/.pth, joblib) executes arbitrary code on deserialization, making a tampered or attacker-supplied model checkpoint a remote-code-execution payload the moment it is loaded. This is the primary model-supply-chain compromise vector. Safe, structured formats (safetensors, ONNX, TFLite, protobuf, HDF5, Core ML) carry weights as data with no executable code path.
The serialization format of a stored artifact is a static, cloud-visible property — its file extension, content type, and any explicit format tag are all readable from the snapshot. The collector resolves those into ai.model_artifact.serialization_format (pickle / pytorch_pickle / joblib / safetensors / onnx / …). A bare .pt/.pth resolves to pytorch_pickle unless an explicit `format=safetensors` tag overrides it — PyTorch's default save uses pickle, so absence of the override is treated as the unsafe default (fail-closed). This control fires on any pickle-family format.

**Remediation:** Re-serialize the model in a safe format — safetensors for transformer weights, ONNX for cross-framework models — and replace the artifact. If a .pt/.pth file genuinely holds safetensors-format data, tag it format=safetensors so the resolver records it as safe.

---

### CTL.MODEL.INTEGRITY.CONFIG.001

**Model Artifact Store Must Have Integrity Verification Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC7.1;

A model artifact store must have the infrastructure to detect unauthorized modification of model checkpoints: S3 Object Lock (tamper-resistance), versioning (a known-good history to compare against), and per-object checksums (SHA-256/CRC). The checksum-comparison activity itself is behavioral, but the configuration that ENABLES it is cloud-visible — this is the same proxy Stave's data-event controls use ("logging enabled" stands in for "audit happens"). Here, "integrity verification configured" stands in for "checksums are compared."
The collector resolves the store's S3 Object Lock state, versioning status, and per-object checksum coverage (and, for a SageMaker Model Package, whether a ModelDataHashValue is recorded) into the derived booleans this predicate reads. Fail-closed and precise on versioning: SUSPENDED is not ENABLED — a suspended bucket has no history to compare a replaced artifact against, so it fires.

**Remediation:** Enable S3 Object Lock (Governance or Compliance mode) and bucket versioning on the model store, and require a checksum algorithm (SHA-256 preferred) on every uploaded artifact. For SageMaker Model Packages, record a ModelDataHashValue.

---

