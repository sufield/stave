# Control Reference — CODEPIPELINE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CODEPIPELINE.ARTIFACT.NOENCRYPT.001

**CodePipeline Artifact Store Must Use KMS Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.1;

CodePipeline artifact store must use a customer-managed KMS key. Without encryption, build artifacts — source code archives, compiled binaries, test results, deployment packages — are stored in plaintext in S3. Anyone with read access to the artifact bucket can access every version of every artifact the pipeline produced.

**Remediation:** Configure the pipeline's artifactStore with an encryptionKey pointing to a customer-managed KMS key ARN. This encrypts all artifacts at rest and gives the organization control over key rotation and access policies.

---

### CTL.CODEPIPELINE.GHOST.ARTIFACT.S3.001

**CodePipeline Artifact Store S3 Bucket Deleted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-10, SC-28; soc2: CC6.1, CC8.1;

CodePipeline artifact store references an S3 bucket that has been deleted. Pipeline executions fail because artifacts cannot be stored or retrieved. If the bucket is re-registered under a different account, build artifacts — source code, compiled binaries, deployment packages — are written to attacker storage.

**Remediation:** Update the pipeline artifact store to an existing bucket: aws codepipeline update-pipeline --pipeline file://pipeline.json (set artifactStore.location to a valid bucket).

---

### CTL.CODEPIPELINE.GHOST.CODEBUILD.001

**CodePipeline Action References Deleted CodeBuild Project**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-10, SI-7; soc2: CC6.1, CC8.1;

CodePipeline action references a CodeBuild project that has been deleted. The pipeline stage fails at execution time with an InvalidActionDeclaration or ResourceNotFoundException. If the project name is re-registered by an attacker in the same account, the pipeline executes attacker-controlled build logic — a supply chain vector identical to the S3 artifact store ghost (CTL.CODEPIPELINE.GHOST.ARTIFACT.S3.001) but targeting compute instead of storage. The attacker receives source code as input artifacts and can substitute poisoned build output for downstream deploy stages.

**Remediation:** Update the pipeline action to reference an existing CodeBuild project: aws codepipeline update-pipeline --pipeline file://pipeline.json. Verify the CodeBuild project exists and the buildspec is under version control. Consider using CodeBuild project tags or ARN-based references instead of name-based references to prevent hijacking.

---

### CTL.CODEPIPELINE.NOAPPROVAL.001

**CodePipeline Must Have Manual Approval Before Production Deploy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.4; soc2: CC8.1;

CodePipeline that deploys to production must include a manual approval action. Without a human gate, a compromised source repository or build stage can push adversarial code directly to production — a SageMaker endpoint, ECS service, or Lambda function — with no review step.

**Remediation:** Add a Manual Approval action before any stage that deploys to production. Configure an SNS topic for approval notifications so the right team is notified. This creates a human checkpoint between build and deploy.

---

### CTL.CODEPIPELINE.OVERPERM.001

**CodePipeline Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

CodePipeline execution roles must be scoped to the minimum permissions required for each stage. An overprivileged pipeline role lets any stage action — including actions triggered by external source events — access resources beyond the pipeline's scope: deploying to production, modifying IAM policies, or reading secrets the pipeline does not need.

**Remediation:** Scope the execution role to the minimum permissions per stage: source pull, build trigger, artifact read/write, and deploy actions. Use per-action role overrides where possible. Remove iam:PassRole on *, s3:*, and sagemaker:* from the pipeline role.

---

### CTL.CODEPIPELINE.V1.001

**CodePipeline Must Use V2 Pipeline Type**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SA-22;

CodePipeline must use the V2 pipeline type. V1 is feature-frozen and lacks V2 improvements: pipeline-level variables, Git tags as triggers, and QUEUED/PARALLEL execution modes. V1 pipelines also lack the full CloudWatch Events integration that V2 uses for change detection, falling back to polling — which is both slower and less auditable.

**Remediation:** Migrate to V2 pipeline type. Create a new V2 pipeline with the same stages and actions, verify execution, then delete the V1 pipeline. V2 is backward-compatible with V1 stage/action definitions.

---

