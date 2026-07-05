# AI Agent Identity Controls — Taxonomy + Coverage Audit

This document is the failure taxonomy and coverage audit for AI-agent-identity
controls. It maps the AI-agent identity failure modes, audits what Stave covers
today, and identifies observation-schema gaps.

| | |
|---|---|
| Audit date | 2026-05-10 |
| Catalog version | 2816 controls |
| Scope | AWS only — Azure / GCP / Anthropic API not yet covered |

## TL;DR

- **Existing AI coverage:** 11 SageMaker + 9 Bedrock + 12 CodeBuild controls; 3 AI-relevant compound chains (`bedrock_ai_data_exposure`, `sagemaker_notebook_exposure`, `sagemaker_training_data_exposure`).
- **Existing controls focus on the perimeter:** network isolation, encryption-at-rest, VPC, guardrails, logging. **Identity-shaped checks are sparse** — only `CTL.BEDROCK.ACCESS.ADMIN.001`, `CTL.BEDROCK.ACCESS.FULLACCESS.001`, `CTL.BEDROCK.ACCESS.LONGTERM.001`, `CTL.BEDROCK.AGENT.GUARDRAIL.001`, and `CTL.SAGEMAKER.NOTEBOOK.ROOT.001` directly check role / agent / API-key identity properties.
- **Observation schema is in good shape for SageMaker (4 asset types) and Bedrock (5 asset types).** The shipped schema does NOT carry `aws_bedrock_knowledge_base` or `aws_bedrock_model_access`, and `aws_sagemaker_endpoint` (the deployed endpoint, distinct from the existing `aws_sagemaker_endpoint_config`) is also missing.
- **Identified gap: ~30–40 identity-shaped controls + 4–6 compound chains** not yet authored, concentrated in Bedrock agents (freshest agent-identity attack surface, lightest current coverage) and SageMaker execution roles.
- **The four highest-risk failure modes (Double Pareto — ~80% of incident risk):** agent role overprivilege, agent ghost references, RAG data-boundary violations, and AI-pipeline cross-service compounds; plus shadow-agent governance.

## Coverage audit

### SageMaker (11 controls, 2 chains)

| Control | Severity | Identity-shaped? | Notes |
|---|---|---|---|
| `CTL.SAGEMAKER.ENDPOINT.REDUNDANCY.001` | medium | No | Resilience |
| `CTL.SAGEMAKER.MODEL.VPC.001` | medium | No | Network |
| `CTL.SAGEMAKER.MODEL.ISOLATION.001` | high | No | Network isolation |
| `CTL.SAGEMAKER.NOTEBOOK.ROOT.001` | medium | **Yes** | Root-on-notebook = identity privilege |
| `CTL.SAGEMAKER.NOTEBOOK.ENCRYPT.001` | high | No | Encryption-at-rest |
| `CTL.SAGEMAKER.NOTEBOOK.VPC.001` | high | No | Network |
| `CTL.SAGEMAKER.NOTEBOOK.INTERNET.001` | high | No | Network — used in chain |
| `CTL.SAGEMAKER.TRAINING.ISOLATION.001` | high | No | Network |
| `CTL.SAGEMAKER.TRAINING.ENCRYPT.VOLUME.001` | high | No | Encryption |
| `CTL.SAGEMAKER.TRAINING.ENCRYPT.INTERCONTAINER.001` | medium | No | Encryption |
| `CTL.SAGEMAKER.TRAINING.VPC.001` | high | No | Network |

**Identity-shaped count: 1 of 11.** The catalog protects the perimeter
(VPC, encryption, internet exposure) but does not check execution-role
permissions, training-data access scope, or notebook role drift.

### Bedrock (9 controls, 1 chain)

| Control | Severity | Identity-shaped? | Notes |
|---|---|---|---|
| `CTL.BEDROCK.VPC.ENDPOINTS.001` | medium | No | Network |
| `CTL.BEDROCK.LOG.INVOCATION.001` | medium | Audit | Used in chain |
| `CTL.BEDROCK.LOG.ENCRYPT.001` | high | No | Encryption |
| `CTL.BEDROCK.ACCESS.ADMIN.001` | high | **Yes** | API key admin privilege |
| `CTL.BEDROCK.ACCESS.FULLACCESS.001` | high | **Yes** | AmazonBedrockFullAccess attached to role |
| `CTL.BEDROCK.ACCESS.LONGTERM.001` | high | **Yes** | Long-lived API key |
| `CTL.BEDROCK.GUARDRAIL.PII.001` | high | Data | PII filter |
| `CTL.BEDROCK.GUARDRAIL.PROMPTATTACK.001` | high | Data | Prompt-injection filter |
| `CTL.BEDROCK.AGENT.GUARDRAIL.001` | high | **Yes** | Agent ↔ guardrail association |

**Identity-shaped count: 4 of 9.** Better identity coverage than
SageMaker but still narrow — checks API-key / role-policy attributes
but does not check what the role actually has access to (S3 buckets,
KMS keys, downstream services), agent tool-list scope, knowledge-base
sources, or agent lifecycle (rotation, ghost references).

### Existing AI-related compound chains

| Chain | Members | Threshold | Severity |
|---|---|---:|---|
| `bedrock_ai_data_exposure` | `BEDROCK.LOG.INVOCATION.001`, `BEDROCK.GUARDRAIL.PII.001`, `BEDROCK.LOG.ENCRYPT.001` | 2 | critical |
| `sagemaker_notebook_exposure` | `SAGEMAKER.NOTEBOOK.INTERNET.001`, `NOTEBOOK.ROOT.001`, `NOTEBOOK.ENCRYPT.001` | 2 | critical |
| `sagemaker_training_data_exposure` | training-encryption + training-VPC + training-isolation members | 2 | (read chain file for details) |

These are useful **starting points**: the data-exposure and
notebook-exposure chains compose perimeter signals, not
identity-overprivilege signals. None of the existing chains compose
across services (Bedrock-agent → Lambda → S3, SageMaker-pipeline →
production-endpoint, etc.). That's the cross-service compound gap.

### Adjacent service coverage (already shipped, not AI-specific)

| Service | Controls | AI-pipeline relevance |
|---|---:|---|
| Step Functions | 113 | High — orchestrates ML pipelines (training → eval → deploy). Existing controls mostly cover ASL hardening, not AI-specific identity flows. |
| Lambda | 56 | High — Bedrock agents invoke Lambdas, SageMaker training calls Lambda preprocessors. Existing controls cover env-secrets, layer secrets, broken refs, ghosts. |
| CodeBuild | 12 | Medium — ML CI/CD pipelines. Existing controls cover role hygiene, public projects, secrets, source. |
| CodePipeline | 0 | **Gap** — no controls. ML model promotion paths run through CodePipeline. |
| ECS | 48 | Medium — covered by `examples/ecs-ssrf-credential-theft/`. Same pattern applies to ML inference containers. |
| EKS | many | Medium — same pattern as ECS for K8s-hosted ML. |

## Observation schema status

### What ships today

**SageMaker** (4 asset types, all under `properties.compute`):

- `aws_sagemaker_notebook` (kind: `sagemaker_notebook`)
- `aws_sagemaker_endpoint_config` (kind: `sagemaker_endpoint_config`)
- `aws_sagemaker_model` (kind: `sagemaker_model`)
- `aws_sagemaker_training_job` (kind: `sagemaker_training`)

Property paths in use: `compute.access.root_access_enabled`,
`compute.encryption.{volume,inter_container}_encrypted`,
`compute.network.{direct_internet_access,in_vpc,network_isolation_enabled}`,
`compute.resilience.multi_instance`.

**Bedrock** (5 asset types, all under `properties.ai`):

- `aws_bedrock_access` (kind: `bedrock_access`)
- `aws_bedrock_agent` (kind: `bedrock_agent`)
- `aws_bedrock_guardrail` (kind: `bedrock_guardrail`)
- `aws_bedrock_logging_config` (kind: `bedrock_logging_config`)
- `aws_bedrock_vpc_config` (kind: `bedrock_vpc_config`)

Property paths in use: `ai.access.{has_admin_privileges, has_full_access_policy, is_long_lived}`,
`ai.agent.guardrail_associated`,
`ai.guardrail.{prompt_attack_filter_high, sensitive_info_filter_enabled}`,
`ai.logging.{encryption_enabled, invocation_logging_enabled}`,
`ai.network.vpc_endpoints_configured`.

### Schema gaps

| Asset type | Use case | Proposed kind | Status |
|---|---|---|---|
| `aws_bedrock_knowledge_base` | RAG data-boundary | `bedrock_knowledge_base` | **Missing** — RAG data-boundary checks need `ai.knowledge_base.data_sources[]` |
| `aws_bedrock_model_access` | Agent role overprivilege | `bedrock_model_access` | **Partial** — `aws_bedrock_access` covers IAM policies; need `ai.model_access.allowed_models[]` for model-allowlist checks |
| `aws_sagemaker_endpoint` | Public inference endpoint | `sagemaker_endpoint` | **Partial** — only `endpoint_config` present; need the deployed endpoint with public-accessibility flag |
| `aws_sagemaker_pipeline` | CI/CD ML cross-service compound | `sagemaker_pipeline` | **Missing** — promotion-path checks need pipeline → role → endpoint linkage |
| `aws_codepipeline_pipeline` | ML model promotion | `codepipeline_pipeline` | **Missing** — no CodePipeline observations or controls today |

Closing these gaps requires adding the missing kinds + property paths to
the obs.v0.1 schema — or reusing existing kinds where possible (e.g.
`bedrock_model_access` may slot under `aws_bedrock_access` with an additional
`ai.model_access.*` block rather than a new asset type).

## Failure taxonomy

### Category A — Agent role overprivilege

Failure modes where an AI service's identity has broader access than
the workload requires. Equivalent to NHI5 ("Overprivileged NHI") from
the OWASP NHI Top 10 mapping.

| # | Failure mode | Example | Service |
|---|---|---|---|
| A1 | Bedrock agent has broad `lambda:InvokeFunction` on `Resource: *` | Agent can invoke any Lambda, not just its tool list | Bedrock |
| A2 | Bedrock agent role has unrestricted `bedrock:InvokeModel` on `*` | Agent can invoke any foundation model, ignoring the model allowlist | Bedrock |
| A3 | Bedrock knowledge base role has `s3:GetObject` on `Resource: *` | Knowledge base indexes data beyond its intended scope | Bedrock |
| A4 | SageMaker training role has `s3:*` on `*` | Training job reads any bucket including non-training data | SageMaker |
| A5 | SageMaker notebook role has `iam:PassRole` for production roles | Researcher's notebook can assume production identities | SageMaker |
| A6 | SageMaker endpoint deployment role has `kms:Decrypt` on customer KMS keys | Inference endpoint can decrypt customer secrets | SageMaker |
| A7 | Step Functions ML pipeline role has `iam:PassRole *` | Orchestration can pass arbitrary roles to AI tasks | Step Functions |
| A8 | CodeBuild ML pipeline role has `sagemaker:CreateEndpoint` + `iam:PassRole` | Build can deploy adversarial models to production endpoints | CodeBuild |

### Category B — Agent lifecycle and governance

Failure modes around stale, unmonitored, or shadow AI identities.
Equivalent to NHI1 ("Improper Offboarding") + NHI8 ("Insufficient
Logging") from the OWASP NHI mapping.

| # | Failure mode | Example | Service |
|---|---|---|---|
| B1 | Bedrock agent invocations not logged to CloudTrail | Agent actions are unaudited | Bedrock |
| B2 | Bedrock agent → deleted Lambda (ghost reference) | Agent's tool list points to a Lambda that no longer exists | Bedrock |
| B3 | SageMaker endpoint has no model-monitoring schedule | Deployed model drifts or is replaced without detection | SageMaker |
| B4 | SageMaker notebook has not been used in 90+ days | Stale researcher credentials with broad access | SageMaker |
| B5 | Bedrock API key has no rotation policy | Long-lived agent credentials | Bedrock |
| B6 | Shadow Bedrock agent — created outside IaC | Ungoverned agent with unknown permissions; no Terraform manages it | Bedrock |
| B7 | SageMaker training job ran 90+ days ago and role still active | Orphaned training role retains permissions long after the job finished | SageMaker |
| B8 | Bedrock guardrail attached to no agent (orphan) | Guardrail definition exists but isn't enforced anywhere | Bedrock |

### Category C — Data boundary violations

Failure modes where AI services cross data-classification or tenancy
boundaries. Equivalent to NHI6 ("Insecure Cloud Deployment") + the S3
PHI marker pattern already used in `s3-tenant-prefix-isolation`.

| # | Failure mode | Example | Service |
|---|---|---|---|
| C1 | Bedrock knowledge base reads PHI-tagged S3 without HIPAA controls | Chatbot returns patient data via RAG retrieval | Bedrock |
| C2 | SageMaker training job reads cross-account S3 unencrypted | Training data crosses account boundary in plaintext | SageMaker |
| C3 | SageMaker public inference endpoint accepts unauthenticated invocation | Anyone on the internet can query the model | SageMaker |
| C4 | Bedrock agent invocation flows through Lambda that writes to non-tenant S3 prefix | Agent output crosses tenant boundary | Bedrock |
| C5 | SageMaker model artifact bucket is public-read | Anyone can download the trained model and inspect weights | SageMaker |
| C6 | Bedrock invocation logs include raw prompts containing PHI | Logs become a PHI surface | Bedrock |

### Category D — Cross-service AI compound chains

Multi-asset compound chains where individual findings are mid-severity
but the composition is critical. Same shape as the existing
`cognito_unauth_phi_s3` and `ecs_ssrf_credential_theft` chains.

| # | Chain | Members (proposed) | Asset compose |
|---|---|---|---|
| D1 | `bedrock_agent_data_exfiltration` | A1 (broad lambda invoke) + B2 (ghost lambda) + C4 (cross-tenant write) | scope_field on agent ARN |
| D2 | `sagemaker_notebook_to_production` | A5 (PassRole production) + S3.MARKER.PHI + iam-trust-condition gap | asset.ID + S3 marker |
| D3 | `bedrock_rag_phi_exposure` | C1 (KB reads PHI) + B1 (no logging) + missing-PII-filter | asset.ID on knowledge base |
| D4 | `sagemaker_pipeline_adversarial_deploy` | A8 (CodeBuild deploys models) + missing-approval-gate + endpoint-public | scope_field on pipeline |
| D5 | `bedrock_agent_overpermissioned_chain` | A1 + A2 + B5 (long-lived key) | asset.ID on agent |
| D6 | `sagemaker_training_data_leak_chain` | A4 (s3:* training role) + C2 (cross-account unencrypted) + missing-VPC | asset.ID on training job |
