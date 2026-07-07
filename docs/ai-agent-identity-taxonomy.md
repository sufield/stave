# AI Agent Identity Controls — Taxonomy + Coverage Audit

This document is the failure taxonomy and coverage audit for AI-agent-identity
controls. It maps the AI-agent identity failure modes, audits what Stave covers
today, and identifies observation-schema gaps.

| | |
|---|---|
| Audit date | 2026-07-07 |
| Catalog version | 2898 controls, 622 chains |
| Scope | AWS only — Azure / GCP / Anthropic API not yet covered |

## TL;DR

- **AI coverage:** 40 SageMaker + 57 Bedrock (incl. AgentCore) + 12 CodeBuild controls; 12 AI-relevant compound chains covering agent overprivilege, data exfiltration, RAG PHI exposure, notebook production escape, training data leaks, and pipeline adversarial deployment.
- **Identity-shaped coverage is strong:** agent role overprivilege (Lambda, S3, model scope), ghost references (Lambda, knowledge base, model), lifecycle (stale agents, idle notebooks, orphan guardrails, shadow agents), cross-account access, PassRole abuse, and AssumeRole scope are all covered.
- **Observation schema covers SageMaker (4 asset types) and Bedrock (5 asset types).** The shipped schema does NOT carry `aws_bedrock_knowledge_base` or `aws_bedrock_model_access` as standalone asset types; KB properties are surfaced via `aws_bedrock_agent` and dedicated KB controls.
- **All six compound chains from the original taxonomy (D1–D6) are now authored**, plus six additional chains not in the original proposal.

## Coverage audit

### SageMaker (40 controls, 6 chains)

| Control | Severity | Identity-shaped? | Notes |
|---|---|---|---|
| `CTL.SAGEMAKER.DOMAIN.AUTH.001` | high | **Yes** | Domain authentication mode |
| `CTL.SAGEMAKER.DOMAIN.SHAREDROLE.001` | high | **Yes** | Shared execution role anti-pattern |
| `CTL.SAGEMAKER.ENDPOINT.DATACAPTURE.001` | medium | Audit | Data capture for monitoring |
| `CTL.SAGEMAKER.ENDPOINT.ENCRYPT.001` | high | No | Encryption-at-rest |
| `CTL.SAGEMAKER.ENDPOINT.ISOLATION.001` | high | No | Network isolation |
| `CTL.SAGEMAKER.ENDPOINT.MONITOR.001` | medium | Audit | Model monitoring schedule |
| `CTL.SAGEMAKER.ENDPOINT.OVERPERM.S3.001` | high | **Yes** | Endpoint role overbroad S3 |
| `CTL.SAGEMAKER.ENDPOINT.REDUNDANCY.001` | medium | No | Resilience |
| `CTL.SAGEMAKER.ENDPOINT.STALE.001` | medium | **Yes** | Stale endpoint lifecycle |
| `CTL.SAGEMAKER.ENDPOINT.VPC.001` | high | No | Network |
| `CTL.SAGEMAKER.GHOST.MODEL.001` | high | **Yes** | Ghost model reference |
| `CTL.SAGEMAKER.MODEL.ISOLATION.001` | high | No | Network isolation |
| `CTL.SAGEMAKER.MODEL.VPC.001` | medium | No | Network |
| `CTL.SAGEMAKER.NOTEBOOK.ASSUMEROLE.001` | high | **Yes** | Unscoped AssumeRole |
| `CTL.SAGEMAKER.NOTEBOOK.ENCRYPT.001` | high | No | Encryption-at-rest |
| `CTL.SAGEMAKER.NOTEBOOK.IDLE.001` | medium | **Yes** | Idle notebook lifecycle |
| `CTL.SAGEMAKER.NOTEBOOK.IMDS.001` | medium | **Yes** | IMDSv2 enforcement |
| `CTL.SAGEMAKER.NOTEBOOK.INTERNET.001` | high | No | Network — used in chain |
| `CTL.SAGEMAKER.NOTEBOOK.LIFECYCLE.001` | medium | **Yes** | Missing lifecycle config |
| `CTL.SAGEMAKER.NOTEBOOK.OVERPERM.ADMIN.001` | high | **Yes** | Notebook admin privilege |
| `CTL.SAGEMAKER.NOTEBOOK.OVERPERM.PASSROLE.001` | high | **Yes** | Notebook PassRole scope |
| `CTL.SAGEMAKER.NOTEBOOK.OVERPERM.S3.001` | high | **Yes** | Notebook overbroad S3 |
| `CTL.SAGEMAKER.NOTEBOOK.ROOT.001` | medium | **Yes** | Root-on-notebook = identity privilege |
| `CTL.SAGEMAKER.NOTEBOOK.VPC.001` | high | No | Network |
| `CTL.SAGEMAKER.TRAINING.DATA.CROSSACCOUNT.001` | high | **Yes** | Cross-account training data |
| `CTL.SAGEMAKER.TRAINING.DATA.UNENCRYPTED.001` | high | No | Unencrypted training data |
| `CTL.SAGEMAKER.TRAINING.ENCRYPT.INTERCONTAINER.001` | medium | No | Encryption |
| `CTL.SAGEMAKER.TRAINING.ENCRYPT.VOLUME.001` | high | No | Encryption |
| `CTL.SAGEMAKER.TRAINING.ISOLATION.001` | high | No | Network |
| `CTL.SAGEMAKER.TRAINING.LOGGING.001` | medium | Audit | Training job logging |
| `CTL.SAGEMAKER.TRAINING.OVERPERM.PASSROLE.001` | high | **Yes** | Training PassRole scope |
| `CTL.SAGEMAKER.TRAINING.OVERPERM.S3.001` | high | **Yes** | Training overbroad S3 |
| `CTL.SAGEMAKER.TRAINING.VPC.001` | high | No | Network |

(8 remaining controls omitted — encryption, monitoring, domain-level checks)

**Identity-shaped count: 17 of 40.** Major expansion from the original 1-of-11:
execution-role permissions, PassRole/AssumeRole scope, cross-account access,
ghost references, stale lifecycle, and admin privilege are now covered.

### Bedrock (57 controls incl. AgentCore, 6 chains)

| Control | Severity | Identity-shaped? | Notes |
|---|---|---|---|
| `CTL.BEDROCK.ACCESS.ADMIN.001` | high | **Yes** | API key admin privilege |
| `CTL.BEDROCK.ACCESS.FULLACCESS.001` | high | **Yes** | AmazonBedrockFullAccess attached |
| `CTL.BEDROCK.ACCESS.LONGTERM.001` | high | **Yes** | Long-lived API key |
| `CTL.BEDROCK.ACCESS.MODELSCOPE.001` | high | **Yes** | Model allowlist enforcement |
| `CTL.BEDROCK.AGENT.ACTIONGROUPS.SPRAWL.001` | medium | **Yes** | Action group sprawl |
| `CTL.BEDROCK.AGENT.CROSSACCOUNT.001` | high | **Yes** | Cross-account agent access |
| `CTL.BEDROCK.AGENT.GHOST.LAMBDA.001` | high | **Yes** | Ghost Lambda reference |
| `CTL.BEDROCK.AGENT.GUARDRAIL.001` | high | **Yes** | Agent ↔ guardrail association |
| `CTL.BEDROCK.AGENT.LOGGING.001` | medium | Audit | Per-agent invocation logging |
| `CTL.BEDROCK.AGENT.OVERPERM.LAMBDA.001` | high | **Yes** | Broad lambda:InvokeFunction |
| `CTL.BEDROCK.AGENT.OVERPERM.MODEL.001` | high | **Yes** | Broad bedrock:InvokeModel |
| `CTL.BEDROCK.AGENT.OVERPERM.S3.001` | high | **Yes** | Overbroad S3 write |
| `CTL.BEDROCK.AGENT.PUBLIC.INVOCATION.001` | high | **Yes** | Public invocation endpoint |
| `CTL.BEDROCK.AGENT.SESSION.TTL.001` | medium | **Yes** | Session TTL governance |
| `CTL.BEDROCK.AGENT.SHADOW.001` | high | **Yes** | Shadow agent (outside IaC) |
| `CTL.BEDROCK.AGENT.STALE.001` | medium | **Yes** | Stale agent lifecycle |
| `CTL.BEDROCK.AGENT.TOOLACCESS.BROAD.001` | high | **Yes** | Broad tool access scope |
| `CTL.BEDROCK.GHOST.KNOWLEDGEBASE.001` | high | **Yes** | Ghost knowledge base |
| `CTL.BEDROCK.KB.DATASOURCE.CROSSACCOUNT.001` | high | **Yes** | KB cross-account data source |
| `CTL.BEDROCK.KB.DATASOURCE.UNENCRYPTED.001` | high | No | KB unencrypted data source |
| `CTL.BEDROCK.KB.MARKER.INDEXES.001` | medium | Data | KB indexes marker |
| `CTL.BEDROCK.KB.OVERPERM.S3.001` | high | **Yes** | KB overbroad S3 read |
| `CTL.BEDROCK.KB.RETRIEVAL.OVERBROAD.001` | high | **Yes** | KB retrieval scope too broad |
| `CTL.BEDROCK.KB.RETRIEVAL.SCOPE.001` | medium | **Yes** | KB retrieval scope config |

(33 remaining controls omitted — AgentCore, guardrails, logging, encryption, VPC, custom models)

**Identity-shaped count: 22 of 57.** Major expansion from the original 4-of-9:
agent role overprivilege (Lambda, S3, model), ghost references, lifecycle
(stale, shadow, session TTL), cross-account, tool-access scope, knowledge-base
data boundaries, and public invocation are now covered.

### Compound chains — all 6 original proposals + 6 additional

| Chain | Members | Threshold | Severity | Status |
|---|---|---:|---|---|
| `bedrock_ai_data_exposure` | LOG.INVOCATION + GUARDRAIL.PII + LOG.ENCRYPT | 2 | critical | Original |
| `bedrock_agent_overpermissioned` | OVERPERM.LAMBDA + GUARDRAIL + LOGGING | 3 | critical | D5 |
| `bedrock_agent_data_exfiltration` | OVERPERM.LAMBDA + GHOST.LAMBDA + OVERPERM.S3 | 3 | critical | **D1 — new** |
| `bedrock_rag_phi_exposure` | KB.MARKER.INDEXES + S3.MARKER.PHI | 2 | critical | D3 |
| `bedrock_agent_tool_phi_exposure` | TOOLACCESS.BROAD + KB.MARKER.INDEXES + S3.MARKER.PHI | 2 | critical | Additional |
| `sagemaker_notebook_exposure` | INTERNET + ROOT + ENCRYPT | 2 | critical | Original |
| `sagemaker_notebook_production_escape` | ASSUMEROLE + IAM.MARKER.PRODUCTION | 2 | high | Additional |
| `sagemaker_notebook_to_production` | OVERPERM.PASSROLE + INTERNET + ROOT | 3 | critical | **D2 — new** |
| `sagemaker_training_data_exposure` | ENCRYPT.VOLUME + ENCRYPT.INTERCONTAINER + ISOLATION | 2 | critical | Original |
| `sagemaker_training_role_overprivileged` | OVERPERM.S3 + OVERPERM.PASSROLE + LOGGING | 2 | critical | Additional |
| `sagemaker_pipeline_adversarial_deploy` | CODEBUILD.ROLE + ENDPOINT.ISOLATION + ENDPOINT.MONITOR | 3 | critical | **D4 — new** |
| `sagemaker_training_data_leak` | OVERPERM.S3 + DATA.CROSSACCOUNT + VPC | 3 | critical | **D6 — new** |

### Adjacent service coverage

| Service | Controls | AI-pipeline relevance |
|---|---:|---|
| Step Functions | 113 | High — orchestrates ML pipelines |
| Lambda | 56 | High — Bedrock agents invoke Lambdas |
| CodeBuild | 12 | Medium — ML CI/CD pipelines; `ROLE.001` used in D4 chain |
| ECS | 48 | Medium — ML inference containers |
| EKS | many | Medium — K8s-hosted ML |

## Observation schema status

### What ships today

**SageMaker** (4 asset types, all under `properties.compute`):

- `aws_sagemaker_notebook` (kind: `sagemaker_notebook`)
- `aws_sagemaker_endpoint_config` (kind: `sagemaker_endpoint_config`)
- `aws_sagemaker_model` (kind: `sagemaker_model`)
- `aws_sagemaker_training_job` (kind: `sagemaker_training`)

**Bedrock** (5 asset types, all under `properties.ai`):

- `aws_bedrock_access` (kind: `bedrock_access`)
- `aws_bedrock_agent` (kind: `bedrock_agent`)
- `aws_bedrock_guardrail` (kind: `bedrock_guardrail`)
- `aws_bedrock_logging_config` (kind: `bedrock_logging_config`)
- `aws_bedrock_vpc_config` (kind: `bedrock_vpc_config`)

### Remaining schema gaps

| Asset type | Use case | Status |
|---|---|---|
| `aws_sagemaker_endpoint` | Deployed endpoint (distinct from config) | **Partial** — controls use config; endpoint-level public-accessibility not yet surfaced |
| `aws_sagemaker_pipeline` | CI/CD ML promotion path | **Missing** — D4 chain uses CodeBuild as proxy |

## Failure taxonomy

### Category A — Agent role overprivilege

| # | Failure mode | Service | Coverage |
|---|---|---|---|
| A1 | Broad `lambda:InvokeFunction` on `*` | Bedrock | `CTL.BEDROCK.AGENT.OVERPERM.LAMBDA.001` |
| A2 | Unrestricted `bedrock:InvokeModel` on `*` | Bedrock | `CTL.BEDROCK.AGENT.OVERPERM.MODEL.001` |
| A3 | KB role has `s3:GetObject` on `*` | Bedrock | `CTL.BEDROCK.KB.OVERPERM.S3.001` |
| A4 | Training role has `s3:*` on `*` | SageMaker | `CTL.SAGEMAKER.TRAINING.OVERPERM.S3.001` |
| A5 | Notebook role has `iam:PassRole` for production | SageMaker | `CTL.SAGEMAKER.NOTEBOOK.OVERPERM.PASSROLE.001` |
| A6 | Endpoint role has broad `kms:Decrypt` | SageMaker | `CTL.SAGEMAKER.ENDPOINT.OVERPERM.S3.001` (S3 axis) |
| A7 | Step Functions ML pipeline has `iam:PassRole *` | Step Functions | Covered by StepFunctions controls |
| A8 | CodeBuild has `sagemaker:CreateEndpoint` + `iam:PassRole` | CodeBuild | `CTL.CODEBUILD.ROLE.001` |

### Category B — Agent lifecycle and governance

| # | Failure mode | Service | Coverage |
|---|---|---|---|
| B1 | Agent invocations not logged | Bedrock | `CTL.BEDROCK.AGENT.LOGGING.001` |
| B2 | Agent → deleted Lambda (ghost) | Bedrock | `CTL.BEDROCK.AGENT.GHOST.LAMBDA.001` |
| B3 | Endpoint has no monitoring schedule | SageMaker | `CTL.SAGEMAKER.ENDPOINT.MONITOR.001` |
| B4 | Notebook idle 90+ days | SageMaker | `CTL.SAGEMAKER.NOTEBOOK.IDLE.001` |
| B5 | API key has no rotation | Bedrock | `CTL.BEDROCK.ACCESS.LONGTERM.001` |
| B6 | Shadow agent (outside IaC) | Bedrock | `CTL.BEDROCK.AGENT.SHADOW.001` |
| B7 | Training role active after job finished | SageMaker | `CTL.SAGEMAKER.ENDPOINT.STALE.001` (lifecycle pattern) |
| B8 | Orphan guardrail (attached to no agent) | Bedrock | `CTL.BEDROCK.AGENT.GUARDRAIL.001` (inverse) |

### Category C — Data boundary violations

| # | Failure mode | Service | Coverage |
|---|---|---|---|
| C1 | KB reads PHI-tagged S3 | Bedrock | `CTL.BEDROCK.KB.MARKER.INDEXES.001` + chain `bedrock_rag_phi_exposure` |
| C2 | Training reads cross-account S3 unencrypted | SageMaker | `CTL.SAGEMAKER.TRAINING.DATA.CROSSACCOUNT.001` + `DATA.UNENCRYPTED.001` |
| C3 | Public inference endpoint | SageMaker | `CTL.SAGEMAKER.ENDPOINT.ISOLATION.001` |
| C4 | Agent output crosses tenant boundary | Bedrock | `CTL.BEDROCK.AGENT.OVERPERM.S3.001` |
| C5 | Model artifact bucket is public-read | SageMaker | Covered by S3 public-access controls |
| C6 | Invocation logs include raw PHI | Bedrock | `CTL.BEDROCK.LOG.CONTENT.001` |

### Category D — Cross-service AI compound chains

| # | Chain | Members | Status |
|---|---|---|---|
| D1 | `bedrock_agent_data_exfiltration` | A1 + B2 + C4 | **Shipped** |
| D2 | `sagemaker_notebook_to_production` | A5 + notebook-internet + notebook-root | **Shipped** |
| D3 | `bedrock_rag_phi_exposure` | C1 + S3.MARKER.PHI | **Shipped** |
| D4 | `sagemaker_pipeline_adversarial_deploy` | A8 + endpoint-isolation + endpoint-monitor | **Shipped** |
| D5 | `bedrock_agent_overpermissioned` | A1 + guardrail + logging | **Shipped** |
| D6 | `sagemaker_training_data_leak` | A4 + C2 + training-VPC | **Shipped** |
