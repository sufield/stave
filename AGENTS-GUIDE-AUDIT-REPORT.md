# Infrastructure Agents Guide — Stave Control Catalog Audit

**Source**: [Cloudgeni Infrastructure Agents Guide](https://github.com/cloudgeni/infrastructure-agents-guide) (13 chapters)
**Catalog**: Stave control catalog (4078 controls, 616 chains)
**Date**: 2026-07-02

## Methodology

Extracted 36 AWS configuration properties from the guide's 13 chapters,
grouped into 5 categories. Searched the Stave control catalog and chain
definitions for each property. Classified as:

| Rating | Meaning |
|--------|---------|
| COVERED | One or more controls directly evaluate this property |
| PARTIAL | Controls exist but don't cover the full scope described in the guide |
| GAP | No controls address this property (and it's evaluable from snapshots) |
| OUT_OF_SCOPE | Property is ephemeral/runtime — not evaluable from config snapshots |

---

## Summary

| Classification | Count | % |
|----------------|-------|---|
| COVERED | 33 | 92% |
| PARTIAL | 2 | 5% |
| GAP | 0 | 0% |
| OUT_OF_SCOPE | 1 | 3% |
| **Total** | **36** | |

**Compound chains**: 25+ chains cover agent-relevant attack paths across
credential theft, privilege escalation, supply chain compromise, and
container escape scenarios.

---

## Category 1: Credential Management (Guide Ch 5)

| # | Property | Status | Controls |
|---|----------|--------|----------|
| 1 | MaxSessionDuration | COVERED | `CTL.IAM.SESSION.DURATION.001`, `CTL.IAM.FEDERATION.SESSION.DURATION.001`, `CTL.IAM.SSO.PERMSET.SESSION.001`, `CTL.IAM.TRUST.SESSION.001` |
| 2 | No long-lived access keys | COVERED | `CTL.IAM.CRED.TTL.EXCEEDED.001`, `CTL.IAM.CRED.SETUPKEY.001`, `CTL.IAM.CRED.SINGLEKEY.001`, `CTL.IAM.CRED.UNUSED45.001`, `CTL.IAM.CRED.UNUSED.001`, `CTL.IAM.ROOT.ACCESSKEY.001`, `CTL.IAM.AGENT.LONGLIVEDKEYS.001` |
| 3 | Secrets in env vars / userdata | COVERED | `CTL.EC2.USERDATA.CREDS.001`, `CTL.EC2.USERDATA.SECRETS.001`, `CTL.ECS.TASKDEF.SECRET.BROKEN.REF.001`, `CTL.LAMBDA.LAYER.SECRETS.001`, `CTL.LAMBDA.MICROVM.SNAPSHOTSECRET.001`, `CTL.K8S.SECRETS.PLAINTEXT.001` |
| 4 | Credential rotation | COVERED | `CTL.IAM.CRED.ROTATION.001`, `CTL.IAM.CRED.EXPIRY.001`, `CTL.IAM.PASSWORD.ROTATION.001`, `CTL.EKS.SECRETS.ROTATION.001`, `CTL.COGNITO.OIDC.SECRETROT.001` |
| 5 | SourceIdentity | COVERED | `CTL.IAM.SESSION.SOURCE.001` |
| 6 | ExternalId / confused deputy | COVERED | `CTL.IAM.TRUST.CONFUSEDDEPUTY.001`, `CTL.IAM.SCP.CONFUSEDDEPUTY.001`, `CTL.S3.PERIMETER.CONFUSEDDEPUTY.001`, `CTL.IAM.TRUST.EXTERNALID.001`, `CTL.LAMBDA.TRIGGER.CONFUSEDDEPUTY.001` |
| 7 | Shared credentials / blast radius | COVERED | `CTL.IAM.IDENTITY.BLASTRADIUS.002`, chain: `identity_blast_radius` |
| 8 | Secrets Manager / SSM encryption | COVERED | `CTL.SSM.SECURETYPE.001`, `CTL.SSM.DOCUMENT.SECRETS.001`, `CTL.EKS.SECRETS.ENCRYPT.001`, `CTL.GLUE.JOB.SECRETS.001`, `CTL.ECS.TASKDEF.SSM.INSECURE.001` |
| 9 | Least privilege / overpermission | COVERED | `CTL.BEDROCK.ACCESS.ADMIN.001`, `CTL.BEDROCK.ACCESS.FULLACCESS.001`, `CTL.BEDROCK.AGENT.OVERPERM.LAMBDA.001`, `CTL.BEDROCK.AGENT.OVERPERM.S3.001`, `CTL.BEDROCK.AGENT.OVERPERM.MODEL.001`, `CTL.IAM.SCP.FULLACCESS.001` + escalation controls |
| 10 | STS session policy scoping | OUT_OF_SCOPE | Ephemeral API parameter passed during `AssumeRole` — not persisted in config snapshots |

## Category 2: Sandboxing (Guide Ch 4)

| # | Property | Status | Controls |
|---|----------|--------|----------|
| 11 | IMDSv2 enforcement | COVERED | `CTL.EC2.IMDSV2.001`, `CTL.EC2.IMDSV2.002`, `CTL.EKS.NODEGROUP.IMDSV2.001`, `CTL.EKS.NODEGROUP.IMDS.HOPLIMIT.001`, `CTL.SAGEMAKER.NOTEBOOK.IMDS.001`, `CTL.ECS.IMDS.INSTANCEROLE.001`, `CTL.ECS.METADATA.CREDENTIAL.001`, `CTL.EC2.IMDS.HOPLIMIT.001`, `CTL.BATCH.IMDS.JOBACCESS.001` |
| 12 | Container privileged mode | COVERED | `CTL.ECS.PRIV.001`, `CTL.EKS.POD.HOSTACCESS.001`, `CTL.ECS.SECURITY.CAPABILITIES.001`; chain: `ecs_privileged_escape` |
| 13 | Read-only root filesystem | COVERED | `CTL.ECS.TASKDEF.READONLY.001`, `CTL.K8S.KUBELET.READONLY.001` |
| 14 | Container network isolation | COVERED | `CTL.ECS.NETWORK.001`, `CTL.ECS.SERVICE.NETWORKMODE.BRIDGE.001`, `CTL.ECS.SERVICE.SG.LBONLY.001` |
| 15 | Lambda VPC placement | COVERED | `CTL.LAMBDA.VPC.SENSITIVE.001`, `CTL.LAMBDA.VPC.SUBNET.001`, `CTL.LAMBDA.VPC.ENDPOINTS.001`, `CTL.LAMBDA.GHOST.VPC.001`, `CTL.LAMBDA.MICROVM.SUBNET.001` |
| 16 | SageMaker VPC / isolation | COVERED | `CTL.SAGEMAKER.NOTEBOOK.VPC.001`, `CTL.SAGEMAKER.MODEL.VPC.001`, `CTL.SAGEMAKER.ENDPOINT.VPC.001`, `CTL.SAGEMAKER.TRAINING.VPC.001`, `CTL.SAGEMAKER.ENDPOINT.ISOLATION.001`, `CTL.SAGEMAKER.MODEL.ISOLATION.001`, `CTL.SAGEMAKER.TRAINING.ISOLATION.001` |
| 17 | Security groups | COVERED | `CTL.EC2.SG.INGRESS.CIDR.001`, `CTL.EC2.SG.RESTRICTED.PORTS.001`, `CTL.EC2.SG.UNUSED.001`, `CTL.VPC.SG.GHOST.001`, `CTL.ECS.SERVICE.SG.LBONLY.001`, `CTL.REDSHIFT.SG.OPEN.001` |
| 18 | ECS task definition security | COVERED | 50 ECS controls covering privileges, filesystem, network, secrets, identity, scaling, monitoring, health, deployment |
| 19 | EKS pod security | COVERED | 115 EKS controls covering pod security, IRSA, network policy, namespace isolation, CSI, federation, encryption, DR |
| 20 | Lambda code signing | COVERED | `CTL.LAMBDA.CODESIGN.001`, `CTL.LAMBDA.CODESIGN.ENFORCE.001` |

## Category 3: Policy & Guardrails (Guide Ch 8)

| # | Property | Status | Controls |
|---|----------|--------|----------|
| 21 | SCP enforcement | COVERED | `CTL.IAM.SCP.ROOT.001`, `CTL.IAM.SCP.CLOUDTRAIL.001`, `CTL.IAM.SCP.GUARDDUTY.001`, `CTL.IAM.SCP.REGIONS.001`, `CTL.IAM.SCP.LEAVEORG.001`, `CTL.IAM.SCP.CONFIG.001`, `CTL.IAM.SCP.CONFUSEDDEPUTY.001`, `CTL.IAM.SCP.TAGAUTH.ENFORCE.001`, `CTL.GUARDRAIL.IAM.SCP.OU.COVERAGE.001` |
| 22 | RCP enforcement | PARTIAL | Only `CTL.IAM.RCP.TAGAUTH.SESSION.001` (tag auth focus). Missing: broad RCP governance, `s3:ResourceOrgID` enforcement, RCP OU coverage |
| 23 | Permission boundaries | COVERED | `CTL.IAM.BOUNDARY.001`, `CTL.IAM.BOUNDARY.WILDCARD.001`, `CTL.IAM.BOUNDARY.MISSING.001`, `CTL.IAM.BOUNDARY.ESCAPE.001`, `CTL.IAM.NEP.BOUNDARY.001`; chain: `iam_boundary_governance_failure` |
| 24 | Bedrock guardrails | COVERED | `CTL.BEDROCK.GUARDRAIL.PII.001`, `CTL.BEDROCK.GUARDRAIL.PROMPTATTACK.001`, `CTL.BEDROCK.GUARDRAIL.CONTENT.001`, `CTL.BEDROCK.GUARDRAIL.TOPIC.001`, `CTL.BEDROCK.AGENT.GUARDRAIL.001` |
| 25 | Data perimeter condition keys | PARTIAL | `CTL.IAM.POLICY.CONDITION.ORGID.001` covers `aws:PrincipalOrgID`. Missing: `aws:SourceVpc`, `aws:SourceVpce`, `aws:PrincipalOrgPaths` condition checks |
| 26 | Trust policy conditions | COVERED | `CTL.IAM.TRUST.CONFUSEDDEPUTY.001`, `CTL.IAM.TRUST.WILDCARD.001`, `CTL.IAM.TRUST.SOURCEARN.001`, `CTL.IAM.TRUST.ORGBOUNDARY.001`, `CTL.IAM.TRUST.SESSION.001` |

## Category 4: Observability (Guide Ch 9)

| # | Property | Status | Controls |
|---|----------|--------|----------|
| 27 | CloudTrail enabled | COVERED | `CTL.CLOUDTRAIL.ENABLED.001` + 48 total CloudTrail controls |
| 28 | Lambda CloudWatch logging | COVERED | `CTL.LAMBDA.LOG.MISSING.001`, `CTL.LAMBDA.LOG.001`, `CTL.LAMBDA.TRACE.001`, `CTL.LAMBDA.ALARM.ERRORS.001`, `CTL.LAMBDA.ALARM.DURATION.001`, `CTL.LAMBDA.ALARM.THROTTLES.001` |
| 29 | VPC Flow Logs | COVERED | `CTL.VPC.FLOWLOG.001`, `CTL.VPC.FLOWLOG.BIDIRECTIONAL.001`, `CTL.VPC.FLOWLOG.FORMAT.001`, `CTL.VPC.FLOWLOG.SUBNET.001`, `CTL.VPC.FLOWLOG.ENCRYPT.001`, `CTL.VPC.FLOWLOG.STATUS.001`, `CTL.VPC.FLOWLOG.DESTINATION.SECURE.001`, `CTL.VPC.TGW.FLOWLOGS.001` |
| 30 | Bedrock invocation logging | COVERED | `CTL.BEDROCK.LOG.INVOCATION.001`, `CTL.BEDROCK.LOG.ENCRYPT.001`, `CTL.BEDROCK.AGENT.LOGGING.001` |
| 31 | S3 access logging | COVERED | `CTL.S3.LOG.001`, `CTL.S3.LOG.BUCKET.VERSIONING.001`, `CTL.S3.LOG.PREFIX.001`, `CTL.S3.LOG.BUCKET.LOCK.001`, `CTL.S3.LOG.RETENTION.001`, `CTL.S3.LOG.BUCKET.LIFECYCLE.001`, `CTL.S3.LOG.BUCKET.PUBLIC.001` |
| 32 | CloudTrail log integrity | COVERED | `CTL.CLOUDTRAIL.LOG.VALIDATION.001`, `CTL.CLOUDTRAIL.VALIDATION.001`, `CTL.CLOUDTRAIL.INTEGRITY.DIGEST.SAMEBUCKET.001` |

## Category 5: Agent-Specific

| # | Property | Status | Controls |
|---|----------|--------|----------|
| 33 | Bedrock agent overpermission | COVERED | `CTL.BEDROCK.AGENT.OVERPERM.LAMBDA.001`, `CTL.BEDROCK.AGENT.OVERPERM.S3.001`, `CTL.BEDROCK.AGENT.OVERPERM.MODEL.001`, `CTL.BEDROCK.AGENT.CROSSACCOUNT.001`, `CTL.BEDROCK.AGENT.ACTIONGROUPS.SPRAWL.001` + 8 more Bedrock agent controls; chain: `bedrock_agent_overpermissioned` |
| 34 | Lambda execution role scoping | COVERED | `CTL.LAMBDA.MICROVM.EXECROLE.001`, `CTL.LAMBDA.MICROVM.WILDCARD.001`, `CTL.LAMBDA.MICROVM.BUILDROLE.001`, `CTL.LAMBDA.ROLE.SHARED.001`; chains: `lambda_credential_exposure`, `lambda_exfiltration_bridge` |
| 35 | ECS task role scoping | COVERED | `CTL.ECS.EXECROLE.OVERBROAD.001`, `CTL.ECS.GHOST.TASKROLE.001`, `CTL.ECS.IMDS.INSTANCEROLE.001`, `CTL.ECS.TASKMETADATA.001/002`; chains: `ecs_ssrf_credential_theft`, `ecs_exec_uncontrolled` |
| 36 | Cross-account access controls | COVERED | Controls across IAM trust, SQS, OpenSearch, Cognito, EKS, Bedrock, StepFunctions; chain: `identity_blast_radius` |

---

## Compound Chain Coverage

Agent-relevant chains mapped to guide chapters:

| Chain | Guide Chapter | Attack Path |
|-------|---------------|-------------|
| `identity_blast_radius` | Ch 5 (Credentials) | Shared role + broad permissions → lateral movement |
| `lambda_credential_exposure` | Ch 5 (Credentials) | Lambda env → credential leak → persistence |
| `lambda_credential_history` | Ch 5 (Credentials) | Historical credential exposure via CloudTrail gaps |
| `ecs_ssrf_credential_theft` | Ch 4 (Sandboxing) | SSRF → IMDS → task role credential theft |
| `ecs_privileged_escape` | Ch 4 (Sandboxing) | Privileged container → host escape |
| `ecs_exec_uncontrolled` | Ch 4 (Sandboxing) | ECS Exec without audit → interactive shell access |
| `bedrock_agent_overpermissioned` | Ch 8 (Policy) | Agent with broad IAM → unintended actions |
| `bedrock_agent_tool_phi_exposure` | Ch 8 (Policy) | Agent tool leaks PII/PHI |
| `bedrock_rag_phi_exposure` | Ch 8 (Policy) | RAG pipeline exposes sensitive data |
| `iam_boundary_governance_failure` | Ch 8 (Policy) | Missing/weak boundaries → privilege escalation |
| `iam_escalation_undetected` | Ch 9 (Observability) | Privilege escalation without CloudTrail detection |
| `iam_privesc_by_attachment` | Ch 9 (Observability) | Policy attachment → escalation path |
| `lambda_layer_supply_chain_compromise` | Ch 3 (Tools) | Malicious layer → code injection |
| `supply_chain_code_injection` | Ch 3 (Tools) | Supply chain → runtime compromise |
| `ecs_image_supply_chain` | Ch 3 (Tools) | Untrusted container image → compromise |
| `ecs_secret_lifecycle` | Ch 5 (Credentials) | Secret rotation gap → stale credentials |
| `secrets_access_ungoverned` | Ch 5 (Credentials) | Secrets Manager without access governance |
| `lambda_blind_execution` | Ch 9 (Observability) | Lambda running without logging/tracing |

---

## PARTIAL Details and Recommendations

### #22 — RCP Enforcement (PARTIAL)

**Current**: 1 control (`CTL.IAM.RCP.TAGAUTH.SESSION.001`) focused narrowly
on tag-based session authorization.

**Guide recommends**: Resource control policies as a complement to SCPs for
data perimeter enforcement — resource-side "who can access this" vs. identity-side
"what can this identity do".

**Recommendations** (report only — no implementation):

1. `CTL.IAM.RCP.OU.COVERAGE.001` — RCP attached to all OUs (mirrors SCP
   OU coverage pattern)
2. `CTL.IAM.RCP.S3.ORGID.001` — S3 RCP enforces `s3:ResourceOrgID`
   condition to prevent cross-org data access
3. `CTL.IAM.RCP.DENY.EXTERNAL.001` — RCP denies access from principals
   outside the organization

### #25 — Data Perimeter Condition Keys (PARTIAL)

**Current**: `CTL.IAM.POLICY.CONDITION.ORGID.001` checks for
`aws:PrincipalOrgID`. No controls for VPC-based conditions.

**Guide recommends**: Full data perimeter using `aws:SourceVpc`,
`aws:SourceVpce`, and `aws:PrincipalOrgPaths` to restrict access to within
the network and organization hierarchy.

**Recommendations** (report only — no implementation):

1. `CTL.IAM.POLICY.CONDITION.SOURCEVPC.001` — S3/SQS/SNS bucket policies
   include `aws:SourceVpc` or `aws:SourceVpce` conditions
2. `CTL.IAM.POLICY.CONDITION.ORGPATH.001` — Trust policies use
   `aws:PrincipalOrgPaths` for hierarchical org restrictions

---

## Guide Chapters vs. Stave Scope

Several guide chapters cover concerns that are outside Stave's evaluation
scope (runtime behavior, not AWS configuration state):

| Guide Chapter | Stave Scope | Notes |
|---------------|-------------|-------|
| Ch 1 (Architecture) | OUT_OF_SCOPE | System design patterns |
| Ch 2 (Agent Runtime) | OUT_OF_SCOPE | Queue management, worker pools, session persistence |
| Ch 3 (Tools & Skills) | PARTIAL | Supply chain controls exist; skill allow-lists are app-level |
| Ch 4 (Sandboxing) | COVERED | Strong overlap — IMDSv2, containers, VPC, code signing |
| Ch 5 (Credentials) | COVERED | Deep coverage — session limits, rotation, blast radius |
| Ch 6 (Data Plane) | PARTIAL | Encryption-at-rest/transit covered; data classification is app-level |
| Ch 7 (Change Control) | OUT_OF_SCOPE | PR validation, CI/CD pipelines |
| Ch 8 (Policy) | COVERED | SCPs, RCPs (partial), boundaries, Bedrock guardrails |
| Ch 9 (Observability) | COVERED | CloudTrail, VPC Flow Logs, Bedrock/Lambda/S3 logging |
| Ch 10 (Autonomy) | OUT_OF_SCOPE | Notifications, stuck-run detection |
| Ch 11 (Testing) | OUT_OF_SCOPE | Trajectory tests, adversarial tests |
| Ch 12 (UX) | OUT_OF_SCOPE | User experience concerns |
| Ch 13 (Risk Framework) | OUT_OF_SCOPE | Decision matrices, compliance mapping |

---

## Conclusion

The Stave control catalog covers **92% (33/36)** of AWS configuration
properties recommended by the Infrastructure Agents Guide. The 2 PARTIAL
items (RCP enforcement, data perimeter condition keys) represent narrower
coverage rather than missing capability — controls exist but don't cover
the full scope the guide describes.

**No gaps exist** in evaluable AWS configuration properties. The 1
OUT_OF_SCOPE item (STS session policy) is an ephemeral API parameter not
present in config snapshots.

Notable Stave advantages beyond the guide's scope:
- **Ghost resource detection** — orphaned VPCs, task roles, Lambda triggers
- **Supply chain controls** — image provenance, layer compromise, code signing
- **Lifecycle controls** — dormant functions, stale agents, unused credentials
- **Compound attack chains** — 25+ chains model multi-step agent compromise paths
