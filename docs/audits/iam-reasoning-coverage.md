# IAM Permission Reasoning Coverage Audit

Systematic verification of 7 areas of IAM permission reasoning
against the Stave control catalog (740 controls, 47 domains).

**Method**: Every coverage claim verified against actual control
YAML predicates. Every gap claim verified against observation
schema and engine capabilities.

## Summary

- **7 areas analyzed**, 5 claimed to have gaps
- **3 areas fully covered** (trust analysis, instance profile core, escalation core)
- **4 areas have real gaps** (policy evaluation, attachment graph, escalation edge cases, resource policies)
- **2 claimed gaps were false** (inline policy hygiene exists; effective permissions covered by NEP namespace)
- **13 verified gaps** classified: 8 Gap A, 2 Gap B, 0 Gap C, 3 Gap E
- **Priority 1 CLOSED** (4 gaps): Rhino parity (20/21, up from 18/21) + SQS/SNS resource policies
- **KMS resource policies CLOSED** (4 controls): cross-account, admin-broad, conditions, pending deletion
- **Priority 2+3 Gap A CLOSED** (5 controls): EC2 shared profile, instance profile escalation, inline on roles, Secrets Manager policy, resource wildcard

## Coverage by Area

### Area 1: IAM Policy Parser and Evaluator

**Existing coverage**: 14 controls in `iam/policy/` + 2 shadow policy controls.

| Control ID | What It Checks |
|---|---|
| CTL.IAM.POLICY.ADMIN.001 | `identity.policies.has_admin_access` — Allow + Action:\* + Resource:\* |
| CTL.IAM.POLICY.PASSROLE.001 | `identity.policies.passrole_unrestricted` — PassRole on Resource:\* |
| CTL.IAM.POLICY.PASSROLE.CONDITION.001 | `identity.policies.passrole_has_service_condition` — PassRole without iam:PassedToService |
| CTL.IAM.POLICY.ASSUMEROLE.001 | `identity.policies.assumerole_unrestricted` — AssumeRole on Resource:\* |
| CTL.IAM.POLICY.SERVICEWILDCARD.001 | `identity.policies.service_wildcards_granted` — `<service>:*` on sensitive services |
| CTL.IAM.POLICY.MFA.001 | `identity.policy.mfa_required_on_destructive_actions` — missing MFA condition |
| CTL.IAM.POLICY.ESCALATION.001 | `identity.policies.has_self_modify` — self-modification capability |
| CTL.IAM.POLICY.SHADOW.001 | `identity.policies.has_not_action` — NotAction construct |
| CTL.IAM.POLICY.SHADOW.002 | `identity.policies.permits_iam_write_via_negative` — negative logic IAM write |
| CTL.IAM.POLICY.SOD.001 | `identity.policies.has_data_and_iam_access` — separation of duties |
| CTL.IAM.POLICY.COMPLEXITY.001 | `identity.policies.statement_count > 25` — policy complexity |
| CTL.IAM.POLICY.CLOUDSHELL.001 | `identity.policies.cloudshell_unrestricted` — unrestricted CloudShell |
| CTL.IAM.POLICY.INLINE.001 | `identity.policies.has_inline_policies` — inline policies on users |
| CTL.IAM.POLICY.DIRECT.001 | `identity.policies.has_direct_policies` — direct attachment on users |

**Verified gaps**:

| # | Gap | Classification | Notes |
|---|-----|----------------|-------|
| 1.1 | General "missing Condition on sensitive action" | Gap B | Only PassRole and MFA have condition checks. Extending to other sensitive actions (DeleteBucket, PutBucketPolicy, CreateGrant) requires new observation properties per action |
| 1.2 | General "missing explicit deny as guardrail" | Gap B | No control checks for absent Deny statements on identity policies. SCP.FULLACCESS.001 checks SCP structure but not identity-policy deny methodology |
| 1.3 | Generic Resource:\* on sensitive actions | Gap A | PassRole and AssumeRole have resource-scoping controls. No general CTL.IAM.POLICY.RESOURCE.WILDCARD checking Resource:\* on s3:\*, kms:\*, dynamodb:\*, etc. Observation property `identity.policies.has_resource_wildcard_on_sensitive` needed |

### Area 2: Attachment Graph for IAM Entities

**Existing coverage**: Much stronger than initially claimed.

The `identity.nep.*` (Net Effective Permissions) namespace provides
combined permission analysis across all policy layers:

| Control ID | What It Checks |
|---|---|
| CTL.IAM.NEP.ADMIN.001 | `identity.nep.is_admin` — admin-equivalent after SCP + boundary + identity policies |
| CTL.IAM.NEP.ESCALATION.001 | `identity.nep.has_escalation_path` — effective escalation including transitive role chains |
| CTL.IAM.NEP.BOUNDARY.001 | `identity.nep.boundary_effective` — boundary meaningfully constrains |
| CTL.IAM.NEP.PHI.001 | `resource.nep.has_non_designated_phi_access` — multi-layer access to PHI |

Group membership is analyzed through escalation controls:
- CTL.IAM.ESCALATE.ADDUSERTOGROUP.001 — group hop via AddUserToGroup
- CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001 — escalate via group policy attachment
- CTL.IAM.ESCALATE.PUTGROUPPOLICY.001 — escalate via group inline policy

User/role blast radius:
- CTL.IAM.IDENTITY.BLASTRADIUS.005 — user reachable resources count
- CTL.IAM.IDENTITY.BLASTRADIUS.006 — user sensitive resource count

Multi-step chain:
- CTL.IAM.ESCALATE.CHAIN.001 — `identity.escalation.can_escalate_to_admin`

**Initially claimed gaps — reclassified**:

| # | Claimed Gap | Verdict | Reason |
|---|-------------|---------|--------|
| 2.1 | Group membership inheritance | **Covered** | Escalation controls evaluate group-hop paths. `identity.escalation.*.resource_scope` includes "belonging-group" and "via-group" values |
| 2.2 | Multi-attachment effective permissions | **Covered** | NEP namespace resolves effective permissions across all layers including multiple attached policies |
| 2.3 | Effective permission reasoning across paths | **Covered** | CTL.IAM.NEP.ADMIN.001 + CTL.IAM.ESCALATE.CHAIN.001 together evaluate transitive paths |

**Remaining real gaps**:

| # | Gap | Classification | Notes |
|---|-----|----------------|-------|
| 2.4 | No standalone group entity observation | Gap E | Groups only analyzed from user perspective (escalation precondition). Cannot answer "what permissions does group X effectively grant?" without user context. Engine evaluates per-entity; no group-as-entity support |
| 2.5 | Policy attachment counts | Gap A | Boolean `has_direct_policies`/`has_inline_policies` but not counts. Observation property `identity.policies.managed_policy_count` and `identity.policies.inline_policy_count` needed for hygiene detection |

### Area 3: Trust Relationship Analysis

**Claim: fully covered. Verdict: CONFIRMED.**

All 6 trust checks map to existing controls:

| # | Check | Control ID | Predicate |
|---|-------|------------|-----------|
| 1 | Broad principal (Principal:\*) | CTL.IAM.TRUST.WILDCARD.001 | `identity.trust_policy.has_wildcard_principal == true` |
| 2 | External account | CTL.IAM.TRUST.EXTERNALID.001 + CTL.IAM.TRUST.ORGBOUNDARY.001 | `cross_account_trust_without_external_id` / `has_org_id_condition == false` |
| 3 | Missing ExternalId | CTL.IAM.TRUST.EXTERNALID.001 | `cross_account_trust_without_external_id == true` |
| 4 | Missing session conditions | CTL.IAM.TRUST.SESSION.001 | `has_assumption_constraints == false` |
| 5 | Risky trust + risky permissions | CTL.IAM.TRUST.OIDC.003 + chains: `service_role_lateral_movement`, `vendor_attack_path`, `third_party_exposure_path` | Compound control + 3 chains |
| 6 | Confused deputy | CTL.IAM.TRUST.CONFUSEDDEPUTY.001 + CTL.IAM.TRUST.SOURCEARN.001 | `confused_deputy_protected == false` / `source_arn_protected == false` |

Additional coverage: 3 OIDC controls (OIDC.001 subject scoping,
OIDC.002 wildcard subject, OIDC.003 OIDC + permissions).

**9 trust controls total. No gaps.**

### Area 4: Instance Profile and Role Association

**Existing coverage**:

| Control ID | What It Checks |
|---|---|
| CTL.EC2.PROFILE.OVERBROAD.001 | `compute.instance_profile.is_overprivileged == true` |
| CTL.EC2.INSTANCE.PROFILE.001 | `compute.iam_instance_profile.attached == false` |
| CTL.EC2.IAMROLE.001 | `compute.iam_profile_attached == false` |
| CTL.EC2.IMDSV2.001 | `compute.network.imdsv2_required == false` |
| CTL.EC2.IMDSV2.002 | IMDSv2 bypass via container host networking |
| Chain: ec2_exposed_instance_path | SNAPSHOT.PUBLIC + SG.RESTRICTED.PORTS + IMDSV2.001 |

**Verified gap**:

| # | Gap | Classification | Notes |
|---|-----|----------------|-------|
| 4.1 | Shared instance profile across multiple EC2 instances | Gap A | ECS has CTL.ECS.TASKROLE.SHARED.001 (`container.task_role.is_shared`), Lambda has CTL.LAMBDA.ROLE.SHARED.001 (`compute.execution_role.is_shared`). No EC2 equivalent. Needs `compute.instance_profile.is_shared` observation property |

### Area 5: Admin-Equivalent and Privilege-Escalation Preconditions

**All 24 ESCALATE controls verified**:

| # | Control ID | Technique |
|---|------------|-----------|
| 1 | CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001 | CreatePolicyVersion + SetDefaultPolicyVersion |
| 2 | CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001 | AttachUserPolicy (self) |
| 3 | CTL.IAM.ESCALATE.PUTUSERPOLICY.001 | PutUserPolicy (self) |
| 4 | CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001 | AttachGroupPolicy (belonging group) |
| 5 | CTL.IAM.ESCALATE.PUTGROUPPOLICY.001 | PutGroupPolicy (belonging group) |
| 6 | CTL.IAM.ESCALATE.ADDUSERTOGROUP.001 | AddUserToGroup (broader group) |
| 7 | CTL.IAM.ESCALATE.CREATEACCESSKEY.001 | CreateAccessKey (on privileged user) |
| 8 | CTL.IAM.ESCALATE.CREATELOGINPROFILE.001 | CreateLoginProfile (on privileged user) |
| 9 | CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001 | UpdateLoginProfile (on privileged user) |
| 10 | CTL.IAM.ESCALATE.RESYNCMFADEVICE.001 | ResyncMFADevice (MFA manipulation) |
| 11 | CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001 | AttachRolePolicy (self) |
| 12 | CTL.IAM.ESCALATE.PUTROLEPOLICY.001 | PutRolePolicy (self) |
| 13 | CTL.IAM.ESCALATE.ASSUMEROLE.001 | AssumeRole (broader role) |
| 14 | CTL.IAM.ESCALATE.UPDATETRUST.001 | UpdateAssumeRolePolicy (modify trust then assume) |
| 15 | CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001 | PassRole to Lambda |
| 16 | CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001 | PassRole to EC2 instance profile |
| 17 | CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001 | PassRole to CloudFormation |
| 18 | CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001 | PassRole to Glue dev endpoint |
| 19 | CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001 | PassRole to DataPipeline |
| 20 | CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001 | SSM SendCommand on privileged instance |
| 21 | CTL.IAM.ESCALATE.STARTBUILD.001 | CodeBuild source injection |
| 22 | CTL.IAM.ESCALATE.CHAIN.001 | Multi-step path to admin (meta-control) |
| 23 | CTL.IAM.ESCALATE.EDITLAMBDA.001 | Edit existing Lambda with powerful role |
| 24 | CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001 | Update existing Glue dev endpoint with powerful role |

#### Rhino Security Labs Technique Mapping

| # | Rhino Technique | Stave Control | Status |
|---|----------------|---------------|--------|
| 1 | CreatePolicyVersion | CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001 | Covered |
| 2 | SetDefaultPolicyVersion | CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001 (combined) | Covered |
| 3 | CreateAccessKey | CTL.IAM.ESCALATE.CREATEACCESSKEY.001 | Covered |
| 4 | CreateLoginProfile | CTL.IAM.ESCALATE.CREATELOGINPROFILE.001 | Covered |
| 5 | UpdateLoginProfile | CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001 | Covered |
| 6 | AttachUserPolicy | CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001 | Covered |
| 7 | AttachGroupPolicy | CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001 | Covered |
| 8 | AttachRolePolicy | CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001 | Covered |
| 9 | PutUserPolicy | CTL.IAM.ESCALATE.PUTUSERPOLICY.001 | Covered |
| 10 | PutGroupPolicy | CTL.IAM.ESCALATE.PUTGROUPPOLICY.001 | Covered |
| 11 | PutRolePolicy | CTL.IAM.ESCALATE.PUTROLEPOLICY.001 | Covered |
| 12 | CreateEC2WithExistingIP | CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001 | Covered |
| 13 | PassRoleToNewLambdaThenInvoke | CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001 | Covered |
| 14 | PassRoleToNewLambda+NewDynamo | CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001 (aggregate) | Covered — trigger variant folded into invocation_vector |
| 15 | PassRoleToNewLambda+ExistingDynamo | CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001 (aggregate) | Covered — trigger variant folded into invocation_vector |
| 16 | PassRoleToNewGlueDevEndpoint | CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001 | Covered |
| 17 | PassRoleToNewCloudFormation | CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001 | Covered |
| 18 | PassRoleToNewDataPipeline | CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001 | Covered |
| 19 | PassRoleToNewCodeStarProject | — | **GAP** |
| 20 | EditExistingLambdaFunctionWithRole | CTL.IAM.ESCALATE.EDITLAMBDA.001 | Covered |
| 21 | UpdateExistingGlueDevEndpoint | CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001 | Covered |

**Score**: 20/21 techniques covered (95.2%). 1 gap (CodeStar — deprecated).

**Verified gaps**:

| # | Gap | Classification | Notes |
|---|-----|----------------|-------|
| 5.1 | PassRoleToNewCodeStarProject | Gap A | CodeStar is deprecated (replaced by CodeCatalyst). Low priority |
| 5.2 | ~~EditExistingLambdaFunctionWithRole~~ | ~~Gap A~~ | **CLOSED** — CTL.IAM.ESCALATE.EDITLAMBDA.001 |
| 5.3 | ~~UpdateExistingGlueDevEndpoint~~ | ~~Gap A~~ | **CLOSED** — CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001 |
| 5.4 | CreateInstanceProfile escalation | Gap A | iam:CreateInstanceProfile + iam:AddRoleToInstanceProfile + ec2:AssociateIamInstanceProfile. Separate from RunInstances vector |

### Area 6: Managed vs Inline Policy Hygiene

**Initially claimed: not covered. Verdict: PARTIALLY FALSE.**

CTL.IAM.POLICY.INLINE.001 EXISTS — checks for inline policies
on IAM users. CTL.IAM.POLICY.DIRECT.001 checks for direct
managed policy attachment on users.

| Control ID | What It Checks |
|---|---|
| CTL.IAM.POLICY.INLINE.001 | `identity.policies.has_inline_policies == true` (users only) |
| CTL.IAM.POLICY.DIRECT.001 | `identity.policies.has_direct_policies == true` (users only) |
| CTL.IAM.POLICY.COMPLEXITY.001 | `identity.policies.statement_count > 25` |

**Remaining real gap**:

| # | Gap | Classification | Notes |
|---|-----|----------------|-------|
| 6.1 | Inline policies on roles and groups | Gap A | CTL.IAM.POLICY.INLINE.001 only fires on `identity.kind == "user"`. Roles and groups with inline policies are not detected. Best practice is managed policies everywhere |

### Area 7: Resource-Based Policy Support

**Existing coverage by service**:

| Service | Controls | Policy Check | Status |
|---------|----------|-------------|--------|
| S3 | 98 | 39 policy-related, 4 dedicated policy controls | Full |
| KMS | 11 | POLICY.001 (wildcard), CROSSACCOUNT.001, ADMIN.BROAD.001, CONDITION.001, PENDING.DELETION.001 | Full |
| Lambda | ~30 | CTL.LAMBDA.INVOKE.PUBLIC.001 (`policy.public_invoke`) | Full |
| ECR | ~10 | CTL.ECR.POLICY.BROAD.001 (`policy.has_broad_cross_account`) | Full |
| SQS | 5 | CTL.SQS.POLICY.PUBLIC.001 (`policy.has_public_access`) | Full |
| SNS | 4 | CTL.SNS.POLICY.PUBLIC.001 (`policy.has_public_access`) | Full |
| Secrets Manager | 7 | CTL.SECRETSMANAGER.POLICY.PUBLIC.001 + rotation + encryption + blast radius | Full |

**Verified gaps**:

| # | Gap | Classification | Notes |
|---|-----|----------------|-------|
| 7.1 | ~~SQS queue resource policy~~ | ~~Gap A~~ | **CLOSED** — CTL.SQS.POLICY.PUBLIC.001 authored |
| 7.2 | ~~SNS topic resource policy~~ | ~~Gap A~~ | **CLOSED** — CTL.SNS.POLICY.PUBLIC.001 authored |
| 7.3 | Secrets Manager resource policy | Gap A | Asset type `secret` (kind: secret) exists. CTL.SECRET.BLAST.002 checks cross-account via derived field but not raw policy Principal |

## Verified Gap List

### Priority 1 — High Security Impact, Gap A (fast implementation)

| # | Gap | Area | Classification | Rationale |
|---|-----|------|----------------|-----------|
| 5.2 | ~~EditExistingLambdaFunctionWithRole~~ | 5 | ~~Gap A~~ | **CLOSED** — CTL.IAM.ESCALATE.EDITLAMBDA.001 |
| 5.3 | ~~UpdateExistingGlueDevEndpoint~~ | 5 | ~~Gap A~~ | **CLOSED** — CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001 |
| 7.1 | ~~SQS queue resource policy~~ | 7 | ~~Gap A~~ | **CLOSED** — CTL.SQS.POLICY.PUBLIC.001 |
| 7.2 | ~~SNS topic resource policy~~ | 7 | ~~Gap A~~ | **CLOSED** — CTL.SNS.POLICY.PUBLIC.001 |

### Priority 2 — Medium Security Impact, Gap A

| # | Gap | Area | Classification | Rationale |
|---|-----|------|----------------|-----------|
| 4.1 | ~~EC2 shared instance profile~~ | 4 | ~~Gap A~~ | **CLOSED** — CTL.EC2.PROFILE.SHARED.001 |
| 5.4 | ~~CreateInstanceProfile escalation~~ | 5 | ~~Gap A~~ | **CLOSED** — CTL.IAM.ESCALATE.CREATEINSTANCEPROFILE.001 |
| 6.1 | ~~Inline policies on roles/groups~~ | 6 | ~~Gap A~~ | **CLOSED** — CTL.IAM.POLICY.INLINE.002 (roles) |
| 7.3 | ~~Secrets Manager resource policy~~ | 7 | ~~Gap A~~ | **CLOSED** — CTL.SECRETSMANAGER.POLICY.PUBLIC.001 |
| 2.5 | Policy attachment counts | 2 | Gap A | Hygiene metric. Deferred — low security impact |

### Priority 3 — Valid Gaps, Higher Implementation Cost

| # | Gap | Area | Classification | Rationale |
|---|-----|------|----------------|-----------|
| 1.1 | General condition block checking | 1 | Gap B | Requires new observation properties per sensitive action. High value but significant extractor work |
| 1.2 | Explicit deny as guardrail | 1 | Gap B | Methodological check — "do you use deny?" Requires extractor to analyze deny statement presence |
| 1.3 | ~~Generic Resource:\* on sensitive actions~~ | 1 | ~~Gap A~~ | **CLOSED** — CTL.IAM.POLICY.RESOURCE.WILDCARD.001 |

### Priority 4 — Architectural Gap

| # | Gap | Area | Classification | Rationale |
|---|-----|------|----------------|-----------|
| 2.4 | Standalone group entity observation | 2 | Gap E | Engine evaluates per-entity. No group-as-entity type exists. Cannot answer "what does group X grant?" without user context. Requires new entity type + engine support for group-level evaluation |

### Deprioritized

| # | Gap | Area | Classification | Rationale |
|---|-----|------|----------------|-----------|
| 5.1 | CodeStarProject escalation | 5 | Gap A | CodeStar is deprecated (replaced by CodeCatalyst). AWS documentation marks it end-of-life. Not worth implementing |

## Recommendations

**Iteration 1** (4 controls, Gap A — fast): Rhino technique parity
- CTL.IAM.ESCALATE.UPDATEFUNCTION.001 — EditExistingLambdaFunctionWithRole
- CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001 — UpdateExistingGlueDevEndpoint
- CTL.IAM.ESCALATE.CREATEINSTANCEPROFILE.001 — CreateInstanceProfile chain
- CTL.IAM.POLICY.INLINE.002 — Inline policies on roles (extend existing)

**Iteration 2** (3 controls, Gap A — resource policies): Event service parity
- CTL.SQS.POLICY.PUBLIC.001 — Public SQS queue policy
- CTL.SNS.POLICY.PUBLIC.001 — Public SNS topic policy
- CTL.SECRETSMANAGER.POLICY.PUBLIC.001 — Public Secrets Manager policy

**Iteration 3** (2 controls, Gap A — blast radius): Instance parity
- CTL.EC2.PROFILE.SHARED.001 — Shared instance profile detection
- CTL.IAM.POLICY.RESOURCE.WILDCARD.001 — Generic Resource:\* detection

**Iteration 4** (Gap B — extractor work): Condition analysis
- Requires extractor changes to emit condition-block presence per action
- CTL.IAM.POLICY.CONDITION.001 — General condition block requirement
- CTL.IAM.POLICY.DENY.001 — Explicit deny guardrail presence

**Deferred** (Gap E): Group entity model
- Requires engine architecture discussion
- Not blocking any customer audit
