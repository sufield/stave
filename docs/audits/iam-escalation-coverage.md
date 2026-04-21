# IAM Privilege Escalation Coverage Audit

Audited: 2026-04-21
Catalog version: 675 controls, 135 IAM/Lambda/CloudTrail/SCP

## Summary

Stave's control catalog provides **full coverage** of all 8
escalation vectors and **strong coverage** of 5 of 6 remediation
areas. The 22 ESCALATE controls map 1:1 to known Rhino Security
Labs / Prowler escalation techniques. The POLICY sub-family covers
policy hygiene (wildcards, self-modification, NotAction shadows).
Chain definitions compose individual controls into multi-step
escalation paths. Two remaining gaps are observation-layer dependent: session
duration conditions in trust policies (Gap B) and CloudTrail
event-level monitoring for specific IAM escalation API calls
(Gap C).

## Escalation Vector Coverage

| # | Vector | Controls | Coverage |
|---|--------|----------|----------|
| 1 | **iam:PassRole to powerful roles** | CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001, CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001, CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001, CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001, CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001, CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001, CTL.IAM.POLICY.PASSROLE.001, CTL.LAMBDA.PASSROLE.001 | **Full** |
| 2 | **sts:AssumeRole into admin roles** | CTL.IAM.ESCALATE.ASSUMEROLE.001, CTL.IAM.POLICY.ASSUMEROLE.001, CTL.IAM.TRUST.EXTERNALID.001 | **Full** |
| 3 | **Self-attach AdministratorAccess** | CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001, CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001, CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001, CTL.IAM.POLICY.ADMIN.001, CTL.IAM.POLICY.ESCALATION.001 | **Full** |
| 4 | **CreatePolicyVersion** | CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001 | **Full** |
| 5 | **UpdateAssumeRolePolicy (trust edit)** | CTL.IAM.ESCALATE.UPDATETRUST.001 | **Full** |
| 6 | **Service pivot (CF/Glue/CB/SSM)** | CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001 (CF), CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001 (Glue), CTL.IAM.ESCALATE.STARTBUILD.001 (CodeBuild), CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001 (SSM) | **Full** |
| 7 | **CreateAccessKey / CreateLoginProfile** | CTL.IAM.ESCALATE.CREATEACCESSKEY.001, CTL.IAM.ESCALATE.CREATELOGINPROFILE.001, CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001, CTL.IAM.ESCALATE.RESYNCMFADEVICE.001 | **Full** |
| 8 | **Self-management of policies** | CTL.IAM.POLICY.ESCALATION.001 (self-modify detection), CTL.IAM.ESCALATE.PUTUSERPOLICY.001, CTL.IAM.ESCALATE.PUTROLEPOLICY.001, CTL.IAM.ESCALATE.PUTGROUPPOLICY.001, CTL.IAM.ESCALATE.ADDUSERTOGROUP.001 | **Full** |

**Supplementary coverage:**
- CTL.IAM.ESCALATE.CHAIN.001 detects multi-step escalation paths
  that compose individual vectors (e.g., PassRole + CreateFunction
  + InvokeFunction)
- CTL.IAM.NEP.ESCALATION.001 checks net effective permissions for
  escalation capability regardless of specific technique
- CTL.IAM.NEP.ADMIN.001 checks whether resolved permissions are
  admin-equivalent

All 8 vectors have Full coverage. Every known single-step and
service-mediated escalation technique enumerated by Rhino Security
Labs has a dedicated control. The CHAIN.001 control covers
multi-step compositions.

## Remediation Coverage

| # | Area | Controls | Coverage |
|---|------|----------|----------|
| 9 | **Wildcard restriction** | CTL.IAM.POLICY.ADMIN.001 (Action:* Resource:*), CTL.IAM.POLICY.SERVICEWILDCARD.001 (service:* on denied list), CTL.IAM.POLICY.ASSUMEROLE.001 (sts:AssumeRole Resource:*), CTL.IAM.POLICY.PASSROLE.001 (iam:PassRole Resource:*) | **Full** |
| 10 | **PassRole condition restriction** | CTL.IAM.POLICY.PASSROLE.001 (wildcard Resource), CTL.IAM.POLICY.PASSROLE.CONDITION.001 (missing iam:PassedToService condition) | **Full** |
| 11 | **Permission boundaries** | CTL.IAM.BOUNDARY.001 (checks boundary is set), CTL.IAM.NEP.BOUNDARY.001 (checks boundary is effective — actually constrains permissions) | **Full** |
| 12 | **MFA on sensitive operations** | CTL.IAM.POLICY.MFA.001 (checks aws:MultiFactorAuthPresent condition on destructive actions) | **Full** |
| 13 | **Session/conditions in trust policies** | CTL.IAM.TRUST.EXTERNALID.001 (ExternalId), CTL.IAM.TRUST.CONFUSEDDEPUTY.001 (SourceAccount), CTL.IAM.TRUST.SOURCEARN.001 (SourceArn). No control checks MaxSessionDuration or source IP conditions. | **Partial** |
| 14 | **CloudTrail monitoring for escalation** | CTL.CLOUDTRAIL.ENABLED.001 (trail exists, multi-region). No control verifies event-level alerting on specific IAM escalation API calls (CreatePolicyVersion, AttachUserPolicy, PassRole). | **Partial** |

## Gaps

### Gap 10: PassRole condition specificity — CLOSED

Closed by CTL.IAM.POLICY.PASSROLE.CONDITION.001. The control
checks `identity.policies.passrole_has_service_condition == false`,
firing when a PassRole grant lacks the iam:PassedToService
condition. Combined with PASSROLE.001 (wildcard Resource), both
the unconstrained-Resource and unconditioned-service cases are
now covered.

### Gap 13: MaxSessionDuration and source IP in trust policies

**Classification: Gap B** (observation data partially available)

Existing controls check trust policy principal binding (ExternalId,
SourceArn, SourceAccount, OIDC subject scope). No control checks:
- MaxSessionDuration (whether assumed-role sessions are time-bounded)
- Source IP conditions (whether trust is geo-restricted)
- MFA conditions on cross-account assumption

The observation contract carries trust policy structure but does
not currently decompose Condition blocks for these specific keys.
Adding them requires extractor work to parse trust policy
conditions beyond the current binary flags.

**Priority: Low.** These are defense-in-depth conditions. The
principal-binding controls (ExternalId, SourceArn) address the
primary confused-deputy and cross-account risks.

### Gap 14: CloudTrail event-level escalation monitoring

**Classification: Gap C** (observation data not available)

CTL.CLOUDTRAIL.ENABLED.001 verifies trails exist and are
multi-region. No control verifies that specific IAM escalation
events (CreatePolicyVersion, AttachUserPolicy, UpdateAssumeRolePolicy,
PassRole) trigger CloudWatch alarms or EventBridge rules.

This requires observation data about CloudWatch alarm configurations
and EventBridge rules — data the observation contract does not
currently capture. The gap is observation-layer: an extractor would
need to enumerate CloudWatch alarms and match them against IAM API
call patterns.

**Priority: Medium.** Detection of escalation events is operationally
important but orthogonal to preventing escalation (which the
ESCALATE controls address). The CLOUDWATCH family has monitoring
controls (CTL.CLOUDWATCH.MONITOR.UNAUTH.001, .AUTHFAIL.001,
.MFADEVICE.001) that cover some event patterns but not IAM
escalation specifically.

## Compound Chain Coverage

11 chain definitions involve IAM escalation controls:

| Chain | Controls | Escalation vectors covered |
|-------|----------|---------------------------|
| `privilege_escalation_path` | ESCALATE.CHAIN.001, POLICY.ESCALATION.001, POLICY.PASSROLE.001, POLICY.SOD.001 | Multi-step paths, self-modify, PassRole, SoD |
| `shadow_logic_escalation` | POLICY.ESCALATION.001, POLICY.SHADOW.001, POLICY.SHADOW.002 | NotAction bypass → self-modify |
| `root_compromise_path` | POLICY.ADMIN.001, ROOT.ACCESSKEY.001, ROOT.HWMFA.001, ROOT.MFA.001 | Root credential compromise |
| `service_role_lateral_movement` | POLICY.ADMIN.001, TRUST.SOURCEARN.001 | Service role assumption without source binding |
| `supply_chain_ingress` | TRUST.EXTERNALID.001, TRUST.OIDC.001-003 | OIDC/cross-account trust exploitation |
| `confused_deputy_path` | TRUST.CONFUSEDDEPUTY.001, TRUST.EXTERNALID.001, CLOUDTRAIL.ENABLED.001 | Third-party confused deputy |
| `persistent_identity_creation` | ADMIN.COUNT.001, SCP.CREATEACCOUNT.001, SCP.FULLACCESS.001 | Persistence via identity creation |
| `scp_governance_collapse` | SCP.DANGEROUS.ALLOWS.001, SCP.OU.COVERAGE.001 | Organizational guardrail removal |
| `identity_blast_radius` | CRED.EXPIRY.001, IDENTITY.BLASTRADIUS.001, MFA.HWKEY.001, POLICY.SOD.001 | Blast radius amplification |
| `shadow_admin_by_accumulation` | ROLE.CATEGORYMIX.001, ROLE.INTENTMISMATCH.001, ROLE.PERMISSIONDRIFT.001 | Gradual permission accumulation |
| `privilege_creep_lateral_movement` | ROLE.CATEGORYMIX.001, ROLE.PERMISSIONDRIFT.001 | Drift-based escalation |

The `privilege_escalation_path` chain directly composes escalation
controls into a multi-step detection. An adopter with chain
detection enabled gets compound-risk scoring on findings that
participate in escalation paths. Without chains, individual controls
still fire independently.

The CloudFront case fixture (aws-cloudfront-2805173) demonstrates
two chains: `admin_role_lambda_bridge` and `cf_iam_escalation`,
both combining IAM and Lambda controls.

## Triage Content Alignment

All 22 ESCALATE controls have per-control triage overrides with
defect/infection/failure authored specifically for each escalation
technique. Cross-referencing against this audit:

- Each ESCALATE control's **defect** accurately names the specific
  permission combination (e.g., "iam:PassRole reaching a role whose
  effective permissions exceed its own, plus
  cloudformation:CreateStack")
- Each ESCALATE control's **infection** describes the specific
  attack mechanism (e.g., "the attacker submits a CloudFormation
  template that performs IAM mutations")
- Each ESCALATE control's **failure** describes the escalation
  outcome (e.g., "privilege escalation via CloudFormation template
  execution")

The 16 POLICY controls similarly have per-control overrides
aligned with their detection scope. No triage content updates
needed based on this audit.

## Recommendations

1. ~~**(Medium) Add PassRole service condition check.**~~
   **CLOSED.** CTL.IAM.POLICY.PASSROLE.CONDITION.001 authored.

2. **(Medium) Add CloudWatch alarm coverage for IAM events.** This
   is observation-layer work — the extractor needs to capture
   CloudWatch alarm configurations. Once available, controls can
   verify alerts exist for escalation-relevant API calls. Addresses
   Gap 14.

3. **(Low) Add trust policy condition depth.** Parse Condition
   blocks for MaxSessionDuration, source IP, and MFA requirements.
   Addresses Gap 13. Lower priority because principal-binding
   controls already cover the primary risk.

4. **(None needed) Escalation vector coverage.** All 8 vectors
   have Full coverage. No new ESCALATE controls needed unless new
   escalation techniques emerge.
