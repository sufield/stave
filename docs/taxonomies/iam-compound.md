# IAM compound risk taxonomy

This document is the source-of-truth catalog of real-world IAM
compound attack patterns. Every pattern below is grounded in published incident
reports, MITRE ATT&CK techniques, Stratus Red Team scenarios,
Rhino Security Labs research, or CSA Top Threats — no theoretical
shapes.

**Citation prefix schema** (per the locked decision in
`bizacademy/aws-compound-control-authoring-plan.md`):
- `MITRE:T1078.004` — MITRE ATT&CK technique ID
- `incident:capital-one-2019` — named incident, year
- `stratus:aws.persistence.iam-create-admin-user` — Stratus Red Team scenario
- `rhino:21-aws-privesc` — Rhino Security Labs methodology
- `csa:top-threats-2024:t1` — CSA Top Threats catalog entry
- `hackerone:1234567` — H1 report ID
- `snyk:gh-oidc-sub-broad` — vendor research with slug

The taxonomy spans six sub-families. Each pattern lists:
- **Name** — slug used as the control's filename suffix
- **Asset types involved** — observation types the predicate reasons across
- **Corpus citation** — prefix-schema reference
- **Trigger** — English description of the condition that should fire the control
- **Counter-example** — configuration that LOOKS similar but isn't risky

The taxonomy is agnostic to current Stave coverage — it names
what should exist.

---

## Sub-family 1: Principal-policy-resource chains (Capital One shape)

Compute resource has an IAM role; the role permits access to a
sensitive data resource; the compute surface is reachable from a
position the attacker can occupy. Each one of the three
conditions is acceptable alone; together they're an exfiltration
path. The unit of analysis is the tuple, not the row.

### 1.1 `principal_chain.ec2_imdsv1_to_sensitive_data`

**Asset types:** `aws_ec2_instance`, `aws_iam_role`, `aws_iam_policy`, `aws_s3_bucket` (or other data resource)

**Corpus citation:** `incident:capital-one-2019` (canonical), `MITRE:T1550.001`

**Trigger:** EC2 instance has IMDSv1 enabled (no token-required mode), an instance profile attached, the attached role's effective permissions include `s3:GetObject` (or DynamoDB / Secrets Manager equivalents) on a bucket whose `data_classification` tag is `confidential`/`sensitive`/`pii`, and the instance is in a subnet with an internet gateway route or has a security group permitting inbound from `0.0.0.0/0` on an application port. All four conditions co-present.

**Counter-example:** Same instance with IMDSv2 enforced (token-required mode); the SSRF→IMDS path collapses even if the other three conditions hold.

### 1.2 `principal_chain.lambda_public_url_to_sensitive_data`

**Asset types:** `aws_lambda_function`, `aws_iam_role`, `aws_iam_policy`, `aws_s3_bucket`

**Corpus citation:** `MITRE:T1078.004`, `MITRE:T1550.001`

**Trigger:** Lambda function has a Function URL with `AuthType: NONE` (or an API Gateway integration with no authorizer), the execution role's effective permissions include cross-resource read on a sensitive data resource, and the function's environment variables suggest data-handling responsibility (KMS key ARN present, secret ARN referenced, bucket name in env).

**Counter-example:** Lambda Function URL with `AuthType: AWS_IAM` and explicit identity-based caller scoping; the public reach goes away.

### 1.3 `principal_chain.ecs_task_public_lb_to_sensitive_data`

**Asset types:** `aws_ecs_task_definition`, `aws_iam_role`, `aws_elbv2_load_balancer`, `aws_s3_bucket`

**Corpus citation:** `MITRE:T1078.004`, `csa:top-threats-2024:t1`

**Trigger:** ECS task definition references a task role whose effective permissions reach sensitive data; the task is the target of a service whose load balancer is internet-facing (scheme=internet-facing) with a security group permitting `0.0.0.0/0` on the application port.

**Counter-example:** Same composition with the load balancer scheme=internal and no overlap with a public ALB target group.

### 1.4 `principal_chain.eks_irsa_pod_public_ingress_to_sensitive_data`

**Asset types:** `aws_eks_cluster`, `kubernetes_pod`, `aws_iam_role` (IRSA), `kubernetes_ingress`, `aws_s3_bucket`

**Corpus citation:** `MITRE:T1078.004`, `stratus:aws.discovery.ec2-imds-pod-iam`

**Trigger:** A Kubernetes pod has a service-account-bound IAM role (IRSA) with effective AWS permissions reaching a sensitive data resource; the pod is exposed via a Service of type LoadBalancer or via an Ingress with no `authentication.spec.enabled` annotation, or via a NetworkPolicy that doesn't egress-restrict the pod.

**Counter-example:** Pod has IRSA but is fronted only by an internal ClusterIP Service with restrictive NetworkPolicy; the data access stays in-cluster.

### 1.5 `principal_chain.cross_account_role_no_source_restriction`

**Asset types:** `aws_iam_role`, `aws_iam_policy`, source-account principal

**Corpus citation:** `MITRE:T1199`, `incident:imperva-2019`

**Trigger:** Role's trust policy permits AssumeRole from a principal in an account outside the AWS organization, the role's effective permissions include data-access or admin-equivalent actions, and no condition on `aws:SourceAccount`, `aws:SourceArn`, `sts:ExternalId`, or `aws:PrincipalOrgID` constrains the assumption.

**Counter-example:** Same cross-account trust with `sts:ExternalId` condition tied to a per-customer secret; the confused-deputy / cross-account-via-leaked-arn paths close.

### 1.6 `principal_chain.imdsv1_dataplane_drift`

**Asset types:** `aws_ec2_instance`, `aws_iam_role`, dataplane traffic posture

**Corpus citation:** `incident:capital-one-2019` (variant: dataplane SSRF), `MITRE:T1078.004`

**Trigger:** EC2 instance with IMDSv1 enabled AND the instance hosts a dataplane that proxies user-supplied URLs (heuristic: instance has a WAF rule pattern for SSRF defenses, suggesting prior incident awareness; or instance is labeled as `proxy`/`gateway`/`webhook-receiver`). Either the WAF presence implies known risk, or the labels imply known data-plane SSRF surface.

**Counter-example:** Instance with IMDSv2 enforced + WAF SSRF rules in place. The infrastructure is hardened against the canonical attack shape regardless of labels.

---

## Sub-family 2: Role assumption & trust policy weaknesses

Trust policies are the negotiated boundary between principals and
roles. Compositional weaknesses here are subtle because the
attached permissions look fine in isolation — the failure is in
*who* can assume the role and under *what* circumstances.

### 2.1 `trust.cross_account_no_external_id_external_account`

**Asset types:** `aws_iam_role`, account-organization context

**Corpus citation:** `MITRE:T1199`, `csa:top-threats-2024:t1`

**Trigger:** Trust policy permits `sts:AssumeRole` from an `AWS` principal in an account whose ID is NOT in the trusting account's AWS Organization, and the trust policy has no `Condition` block referencing `sts:ExternalId`. The cross-account-leaked-ARN attack walks straight in.

**Counter-example:** Cross-account trust with `sts:ExternalId` condition tied to a value provisioned out-of-band per customer.

### 2.2 `trust.service_principal_no_source_restriction`

**Asset types:** `aws_iam_role`

**Corpus citation:** `MITRE:T1199` (confused deputy variant)

**Trigger:** Trust policy permits assumption by an AWS service principal (`lambda.amazonaws.com`, `cloudformation.amazonaws.com`, `events.amazonaws.com`, `sns.amazonaws.com`, `s3.amazonaws.com`, etc.) without `aws:SourceAccount` or `aws:SourceArn` condition. Any caller of that service from any account can use the role's permissions.

**Counter-example:** Same service-principal trust with `aws:SourceAccount: 111122223333` AND `aws:SourceArn` pinned to the specific bucket/function/etc. that's allowed to invoke.

### 2.3 `trust.wildcard_principal`

**Asset types:** `aws_iam_role`

**Corpus citation:** `MITRE:T1098.003`, `hackerone:any-aws-wildcard-trust`

**Trigger:** Trust policy contains `"Principal": "*"` or `"Principal": {"AWS": "*"}` without a follow-on `Condition` that bounds who can satisfy. Anyone in any AWS account assumes.

**Counter-example:** Wildcard principal narrowed by `aws:PrincipalOrgID` to the trusting account's organization — equivalent to a per-org trust but expressed compactly.

### 2.4 `trust.broken_string_equals_userid`

**Asset types:** `aws_iam_role`

**Corpus citation:** `rhino:weak-trust-string-equals`

**Trigger:** Trust policy uses `StringEquals` on `aws:userid` or `aws:username` referencing an ID format the docs explicitly say can be reused (e.g., a deleted-then-recreated user gets the same name). The trust expression *looks* tight but isn't.

**Counter-example:** Trust uses `StringEquals` on `aws:userid` with the role's *unique ID* form (`AIDA...:session-name`) which is non-reusable.

### 2.5 `trust.cross_service_to_attacker_owned_resource`

**Asset types:** `aws_iam_role`, AWS service identity referenced in trust

**Corpus citation:** `MITRE:T1199`, `stratus:aws.persistence.iam-create-user-login-profile`

**Trigger:** Trust policy permits a service that's commonly invoked by *external* parties (CloudFormation triggered from a third-party orchestrator, Lambda invoked by S3 event from a cross-account bucket, EventBridge cross-account rule). Service plus invocation context = third-party attack surface.

**Counter-example:** Same service-principal trust where the `aws:SourceArn` pins to a resource the trusting account owns and controls.

### 2.6 `trust.allow_assumerole_back_into_high_privilege`

**Asset types:** `aws_iam_role` (chained pair)

**Corpus citation:** `rhino:role-chaining-escalation`

**Trigger:** Role A's trust policy permits assumption by Role B; Role B's effective permissions include `sts:AssumeRole` on Role C (which has elevated privileges); Role A → B → C chain creates a path the operator didn't directly grant.

**Counter-example:** Role A trusts only specific human identities or only specific services; Role B's `sts:AssumeRole` is scoped to roles inside a narrow permission boundary.

---

## Sub-family 3: Privilege escalation paths

The Rhino Security Labs catalog enumerates ~21 distinct AWS IAM
privilege escalation methods. The patterns below pull the
highest-value ones — each fires when a principal has a permission
that, combined with another configuration fact, enables stepping
to a higher-privilege identity.

### 3.1 `privesc.passrole_to_higher_privilege`

**Asset types:** `aws_iam_principal`, target role, principal's permission set, target role's permission set

**Corpus citation:** `rhino:01-passrole-passrole`, `MITRE:T1548.005`

**Trigger:** Principal has `iam:PassRole` permission scoped to a role whose effective permissions exceed the principal's permission boundary or attached policies. The principal can stand up an EC2/Lambda/ECS resource with that role and use it as a stepping-stone.

**Counter-example:** Principal has `iam:PassRole` only on roles whose permissions are a subset of the principal's own — no escalation possible.

### 3.2 `privesc.put_inline_policy_self_or_peer`

**Asset types:** `aws_iam_principal`, target identity, permission boundary

**Corpus citation:** `rhino:08-put-user-policy`, `MITRE:T1098`

**Trigger:** Principal has `iam:PutUserPolicy` or `iam:PutRolePolicy` permission on itself or on a peer with the same permission boundary; current attached policies stay inside the boundary, but inline grants can be authored that exceed it (boundary check applies only at AttachPolicy/PutPolicy time for *unique* policies — putting an inline that overlaps doesn't always trigger the boundary check).

**Counter-example:** Principal has `iam:PutUserPolicy` scoped only to its OWN identity, and the boundary explicitly denies any inline policy authoring (rare but exists).

### 3.3 `privesc.update_assume_role_policy_on_high_privilege`

**Asset types:** `aws_iam_principal`, target role, target role's permission set

**Corpus citation:** `rhino:04-update-assume-role-policy`, `MITRE:T1098.003`

**Trigger:** Principal has `iam:UpdateAssumeRolePolicy` on a target role whose attached/inline policies grant elevated privileges. The principal rewrites the trust to permit its own assumption, then assumes.

**Counter-example:** Permission scoped only to roles tagged `low-privilege` or with explicit deny on `iam:UpdateAssumeRolePolicy` for any role carrying elevated tags.

### 3.4 `privesc.create_access_key_for_other_user`

**Asset types:** `aws_iam_principal`, target user

**Corpus citation:** `rhino:11-create-access-key`, `MITRE:T1098.001`

**Trigger:** Principal has `iam:CreateAccessKey` permission with resource scope including OTHER users (not just self), and at least one of those users has higher privileges than the principal.

**Counter-example:** `iam:CreateAccessKey` scoped to `Resource: "arn:aws:iam::*:user/${aws:username}"` — self-only.

### 3.5 `privesc.attach_high_privilege_managed_policy`

**Asset types:** `aws_iam_principal`, attached-policy ARN scope, target identity

**Corpus citation:** `rhino:09-attach-user-policy`, `MITRE:T1098`

**Trigger:** Principal has `iam:AttachUserPolicy` / `iam:AttachRolePolicy` / `iam:AttachGroupPolicy` with a `Resource` scope that includes a high-privilege managed policy ARN (e.g., `arn:aws:iam::aws:policy/AdministratorAccess`, `arn:aws:iam::aws:policy/IAMFullAccess`).

**Counter-example:** Attach permission scoped to a specific allowlist of low-privilege managed policies via resource ARN constraints.

### 3.6 `privesc.create_policy_version_then_set_default`

**Asset types:** `aws_iam_principal`, target customer-managed policy

**Corpus citation:** `rhino:02-create-policy-version`, `MITRE:T1098`

**Trigger:** Principal has BOTH `iam:CreatePolicyVersion` AND `iam:SetDefaultPolicyVersion` (or `iam:CreatePolicyVersion` with `--set-as-default`) on a customer-managed policy that's attached to a higher-privilege identity. The principal can author a new policy version with elevated permissions and promote it to default — every identity using the policy now has the new permissions.

**Counter-example:** `iam:CreatePolicyVersion` is granted without `iam:SetDefaultPolicyVersion`; the new version doesn't take effect without admin promotion.

---

## Sub-family 4: Policy composition pitfalls

Effective permissions are the union/intersection of multiple
policies (attached managed, inline, group memberships, permission
boundary, SCP). When the composition produces effective permissions
that diverge from the operator's narrative intent for any *single*
policy, the gap is the vulnerability. These controls flag for
human review — the compositional risk needs context to confirm.

### 4.1 `composition.inline_shadows_managed_deny`

**Asset types:** `aws_iam_principal`, attached managed policies, inline policies

**Corpus citation:** `csa:top-threats-2024:t1`

**Trigger:** Principal has a managed policy with an explicit `Deny` on a sensitive action (e.g., `s3:DeleteBucket`), AND an inline policy with an `Allow` on a broader action set that *includes* the denied action (e.g., `s3:*`). In AWS, explicit deny wins — but composition that *looks* like it would also work via `NotAction` or different `Condition` can confuse the operator. Flag for review.

**Counter-example:** Inline policy explicitly excludes the denied action from its action list, making the deny stand alone.

### 4.2 `composition.cross_group_deny_allow_conflict`

**Asset types:** `aws_iam_user`, group memberships, group-attached policies

**Corpus citation:** `rhino:group-policy-composition`

**Trigger:** User is a member of multiple groups; one group's policies deny an action on a resource; another group's policies allow the same action on the same resource with a `Condition` that doesn't fully overlap with the deny's condition. The effective permission depends on whether the runtime caller satisfies the allow's condition AND fails the deny's — non-obvious from reading any single group's policy.

**Counter-example:** Groups have non-overlapping action scopes (one group for S3, another for EC2); no action-resource conflict.

### 4.3 `composition.notaction_unintended_widening`

**Asset types:** `aws_iam_principal`, attached policy

**Corpus citation:** `csa:top-threats-2024:t1`

**Trigger:** Policy uses `NotAction` with a small exclusion list and `Resource: "*"`. Effective permission: *everything except the listed actions* on *every resource*. Even with a few well-chosen exclusions, the residual permission set is enormous and almost certainly broader than the operator's narrative intent.

**Counter-example:** Policy uses `Action` with an explicit allowlist instead of `NotAction` — even an over-broad allowlist is more reviewable than an exclusion list.

### 4.4 `composition.resource_wildcard_with_cumulative_breadth`

**Asset types:** `aws_iam_principal`, attached policy

**Corpus citation:** `csa:top-threats-2024:t1`

**Trigger:** Policy uses `Resource: "*"` with an action set that's narrow individually but cumulatively covers a sensitive operation surface (e.g., `s3:ListAllMyBuckets` + `s3:GetBucketLocation` + `s3:GetBucketTagging` — each looks "metadata only," cumulatively gives full bucket reconnaissance across the account).

**Counter-example:** Policy uses `Resource: "arn:aws:s3:::specific-bucket-name"` even when the action list is broad — the resource scope makes the impact bounded.

### 4.5 `composition.deny_condition_doesnt_constrain_caller`

**Asset types:** `aws_iam_principal`, attached policy with deny

**Corpus citation:** `rhino:deny-condition-bypass`

**Trigger:** Policy has a `Deny` statement with a `Condition` block whose key isn't actually populated in the caller's identity (e.g., `Condition: {StringEquals: {"aws:RequestTag/data-classification": "public"}}` — but the principal's calls don't set request tags). The deny doesn't constrain the principal in question because the condition is never evaluated against a present value.

**Counter-example:** Deny condition keys are guaranteed to be present in every call (e.g., `aws:CalledVia`, `aws:SecureTransport`, `aws:CurrentTime`).

### 4.6 `composition.scp_gap_for_root_equivalent`

**Asset types:** `aws_organization`, `aws_organizational_unit`, member account, SCP

**Corpus citation:** `MITRE:T1078.004`, `incident:imperva-2019`

**Trigger:** Member account belongs to an OU whose effective SCP (intersection up the tree) does NOT deny actions that should require root-level intervention: `aws-portal:*`, `organizations:LeaveOrganization`, `iam:DeleteAccountPasswordPolicy`, `cloudtrail:StopLogging` at the account-organization-trail level. Any high-privilege identity in the account can take these actions.

**Counter-example:** SCP at the OU or organization root explicitly denies the high-blast-radius action set.

---

## Sub-family 5: Federation & Identity Center paths

Federated identity is where externally-issued trust meets
internally-granted permissions. The composition is at the trust
policy boundary: who can the IdP assert? What does the trust
policy let those assertions become?

### 5.1 `federation.oidc_broad_sub_to_elevated_role`

**Asset types:** `aws_iam_openid_connect_provider`, `aws_iam_role` trusting OIDC

**Corpus citation:** `snyk:gh-oidc-sub-broad`, `MITRE:T1199`

**Trigger:** Role trusts an OIDC provider where the trust policy's `Condition` on `<provider>:sub` claim uses a wildcard (`*`) or broad pattern, and the role's attached permissions include elevated actions. Any caller who can satisfy the broad `sub` pattern assumes.

**Counter-example:** Same trust with a pinned `<provider>:sub` value (full unique subject identifier).

### 5.2 `federation.github_oidc_no_repo_scope`

**Asset types:** `aws_iam_openid_connect_provider` (token.actions.githubusercontent.com), `aws_iam_role`

**Corpus citation:** `snyk:gh-oidc-sub-broad`, `incident:popular-public-oidc-misconfig-2023`

**Trigger:** Role trusts `token.actions.githubusercontent.com` and the trust policy's `sub` condition is either missing or uses `repo:my-org/*:*` or `repo:*:*` (any repo, any workflow). Any GitHub Actions workflow in the trusted GitHub org can assume.

**Counter-example:** `sub` condition pinned to `repo:my-org/my-repo:ref:refs/heads/main` (specific repo + specific branch) or `repo:my-org/my-repo:environment:prod` (specific environment with branch-protection rules).

### 5.3 `federation.saml_no_group_filter`

**Asset types:** `aws_iam_saml_provider`, `aws_iam_role` trusting SAML

**Corpus citation:** `MITRE:T1078.004`, `csa:top-threats-2024:t1`

**Trigger:** Role trusts a SAML provider with no `Condition` on the SAML `Group` or `email` or `eduPersonAffiliation` attribute. Any federated user from the IdP assumes; the IdP becomes the de-facto authorization layer with no AWS-side defense.

**Counter-example:** Trust policy includes `Condition: {StringEquals: {"saml:Group": "aws-elevated-access"}}` (or similar) pinning to a specific IdP-side group.

### 5.4 `federation.identity_center_broad_assignment`

**Asset types:** `aws_sso_permission_set`, `aws_sso_group_assignment`, member account

**Corpus citation:** `MITRE:T1098.003`

**Trigger:** Identity Center permission set with elevated privileges (`AdministratorAccess`, `PowerUserAccess`, or a custom set granting `*:*` on critical services) assigned to a group whose membership crosses organizational boundaries (e.g., includes external contractors, includes everyone-by-default, or includes a group that's `AzureAD/All Users`).

**Counter-example:** Same permission set assigned only to a narrowly-scoped group with a documented exit/offboarding workflow.

### 5.5 `federation.external_idp_with_role_chaining`

**Asset types:** `aws_iam_openid_connect_provider` (or SAML), federated role, downstream chainable roles

**Corpus citation:** `rhino:role-chaining-escalation`, `MITRE:T1199`

**Trigger:** External IdP federation grants a federated role; the federated role's attached permissions include `sts:AssumeRole` on additional roles (chaining beyond the IdP-asserted identity). Combined with §5.1-§5.4, the external IdP becomes a stepping-stone past the principal-level trust expression.

**Counter-example:** Federated role explicitly denies `sts:AssumeRole` or scopes it to a small set of low-privilege roles.

### 5.6 `federation.session_no_duration_ceiling`

**Asset types:** Trust policy, `MaxSessionDuration` on role

**Corpus citation:** `MITRE:T1550.001`

**Trigger:** Federated role's `MaxSessionDuration` is the AWS upper bound (12 hours) and the role has elevated permissions, while the IdP's own session length is much shorter. The role token outlives the IdP session, breaking the "log out the user" invariant — a leaked token persists past IdP revocation.

**Counter-example:** `MaxSessionDuration` set to ≤1 hour for elevated roles, forcing token refresh through the IdP regularly.

---

## Sub-family 6: Auth strength composition

Effective authentication strength = (factor count) × (scope) ×
(rotation). When a principal has high-privilege permissions and
weak authentication, the composition is the risk — neither half is
catastrophic alone, but co-presence sets up the compromise pattern
behind most public AWS breaches.

### 6.1 `auth_strength.high_privilege_no_mfa_enforcement`

**Asset types:** `aws_iam_user`, attached policies, trust/permission boundary

**Corpus citation:** `MITRE:T1078.004`, `incident:imperva-2019`

**Trigger:** IAM user has attached or inline policies granting elevated permissions (`iam:*`, `s3:*` on production buckets, `kms:Decrypt` on production keys), AND no policy condition enforces `aws:MultiFactorAuthPresent` for sensitive actions, AND no Service Control Policy or permission boundary applies the MFA check at a higher level.

**Counter-example:** Same user with policies that include `Condition: {Bool: {"aws:MultiFactorAuthPresent": "true"}}` on sensitive actions, OR same user behind an SCP that denies sensitive actions without MFA.

### 6.2 `auth_strength.old_access_key_high_privilege`

**Asset types:** `aws_iam_user`, access key age, attached permissions

**Corpus citation:** `MITRE:T1078.004`, `incident:imperva-2019`, `incident:twitch-2021`

**Trigger:** IAM access key is older than 90 days AND the owning principal has elevated permissions. Long-lived credentials with broad scope is the canonical AWS breach pattern — leaked access keys go undetected for the credential's full lifetime.

**Counter-example:** Access key under 30 days old OR principal's permissions are narrowly scoped to a single non-sensitive service.

### 6.3 `auth_strength.console_access_weak_password_policy`

**Asset types:** `aws_iam_user`, account-level password policy, attached permissions

**Corpus citation:** `csa:top-threats-2024:t1`

**Trigger:** IAM user has console (login profile) access enabled, the account password policy doesn't meet minimum strength (length < 14, no rotation requirement, no complexity rules), AND the user has elevated permissions. Triple composition: weak password + console access + elevated reach.

**Counter-example:** Account-level password policy is strong (length ≥ 14, rotation < 90 days, complexity required) regardless of any individual user's permission set.

### 6.4 `auth_strength.scp_doesnt_block_root_equivalent`

**Asset types:** `aws_organization`, organizational unit, SCP, member-account high-privilege identity

**Corpus citation:** `MITRE:T1098.003`, `csa:top-threats-2024:t1`

**Trigger:** Member account is in an OU whose effective SCP doesn't deny actions that should require human intervention OR a separate-account workflow: `aws-portal:*` (billing), `organizations:LeaveOrganization`, `cloudtrail:StopLogging` on org trails, `config:DeleteConfigurationRecorder`, `guardduty:DeleteDetector`. A high-privilege identity in the member account can take catastrophic-blast-radius actions unilaterally.

**Counter-example:** OU's effective SCP explicitly denies the catastrophic action set; only the management account can perform them.

### 6.5 `auth_strength.cross_account_assume_no_mfa`

**Asset types:** Source-account user, target-account `aws_iam_role`

**Corpus citation:** `MITRE:T1199`, `MITRE:T1550.001`

**Trigger:** Role in target account permits assumption from source account; target role has elevated permissions; trust policy doesn't include `aws:MultiFactorAuthPresent` condition. A compromised long-lived key in the source account immediately gives elevated access in the target account.

**Counter-example:** Trust policy includes `Condition: {Bool: {"aws:MultiFactorAuthPresent": "true"}}` requiring the source-account caller to have authenticated with MFA before assumption.

### 6.6 `auth_strength.federated_session_no_max_duration_for_elevated`

**Asset types:** `aws_iam_role` (federated), `MaxSessionDuration`

**Corpus citation:** `MITRE:T1550.001`

**Trigger:** Federated role has elevated permissions AND `MaxSessionDuration` set to ≥ 4 hours. Long-lived federated sessions outlive most IdP revocation workflows — a token-theft scenario keeps working long after the user is offboarded.

**Counter-example:** Federated role with elevated permissions has `MaxSessionDuration` ≤ 1 hour, forcing IdP roundtrip regularly enough that revocation is meaningful.

---

## Cross-cutting notes

**On detection-vs-flagging.** Several patterns above — especially
in §4 (policy composition) — flag configurations for human review
rather than asserting definitive risk. The descriptions explicitly
say so. A control whose YAML carries `scope: compound` AND a
"Flag for review" framing in its description is honest about its
epistemic limit; a control that claims to *know* the composition
is risky when the determination genuinely requires context
overpromises.

**On asset-type coverage.** Several patterns require asset types
the current observation contract may not collect (e.g., effective
permission set as a joined view, OIDC subject claim patterns,
SCP effective intersection). Where a pattern requires a new asset
type or new observation field, that gap routes through a separate
observation-contract change — not through control authoring.

**On the canonical corpus.** The citation prefix schema in this
doc is enforced as a CI rule. The actual reference
materials (Stratus Red Team techniques, Rhino Security Labs
methodology pages, CSA Top Threats reports, MITRE ATT&CK pages,
H1 reports) are external and assembling a searchable local
mirror is separate work. The CI rule enforces that compound
controls *cite*; verifying the citation resolves is a manual
review pass.

**On Capital One specifically.** The Capital One framing
(per-resource framework checks would have passed; the breach
happened because of resource composition) is the canonical wedge
for the comparison doc (P3) and for downstream content. Pattern
§1.1 (`principal_chain.ec2_imdsv1_to_sensitive_data`) is the
exact-replica control; pattern §1.6
(`principal_chain.imdsv1_dataplane_drift`) is the
generalization. Both cite the incident; downstream content cites
both controls.
