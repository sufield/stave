# Identity Domain

Contract fields for AWS IAM observations and derived policy analysis.
Namespace prefix: `identity.*`. Also covers `identity.policy.*`
(shadow-logic analysis on individual policies, kept separate from
`identity.policies.*` which aggregates per-principal).

Part of the [observation contract](README.md).

## IAM Domain (identity.*)

For IAM evaluation, these property namespaces are the stability surface.

### Account-level (`aws_iam_account`)

| Field | Type | Description |
|-------|------|-------------|
| `identity.kind` | string | `"account"` — discriminator |
| `identity.root.mfa_enabled` | bool | Root account has MFA configured |
| `identity.root.has_access_keys` | bool | Root account has active access keys |

### User-level (`aws_iam_user`)

| Field | Type | Description |
|-------|------|-------------|
| `identity.kind` | string | `"user"` — discriminator |
| `identity.console_access.enabled` | bool | Console login is enabled |
| `identity.console_access.mfa_enabled` | bool | MFA enabled for console access |
| `identity.credentials.unused` | bool | No activity for 90+ days |
| `identity.access_keys.has_stale_key` | bool | Any access key older than 90 days |
| `identity.policies.has_inline_policies` | bool | Inline policies attached to user |
| `identity.policies.has_direct_policies` | bool | Managed policies attached directly |
| `identity.policies.has_admin_access` | bool | User has admin-level access |
| `identity.policies.service_wildcards_granted` | []string/null | Service names for which the principal's attached policies grant `<service>:*` on `Resource: "*"` in at least one Allow statement. See the dedicated subsection below for semantic details. `null` when the principal has no attached policies; `[]` when policies exist but none qualify. |
| `identity.user.reachable_resources_count` | int | Resources reachable through user's attached and inline policies |
| `identity.user.sensitive_resource_count` | int | Sensitive resources (PHI/PII/confidential) reachable through user's policies |

### Password policy (`aws_iam_password_policy`)

| Field | Type | Description |
|-------|------|-------------|
| `identity.kind` | string | `"password_policy"` — discriminator |
| `identity.password_policy.minimum_length` | integer | Minimum password length |
| `identity.password_policy.require_uppercase` | bool | Uppercase required |
| `identity.password_policy.require_lowercase` | bool | Lowercase required |
| `identity.password_policy.require_numbers` | bool | Numbers required |
| `identity.password_policy.require_symbols` | bool | Symbols required |
| `identity.password_policy.reuse_prevention_count` | integer | Password history depth |

---


## Cross-environment pivot namespace

The `identity.role.cross_env.*` namespace tracks transitive trust
paths from non-production to production environments.

| Property | Type | Description |
|---|---|---|
| `identity.role.cross_env.reachable_from_lower_env` | bool | Prod resource reachable from non-prod |
| `identity.role.cross_env.source_env` | string | `development`, `staging`, `qa` |
| `identity.role.cross_env.path_hop_count` | int | Hops from non-prod to prod |
| `identity.role.cross_env.via_bridge_role` | string | ARN of the bridge role |

**Controls:** CTL.IAM.CROSS.ENV.PATH.001 (graph-based transitive trust).

---

## Privilege escalation namespace

The `identity.escalation.*` namespace tracks multi-step permission
chains that lead to administrative access.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.can_escalate_to_admin` | bool | Principal can chain to admin |
| `identity.escalation.escalation_vector` | string | `PassRoleToLambda`, `CreatePolicyVersion`, etc. |
| `identity.escalation.steps` | string[] | Ordered API actions in the chain |
| `identity.escalation.target_admin_role` | string | ARN of the admin role reached |
| `identity.escalation.step_count` | int | Number of steps in the chain |

**Controls:** CTL.IAM.ESCALATE.CHAIN.001 (multi-step escalation path).

### Per-technique escalation sub-namespaces

Each sub-namespace under `identity.escalation.<technique>` records whether a
single, named escalation technique applies to the principal. The extractor (or
a downstream derivation) computes the technique's preconditions — action-level
IAM permissions, Resource-ARN scoping, group membership for group-hop
techniques — and emits `.present: true` when they all hold. Controls stay
declarative over `<technique>.present`; the permission analysis lives upstream
in one place.

This is the convention used by `CTL.IAM.ESCALATE.STARTBUILD.001` and
`CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001`, now extended by the direct
self-escalation cluster below.

#### Self policy manipulation (`identity.escalation.attach_user_policy_self`)

Rhino cluster #1 — `iam:AttachUserPolicy` where the Resource includes the
principal's own user ARN. The principal can attach any managed policy
(including `arn:aws:iam::aws:policy/AdministratorAccess`) to itself.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.attach_user_policy_self.present` | bool | Principal has `iam:AttachUserPolicy` scoped to its own user ARN |
| `identity.escalation.attach_user_policy_self.target_user_arn` | string | The principal's own ARN (self-target) |
| `identity.escalation.attach_user_policy_self.resource_scope` | string | `"self"`, `"wildcard"`, or `"user-set"` — how the Resource field resolves |
| `identity.escalation.attach_user_policy_self.reachable_managed_policies` | string[] | Managed-policy ARNs the principal can attach (empty means "any" when resource_scope is `wildcard`) |

#### Self inline policy (`identity.escalation.put_user_policy_self`)

Rhino cluster #2 — `iam:PutUserPolicy` where the Resource includes the
principal's own user ARN. The principal can write an arbitrary inline policy
onto itself.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.put_user_policy_self.present` | bool | Principal has `iam:PutUserPolicy` scoped to its own user ARN |
| `identity.escalation.put_user_policy_self.target_user_arn` | string | The principal's own ARN |
| `identity.escalation.put_user_policy_self.resource_scope` | string | `"self"`, `"wildcard"`, or `"user-set"` |

#### Group managed policy (`identity.escalation.attach_group_policy`)

Rhino cluster #3 — `iam:AttachGroupPolicy` where the Resource is a group the
principal belongs to. Attaching a managed policy to the group elevates every
member including the principal.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.attach_group_policy.present` | bool | Principal can attach a managed policy to a group it belongs to |
| `identity.escalation.attach_group_policy.target_group` | string | Group name or ARN |
| `identity.escalation.attach_group_policy.resource_scope` | string | `"belonging-group"`, `"wildcard"`, or `"group-set"` |
| `identity.escalation.attach_group_policy.reachable_managed_policies` | string[] | Managed-policy ARNs the principal can attach |

#### Group inline policy (`identity.escalation.put_group_policy`)

Rhino cluster #4 — `iam:PutGroupPolicy` where the Resource is a group the
principal belongs to.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.put_group_policy.present` | bool | Principal can write an inline policy on a group it belongs to |
| `identity.escalation.put_group_policy.target_group` | string | Group name or ARN |
| `identity.escalation.put_group_policy.resource_scope` | string | `"belonging-group"`, `"wildcard"`, or `"group-set"` |

#### Policy version manipulation (`identity.escalation.create_policy_version`)

Rhino cluster #5 — `iam:CreatePolicyVersion` plus `iam:SetDefaultPolicyVersion`
on a managed policy attached to the principal (directly or via a belonging
group). Creating a new version with broader permissions and marking it default
updates the effective policy for every attached principal.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.create_policy_version.present` | bool | Principal can create and activate a new version of a managed policy attached to itself or a belonging group |
| `identity.escalation.create_policy_version.target_policy_arn` | string | ARN of the managed policy |
| `identity.escalation.create_policy_version.attachment_path` | string | `"direct"` (attached to the user) or `"via-group"` (attached to a group the user belongs to) |
| `identity.escalation.create_policy_version.attachment_group` | string/null | Group name when `attachment_path` is `"via-group"`; `null` otherwise |
| `identity.escalation.create_policy_version.has_create_version` | bool | Principal has `iam:CreatePolicyVersion` on the target policy |
| `identity.escalation.create_policy_version.has_set_default` | bool | Principal has `iam:SetDefaultPolicyVersion` on the target policy |

#### Group membership manipulation (`identity.escalation.add_user_to_group`)

Rhino cluster #6 — `iam:AddUserToGroup` where a candidate target group exists
whose effective permissions exceed the principal's current ones.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.add_user_to_group.present` | bool | Principal can add itself to a group whose permissions exceed its own |
| `identity.escalation.add_user_to_group.target_group` | string | Group name or ARN |
| `identity.escalation.add_user_to_group.permission_delta` | string[] | Actions the target group grants beyond the principal's current permissions |

**Controls:** `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`,
`CTL.IAM.ESCALATE.PUTUSERPOLICY.001`,
`CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001`,
`CTL.IAM.ESCALATE.PUTGROUPPOLICY.001`,
`CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001`,
`CTL.IAM.ESCALATE.ADDUSERTOGROUP.001`.

#### Role assumption (`identity.escalation.assume_role`)

Rhino role-assumption cluster #1 — `sts:AssumeRole` reaches at least one role
whose attached permissions exceed the principal's current ones AND whose trust
policy permits this principal. The principal does not grant itself permissions;
it pivots into a role that already has them.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.assume_role.present` | bool | Principal has `sts:AssumeRole` scoped to a role whose trust permits it and whose permissions exceed the principal's |
| `identity.escalation.assume_role.target_role_arn` | string | ARN of the broader-permissioned role reachable via `AssumeRole` |
| `identity.escalation.assume_role.permission_delta` | string[] | Actions the target role grants beyond the principal's current permissions |
| `identity.escalation.assume_role.trust_pathway` | string | How the trust policy admits the principal: `"direct"` (Principal names the user/role ARN), `"account-root"` (account root trust delegating via IAM permission), `"wildcard-aws"` (`"AWS": "*"` with no restricting Condition), `"oidc"`, `"saml"` |
| `identity.escalation.assume_role.has_external_id_requirement` | bool | Trust policy requires `sts:ExternalId` — present for accuracy even when it doesn't prevent self-assumption |

#### Trust policy modification (`identity.escalation.update_trust_policy`)

Rhino role-assumption cluster #2 — `iam:UpdateAssumeRolePolicy` on any role
whose attached permissions exceed the principal's. The principal can rewrite
the role's trust to admit itself and then assume it in a later call. Listed
separately from `assume_role` because the remediation is different: remove
`iam:UpdateAssumeRolePolicy` from the principal (or narrow its Resource),
rather than remove `sts:AssumeRole`.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.update_trust_policy.present` | bool | Principal has `iam:UpdateAssumeRolePolicy` reaching a role whose permissions exceed its own |
| `identity.escalation.update_trust_policy.target_role_arn` | string | ARN of the target role |
| `identity.escalation.update_trust_policy.permission_delta` | string[] | Actions the target role grants beyond the principal's current permissions |
| `identity.escalation.update_trust_policy.resource_scope` | string | `"target-role"` (Resource names the specific role ARN), `"wildcard"` (`"Resource": "*"`), or `"role-set"` (Resource is a list that includes the target) |

**Controls:** `CTL.IAM.ESCALATE.ASSUMEROLE.001`,
`CTL.IAM.ESCALATE.UPDATETRUST.001`.

#### PassRole pivots (service-mediated escalation)

Each `passrole_<service_action>` sub-namespace records whether a principal
can pivot into a broader-permissioned role through a specific AWS service
action. The pattern was established by the already-shipped
`passrole_createstack`, `passrole_runinstances`, and `startbuild_source_write`
sub-namespaces; this cluster extends it to Lambda, Glue, SSM, and DataPipeline.
Multi-step prerequisites (e.g., CreateFunction + InvokeFunction, CreatePipeline
+ ActivatePipeline) are folded into each `.present` boolean upstream; the
diagnostic sub-fields expose which sub-conditions held so the finding is
actionable.

##### `identity.escalation.passrole_createfunction`

Lambda: `iam:PassRole` + `lambda:CreateFunction` + an invocation path
(`lambda:InvokeFunction`, function URL creation, or trigger wiring).

| Property | Type | Description |
|---|---|---|
| `identity.escalation.passrole_createfunction.present` | bool | All Lambda escalation preconditions hold |
| `identity.escalation.passrole_createfunction.target_role` | string | ARN of the broader-permissioned execution role the principal can pass to Lambda |
| `identity.escalation.passrole_createfunction.permission_delta` | string[] | Actions the target role grants beyond the principal's current permissions |
| `identity.escalation.passrole_createfunction.invocation_vector` | string | How the function is reachable after creation: `"invoke_function"`, `"function_url"`, `"trigger"`, or `"multiple"` |
| `identity.escalation.passrole_createfunction.runtime` | string | Runtime of the function (diagnostic only, e.g., `"python3.12"`, `"nodejs20.x"`) |

##### `identity.escalation.passrole_createdevendpoint`

Glue: `iam:PassRole` + `glue:CreateDevEndpoint` on a role with broader
permissions. Access to the endpoint is via SSH registration on creation.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.passrole_createdevendpoint.present` | bool | Glue escalation preconditions hold |
| `identity.escalation.passrole_createdevendpoint.target_role` | string | ARN of the broader-permissioned role the principal can pass to Glue |
| `identity.escalation.passrole_createdevendpoint.permission_delta` | string[] | Actions the target role grants beyond the principal's current permissions |
| `identity.escalation.passrole_createdevendpoint.endpoint_type` | string | Endpoint size class (diagnostic, e.g., `"standard"`, `"G.1X"`, `"G.2X"`) |

##### `identity.escalation.passrole_sendcommand`

SSM: `ssm:SendCommand` or `ssm:StartSession` on an EC2 instance whose
attached instance-profile role carries broader permissions. Distinct from
`passrole_runinstances` — that creates a fresh instance with an attacker-
chosen profile; this exploits an already-running one.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.passrole_sendcommand.present` | bool | SSM escalation preconditions hold |
| `identity.escalation.passrole_sendcommand.target_role` | string | ARN of the instance-profile role attached to the reachable instance |
| `identity.escalation.passrole_sendcommand.permission_delta` | string[] | Actions the target role grants beyond the principal's current permissions |
| `identity.escalation.passrole_sendcommand.target_instance` | string | Instance ID or ARN the principal can reach |
| `identity.escalation.passrole_sendcommand.invocation_method` | string | `"send_command"`, `"start_session"`, or `"both"` |

##### `identity.escalation.passrole_createpipeline`

DataPipeline: `iam:PassRole` + `datapipeline:CreatePipeline` +
`datapipeline:ActivatePipeline` on a role with broader permissions.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.passrole_createpipeline.present` | bool | DataPipeline escalation preconditions hold |
| `identity.escalation.passrole_createpipeline.target_role` | string | ARN of the broader-permissioned role the principal can pass to DataPipeline |
| `identity.escalation.passrole_createpipeline.permission_delta` | string[] | Actions the target role grants beyond the principal's current permissions |
| `identity.escalation.passrole_createpipeline.has_activate_permission` | bool | Principal holds `datapipeline:ActivatePipeline` — required to trigger pipeline execution |

**Controls:** `CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001`,
`CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001`,
`CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001`,
`CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001`.

#### Credential manipulation on another user

Rhino Security Labs' credential-manipulation cluster — four techniques
where the principal manipulates another IAM user's authentication
material to impersonate that user. Unlike the Cluster 1 self-policy
techniques where `target_user_arn` refers to the principal's own ARN,
in this cluster `target_user_arn` identifies the **victim user** — the
privileged user whose credentials the principal can forge, reset, or
disarm. Same field name, different semantic; documented here so the
reuse doesn't confuse operators reading the finding.

##### `identity.escalation.create_access_key`

`iam:CreateAccessKey` reaching another user with broader permissions.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.create_access_key.present` | bool | Principal can create an access key for a user whose permissions exceed its own |
| `identity.escalation.create_access_key.target_user_arn` | string | **Victim** user ARN (not self) |
| `identity.escalation.create_access_key.permission_delta` | string[] | Actions the victim holds beyond the principal's current permissions |
| `identity.escalation.create_access_key.resource_scope` | string | `"target-user"`, `"wildcard"`, or `"user-set"` |
| `identity.escalation.create_access_key.target_has_max_keys` | bool | Victim already has AWS's two-access-key maximum; attack additionally requires `DeleteAccessKey` |

##### `identity.escalation.update_login_profile`

`iam:UpdateLoginProfile` reaching another user with broader permissions.
Requires the victim to already have a console login profile.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.update_login_profile.present` | bool | Principal can reset the console password of a user whose permissions exceed its own |
| `identity.escalation.update_login_profile.target_user_arn` | string | Victim user ARN |
| `identity.escalation.update_login_profile.permission_delta` | string[] | Actions the victim holds beyond the principal's current permissions |
| `identity.escalation.update_login_profile.resource_scope` | string | `"target-user"`, `"wildcard"`, or `"user-set"` |
| `identity.escalation.update_login_profile.target_has_mfa` | bool | Victim has an MFA device enrolled; MFA-bypass via `ResyncMFADevice` or `DeactivateMFADevice` may be a prerequisite for a successful console login |

##### `identity.escalation.create_login_profile`

`iam:CreateLoginProfile` reaching a user with broader permissions who
currently has no console login profile — typically a programmatic-only
service account.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.create_login_profile.present` | bool | Principal can create a console login profile for a user whose permissions exceed its own AND who has no existing profile |
| `identity.escalation.create_login_profile.target_user_arn` | string | Victim user ARN |
| `identity.escalation.create_login_profile.permission_delta` | string[] | Actions the victim holds beyond the principal's current permissions |
| `identity.escalation.create_login_profile.resource_scope` | string | `"target-user"`, `"wildcard"`, or `"user-set"` |
| `identity.escalation.create_login_profile.target_has_existing_profile` | bool | Victim already has a login profile; `CreateLoginProfile` fails in that case (folded into `.present=false`, retained for observability) |

##### `identity.escalation.resync_mfa_device`

`iam:ResyncMFADevice` reaching another user with broader permissions.
Standalone MFA bypass; pairs with `update_login_profile` or
`create_access_key` on the same victim for full takeover.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.resync_mfa_device.present` | bool | Principal can resynchronize or manipulate the MFA device of a user whose permissions exceed its own |
| `identity.escalation.resync_mfa_device.target_user_arn` | string | Victim user ARN |
| `identity.escalation.resync_mfa_device.permission_delta` | string[] | Actions the victim holds beyond the principal's current permissions |
| `identity.escalation.resync_mfa_device.resource_scope` | string | `"target-user"`, `"wildcard"`, or `"user-set"` |
| `identity.escalation.resync_mfa_device.target_has_mfa` | bool | Victim has an MFA device enrolled — precondition for the technique |

**Controls:** `CTL.IAM.ESCALATE.CREATEACCESSKEY.001`,
`CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001`,
`CTL.IAM.ESCALATE.CREATELOGINPROFILE.001`,
`CTL.IAM.ESCALATE.RESYNCMFADEVICE.001`.

#### Role-side self-policy modification

Role-side analogues of the user-side direct self-policy techniques
(`attach_user_policy_self` and `put_user_policy_self` in Cluster 1). AWS
provides distinct API actions for role-targeting (`iam:AttachRolePolicy`,
`iam:PutRolePolicy`) so they warrant distinct per-technique sub-namespaces
and distinct controls — the kept user-side gate on the Cluster 1 controls
correctly suppresses role-side signals, and the role-side gate on these
controls correctly suppresses user-side. No group-attachment analogue
because IAM groups are user-only.

##### `identity.escalation.attach_role_policy`

Role with `iam:AttachRolePolicy` scoped to its own role ARN (directly, by
wildcard, or by a role-set that includes it). Attaching any broad managed
policy to self is a one-call escalation.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.attach_role_policy.present` | bool | Role has `iam:AttachRolePolicy` scoped to its own role ARN |
| `identity.escalation.attach_role_policy.target_role_arn` | string | The role's own ARN (self-target) |
| `identity.escalation.attach_role_policy.resource_scope` | string | `"self"`, `"wildcard"`, or `"role-set"` — how the Resource field resolves |
| `identity.escalation.attach_role_policy.reachable_managed_policies` | string[] | Managed-policy ARNs the role can attach (empty means "any" when resource_scope is `wildcard`) |

##### `identity.escalation.put_role_policy`

Role with `iam:PutRolePolicy` scoped to its own role ARN. Writing an
arbitrary inline policy to self is a one-call escalation.

| Property | Type | Description |
|---|---|---|
| `identity.escalation.put_role_policy.present` | bool | Role has `iam:PutRolePolicy` scoped to its own role ARN |
| `identity.escalation.put_role_policy.target_role_arn` | string | The role's own ARN |
| `identity.escalation.put_role_policy.resource_scope` | string | `"self"`, `"wildcard"`, or `"role-set"` |

**Controls:** `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001`,
`CTL.IAM.ESCALATE.PUTROLEPOLICY.001`.

---


## Shadow logic namespace

The `identity.policy.shadow_logic.*` namespace tracks negative logic
patterns (NotAction, NotResource) in IAM policies.

| Property | Type | Description |
|---|---|---|
| `identity.policy.shadow_logic.has_not_action` | bool | Policy uses NotAction construct |
| `identity.policy.shadow_logic.has_not_resource` | bool | Policy uses NotResource construct |
| `identity.policy.shadow_logic.permits_iam_write_via_negative` | bool | Negative logic gap includes IAM write actions |
| `identity.policy.shadow_logic.shadowed_actions` | string[] | Actions that fall through the negative logic gap |

**Controls:** CTL.IAM.POLICY.SHADOW.001 (NotAction detected),
.002 (IAM write via negative logic).

---

## Service-wildcard grants

The `identity.policies.service_wildcards_granted` field is a list of AWS
service names (e.g., `cloudtrail`, `kms`, `aws-marketplace`) for which the
principal's attached policies include at least one Allow statement that
simultaneously:

1. Has `Action` matching `<service>:*` (explicitly named), and
2. Has `Resource` matching literal `"*"` (or a list containing `"*"`).

Service-wildcard grants are service-scoped but still exceed least-privilege
for specific high-blast-radius services — `cloudtrail:*` enables trail
tampering, `kms:*` enables full key management, `aws-marketplace:*` enables
resource provisioning with billing impact. Prowler's IAM service-wildcard
family and Pacu's equivalent checks treat this pattern as a distinct
finding class. The field is the raw signal that makes those checks
expressible; a future `CTL.IAM.POLICY.SERVICE_WILDCARD.001` (parameterized
on a `denied_service_wildcards` list) will consume it.

### Derivation rule

For each service `S` granted by any attached policy:

- Walk every statement in the principal's attached policies (inline and
  managed, direct and via group membership).
- Consider a statement if **all** of the following hold:
  - `Effect = Allow`
  - `Action` is a scalar or list containing a literal entry equal to
    `<S>:*`
  - `Resource` is either the literal string `"*"` or a list containing
    the literal string `"*"`
- If at least one statement matches all three conditions, add `S` to the
  field.

The two conditions (Action = `<S>:*` and Resource = `"*"`) must be
satisfied in the **same** statement. A policy with one statement granting
`<S>:*` on `"arn:aws:specific/*"` and a separate statement granting
`"s3:GetObject"` on `"*"` does **not** add `S` — neither statement
satisfies both conditions together.

### Explicit exclusions

| Construct | Treatment | Why |
|---|---|---|
| `NotAction: "<anything>"` statements | Not traversed by this field. | Covered by `identity.policy.shadow_logic.has_not_action` and `CTL.IAM.POLICY.SHADOW.001` / `.002`. |
| `NotResource: "<anything>"` statements | Not traversed by this field. | Covered by `identity.policy.shadow_logic.has_not_resource`. |
| `Effect: Deny` statements | Ignored. | The field captures the presence of the unsafe Allow. Any Deny that narrows the effective permission is a separate net-effective concern handled by `CTL.IAM.NEP.*`. |
| Condition-scoped Allows (e.g., `aws:PrincipalOrgID`, `aws:SourceVpc`, `aws:SourceIp` with CIDR, `aws:SourceArn`) | Ignored. The service is listed regardless of Condition. | Matches Prowler's methodology, which fires on the Allow grant itself. Parallel to `storage.access.has_wildcard_principal` (raw) vs `storage.access.policy_is_effectively_public` (Condition-aware). A Condition-aware effective variant of this field can ship later as a peer without breaking this one. |
| `Action: "*"` (bare — not scoped to a single service) | Not represented in this field. | Captured by `identity.policies.has_admin_access`. Predicates that want "does this principal have `<S>:*` effectively" should OR the two signals: `has_admin_access OR <S> in service_wildcards_granted`. |
| `Resource` values other than literal `"*"` (e.g., `arn:aws:*:*:*:*`) | Not treated as wildcard. | Narrow, mechanical definition. An "effectively-wildcarded ARN pattern" variant can land later if methodology demands it. |

### Null vs empty

- `null` (or field omitted) — the principal has no attached policies at
  all. No derivation was performed.
- `[]` (empty array) — policies exist but no statement satisfies both
  conditions. The derivation ran and produced a clean result.

Predicates that want to fire only on unsafe grants should gate on
`op: present` before checking array membership, the same pattern used by
`CTL.IAM.POLICY.SCOPING.001`'s predicate for
`storage.access.policy_has_scoping_condition`. Absence and empty both
indicate "no service-wildcard grant"; neither should produce a finding.

### Service-name normalization

Service names in the array use the **AWS API prefix form** verbatim:
`cloudtrail`, `kms`, `aws-marketplace`, `s3`, `ec2`, `iam`, etc. Not
capitalized, not the long-form service title. An extractor observing
`"Action": "CloudTrail:*"` (mixed case) must normalize to `cloudtrail`
before adding to the array — AWS IAM treats action prefixes as
case-insensitive, and the contract enforces the lowercase-prefix
convention for deterministic comparison.

**Controls:** none yet. The predicate and control work lands in a
separate follow-up iteration keyed on `params.denied_service_wildcards`.

---


## Vendor trust namespace

The `identity.vendor_trust.*` namespace tracks third-party SaaS
vendor access via cross-account roles.

| Property | Type | Description |
|---|---|---|
| `identity.vendor_trust.is_external_vendor` | bool | Role trusts an external vendor account |
| `identity.vendor_trust.vendor_name` | string | Vendor name (datadog, wiz, vanta, etc.) |
| `identity.vendor_trust.last_used_days_ago` | int | Days since role was last assumed |
| `identity.vendor_trust.is_dormant` | bool | Unused > 90 days |
| `identity.vendor_trust.reachable_sensitive_count` | int | Sensitive resources (PHI/PII) reachable |
| `identity.vendor_trust.has_external_id` | bool | Trust policy requires external ID |

**Controls:** CTL.IAM.VENDOR.DORMANT.001 (ghost access),
.OVERPRIVILEGED.001 (excessive sensitive reach).

---

## Trust policy namespace

The `identity.trust_policy.*` namespace tracks confused deputy
protection on IAM role trust policies. The extractor analyzes each
role's trust policy document and computes boolean flags indicating
whether protective conditions are present.

| Property | Type | Description |
|---|---|---|
| `identity.trust_policy.has_third_party_principal` | bool | Trust policy contains a principal from an AWS account outside the organization |
| `identity.trust_policy.confused_deputy_protected` | bool | Trust policy has sts:ExternalId or aws:SourceAccount condition (non-wildcard) |
| `identity.trust_policy.has_aws_service_principal` | bool | Trust policy contains an AWS service principal (*.amazonaws.com) |
| `identity.trust_policy.source_arn_protected` | bool | Trust policy has aws:SourceArn or aws:SourceAccount condition |

The extractor must classify each principal in the trust policy:
- **AWS service** — ends with `.amazonaws.com` (Lambda, S3, SNS, etc.)
- **Same-org account** — 12-digit account ID in the organization's account list
- **Third-party account** — 12-digit account ID NOT in the organization

A condition key set to `*` (wildcard) does NOT count as protection.

**Controls:** CTL.IAM.TRUST.CONFUSEDDEPUTY.001 (third-party trust
without ExternalId), CTL.IAM.TRUST.SOURCEARN.001 (service principal
without SourceArn).

---

## Entitlement entropy namespace

The `identity.*` namespace extends with properties for privilege creep
detection. The extractor computes these by analyzing attached policies,
Access Advisor last-accessed data, and the role's tag inventory.

| Property | Type | Description |
|---|---|---|
| `identity.role_active_days` | int | Days since role was created or last assumed |
| `identity.unused_service_ratio` | float | Ratio of services with last_authenticated nil or >90d to total accessible services |
| `identity.has_incompatible_categories` | bool | Role spans structurally incompatible permission category pairs |
| `identity.permission_categories` | []string | Categories present: data_read, data_write, iam_write, secrets_access, compute_control, etc. |
| `identity.intent_mismatch` | bool | Actual permission categories contradict declared role-type tag |
| `identity.entropy_data_complete` | bool | Access Advisor, policy inventory, and tags all present |
| `identity.tags.role-type` | string | Declared purpose: application, data-pipeline, readonly, admin, security, ci-cd, break-glass, service-account |

**Permission category taxonomy** — the extractor categorizes each
IAM action into one of: data_read, data_write, iam_read, iam_write,
secrets_access, compute_control, network_control, crypto_control,
crypto_use, audit_read, audit_control. A role is flagged for
incompatible categories when it spans pairs like data_read+iam_write,
compute_control+iam_write, or audit_control+data_read.

**Access Advisor** — the extractor calls
`iam:GenerateServiceLastAccessedDetails` (async) and
`iam:GetServiceLastAccessedDetails` to determine which services have
been used. Services with `last_authenticated` nil or older than 90
days count as unused.

**Controls:** CTL.IAM.ROLE.PERMISSIONDRIFT.001 (unused accumulation),
.CATEGORYMIX.001 (incompatible categories),
.INTENTTAG.001 (missing role-type tag),
.INTENTMISMATCH.001 (tag vs. actual),
.ENTROPY.INCOMPLETE.001 (missing data).

---


## `identity.tag_auth.*` — tag-based authorization scheme integrity (derived)

The collector parses the organization's SCPs and RCPs and emits one boolean per
layer of the tag-based authorization scheme, encoding **correctness** (a layer
present with the wrong condition key/operator reports `false`). On the
`aws_organization` asset (`identity.kind == organization`).

| Field | Type | Meaning |
|-------|------|---------|
| `identity.tag_auth.sensitive_actions_tag_gated` | bool | Every declared sensitive action is denied by an SCP with an `aws:PrincipalTag/<prefix>` condition (not `aws:RequestTag`). |
| `identity.tag_auth.tag_mutation_locked` | bool | All six tag-mutation actions are locked to the tagger role via `aws:TagKeys` (exempt prefix) + `StringNotLike` on `aws:PrincipalArn`. |
| `identity.tag_auth.session_tag_injection_blocked` | bool | Two **separate** RCP statements (OR logic), both scoped by exempt `aws:TagKeys`, deny `sts:TagSession` for non-tagger and out-of-org principals. |
| `identity.tag_auth.tagger_role_protected` | bool | All 13 IAM role-mutation actions denied on both the tagger and deployment role, exempting only the deployment role. |

Controls: `CTL.IAM.SCP.TAGAUTH.ENFORCE.001`, `CTL.IAM.SCP.TAGAUTH.MUTATION.001`, `CTL.IAM.RCP.TAGAUTH.SESSION.001`, `CTL.IAM.SCP.TAGAUTH.TAGGER.001`, and the compound `CTL.IAM.TAGAUTH.COMPLETE.001` (reads all four). Params (tag_prefix, tagger_role, deployment_role, sensitive_actions) are collector inputs; defaults `scp-`, `tagger`, `stacksets-exec-*`, and the four IAM credential actions.
