# E2E Test: IAM direct self-escalation cluster (Rhino techniques 1-6)

## Case summary

- **Pattern**: Privilege-escalation techniques where an IAM principal modifies its
  own policies or group memberships to grant itself broader permissions. Rhino
  Security Labs cluster covering the six "direct policy manipulation on self"
  techniques; same set Prowler's `iam_policy_allows_privilege_escalation` and
  Pacu's `iam__privesc_scan` enumerate.
- **Controls exercised**: six per-technique `CTL.IAM.ESCALATE.*.001` controls,
  each gated on `identity.kind == "user"` plus `<technique>.present == true`.
- **Regression guard**: verifies each technique fires only on its own user and
  that the `kind == user` gate suppresses role assets even when they carry the
  same escalation field.

## Assets

| Principal | Technique populated | Fires |
|---|---|---|
| `alice-attach-user-self` | `attach_user_policy_self.present = true` (resource_scope=self) | ✅ `ATTACHUSERPOLICY.001` |
| `bob-put-user-self` | `put_user_policy_self.present = true` (resource_scope=wildcard) | ✅ `PUTUSERPOLICY.001` |
| `carol-attach-group` | `attach_group_policy.present = true` (target_group=developers) | ✅ `ATTACHGROUPPOLICY.001` |
| `dave-put-group` | `put_group_policy.present = true` (target_group=developers) | ✅ `PUTGROUPPOLICY.001` |
| `eve-create-policy-version` | `create_policy_version.present = true` (via-group developers) | ✅ `CREATEPOLICYVERSION.001` |
| `frank-add-to-group` | `add_user_to_group.present = true` (target_group=admins, permission_delta=[iam:*, s3:*]) | ✅ `ADDUSERTOGROUP.001` |
| `grace-clean` | every user-side technique `.present = false` | — |
| `some-service-role` | `kind = role` + user-only techniques AND role-side techniques `.present = true` | ✅ `ATTACHROLEPOLICY.001` + `PUTROLEPOLICY.001` (user-only ones stay suppressed by the kept user-gate) |
| `heidi-clean-role` | `kind = role` + both role-side techniques `.present = false` | — |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001` | critical | `kind=user AND attach_user_policy_self.present=true` | 1 |
| `CTL.IAM.ESCALATE.PUTUSERPOLICY.001` | critical | `kind=user AND put_user_policy_self.present=true` | 1 |
| `CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001` | critical | `kind=user AND attach_group_policy.present=true` | 1 |
| `CTL.IAM.ESCALATE.PUTGROUPPOLICY.001` | critical | `kind=user AND put_group_policy.present=true` | 1 |
| `CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001` | critical | `create_policy_version.present=true` (any principal kind) | 1 |
| `CTL.IAM.ESCALATE.ADDUSERTOGROUP.001` | critical | `kind=user AND add_user_to_group.present=true` | 1 |
| `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001` | critical | `kind=role AND attach_role_policy.present=true` | 1 |
| `CTL.IAM.ESCALATE.PUTROLEPOLICY.001` | critical | `kind=role AND put_role_policy.present=true` | 1 |
| **Total** | | | **8** |

## Expected result

- Exit code: 3
- Findings: 8
- Assets evaluated: 9, unsafe: 7

## Notes

The diagnostic sub-fields (`target_user_arn`, `resource_scope`,
`reachable_managed_policies`, `target_group`, `attachment_path`, `has_create_version`,
`has_set_default`, `permission_delta`) are present on each failing asset so a
CI operator reading the finding can identify the specific permission
configuration that enabled the technique without opening the AWS console.
Controls don't predicate on these sub-fields — they carry context for humans and
for downstream consolidation.

The role asset (`some-service-role`) intentionally carries BOTH user-only
techniques (`attach_user_policy_self`, `put_user_policy_self`) and role-side
techniques (`attach_role_policy`, `put_role_policy`) set to `.present = true`.
The user-only controls stay silent on it because their AWS actions
(`iam:AttachUserPolicy`, `iam:PutUserPolicy`) literally do not target roles;
the kept user-gate on those controls suppresses the role even when the field
is populated. The two role-side controls fire as intended. This asset
verifies both gate directions — user-gated stays silent on role, role-gated
fires on role — in a single observation.

`heidi-clean-role` is the role-side counterpart to `grace-clean` — both
role-side techniques `.present = false`, stays silent.

The fixture snapshots have no `generated_by.source_type`, which Stave accepts
by default — the same as every escalation fixture in this repo
(`e2e-iam-escalate-startbuild`, `e2e-iam-escalate-passrole-*`).
