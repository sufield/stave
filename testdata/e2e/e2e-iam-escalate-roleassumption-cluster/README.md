# E2E Test: IAM role-assumption escalation cluster (Rhino two-technique pattern)

## Case summary

- **Pattern**: Privilege escalation via role assumption rather than self-policy
  modification. Two adjacent Rhino Security Labs techniques:
  - `sts:AssumeRole` into a role with broader permissions whose trust admits
    the principal.
  - `iam:UpdateAssumeRolePolicy` to add the principal to a role's trust, then
    assume it.
  The controls are kept separate because the remediation diverges — one is
  fixed by removing `sts:AssumeRole` or narrowing the target role's trust;
  the other is fixed by removing `iam:UpdateAssumeRolePolicy` or narrowing
  its Resource scope. Merging them would produce a finding that doesn't point
  at the correct fix.
- **Controls exercised**: `CTL.IAM.ESCALATE.ASSUMEROLE.001` and
  `CTL.IAM.ESCALATE.UPDATETRUST.001`, both gated on `identity.kind == "user"`
  and on their technique-specific `.present == true`.

## Assets

| Principal | Technique populated | Fires |
|---|---|---|
| `alice-assume-role` | `assume_role.present = true` (target=admin-deploy-role, trust_pathway=direct) | ✅ `ASSUMEROLE.001` |
| `bob-update-trust` | `update_trust_policy.present = true` (target=admin-deploy-role, resource_scope=wildcard) | ✅ `UPDATETRUST.001` |
| `carol-both-techniques` | both `.present = true` (target=break-glass, trust_pathway=account-root) | ✅ `ASSUMEROLE.001` + `UPDATETRUST.001` |
| `dana-clean` | both `.present = false` | — |
| `some-service-role` | `kind = role` + both `.present = true` | ✅ `ASSUMEROLE.001` + `UPDATETRUST.001` (role-side coverage — kind gate lifted) |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.IAM.ESCALATE.ASSUMEROLE.001` | critical | `assume_role.present=true` (any principal kind) | 3 |
| `CTL.IAM.ESCALATE.UPDATETRUST.001` | critical | `update_trust_policy.present=true` (any principal kind) | 3 |
| **Total** | | | **6** |

## Expected result

- Exit code: 3
- Findings: 6
- Assets evaluated: 5, unsafe: 4 (Carol fires twice; the role fires twice)

## Notes on compounding

Carol exhibits both techniques — the full two-step Rhino pattern. Each control
fires independently because each has its own remediation; the RiskEngine
produces the compound reading (both techniques on the same principal with
overlapping target role) without any new engine wiring. Same emergent-
compound rule established by the ACCESS.004 + CONTROLS.001 pair and the
AP.BYPASS.001 + AP.POLICY.001 pair in earlier iterations.

`has_external_id_requirement` on the `assume_role` sub-object is captured
faithfully (false in the fixture) even though it does not prevent the
finding — it's a diagnostic that helps an operator decide whether the role
was *supposed* to require an ExternalId and lost it in drift, versus was
intentionally broad.

`trust_pathway` values in the fixture exercise both `direct` (the trust
policy names the principal's ARN) and `account-root` (the trust delegates
to the account root, which relies on an IAM permission grant to the
principal to be useful).

The role asset fires both controls — this coverage was lifted in the
role-side coverage iteration after the initial Cluster 2 commit. Role
chaining (a role assuming another role via `sts:AssumeRole`) and roles
holding `iam:UpdateAssumeRolePolicy` are both well-documented methodology
patterns; the original Cluster 2 commit gated on `identity.kind == user`
as a scope boundary and that gate was lifted once the full 19-control
audit confirmed the `.present` booleans were already principal-kind-
agnostic.

`args.txt` uses `--allow-unknown-input` because the fixture snapshots carry
no `generated_by.source_type` — same convention as every other escalation
fixture (`e2e-iam-escalate-startbuild`, `e2e-iam-escalate-passrole-*`,
`e2e-iam-escalate-self-cluster`).
