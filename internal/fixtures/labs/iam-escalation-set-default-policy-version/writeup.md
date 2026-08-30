# CreatePolicyVersion Escalation Scenario

## Corrected Fact

`iam:CreatePolicyVersion` accepts a `SetAsDefault` parameter (boolean)
that activates the new version immediately. A principal with only
`iam:CreatePolicyVersion` — without `iam:SetDefaultPolicyVersion` — can
create a new policy version granting `"Action": "*"` and make it the
default in a single API call. `iam:SetDefaultPolicyVersion` is a
separate standalone vector (switching between existing versions).

Source: AWS IAM API Reference, `CreatePolicyVersion` — `SetAsDefault`
parameter, type Boolean.

Prior partial encoded `has_set_default: false` as compensating. This is
incorrect: the absence of `iam:SetDefaultPolicyVersion` does not prevent
escalation via `iam:CreatePolicyVersion`.

## Fixtures

### bad
User with `iam:CreatePolicyVersion` on `*`, no boundary. Direct
escalation path.

### bad-boundary-versionable (trap)
User with customer-managed boundary B and `iam:CreatePolicyVersion` on
`*`. The grant covers B's ARN, so the user can create a new version of
the boundary itself — "has boundary" is NOT a compensator when the
boundary is versionable.

### partial (boundary-capped)
User with customer-managed boundary B (read-only). Grant scoped to
`arn:aws:iam::111122223333:policy/AppPolicy` only. AppPolicy is
attached to the user. The user can version AppPolicy but NOT the
boundary — the boundary caps effective permissions.

### clean
No `iam:CreatePolicyVersion` grant. No escalation path.

## Trap Pair Differential

bad-boundary-versionable and partial differ only in the grant's
`Resource` element:

| Field | Trap | Partial |
|---|---|---|
| `target_policy_arn` | `arn:aws:iam::111122223333:policy/*` | `arn:aws:iam::111122223333:policy/AppPolicy` |
| `boundary.permissions_boundary_set` | true | true |
| Boundary versionable? | Yes (grant covers boundary ARN) | No (grant scoped to AppPolicy) |
| Escalation outcome | Exploitable | Not exploitable |

## Chain-Layer Table

| Fixture | Atomic | Expected | Actual | Status |
|---|---|---|---|---|
| bad | 1 | exploitable | exploitable | MATCH |
| bad-boundary-versionable | 1 | exploitable | exploitable | MATCH |
| partial (boundary-capped) | 1 | not-exploitable | exploitable | EVIDENCE-GATED |
| clean | 0 | 0 | 0 | MATCH |

### EVIDENCE-GATED: partial

The engine classifies the boundary-capped partial as `exploitable`
because the control predicate tests only `present: true`. Distinguishing
boundary-capped from uncapped requires grant-resource ∩
boundary-versionability reasoning — a field the collector contract does
not yet provide. The atomic finding is correct (the grant exists); the
chain-layer overcount is the gap.

## Chain-Layer Known Answers: Other Partials

Recorded, not rebuilt. These partials belong to their own scenarios.

| Scenario | Partial Configuration | Atomic | Expected | Actual | Status |
|---|---|---|---|---|---|
| CreateLoginProfile | self-scoped (`user/${aws:username}`) | 1 | 0 (persistence) | one_away | MISMATCH |
| UpdateLoginProfile | MFA-gated (`target_has_mfa: true`) | 1 | one_away | one_away | MATCH |

### MISMATCH: CreateLoginProfile self-scoped

The engine reports `one_away` for a self-scoped CreateLoginProfile.
Expected: 0 (self-scoped is persistence, not escalation — the user
already has the principal's permissions). The engine does not reason
about `resource_scope` containing `${aws:username}`, which limits the
action to the caller's own user. Deferred: chain-layer resource-scope
reasoning.
