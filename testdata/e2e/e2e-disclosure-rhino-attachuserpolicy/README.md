# Disclosure: Rhino Security Labs — iam:AttachUserPolicy on self

Source: Spencer Gietzen, *AWS IAM Privilege Escalation Methods*,
Rhino Security Labs (2018), technique #1 — "IAM — Attach to user".
Also covered by Pacu's `iam__privesc_scan` and Prowler's
`iam_policy_allows_privilege_escalation`.

## Pattern

A principal holds `iam:AttachUserPolicy` whose Resource field
includes its own user ARN (explicitly, via `"*"`, or via a
user-set that contains it). One API call —
`AttachUserPolicy --user-name self --policy-arn AdministratorAccess`
— makes the principal admin. No other permission, vulnerability,
or social step is required.

This is the cleanest one-step privesc in Rhino's catalogue and
remains relevant because least-privilege scoping of IAM
self-management is easy to get wrong (operators routinely
grant `iam:*` on `Resource: "*"` to user-management roles).

## Fixture mechanics

- Asset: `aws_iam_user` `eve` with
  `identity.escalation.attach_user_policy_self.present: true`.
- Resource scope: `self` — the user's own ARN is in the policy
  Resource field.
- Reachable managed policies includes
  `arn:aws:iam::aws:policy/AdministratorAccess`.
- Both snapshots are unsafe (the privesc path persists).

Control fired: `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`.
