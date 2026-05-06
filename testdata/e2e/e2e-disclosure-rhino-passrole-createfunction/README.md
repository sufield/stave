# Disclosure: Rhino Security Labs — IAM PassRole + Lambda CreateFunction

Source: Spencer Gietzen, *AWS IAM Privilege Escalation Methods*,
Rhino Security Labs (2018) — public research catalogue of 24 IAM
privilege-escalation paths, also enumerated by Pacu's
`iam__privesc_scan` and Prowler's
`iam_policy_allows_privilege_escalation`.

## Pattern

A principal holds three capabilities that compose into admin:

1. `iam:PassRole` reaching a role whose effective permissions
   exceed the principal's own (here, an admin Lambda execution
   role).
2. `lambda:CreateFunction` — the principal can author a new
   Lambda function under that role.
3. An invocation vector — `lambda:InvokeFunction`, a function
   URL, or any wired trigger — that lets the principal cause
   the function to run.

Any code the principal uploads runs with the target role's
authority. This is a one-pivot path from non-admin to admin.

## Fixture mechanics

- Asset: `aws_iam_user` `mallory` with
  `identity.escalation.passrole_createfunction.present: true`.
- Permission delta: `iam:CreatePolicy`, `iam:AttachRolePolicy`,
  `s3:*` — non-trivially exceeds the principal's own scope.
- Both snapshots are unsafe (the privesc path persists across
  the window).

Control fired: `CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001`.
