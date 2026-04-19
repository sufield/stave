# Entitlement Entropy — Shadow Admin Finder

Entitlement entropy detects privilege creep — the structural condition
where an IAM role has accumulated permissions beyond its original scope,
creating hidden lateral movement paths that do not appear dangerous when
viewed through any single permission in isolation.

## The problem

A role starts as `S3-ReadOnly`. Over two years, someone adds
`kms:Decrypt`, then `lambda:InvokeFunction`, then
`secretsmanager:GetSecretValue`, then `iam:GetRole`. The role is still
named `S3-ReadOnly`. It has no admin policy. No scanner that evaluates
permissions in isolation will flag it. But it can now read encrypted
PHI, trigger arbitrary Lambda functions, retrieve any secret, and
enumerate the IAM inventory. This is a Shadow Admin by accumulation.

## Three deterministic signals

### Signal 1: Unused permission accumulation

Source: AWS Access Advisor last-accessed data. A role with 30 accessible
services where 25 are never used has accumulated permissions far beyond
its operational scope.

**Control:** CTL.IAM.ROLE.PERMISSIONDRIFT.001 — fires when >20% of
services are unused for >90 days. Threshold overridable via
`stave/permission-drift-threshold` tag on the role.

### Signal 2: Permission category mixing

Source: permission action categorization against a defined taxonomy.
Structurally incompatible pairs: data_read + iam_write (access data
AND modify who else can), compute_control + iam_write (create compute
AND grant it permissions), audit_control + data_read (access data AND
cover tracks).

**Control:** CTL.IAM.ROLE.CATEGORYMIX.001 — fires when a role spans
any incompatible category pair.

### Signal 3: Tag-declared intent vs. actual permissions

Source: `role-type` tag value compared against a compatibility matrix.
A role tagged `readonly` with `iam_write` permissions is a governance
failure.

**Controls:** CTL.IAM.ROLE.INTENTTAG.001 (tag must exist),
CTL.IAM.ROLE.INTENTMISMATCH.001 (permissions must match tag).

## Safety chains

Two compound chains escalate when multiple signals fire simultaneously:

**shadow_admin_by_accumulation** — permission drift + category mixing
+ intent mismatch. Three signals confirm the role is a Shadow Admin.

**privilege_creep_lateral_movement** — category mixing + permission
drift. Data access combined with IAM write, plus high unused ratio.

## Business value

1. **Continuous access review** — SOC2 CC6.3, PCI-DSS 7.2, HIPAA
   164.312(a)(2)(i) all require periodic access reviews. These controls
   make privilege creep continuously detectable, not just at audit time.
2. **Blast radius reduction** — the unused permissions on a compromised
   role ARE the blast radius. Removing them shrinks the attack surface.
3. **Governance forcing function** — the `role-type` tag requirement
   converts access reviews from "read the name and guess" to "compare
   declared purpose against actual permissions."
4. **Evidence for remediation conversations** — Access Advisor data
   makes unused permissions an operational fact, not a security assertion.

## Observation properties

See [Observation Contract](contract/README.md#entitlement-entropy-namespace)
for the full property table.

## Key files

| File | Purpose |
|------|---------|
| `controls/iam/entropy/CTL.IAM.ROLE.PERMISSIONDRIFT.001.yaml` | Unused permission accumulation |
| `controls/iam/entropy/CTL.IAM.ROLE.CATEGORYMIX.001.yaml` | Incompatible category pairs |
| `controls/iam/entropy/CTL.IAM.ROLE.INTENTTAG.001.yaml` | Missing role-type tag |
| `controls/iam/entropy/CTL.IAM.ROLE.INTENTMISMATCH.001.yaml` | Tag vs. actual mismatch |
| `controls/iam/entropy/CTL.IAM.ROLE.ENTROPY.INCOMPLETE.001.yaml` | Missing data |
| `chains/shadow_admin_by_accumulation.yaml` | 3-signal compound chain |
| `chains/privilege_creep_lateral_movement.yaml` | 2-signal compound chain |
