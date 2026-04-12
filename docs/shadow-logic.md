# Shadow Logic Detection

Shadow logic detection answers: "Do your IAM policies accidentally
allow dangerous actions through negative logic gaps?"

IAM policies using `NotAction` or `NotResource` create implicit
grants for everything outside the exclusion list. As AWS adds new
services and actions, these implicit grants grow silently — a
policy written today that excludes 10 actions will inadvertently
allow the 11th action added next quarter.

## The shadow effect

```
Policy: "Allow all actions EXCEPT [list of 50 actions]"
Reality: Allows iam:PutRolePolicy (not in the exclusion list)
Result: Privilege escalation via negative logic gap
```

A `NotAction` policy says "everything except X." But the exclusion
list is never complete. Attackers enumerate the gap to find actions
like `iam:PutRolePolicy`, `iam:CreateUser`, or
`iam:AttachRolePolicy` that fall through.

## How it works

The extractor parses IAM policy documents, identifies `NotAction`
and `NotResource` constructs, and resolves the effective permissions
that fall through the negative logic gap:

```yaml
properties:
  identity:
    kind: policy
    policy:
      shadow_logic:
        has_not_action: true
        has_not_resource: false
        permits_iam_write_via_negative: true
        shadowed_actions: ["iam:PutRolePolicy", "iam:CreateUser"]
```

## Controls

### CTL.IAM.POLICY.SHADOW.001 — NotAction construct detected

```
Fires when: has_not_action == true
Severity: high
```

The policy uses negative logic. All actions outside the exclusion
list are implicitly allowed.

**Remediation:** Replace `NotAction` with an explicit `Action` list.
Enumerate the specific actions needed.

### CTL.IAM.POLICY.SHADOW.002 — IAM write via negative logic

```
Fires when: permits_iam_write_via_negative == true
Severity: critical
```

The negative logic gap includes IAM write actions. An attacker can
exploit this to escalate privileges.

**Remediation:** Ensure `iam:PutRolePolicy`, `iam:CreateUser`,
`iam:AttachRolePolicy`, and `iam:CreatePolicyVersion` are either
explicitly denied or absent from the allowed actions.

## Safety chain: shadow_logic_escalation

```yaml
id: shadow_logic_escalation
controls:
  - CTL.IAM.POLICY.SHADOW.001
  - CTL.IAM.POLICY.SHADOW.002
  - CTL.IAM.POLICY.ESCALATION.001
escalation_threshold: 2
compound_severity: critical
```

## Key files

| File | Purpose |
|---|---|
| `controls/iam/policy/CTL.IAM.POLICY.SHADOW.001-002.yaml` | 2 shadow logic controls |
| `chains/shadow_logic_escalation.yaml` | Compound chain definition |
