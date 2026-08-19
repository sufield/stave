# Lab 04 — Predicates

A predicate is the evaluation rule inside a control. When it matches, the
state is unsafe.

## Anatomy of a Predicate

From CTL.IAM.TRUST.MFA.001:

```yaml
unsafe_predicate:
  all:
    - field: properties.identity.kind
      op: eq
      value: role
    - field: properties.identity.trust_policy.has_cross_account_trust
      op: present
    - field: properties.identity.trust_policy.has_cross_account_trust
      op: eq
      value: true
    - field: properties.identity.trust_policy.has_mfa_condition
      op: ne
      value: true
```

`all:` means every clause must match (conjunction). Each clause has three
parts: a field path, an operator, and an expected value.

## Operators

Stave supports 17 predicate operators:

| Operator | Meaning |
|----------|---------|
| `eq` | equals |
| `ne` | not equals |
| `gt`, `lt`, `gte`, `lte` | comparisons |
| `present` | field exists |
| `missing` | field does not exist |
| `in` | value in list |
| `contains` | substring or element match |
| `list_empty` | empty list |
| `any_match` | any list element matches |
| `not_subset_of_field` | list not subset of another |
| `neq_field` | differs from another field |
| `not_in_field` | value not in another field's list |
| `any_in_field` | list intersects another field |
| `any_identity_match` | iterate identities list |

Most controls use `eq`, `ne`, `present`, and `missing`.

## A Two-Clause Predicate

Now look at the AuthAge control:

```bash
stave explain CTL.IAM.TRUST.MFA.AUTHAGE.001 --controls internal/controls
```

```
Rules:
  - properties.identity.kind eq role (all[0])
  - properties.identity.trust_policy.has_mfa_condition present <nil> (all[1])
  - properties.identity.trust_policy.has_mfa_condition eq true (all[2])
  - properties.identity.trust_policy.has_multifactor_auth_age ne true (all[3])
```

This predicate is more subtle. It fires when MFA IS present
(`has_mfa_condition eq true`) but the MFA has no time-bound
(`has_multifactor_auth_age ne true`). The predicate defines the unsafe
state precisely: MFA exists but lacks teeth.

## Mental Model

Given the bad fixture from Lab 02, trace the evaluation:

1. `identity.kind eq role` → `"role" == "role"` → match
2. `has_mfa_condition present` → field exists → match
3. `has_mfa_condition eq true` → `true == true` → match
4. `has_multifactor_auth_age ne true` → `false != true` → match

All four match. The predicate fires. The state is unsafe.

## Verify

Using the clean fixture (`mfa-authage/clean/`), trace the same four rules.
Which rule breaks the match?

Next: [Lab 05 — Red-Green Loop](05-red-green-loop.md)
