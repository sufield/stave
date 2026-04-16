# CEL Predicate Reference

Complete reference for the Common Expression Language predicates used in control `unsafe_predicate` blocks.

---

## Property Access

Properties are accessed via dot notation on the `properties` field path:

```
properties.storage.kind
properties.compute.network.imdsv2_required
properties.storage.tags.team
```

Nested maps are traversed with dots. Array elements are not directly indexed — use list operations.

## Operators

### Comparison Operators (ctrl.v1 DSL)

| Operator | Meaning | Example |
|----------|---------|---------|
| `eq` | Equals | `field: properties.x, op: eq, value: true` |
| `ne` | Not equals | `field: properties.x, op: ne, value: "enabled"` |
| `gt` | Greater than | `field: properties.count, op: gt, value: 10` |
| `lt` | Less than | `field: properties.count, op: lt, value: 5` |
| `gte` | Greater than or equal | `field: properties.age, op: gte, value: 90` |
| `lte` | Less than or equal | `field: properties.age, op: lte, value: 30` |
| `in` | Value in list | `field: properties.region, op: in, value: ["us-east-1", "us-west-2"]` |
| `missing` | Field does not exist | `field: properties.tags.team, op: missing, value: true` |
| `present` | Field exists | `field: properties.encryption, op: present, value: true` |
| `list_empty` | List is empty | `field: properties.rules, op: list_empty, value: true` |
| `contains` | String contains substring | `field: properties.arn, op: contains, value: "prod"` |

### Logic Blocks

```yaml
unsafe_predicate:
  all:                    # AND — all conditions must be true
    - field: properties.x
      op: eq
      value: false
    - field: properties.y
      op: eq
      value: false

  any:                    # OR — at least one must be true
    - field: properties.x
      op: eq
      value: false
    - field: properties.y
      op: eq
      value: false
```

Nesting is supported:

```yaml
unsafe_predicate:
  all:
    - field: properties.kind
      op: eq
      value: bucket
    - any:
        - field: properties.public
          op: eq
          value: true
        - field: properties.policy_public
          op: eq
          value: true
```

## isMissing Behavior

When a predicate references a field that does not exist in the asset properties:

- **`eq` / `ne` operators**: The evaluation engine calls `isMissing()`. If the field is structurally absent (no such key in the properties map), the predicate returns an error and the verdict is **INCONCLUSIVE**.
- **`missing` operator**: Explicitly checks for absence. Returns `true` when the field does not exist. Does not produce INCONCLUSIVE.
- **`present` operator**: Returns `false` when the field does not exist. Does not produce INCONCLUSIVE.

This distinction is critical for the `stave coverage` silent risk detection: a predicate using `eq` on a potentially absent field may produce INCONCLUSIVE or a false PASS depending on the predicate structure.

## Type Coercion

Boolean string coercion is applied during property normalization:

| Input | Coerced To |
|-------|------------|
| `"true"` (string) | `true` (bool) |
| `"false"` (string) | `false` (bool) |
| `"True"`, `"TRUE"` | `true` (bool) |
| `"False"`, `"FALSE"` | `false` (bool) |

Numeric strings are NOT coerced. `"42"` remains a string.

## Common Patterns

### Tag existence check

```yaml
- field: properties.storage.tags.team
  op: missing
  value: true
```

### Asset type guard

```yaml
all:
  - field: properties.compute.kind
    op: eq
    value: instance
  - field: properties.compute.network.has_public_ip
    op: eq
    value: true
```

The first rule acts as a type guard — the second rule only applies to assets where `kind == "instance"`.

### Negated existence (field must exist)

```yaml
- field: properties.encryption.key_arn
  op: missing
  value: false
```

This checks that the field IS present (`missing == false`).

## Error Conditions

| Condition | Verdict |
|-----------|---------|
| Field absent, operator is `eq`/`ne` | INCONCLUSIVE |
| Field absent, operator is `missing`/`present` | Evaluates normally |
| Type mismatch (string compared to bool) | INCONCLUSIVE |
| CEL compilation error (malformed predicate) | INCONCLUSIVE (logged at Error) |
| Division by zero or arithmetic error | INCONCLUSIVE |
