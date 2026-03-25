---
title: "Evaluation Semantics"
sidebar_label: "Evaluation Semantics"
sidebar_position: 3
description: "Deterministic evaluation behavior, predicate matching rules, and output semantics."
---

# Evaluation Semantics

This covers how Stave evaluates controls over observations and how results
are produced.

## Determinism Model

Given the same:

- control files
- observation files
- CLI flags (including `--max-unsafe`)
- `--now` value

Stave produces identical output.

`--now` controls evaluation time for duration-based logic. For reproducible
CI runs, always set `--now` explicitly.

## Snapshot Ordering

Observation snapshots are evaluated in ascending `captured_at` order.

- Duration checks use elapsed time across ordered snapshots.
- Recurrence checks count unsafe episodes in the configured window.

## Decision Model

Each evaluated `(control, asset)` pair yields one decision row when
explain-all output is enabled.

Decision values:

- `VIOLATION`
- `PASS`
- `INCONCLUSIVE`
- `NOT_APPLICABLE`
- `SKIPPED`

The output summary aggregates violations and asset-level totals.

## Predicate Evaluation (CEL)

Control predicates defined in `unsafe_predicate` are compiled to
[CEL (Common Expression Language)](https://github.com/google/cel-spec)
expressions and evaluated by the `cel-go` runtime. This provides:

- Type-safe expression evaluation
- Thread-safe compiled program caching
- Deterministic results across platforms

The compilation pipeline:

1. YAML `unsafe_predicate` rules are parsed into `policy.UnsafePredicate`
2. The CEL compiler translates each predicate into a CEL expression
3. Compiled programs are cached by expression string for reuse
4. At evaluation time, asset properties are bound as CEL variables

### Logical Combinators

- `all`: logical AND — every rule must match for the predicate to be true
- `any`: logical OR — at least one rule must match

Nested combinators are supported (e.g., `any` containing `all` blocks).

### Field Lookup

Field references use dot-separated paths into asset properties:

```
properties.storage.visibility.public_read
```

The CEL environment resolves these paths against the flattened asset
property map at evaluation time.

### Parameterized Controls

Controls can reference dynamic values via `value_from_param`:

```yaml
unsafe_predicate:
  any:
    - field: properties.storage.tags.data-classification
      op: in
      value_from_param: sensitive_classifications
params:
  sensitive_classifications:
    - phi
    - pii
```

Parameters are resolved from the control's `params` map before CEL
compilation.

### Semantic Aliases

Common predicate patterns are available as named aliases (e.g.,
`s3.is_public_readable`, `s3.has_full_control_public`). Aliases expand to
full `unsafe_predicate` blocks at load time. See `stave controls aliases`
to list available aliases.

## Predicate Operator Reference

Supported operators in `ctrl.v1`:

| Operator | Description |
|----------|-------------|
| `eq` | Equal (exact match) |
| `ne` | Not equal |
| `gt` | Greater than |
| `lt` | Less than |
| `gte` | Greater than or equal |
| `lte` | Less than or equal |
| `in` | Value is in a list |
| `missing` | Field does not exist |
| `present` | Field exists |
| `contains` | String/list contains value |
| `any_match` | Any element in list matches |
| `neq_field` | Not equal to another field's value |
| `not_in_field` | Value not in another field's list |
| `list_empty` | List field is empty |
| `not_subset_of_field` | Not a subset of another field's list |

## Missing-Field Semantics

Important behavior for control authors:

- Missing fields do **not** satisfy `eq false` — only explicitly set
  `false` triggers `eq false`.
- Missing fields **can** satisfy `ne <value>` — absence counts as
  "not equal."
- `missing` and `present` are explicit existence checks.

Use explicit predicates for absent/optional data to avoid accidental
matches.

## Output Contract Version

Evaluation output uses schema version `out.v0.1` in the `schema_version`
field.

See:

- [Output Schema](schema/out.v0.1.md)
- [Observation Contract](observation-contract.md)
- [Control Schema](schema/ctrl.v1.md)
