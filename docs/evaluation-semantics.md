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
- Recurrence checks count unsafe exposure windows in the configured window.

### Determinism details

- `now` defaults to the last snapshot's `captured_at`; the wall clock is used
  only in the zero-snapshot edge case (so always pass `--now` in CI).
- Findings are sorted by control ID then asset ID.
- Output contains no floating-point fields (durations are emitted as integer
  hours), avoiding cross-platform float formatting differences.

## Timeline Semantics

Stave builds a per-asset timeline from the ordered snapshots. Two rules govern
how the timeline interprets state changes:

- **Absence is not evidence of safety.** When an asset is missing from a
  snapshot, no state transition occurs — an asset that was unsafe stays unsafe.
  This prevents false negatives when an asset temporarily disappears from
  observations.

  ```
  t0: bucket public=true  → unsafe
  t1: bucket absent       → unsafe (unchanged)
  t2: bucket public=true  → unsafe (episode continues)
  ```

- **Open episodes stay open.** An episode closes only on explicit evidence of
  safety (an observed unsafe→safe transition). An episode still unsafe at the
  final snapshot remains open and is not treated as a completed, closed episode.

### Episode-based duration

Unsafe duration is measured from the start of the **current** episode, not the
first-ever unsafe observation. A bucket that went unsafe, was remediated, then
went unsafe again reports the duration of the latest episode. The "why now"
narrative reads "unsafe since &lt;current episode start&gt;". Recurrence findings
do not carry a duration, because the first-to-last span would include
intervening safe periods.

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

### Coverage, INCONCLUSIVE, and confidence

Stave tracks data-quality metrics per asset timeline — observation count, the
covered time span (first-seen to last-seen), and the largest gap between
consecutive observations. These gate certainty, never violations:

- **Duration controls:** when no violation is detected but the covered span is
  shorter than the `--max-unsafe` window (or a large observation gap leaves the
  window unverified), the decision is `INCONCLUSIVE` rather than `PASS`.
- **Recurrence controls:** when the covered span is shorter than the
  configured recurrence window, the decision is `INCONCLUSIVE`.

When a decision is not inconclusive, a separate **confidence** level is derived
from the largest observation gap relative to the required window:

- `high` — largest gap is at most 25% of the window
- `medium` — largest gap is at most 50% of the window
- `low` — largest gap exceeds 50% of the window

Confidence is independent of the decision: a `PASS` or `VIOLATION` can carry
`low` confidence when the supporting observations are sparse.

### Decision precedence

```
1. VIOLATION  (unsafe state with threshold exceeded)
2. INCONCLUSIVE  (insufficient coverage / large gaps)
3. PASS
```

`VIOLATION` always takes precedence over `INCONCLUSIVE`, so insufficient data
can never hide a confirmed security issue. The governing principle: never claim
safety when you only lack evidence of danger.

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
properties.storage.access.public_read
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
| `any_in_field` | List field has at least one element also in another field's list (complement of `not_subset_of_field`) |

## Missing-Field Semantics

Important behavior for control authors:

- Missing fields do **not** satisfy `eq false` — only explicitly set
  `false` triggers `eq false`.
- Missing fields **can** satisfy `ne <value>` — absence counts as
  "not equal."
- `missing` and `present` are explicit existence checks.

Use explicit predicates for absent/optional data to avoid accidental
matches.

### Fail-Open vs Fail-Closed by Operator

Stave's predicate operators split into two camps when the field they
test is absent. Knowing which camp matters when an extractor drops a
field — different operators interpret the absence differently.

| Operator | Missing-field interpretation | Reason |
|----------|------------------------------|--------|
| `eq`     | Field absent → rule does NOT match (fail-open)  | Cannot equal a value that was never set |
| `ne`     | Field absent → rule MATCHES (**fail-closed**)   | The author wrote `ne true` because that is the safety property; absence means "we cannot prove safety" |
| `gt`/`lt`/`gte`/`lte` | Field absent → does NOT match (fail-open) | A comparison against a missing number is undefined; "no signal" is not a violation |
| `in`     | Field absent → does NOT match (fail-open)       | Cannot be in a list when no value exists |
| `contains` | Field absent → does NOT match (fail-open)     | Same logic as `in` |
| `missing` | Field absent → matches when `value: true` (explicit) | This is the test for absence |
| `present` | Field absent → matches when `value: false` (explicit) | This is the test for presence |
| `list_empty` | Field absent → matches (treats absence as empty) | "Empty" includes "not there" |
| `*_field` operators | Either side absent → does NOT match (fail-open) | Cross-field comparisons need both to be present |

The asymmetry between `eq` and `ne` is **intentional**. A control
author writes `ne true` for properties that must be true to be safe
(`encryption_enabled`, `require_tls`). If the extractor drops that
field, a fail-open `ne` would silently pass the asset, which is the
opposite of what the author asked for. Fail-closed `ne` matches the
operator's safety reading: "I assert the field is NOT this value;
if there is no field, my assertion is unverified."

If you need `ne` to fail open (treat missing as pass), pair it with
an explicit `present` check:

```yaml
all:
  - field: properties.encryption_enabled
    op: present
    value: true
  - field: properties.encryption_enabled
    op: ne
    value: true
```

The `present` clause guards the `ne` so missing fields short-circuit
the rule before `ne`'s fail-closed semantics fire.

## Output Contract Version

Evaluation output uses schema version `out.v0.1` in the `schema_version`
field.

See:

- [Output Schema](schema/out.v0.1.md)
- [Observation Contract](contract/README.md)
- [Control Schema](schema/ctrl.v1.md)
