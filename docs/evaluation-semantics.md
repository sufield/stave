---
title: "Evaluation Semantics"
sidebar_label: "Evaluation Semantics"
sidebar_position: 3
description: "Deterministic evaluation behavior, predicate matching rules, and output semantics."
---

# Evaluation Semantics

This page defines how Stave evaluates controls over observations and how results are produced.

## Determinism Model

Given the same:

- control files
- observation files
- CLI flags (including `--max-unsafe`)
- `--now` value

Stave produces identical output.

`--now` controls evaluation time for duration-based logic. For reproducible CI runs, always set `--now` explicitly.

## Snapshot Ordering

Observation snapshots are evaluated in ascending `captured_at` order.

- Duration checks use elapsed time across ordered snapshots.
- Recurrence checks count unsafe episodes in the configured window.

## Decision Model

Each evaluated `(control, resource)` pair yields one decision row when explain-all output is enabled.

Decision values:

- `VIOLATION`
- `PASS`
- `INCONCLUSIVE`
- `NOT_APPLICABLE`
- `SKIPPED`

The output summary aggregates violations and resource-level totals.

## Predicate Matching Rules

The control DSL evaluates `unsafe_predicate` using:

- `all`: logical AND
- `any`: logical OR

Nested predicates are supported.

Field lookup is path-based (for example, `properties.storage.visibility.public_read`).

## Predicate Operator Reference

Supported operators in `ctrl.v1`:

- `eq`
- `ne`
- `gt`
- `lt`
- `gte`
- `lte`
- `in`
- `missing`
- `present`
- `contains`
- `any_match`
- `neq_field`
- `not_in_field`
- `list_empty`
- `not_subset_of_field`

## Missing-Field Semantics

Important behavior for authoring:

- missing fields do not satisfy `eq false`
- missing fields can satisfy `ne <value>`
- `missing` and `present` are explicit existence checks

Use explicit predicates for absent/optional data to avoid accidental matches.

## Output Contract Version

Evaluation output uses schema version `out.v0.1` in the `schema_version` field.

See:

- [Output Schema](schema/out.v0.1.md)
- [Observation Schema](schema/obs.v0.1.md)
- [Control Schema](schema/ctrl.v1.md)
