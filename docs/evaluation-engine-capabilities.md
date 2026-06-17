---
title: "Evaluation Engine Capabilities"
sidebar_label: "Engine Capabilities"
description: "What Stave's CEL-backed evaluation engine supports, what the shipped S3 / IAM / DocumentDB controls actually exercise, and what is retained as candidate code for future domains."
---

# Evaluation Engine Capabilities

This page inventories what the evaluation engine can express, not
what the shipped catalog uses. The split matters: several
operators and features were built for domains that the MVP catalog
does not yet ship controls for (network reachability, identity
chains, recurrence over time-series). They are real, tested, and
reachable — they just have no production caller today.

When a reference says *"used by S3 controls"* the feature has at
least one shipped YAML invoking it; *"candidate"* means the engine
supports it but no shipped control exercises it yet. Both kinds
are stable: the engine surface is the contract, not the catalog's
current usage.

## Predicate Operators

The closed vocabulary of operators the `unsafe_predicate` YAML
can use. New operators require a code change; arbitrary user
expressions are deliberately not supported.

| Op | Meaning | Exercised by shipped controls |
|----|---------|------------------------------|
| `eq` | Field equals literal | Yes |
| `ne` | Field differs from literal | Yes |
| `in` | Field value is one of a literal list | Yes |
| `missing` | Field is absent from the asset | Yes |
| `present` | Field is set (non-null, non-empty) | Yes |
| `contains` | Field's string / list contains a literal | Yes |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison against a literal | Yes |
| `any_match` | At least one element of a list field matches a sub-predicate | Yes |
| `any_in_field` | At least one element of list A is also in list B (intersection ≠ ∅) | Yes |
| `not_subset_of_field` | List A has at least one element not in list B | Yes (cross-account access controls) |

Each operator is single-purpose. Composite logic comes from
`any` / `all` predicate nodes — not from operator overloading.

## Predicate Composition

Tree shape (`controls/*.yaml`):

```yaml
unsafe_predicate:
  all:                    # AND
    - field: encryption.enabled
      op: eq
      value: false
    - any:                # OR
        - field: policy.principal
          op: eq
          value: "*"
        - field: acl.public_read
          op: eq
          value: true
```

- `all` — every child must hold (logical AND)
- `any` — at least one child must hold (logical OR)
- Leaves are field-op-value triples

Nesting is unrestricted; the engine evaluates depth-first with
short-circuiting.

## Control Types

Every control declares a `type` that selects its evaluation
strategy. The engine implements five:

| Type | Status |
|------|--------|
| `unsafe_state` | Used — the default; the large majority of shipped controls |
| `unsafe_duration` | Used — multi-snapshot dwell measurement |
| `unsafe_recurrence` | Used — asset re-entering an unsafe state within a window |
| `prefix_exposure` | Used — violation when protected prefixes are publicly readable |
| `marker` | Used — records an informational fact for chain composition; never a violation on its own |

The `ctrl.v1` schema rejects any `type` outside these five at load
time. A control whose `type` is empty or otherwise unrecognized
resolves to the internal `unknown` type, which has no strategy: it
is **skipped**, not failed — it appears in `skipped_controls` with
reason *"control type cannot be evaluated"*.

## Asset Evaluation

The engine binds an asset's `properties` map to CEL variables
using dotted-path lookups (`storage.encryption.algorithm` →
`properties.storage.encryption.algorithm`). Missing intermediate
keys collapse to `missing` rather than runtime errors — so a
control written against optional fields does not crash on assets
that never set them.

| Feature | Status |
|---------|--------|
| Dotted-path access into nested maps | Used by all controls |
| List indexing and `any_match` traversal | Used by S3, IAM, DocumentDB |
| Cross-field comparison within one asset | Used (`not_subset_of_field`) |
| Cross-asset evaluation (joins across snapshots) | **Candidate** — engine supports it via chain definitions, not exposed through `ctrl.v1` YAML |

## Time and Duration

`unsafe_duration` controls measure how long an asset has been in
an unsafe state across snapshots.

| Feature | Status |
|---------|--------|
| Single-snapshot evaluation (`unsafe_state`) | Used |
| Multi-snapshot duration measurement (`unsafe_duration`) | Used |
| Approaching-threshold risk signals (configurable percentage of `--max-unsafe`) | Used |
| Recurrence detection (asset re-entering unsafe state after exiting) | **Candidate** — engine plumbing present; no shipped control invokes it |
| Time-of-day / business-hours windows | Not implemented |

## Identity & Chain Evaluation

Chains compose individual control findings into attack-path
verdicts using a closed capability vocabulary (`audit_trail_destroyed`,
`s3_data_access`, `iam_credential_theft`, etc., defined in
`internal/core/capabilities/capabilities.go`).

| Feature | Status |
|---------|--------|
| Capability tagging on control findings | Used (`compound_risk` definitions in chains) |
| Chain pre/post-condition evaluation | Used (HIPAA compound chains, IAM privesc patterns) |
| Identity reachability across roles and policies | **Candidate** — IAM blast-radius examples exercise this through the library API; no `ctrl.v1` control composes it as a chain yet |
| Multi-account capability propagation | **Candidate** — exercised in `examples/iam-21-privesc-5-patterns/`, not in shipped chain YAML |

## Output Surface

What the engine emits regardless of catalog domain.

| Output | Status |
|--------|--------|
| `findings[]` with control ID, asset ID, evidence | Used |
| `risk_signals[]` for approaching-threshold items | Used |
| `remediation_groups[]` clustering same-fix findings per asset | Used |
| Logic trace JSON (`apply --trace`) — step-by-step reasoning record | Used |
| SARIF v2.1.0 export | Used |
| SIR fact export (`stave export-sir`) — JSON / JSONL / SMT-LIB v2 for external reasoning engines | Used |
| Schema-validated outputs (`out.v0.1`, `diagnose.v1`) | Used |

## Why The Split Exists

The candidate code is not dead code. It is reachable through the
library API (`pkg/stave`) and exercised by the
`examples/` programs. It is "candidate" in the sense that no
shipped YAML control currently invokes it through the standard
`stave apply` path. The split is intentional:

1. The catalog ships only what has fixtures, golden tests, and
   review sign-off as a shipped control.
2. The engine carries forward features built for domains the
   catalog will reach in MVP 1.0+ (network reachability, identity
   propagation, time-series recurrence).
3. New domains add controls, not engine changes — the engine is
   already broader than the catalog.

See [Limits](project/limits.md) for the inverse — what the engine
deliberately does not do.

## Related

- [Controls Reference](controls/reference.md) — every shipped YAML
- [Stave and Z3](../../docs-content/explanation/z3-solver.md) — when CEL is not the right tool
- [Fact Export](../../docs-content/reference/fact-export.md) — the 24-predicate vocabulary the engine exports
- [Reasoning Engines (how-to)](../../docs-content/how-to/reasoning-engines.md) — picking + running an external engine
