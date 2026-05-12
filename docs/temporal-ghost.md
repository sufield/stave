# Temporal Ghost Detection

Shipped: `28b41bb9b`

A **temporal ghost** is a configuration reference that was valid in
a previous snapshot but is invalid in the current one — the
referenced resource was deleted between observations. Unlike
single-snapshot ghost detection (which compares references against
the *current* inventory and is vulnerable to extractor-race false
positives), temporal ghost detection compares against *historical*
inventory to confirm a resource genuinely existed-then-disappeared.

## Why this shape exists

Stave's broader ghost-reference family (23 controls covering IAM
policies, resource policies, event triggers, compute dependencies,
network infrastructure, cross-account trust, etc.) catches dangling
references against a single snapshot's inventory. That single-snapshot
mode has one structural weakness: if the collector races a deletion
and a re-creation, the reference can look like a ghost when it isn't.

Temporal ghost detection eliminates the race. A reference is
confirmed-ghost only when **two independent snapshots** witness the
disappearance — the referenced resource was present in snapshot N-1,
absent in snapshot N, and the reference persists. This is the
**highest-confidence** ghost finding the catalog produces.

The two controls that ship with this shape:

| Control | Shape | Severity |
|---|---|---|
| `CTL.GHOST.TEMPORAL.RESOURCE.001` | Resource present in snapshot N-1, absent in N, references persist in N | high |
| `CTL.GHOST.TEMPORAL.PERMISSION.001` | Policy Resource pattern broadened from specific ARN → wildcard between snapshots, coinciding with a resource deletion in the same window — a scope expansion disguised as cleanup | medium |

## `CTL.GHOST.TEMPORAL.RESOURCE.001`

Predicate:

```yaml
unsafe_predicate:
  all:
    - field: properties.governance.kind
      op: eq
      value: temporal_analysis
    - field: properties.governance.ghost.has_temporal_ghost
      op: eq
      value: true
```

The collector emits a synthetic `temporal_analysis` asset that
encodes the cross-snapshot comparison. `has_temporal_ghost` flips
to `true` only when both observations confirm the deletion — single
absence does not fire the control.

Severity inheritance (from the control description):

| Reference type | Severity |
|---|---|
| Write permissions to reclaimable resources | critical |
| Monitoring targets that disappeared | critical |
| Read permissions | high |
| Configuration references | medium |

## `CTL.GHOST.TEMPORAL.PERMISSION.001`

Predicate:

```yaml
unsafe_predicate:
  all:
    - field: properties.identity.kind
      op: eq
      value: role
    - field: properties.identity.policy.has_broadened_scope
      op: eq
      value: true
```

Detects a specific failure mode: someone tries to "fix" a ghost
reference by widening the policy's `Resource` pattern (e.g.,
`arn:aws:s3:::specific-bucket/*` → `arn:aws:s3:::*`). The widening
satisfies the ghost-reference detector but **expands the blast
radius** of any future re-creation. The resource that was deleted
was specific; the new wildcard pattern admits any future bucket the
account creates, including one an attacker could provision under
the same role's trust boundary.

Same pattern operators encounter in incident postmortems:
*"We deleted the bucket but the policy still referenced it. We
broadened the pattern to make the policy parse. Six months later
we created a new bucket and the role had read access we didn't
intend."*

## How the collector emits the temporal evidence

Stave's two-snapshot semantics handle this generically — the
collector compares snapshot N-1 against snapshot N during projection
and emits a `governance.temporal_analysis` asset carrying the
cross-snapshot booleans:

```json
{
  "id": "temporal-analysis-2026-05-11",
  "type": "aws_temporal_analysis",
  "vendor": "aws",
  "properties": {
    "governance": {
      "kind": "temporal_analysis",
      "ghost": {
        "has_temporal_ghost": true,
        "deleted_arn": "arn:aws:lambda:us-east-1:111122223333:function:archived-job",
        "snapshots": ["2026-05-04T00:00:00Z", "2026-05-11T00:00:00Z"]
      }
    }
  }
}
```

The control predicate reads only `has_temporal_ghost`; the
auxiliary fields surface in the finding's evidence block so an
auditor can see which ARN disappeared and across which window.

## Relationship to the broader ghost family

| Detection mode | Confidence | Example controls |
|---|---|---|
| Single-snapshot ghost (current-inventory check) | Standard — vulnerable to extractor races | `CTL.IAM.POLICY.GHOSTREF.001`, `CTL.CLOUDFRONT.GHOST.ORIGIN.001`, `CTL.COGNITO.GHOST.PRESIGNUP.001` (and 18 more) |
| **Temporal ghost (cross-snapshot confirmation)** | **Highest** — confirmed-deleted by two observations | `CTL.GHOST.TEMPORAL.RESOURCE.001`, `CTL.GHOST.TEMPORAL.PERMISSION.001` |

The two modes are **complementary**, not competing:

- Single-snapshot ghost fires immediately when a reference looks
  dangling. Useful for real-time CI/CD gating; some false-positive
  rate during collector races is acceptable when the cost of a
  false fix is low.
- Temporal ghost fires only after two snapshots confirm the
  deletion. Useful for audit-grade evidence and for compound chains
  that need a low-false-positive primitive.

## Related

- [`docs/time-features-audit.md`](time-features-audit.md) — full
  inventory of time-axis features; this control covers row 13.
- [`docs/compliance/owasp-nhi-top10.md`](compliance/owasp-nhi-top10.md)
  NHI1 (Improper Offboarding) — temporal-ghost is the
  highest-confidence flavor of the offboarding-failure family.
- E2E fixtures under
  [`testdata/e2e/e2e-forge-ghost-temporal-resource-001-{fail,pass}/`](../testdata/e2e/)
  and the permission variant exercise the predicates against
  synthesized two-snapshot observation pairs.
- The single-snapshot ghost family — 23 controls listed in
  [`README.md`](../README.md)'s Features section.

## Commit

The feature shipped in `28b41bb9b`:

> feat(ghostref): temporal ghost detection — capstone of ghost family
>
> 2 controls using time-series observation model to detect resources
> that became ghosts between snapshots. Highest-confidence ghost
> findings — confirmed by two independent observations.
