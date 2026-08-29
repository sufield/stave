---
title: "Architectural Boundaries"
sidebar_label: "Boundaries"
sidebar_position: 2
description: "What Stave verifies, what it deliberately does not, and where downstream trust attaches. Three boundaries are observation value correctness, clock pinning, and ghost-reference cross-inventory. These are architectural decisions."
---

# Architectural Boundaries

Stave is a pure-function evaluator: files in, findings out, no network, credentials or exec. Three properties operators commonly assume are checked by Stave fall **outside** that function. 

They are decisions the architecture forces, with corresponding operational responsibilities elsewhere in the pipeline. 

## What Stave verifies

**Observation structure.** 

JSON Schema conformance against `obs.v0.1`. Wrong types, missing required fields, unknown additional properties all fail.

**Control predicates against observation values.** 

CEL evaluation of declared invariants against the values the collector wrote into the snapshot.

**Compound compositions across controls.** 

The chain engine groups co-failing controls by `scope_field` or `asset.ID` and fires compound findings when the escalation threshold is met.

**Fact export for external reasoning.** The SIR projector emits predicates that solvers (Z3, cvc5, Soufflé, Clingo, Prolog) consume independently.

## What Stave does NOT verify

| Boundary | What's checked elsewhere | Where the trust attaches |
|---|---|---|
| Observation **value** correctness | Schema validates types, not whether values match real cloud state | The collector |
| Cross-inventory **ghost references** at evaluation time | The collector pre-computes `has_ghost_*` booleans by walking the inventory | The collector |
| **Time-dependent** verdicts without `--eval-time` | System wall clock drives duration / TTL / freshness checks | The caller of `stave apply` |

The rest of this document explains each boundary, the mitigation
discipline, and what an UNSAT verdict from a solver says.

## Boundary 1 — Observation value correctness

### What the schema does

Schema validation rejects:
- Wrong types (`public_read: "no"` when boolean expected)
- Missing required fields
- Unknown additional properties (`additionalProperties: false`)

### What the schema does NOT do

Schema validation accepts any observation whose **shape** is legal,
including ones where the values are wrong. A bucket observation
with `access.public_read: false` and a `policy.raw_policy` field
that grants `Principal: "*"` on `s3:GetObject` is structurally
valid. Stave's S3 controls read `access.public_read` (a boolean)
and do not parse `raw_policy` — so the public bucket appears safe.

> If a collector sets `public_read: false` for a bucket that IS
> public, Stave will not detect the error. The schema says "this
> field must be a boolean" — it is. The value is the collector's
> responsibility.

### Why this can't move into Stave

The interface is standardized so that the Stave core is independent of any cloud provider specific JSON format. We can add support to new cloud providers without changing the stave core. Add a new collector that is specific to the new cloud provider and transform it to the standard Stave observation contract.

### Mitigations

1. **Cross-check controls** where feasible. Some controls do read
   multiple related properties and surface contradictions as their
   own predicate. These exist for high-value pairs (encryption
   flag + KMS key id, public-access flags + ownership controls).
   Audit `internal/controldata/embedded/` for `mismatch` /
   `inconsistent` controls; add more for property pairs that
   matter when adding a new control family.
2. **Collector unit tests.** Each collector should test that its
   derived booleans match sample raw data. The schema defines
   WHAT to produce; the collector test suite verifies CORRECTNESS
   of values.
3. **Multiple collectors.** Running two independent collectors on
   the same account and diffing their observations surfaces value
   disagreements that neither collector's tests would catch.

### What this means for proofs

When Z3 returns UNSAT (safe), the proof is:

> Given the values in this observation, no dangerous state is
> reachable in the chains the SIR can express.

If the values are wrong, the proof is valid but vacuous which means correct
logic on incorrect premises. The proof's trustworthiness equals
the collector's trustworthiness. Naming the collector explicitly
in evidence packets (already part of `generated_by.tool`) keeps
the chain of custody visible.

## Boundary 2 — Clock-dependent determinism

### What is deterministic

Same observation + same control + same `--eval-time` value → byte-
identical output, every time. This is the standard CI/CD-grade
determinism Stave's evaluation engine provides.

### What is NOT deterministic without `--eval-time`

Time-dependent controls (credential TTL, observation freshness,
unsafe duration thresholds) use `time.Now()` when `--eval-time` is
absent. Same fixture run a year apart yields different verdicts
because the clock-relative answer is correct.

The audit measured this on
`examples/cognito-iteration2-unauth/fixtures/cross-resource-config`:

| `--eval-time` | Findings | md5 of JSON output |
|---|---|---|
| 2026-01-01 | 2 | c9f1ed7de1dce8b074165b3e503d19cd |
| 2027-06-01 | 9 | 825c013af47f58b51d096c0b31277979 |

The 7-finding delta is duration-gated SLA promotions: at the later
clock, several violations have been "exposed for longer than
`--max-unsafe`" and now count.

### When time-dependent verdicts are CORRECT to vary

A credential at 89 days with a 90-day declared TTL is compliant
today and non-compliant tomorrow. Producing the same answer on
both days would be **wrong**. The credential really did age out.
This is correct temporal evaluation.

### Recommendations by context

- **CI/CD pipelines:** pass `--eval-time` (typically the build-trigger
  commit time or the observation's `captured_at`). Locks the
  verdict to a reproducible reference point.
- **Interactive use without `--eval-time`:** correct default. You want
  today's answer about today's credentials.
- **Agent OODA loops:** pass `--eval-time` derived from the observation,
  not the agent's clock. This prevents the assertion target from
  moving while the agent iterates.

  ```bash
  stave apply --observations testdata/e2e/e2e-01-violation/observations \
      --eval-time "$(jq -r '.captured_at' testdata/e2e/e2e-01-violation/observations/*.json | sort | head -1)"
  ```

### Which controls are time-dependent

Any control whose predicate references duration, age, or freshness.
The catalog tag is `domain: identity` (for credential TTL) plus
the `attack_stage: credential_access` family; `stave search
"duration"` enumerates them. The cross-cutting category is
"requires `--eval-time` for determinism."

## Boundary 3 — Ghost reference detection

### How ghost controls fire

Controls named `CTL.*.GHOST.*` (and `CTL.IAM.POLICY.GHOSTREF.*`,
the cross-asset analogue) fire on **collector-set boolean**
properties: `has_ghost_principal`, `has_ghost_resource_refs`,
`has_ghost_trigger`, etc. The predicate reads one boolean. The
predicate does not walk the inventory.

> Zero Go code at evaluation time computes ghost references.
> Every `has_ghost_*` field name in the catalog is sourced from
> the collector. Stave reads booleans, not inventories.

### The deleted-vs-not-collected ambiguity

The collector decides `has_ghost_principal: true`. If the collector
queried the principal's resource type and didn't find it, the
ghost is real. If the collector didn't query that resource type
at all (permission gap, region miss, vendor API failure), the
absence is meaningless and the ghost is a false positive. Stave
has no way to tell the two cases apart from the observation
alone.

The most reliable ghost detection uses **temporal comparison**:

  - Snapshot N-1: resource exists, policy references it
  - Snapshot N: resource absent, policy still references it
  - Conclusion: resource was deleted, reference is a ghost

Single-snapshot ghost detection has inherent false-positive risk
from incomplete collection.

### Why this design

Moving cross-inventory reasoning into Stave's evaluation engine
would couple it to the observation model and tie Stave to vendor-specific inventory semantics.

The collector already understands its own inventory. Asking the
collector to write one boolean is the same abstraction the
collector-derived booleans use for every other cross-resource
fact (public-access composition, encryption-key reachability,
trust-chain depth).

### Collector contract for `has_ghost_*`

A collector that emits `has_ghost_*: true` is asserting:

1. The reference was identified inside a policy / config block.
2. The referenced **resource type** was within collection scope.
3. The resource was not found.
4. Ideally: the resource was present in a prior snapshot (temporal
   confirmation).

When (2) fails. The resource type was not queried. The collector
SHOULD emit `has_ghost_*: false` rather than `true`. Absence due
to incomplete collection is not a ghost.

### What this means for downstream consumers

Ghost-finding counts are bounded by collector completeness. A
collector with broad coverage produces trustworthy ghost counts.
A narrow collector produces ambiguous ones. Treat ghost findings
as "investigate" rather than "incident" until the collection
scope is verified.

## Implications for downstream consumers

| Consumer | What to assume | What to verify externally |
|---|---|---|
| Z3 / cvc5 / Yices UNSAT verdict | Logic is sound | Collector produced correct values; observation captured the right time |
| Ghost-finding counts | Lower bound | Collector covered the referenced resource types |
| CI/CD pass/fail | Reproducible per `--eval-time` | Pipeline always passes `--eval-time` |
| Agent self-correction loop | Verdict converges per fixed `--eval-time` | Agent passes `--eval-time` and uses the observation's `captured_at` |

## Related

- [Architecture Overview](overview.md) — the pipeline this document scopes
- [Fact Export reference](https://www.systeminvariant.dev/docs/reference/fact-export) — the SIR's projected scope (separate boundary, separate doc)
- [How to use a reasoning engine with Stave facts](https://www.systeminvariant.dev/docs/how-to/controls/reasoning-engines) — composing UNSAT verdicts with the scope caveat
