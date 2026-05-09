# Export Hydration — Iteration B Status Audit

Date: 2026-05-09
Audit run: HEAD = c6dc51143 (reasoning-trace commit)

## What Iteration B's spec asked for

Surface four pieces of engine-level data through the public
export APIs (`PolicyExport`, `GraphExport`, `InvariantExport`)
so external consumers — Z3 / cvc5 solvers, MCP-served AI
agents, custom reasoners — operate on the same data the CEL
engine already uses:

1. Transitive role-chain paths (multi-hop reachability)
2. Per-asset lifecycle (FirstUnsafeAt / LastSeenUnsafeAt /
   UnsafeDurationHours)
3. Drift state (PROVISIONED / DECOMMISSIONED / RECONFIGURED)
4. Effective permission sets (after Allow ∩ ¬Deny ∩ Boundary)

## What the audit found

### 1. Transitive role chains — MISSING from GraphExport

`pkg/stave.GraphExport` carries direct edges (`finding_about`,
`chain_member`) and aggregate reachability counts on
`Finding.Reachability` (`TotalReachablePrincipals`,
`PrivilegedPrincipalCount`, `BlastRadiusScore`,
`ExternalPrincipalReachable`). It does **not** carry the path
tuples Z3 reachability queries need (principal → hop1 →
hop2 → role → resource).

Engine source: the SIR builder's `RoleChain` walker
(`internal/core/sir/...`) computes multi-hop chains and emits
them as nested `IdentityFact.RoleChains[]`. `cmd/exportsir` does
surface them as `can_assume(from, to)` JSONL triples — but
`GraphExport.Edges` does not include those triples.

To close this without reimplementing: refactor `ExportGraph`
to take an optional `*sir.Document` argument or read it from
`Assessment` (which doesn't carry it today), then walk
`doc.Identities[].RoleChains` and project each hop to a
`TransitiveReachability` entry. Roughly a 3–5 hour refactor:
new field on GraphExport, plumbing through `applycore.Run`
to attach the SIR doc to the Result, golden updates across
the e2e fixtures that exercise multi-hop trust.

### 2. Lifecycle — SHIPPED on FindingNode

Commit ffe327e9c added `FindingNode.Lifecycle *FindingLifecycle`
carrying `FirstUnsafeAt`, `LastSeenUnsafeAt`,
`UnsafeDurationHours` — pulled from the same
`Evidence.FirstUnsafeAt / LastSeenUnsafeAt /
UnsafeDurationHours` fields the CEL engine populates.

`pkg/stave.Finding.HasTemporalEvidence()` is the gate; nil
when no temporal evidence is present, populated otherwise.
Symmetric `AssetNode.Lifecycle` is not yet present — the
finding-level shape is sufficient for current Z3 dwell-time
queries (every Z3 query targets a specific finding, not a
naked asset).

### 3. Drift state — MISSING from exports

`internal/core/asset/drift.go` defines `DriftType =
{PROVISIONED, DECOMMISSIONED, RECONFIGURED}` and
`drift_diff.go` computes the per-snapshot delta. The SIR
builder also emits `is_provisioned("true")` /
`is_decommissioned("true")` JSONL triples per asset.

GraphExport's `AssetNode` has only `{ID, Type, HasFinding}` —
no drift state. To add: extend `AssetNode` with `DriftState
string` (one of `provisioned|decommissioned|reconfigured|
stable`), populate from each asset's `Lifecycle.Provisioned`
/ `Decommissioned` booleans on the SIR `AssetFact` (same
source the JSONL projector reads).

Same plumbing prerequisite as transitive chains: GraphExport
needs SIR-doc access. Combining (1) + (3) into one refactor
amortises the plumbing cost.

### 4. Effective permissions — MISSING from PolicyExport

`PolicyExport` carries `ResourcePolicies`, `TrustPolicies`,
`KMSKeyPolicies`, `AssetRelationships` — all raw policy
documents. It does **not** carry the resolved
`(principal, action, resource)` permission set after
Allow/Deny/Boundary aggregation.

The aggregation logic lives at
`internal/platform/providers/aws/iam/resolve.go`. That
package is provider-internal and not currently exposed
through a port. To surface it cleanly requires either:

  - Defining an `EffectivePermissionResolver` port in
    `internal/core/ports/` and registering an AWS
    implementation, then calling it from
    `pkg/stave/internal/policyexport/extract.go`.
  - OR running a parallel resolution inside the export path,
    which the spec explicitly forbids ("don't reimplement").

Both are 4–8 hour pieces of work depending on how rich the
port surface needs to be.

## What was already shipped vs. what remains

| Deliverable | Status |
|---|---|
| Lifecycle on FindingNode | shipped (commit ffe327e9c) |
| ForbiddenState in InvariantExport | shipped (Iteration A) |
| intent_rationale in InvariantExport | shipped (Iteration A) |
| Transitive role chains in GraphExport | **deferred** — needs SIR-doc plumbing |
| Drift state on AssetNode | **deferred** — same plumbing |
| Effective permissions in PolicyExport | **deferred** — needs new port |

## Recommended next-session sequencing

1. Plumb the SIR document from `applycore.Run` to the export
   layer (one refactor, ~2h).
2. Use that plumbing to add transitive role chains AND drift
   state to GraphExport (combined ~3h, single golden
   regeneration pass).
3. Define the `EffectivePermissionResolver` port and surface
   resolved permissions through PolicyExport (~6h, larger
   golden impact across many policy fixtures).

Determinism rules from the spec apply throughout: sort paths,
use stable IDs, no wall-clock reads. The lifecycle work that
already shipped (ffe327e9c) is the model to follow.

## Why this audit exists

The Iteration B spec said "verify what's already in the
exports — only build what's missing after Phase A." The
shipped work covered Phase A's discovery and one of the four
deliverables (lifecycle). The remaining three were merged
into the catch-all `[completed] Iter B: hydrate exports with
what's missing` task, which overstated coverage. This audit
records the actual gap honestly so the next session can pick
up the refactor without redoing the diagnosis.
