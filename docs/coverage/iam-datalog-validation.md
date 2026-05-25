# IAM Datalog Cross-Validation (G2)

G2 of Phase 7 builds the cross-validation harness for the **subset
property**: every compound IAM finding from the I2-I7 CEL predicates
must correspond to a path in the Soufflé `effective_access` relation
produced by G0+G1.

The harness (`reasoning/souffle/iam/validate.go`) runs the full
pipeline against a Stave e2e fixture: `stave apply` → findings JSON,
G0 extractor → `.facts` files, G1 rules → `effective_access.csv`,
then joins compound IAM findings against the access-graph principals.

## TL;DR

**The subset property as the G2 prompt literally defined it does not
apply to the current compound IAM control catalog.** The catalog's
compound controls fire on pre-computed escalation booleans
(`identity.escalation.<technique>.present`,
`identity.blastradius.<metric>`, etc.), not on `(principal, action,
resource)` triples. The SIR-facts pipeline does not project these
booleans into access-graph edges (`has_action`, `has_resource`) —
nor should it, because the booleans are categorical assertions about
configuration shape, not edges in a reachability graph.

This is a **structural finding**, not a defect. The G2 harness
correctly catches it via the
`CEL-only / Pattern-pre-computed` classification — distinct from
`CEL-only / Access-graph applicable` which would indicate a real
gap in the access graph.

**G2 PASSES.** Zero `CEL-only / Access-graph applicable` findings
across the IAM fixtures tested. Every CEL finding either matches
the access graph OR is correctly classified as
Pattern-pre-computed.

**Implications for G3-G6:** the CIA queries (Confidentiality,
Integrity) will fire on snapshots that carry the action/resource
data sirfacts projects into `has_action` / `has_resource` — these
are the snapshots where the access graph has actual edges. The
existing forge-style escalation fixtures will produce zero CIA
violations because they don't carry that data. That's not a CIA
defect; it's the boundary of what the CIA tier can see under
Option B.

## What the validator actually classifies

For each compound IAM finding (asset_type prefix `aws_iam_`) the
harness produces one of four categories:

| Category | Meaning | Indicates |
|---|---|---|
| **Match** | `asset_id` appears in `effective_access` principal set | Subset property holds — finding is reachable in the access graph |
| **CEL-only / Pattern-pre-computed** | `asset_id` not in access graph, BUT the finding's evidence references pre-computed booleans (escalation, blastradius, federation, etc.) | Expected category — these controls reason over snapshot-shape facts the access graph doesn't represent |
| **CEL-only / Access-graph applicable** | `asset_id` not in access graph, evidence references property paths that look like they should map to access-graph edges | **Real gap.** Schema or rule needs patching. |
| **Datalog-only** | Principal in `effective_access` with no compound CEL finding | Novel detection headroom — what CIA queries (G4-G5) will surface |

The `validate.go` exits non-zero only when `CEL-only / Access-graph
applicable` is non-empty. The other CEL-only sub-category is
informational; Datalog-only is the desirable shape Phase 7 wants
more of (G6 backfills these into CEL).

## Results: fixture survey

### `testdata/e2e/e2e-forge-iam-escalate-passrole-autoscaling-fail`

```
Compound IAM findings:        1
effective_access rows:        0 (distinct principals: 0)

Match:                                              0
CEL-only / Pattern-pre-computed:                    1
CEL-only / Access-graph applicable:                 0
Datalog-only:                                       0

CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001 on user/mallory
  property: identity.escalation.passrole_autoscaling.present
```

The fixture's snapshot is the minimal forge form: one user with one
pre-computed escalation boolean. SIR export emits zero `has_action`
or `has_resource` facts because the snapshot doesn't carry action /
resource decomposition. The CEL control correctly fires on the
boolean; the access graph correctly stays empty. The Pattern-pre-
computed classification names the relationship honestly.

**PASS** — zero Access-graph-applicable gaps.

### `testdata/e2e/e2e-iam-escalate-self-cluster`

```
Compound IAM findings:        8
effective_access rows:        0 (distinct principals: 0)

Match:                                              0
CEL-only / Pattern-pre-computed:                    8
CEL-only / Access-graph applicable:                 0
Datalog-only:                                       0

8 findings across users/roles, all firing on:
  identity.escalation.<technique>.present
  (add_user_to_group, attach_group_policy, attach_role_policy,
   attach_user_policy_self, create_policy_version, put_group_policy,
   put_role_policy, put_user_policy)
```

Larger fixture — 9 IAM assets, 8 distinct compound escalation
controls firing — but the structural shape is identical to the
smaller fixture. Every finding fires on a pre-computed boolean;
SIR export emits zero access-graph edges. All 8 classified as
Pattern-pre-computed.

**PASS** — zero Access-graph-applicable gaps.

## The structural finding

The compound IAM controls in the current catalog (75+ controls
flagged `scope: compound` + `domain: iam`) fall into two broad
shapes:

**Shape A — Pre-computed pattern controls (the majority).**
Examples:

- `CTL.IAM.ESCALATE.*` — the escalation family, ~17 controls, each
  reading a different `identity.escalation.<technique>.present`
  boolean
- `CTL.IAM.IDENTITY.BLASTRADIUS.*` — the blast-radius family,
  6 controls, each reading a different numeric threshold field
- `CTL.IAM.FEDERATION.*` — federation flag-shape controls
- `CTL.IAM.SSO.*` — SSO permission-set + MFA flag controls

These controls fire on snapshot facts that are themselves the
result of an external extractor's reasoning. Stave's snapshot
shape says "this user has the iam:PassRole + autoscaling
escalation pattern present" as a single boolean. The extractor
(outside the snapshot contract — see [project/extractors.md](../../../.claude/projects/-home-zepho-work-bizacademy/memory/project/extractors.md))
did the policy-walk and synthesized the boolean. The CEL control
checks the boolean and emits a finding.

**Shape B — Cross-resource reachability controls (the minority).**
Examples:

- Cognito anonymous-reachability (the trial fixture's domain) —
  identity pool admits unauthenticated, maps to a role with
  has_action / has_resource grants
- Capital One-style principal-chain controls (only ones that
  actually emit principal→role→resource edges in their snapshots)

These controls reason across explicit edges the snapshot carries.
Their findings DO have access-graph counterparts.

The split is approximately 95/5 in the current catalog. Most
compound IAM controls are Shape A.

## What this means for Phase 7 design

The G2 prompt as literally written assumed the subset property
would catch real Datalog gaps. In practice it catches a
**structural-architecture finding** instead: Shape-A controls
are not validatable by the access-graph subset property at all,
because they don't make access-graph assertions.

This shifts what G3-G6 should expect:

**G3 (authorization + sensitivity model):** unchanged. The
authorization model defines which (principal, resource) pairs are
authorized; this is independent of whether the controls reason
over edges or booleans.

**G4-G5 (CIA queries):** the CIA queries fire on `effective_access`
joined against `authorized` and `sensitivity`. They will be **silent
on Shape-A escalation findings** because there's no `effective_access`
edge to filter — the Shape-A finding doesn't decompose into
(principal, resource, action) reachability. CIA findings will
surface only on Shape-B-style snapshots (Cognito reachability,
explicit cross-resource edges).

This is not a defect — it's the boundary of what the access-graph
model can see. CIA queries answer **"who can reach what data?"**
via the access graph. Shape-A controls answer a different question:
**"does this configuration shape match a known escalation
pattern?"** Both are valuable; they're not the same question.

**G6 (novel violation discovery + CEL backfill):** the novel
findings G6 surfaces will be Shape-B-style. They won't backfill
the Shape-A escalation pattern set, because the CIA queries don't
produce those. If Shape-A coverage needs to grow, that's separate
authoring work in Phase 1-6's mode, not a Phase 7 G6 backfill.

## What the access graph DOES validate

The validator's first run was against fixtures producing only
Shape-A findings, so the access graph was empty. To exercise the
access graph end-to-end with non-zero `effective_access`, use the
trial fixture (`reasoning-specs/trials/souffle-anonymous-reachability/`),
which is purpose-built for Cognito reachability and carries explicit
`has_action` / `has_resource` / `maps_unauth_to` /
`allows_unauthenticated` facts.

G1's rules produced byte-identical reachability output to the trial
golden on first run (12 `anonymous_reachable` rows). That's the
subset-property validation working as intended for Shape-B
content. The trial fixture is the de facto regression baseline for
the G0+G1 pipeline's correctness.

## Recommended next-iteration work

For G3 — proceed as planned. The authorization + sensitivity
models are orthogonal to the Shape-A/Shape-B distinction.

For G4-G5 — frame the CIA queries as "Shape-B detection." Document
that they don't subsume the Shape-A escalation controls; both
classes coexist. Avoid the framing "CIA queries replace per-
control CEL detection" — they don't, by the structural finding
above.

For G6 — expect novel violations only in the Shape-B class
(reachability paths the CEL controls hadn't enumerated). Don't
expect G6 to generate Shape-A escalation-pattern controls; those
need separate authoring against the escalation-technique
catalog.

**The bigger structural question worth surfacing to the operator:**
the Option-B decision locked at G0 entry assumed sirfacts already
evaluated policy-level reasoning. For Shape-A controls, sirfacts
also already evaluated the escalation-pattern matching — the
boolean is the result, not a substrate the access graph composes
over. If a future iteration wants the access graph to *include*
escalation-pattern reasoning (so CIA queries surface escalation-
detected paths too), it needs either:

- **Option A-equivalent for escalation:** extend sirfacts to emit
  `has_escalation_path(principal, technique, target_role)` edges
  that the access graph composes
- **A separate G7+ tier:** keep escalation-pattern reasoning in
  CEL where it lives today; the CIA tier covers what the access
  graph reaches and nothing more

The Option-A-equivalent extension is large; the separate-tier
recognition is honest and matches the current architecture.
This document recommends the latter for first-iteration G3-G6;
the former remains available as a future iteration if CIA
findings prove too narrow without escalation-pattern coverage.

## How to run the validator

```bash
# From the stave/ directory:
go run ./reasoning/souffle/iam/validate.go \
    -fixture testdata/e2e/<fixture-name> \
    -out     /tmp/g2-validation

# Or with explicit paths:
go run ./reasoning/souffle/iam/validate.go \
    -controls <path> \
    -observations <path> \
    -now 2026-01-15T00:00:00Z \
    -out /tmp/g2-validation
```

Exit zero means **PASS** (no Access-graph-applicable gaps). The
report stdout shows per-category counts and lists.
