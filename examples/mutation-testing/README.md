# Mutation Testing — Detection Coverage Verification

Iteration 3 of the perturbation/compatibility/mutation tooling
plan. Generates one mutation per boolean leaf in a safe
observation, runs `stave apply` on each, and classifies
mutations as KILLED (a finding fired) or SURVIVED (no finding —
either a coverage gap or a property that wasn't security-
relevant in isolation).

```
safe-observation.obs.json
       ↓
mutate.py (operators in mutations/)   → mutations/<id>/observations/...
       ↓                                + manifest.json
verify.py runs stave apply per mutation
       ↓
report.json: baseline, killed, survived, mutation_score
```

## Mutation operators

The framework is operator-pluggable; each operator lives in
`mutations/<name>.py` and exposes a
`mutations(observation: dict) -> Iterator[Mutation]` function.
The framework ships one operator:

| Operator | Behaviour |
|---|---|
| `flip_boolean` | One mutation per boolean leaf; flips True↔False in place |

The plan's other proposed operators (`broaden-policy`,
`remove-condition`, `add-principal`, `disable-logging`) are
deliberate scope cuts — see "Why one operator first" below.

## Run

```bash
cd <repo-root>/stave
make build
bash examples/mutation-testing/run.sh
```

Default fixture: `examples/cognito-iteration2-unauth/fixtures/
remediated-config/observations` — a Cognito identity pool with
`allow_unauthenticated=false` and all 6 dependent detail flags
set to safe values. The framework generates 7 mutations
(one per boolean), runs Stave on each, and classifies them.

Expected output:

```
=== Summary ===
{
  "baseline_findings": 1,
  "total_mutations": 7,
  "killed": 1,
  "survived": 6,
  "mutation_score": 0.1429
}

=== Surviving mutations (coverage gaps) ===
{ "path": "...unauth_role_broad",       "before": false, "after": true }
{ "path": "...unauth_role_has_iam",     "before": false, "after": true }
{ "path": "...unauth_role_has_s3",      "before": false, "after": true }
{ "path": "...unauth_role_has_ddb",     "before": false, "after": true }
{ "path": "...unauth_role_has_lambda",  "before": false, "after": true }
{ "path": "...is_unauth_unused",        "before": false, "after": true }
```

The single kill is `access.allow_unauthenticated: false → true`
flipping `IDENTITY.GUEST.001` from passing to failing.

## What the survival pattern reveals (the actual demo value)

**6 surviving mutations on this fixture is not a coverage
gap — it's a catalog-design surfacing.**

The 6 detail-level controls (`UNAUTH.BROAD`, `UNAUTH.IAM`,
`UNAUTH.S3`, `UNAUTH.DDB`, `UNAUTH.LAMBDA`, `UNAUTH.UNUSED`)
all use **gate-AND-detail compound predicates**:

```yaml
unsafe_predicate:
  all:
    - field: properties.identity.kind
      op: eq
      value: cognito_identity_pool
    - field: properties.identity.access.allow_unauthenticated
      op: eq
      value: true                 # ← THE GATE
    - field: properties.identity.cognito.unauth_role_has_s3
      op: eq
      value: true                 # ← THE DETAIL
```

Flipping just the detail flag (`unauth_role_has_s3: false →
true`) without also flipping the gate doesn't trip the
predicate. That's intentional catalog design: the detail
controls are refinements of `IDENTITY.GUEST.001` and shouldn't
fire when guest access is off.

So **single-property mutation testing has a structural
limit**: it cannot kill compound-predicate detail controls.
Killing them needs multi-property mutations — the cross-product
of {gate-flip} × {one detail flip}. That's exponential and
deliberately out of scope for this framework, but the
framework correctly surfaces the limit.

For controls with non-compound predicates (e.g. the Iteration 6
`ADVANCED.SECURITY.001` family — kind + single boolean) the
single-flip operator kills 1-for-1. Try:

```bash
bash examples/mutation-testing/run.sh \
    examples/cognito-iteration6-advsec/fixtures/remediated-config/observations
```

## What a real coverage gap looks like

A genuine coverage gap is a surviving mutation whose property
the catalog SHOULD detect but doesn't. The current Cognito
example surfaces no genuine gaps — every survivor is the
gate-AND-detail compound-predicate signature, not an
oversight.

When a real gap surfaces, the survivor's `path` names the
property and the operator names the mutation shape. That's the
operator-author's signal to either:

1. Add a control reading the property (the property matters but
   no control was authored), OR
2. Document the property as not-security-relevant (the operator
   is mutating something the catalog deliberately ignores).

The mutation score becomes a quality metric for the catalog
once enough operators are wired and a meaningful baseline
exists.

## Why one operator first

The plan called out: "Start with one service domain (S3 or
Cognito) and validate the framework. Expand after the mutation
operators are proven."

`flip_boolean` is the simplest operator and validates the
framework end-to-end:

- mutate.py reads → operators yield mutations → file layout
  matches `stave apply`'s expectations
- verify.py runs Stave per mutation → counts findings →
  classifies KILL/SURVIVE
- The reporting surface (manifest.json + report.json) carries
  enough metadata that future operators slot in without
  changing the orchestrator

Once this passes its own demo, the plan's other operators
(`broaden-policy`, `remove-condition`, `add-principal`,
`disable-logging`) become drop-in additions to `mutations/`.
Each operator owns one transformation; mutate.py aggregates;
verify.py is operator-agnostic.

## Constraints (matches the iteration plan)

- **External tool only** — no Stave core changes. Three
  scripts + one operator module under `examples/`.
- **Mutates observation JSON, not Stave internals** — the
  framework treats Stave as a black box and exercises the
  full evaluation pipeline as users would.
- **Each mutation is one property change** — compound
  mutations are exponential and explicitly out of scope.
  The framework documents the coverage limit (gate-AND-detail
  predicates need multi-property mutations) without
  attempting to fix it.
- **Targets CEL control coverage only** — the SMT / Clingo /
  Datalog engines are out of scope. Engine mutation testing
  is a separate future tool.

## Future extensions (out of scope)

- **More operators.** `broaden-policy` (replace specific
  resource ARN with `*`), `remove-condition` (drop a Condition
  from a policy statement), `add-principal` (add `*` to a
  resource policy Principal), `disable-logging` (set
  logging/monitoring booleans to false). Each is one new file
  under `mutations/`; the orchestrator picks them up
  automatically.
- **Multi-property mutations.** Pair-wise or N-way mutations
  to kill gate-AND-detail compound predicates. Bound the
  combinatorics by reading the catalog's predicate trees and
  emitting only the property-pairs that appear together in some
  predicate's `all:` block.
- **Per-finding kill attribution.** Today KILL just means
  "finding count went up." Attribute each kill to a specific
  control via the finding diff, so survivors can be classified
  as "no control of any catalog covers this property" vs "a
  control could have caught this but didn't."
- **CI gate.** Run mutation testing on every catalog change;
  fail the build if mutation_score drops below a configured
  threshold.
