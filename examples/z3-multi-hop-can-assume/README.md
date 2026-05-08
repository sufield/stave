# z3-multi-hop-can-assume

Asks whether a starting principal
reaches a target principal through a chain of 1, 2, or 3
sts:AssumeRole hops, where each hop requires reciprocal trust on
both sides.

## What this proves

Multi-hop role-assumption privesc — the configuration where no
single role grant looks dangerous in isolation, but the chain of
admits permits an unprivileged user to land in an admin-equivalent
role. Each individual hop has documented business justification:
developers need onboarding, onboarding needs operator escalation
for incident response, operator-role escalates to admin under
break-glass. The hops are individually defensible. The chain is
indefensible.

CEL would flag each role's policy in isolation (or not — operator
escalating to admin via a documented break-glass procedure is a
common, intentional pattern). What CEL cannot ask: "does the
*composition* of these admits hand the unprivileged developer a
direct path to admin?" That requires reasoning over a graph, and
graphs are SMT's home turf.

## The reachability question

```
Fact base: can_assume(from, to) per emitted edge.
 Closed-world: only the asserted edges hold.

Query: exists hop1, hop2 . start --can_assume--> hop1
 --can_assume--> hop2
 --can_assume--> finish
 (or shorter: 1-hop direct, 2-hop with one intermediate)

start = arn:aws:iam::444455556666:user/developer
finish = arn:aws:iam::444455556666:role/admin-role
```

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `vulnerable` | **sat** | **sat** | (see below) |
| `remediated` | **unsat** | **unsat** | n/a |

Z3 + cvc5 witness on `vulnerable`:

```
start = arn:aws:iam::444455556666:user/developer
hop1 = arn:aws:iam::444455556666:role/onboarding-role
hop2 = arn:aws:iam::444455556666:role/operator-role
finish = arn:aws:iam::444455556666:role/admin-role
```

The four-element witness names the entire chain. That's the
reveal — Z3 doesn't just say "yes, reachable"; it produces the
specific (start, hop1, hop2, finish) tuple security can review.

In `remediated`, operator-role's `trust_policy_json` no longer
admits onboarding-role. The closed-world axiom strips the
`(onboarding-role, operator-role)` edge from `can_assume`. No
assignment of (hop1, hop2) satisfies the disjunction; the solver
returns unsat in milliseconds. Cutting one trust admit collapses
the entire transitive reachability set.

## Why CEL doesn't say this

CEL evaluates per-asset, per-control. Each of the four
identities (developer, onboarding-role, operator-role,
admin-role) might pass every per-asset control:

- `developer`: has only `sts:AssumeRole` on `onboarding-role`.
 Scoped resource, single action. Documented onboarding flow. Pass.
- `onboarding-role`: trust admits `developer` (the documented
 onboarding flow). Has `sts:AssumeRole` on `operator-role`
 (the documented escalation flow). Pass.
- `operator-role`: trust admits `onboarding-role`. Has
 `sts:AssumeRole` on `admin-role` (break-glass). Pass.
- `admin-role`: trust admits `operator-role`. Pass.

What CEL can't ask: "does this graph of admits *compose* into a
path from developer to admin?" That requires:

1. Cross-asset reasoning: trust admit on role X depends on
 policy of identity Y elsewhere
2. Transitive closure: composition of edges, not single-edge
 assertions
3. Closed-world enumeration: "given only these edges, is finish
 reachable from start?"

All three are first-class operations in SMT. The query is 30
lines; it produces both the verdict (unsat → safe) and the
witness (sat → here is the exact chain to fix).

## Run

```bash
cd stave
make build
bash examples/z3-multi-hop-can-assume/run.sh
```

Expected output (also captured in `expected/output.txt`):

```
vulnerable expected=sat z3=sat cvc5=sat OK
remediated expected=unsat z3=unsat cvc5=unsat OK
```

Requires:
- `z3` 4.x on PATH (required)
- `cvc5` 1.3+ on PATH (decisive; the multi-hop fact set is
 small — fewer than 20 assume edges — so finite-model-find
 does not need timeout fallback)

## What this is not

- **Not unbounded reachability.** The query asks about chains of
 length ≤ 3. SMT-LIB doesn't have first-class transitive closure
 (Datalog/Soufflé does, naturally). For longer chains, either
 unroll the disjunction further (1–N hop OR clauses, mechanical),
 or switch reasoning engines. The bound matches the kernel's
 `MaxChainDepth` for fairness.

- **Not action-aware.** `can_assume` is a binary edge — it
 doesn't say which action triggered the trust admit (`sts:AssumeRole`
 vs. `sts:AssumeRoleWithWebIdentity` vs. `sts:AssumeRoleWithSAML`).
 The kernel's `IdentityFact.RoleChains` carries this through the
 `HopType` field; the extractor collapses all assume variants
 to a single `can_assume` edge. A future ternary or
 per-action edge predicate (`assumes_via(from, to, action)`)
 would let queries discriminate, at the cost of serializer
 refactor (binary-only today).

- **Not condition-aware.** Trust policies can carry conditions
 (`aws:PrincipalOrgID`, `aws:SourceAccount`, IP restrictions).
 The extractor ignores conditions — both sides "agree" purely
 on Effect+Action+Principal. A condition-aware extractor would
 need to know what runtime values to evaluate against, which is
 out of scope for static configuration analysis. The
 conservative behavior is correct for security: a condition
 attacker-controlled can be satisfied, so emitting the edge
 produces the right alert; a condition that legitimately
 restricts the trust would need separate policy review.
