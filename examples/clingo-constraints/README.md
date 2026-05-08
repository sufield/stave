# clingo-constraints

ASP/Clingo constraint enumeration over the Stave fact set.
Z3 finds one witness; ASP enumerates the complete set of
ground triples that satisfy each constraint.

## What this answers

The CISO question: "Across this configuration, list every
(asset, principal, resource) triple that constitutes a
violation under our policy." That's a complete-enumeration
question, not a satisfiability one. ASP's stable-model
semantics gives the full ground set in one solve.

The same fact base flows through Z3 (one path) and Clingo
(every path); compose them in a comparison harness and the
disagreement reveals a blind spot in either.

## What the constraints cover

`constraints.lp` defines six violation patterns and one
latent-risk pattern. Each is a conjunction over Stave's
emitted predicates — no rules, no derivation, just direct
ground composition.

| Rule | Conjunction | Catches |
|---|---|---|
| V1 `exploitable_overperm` | `contributed_by(R, _) ∧ trusts_service(R, S)` | Role with a known finding AND assumable by a compute service |
| V2 `privesc_chain_2hop` | `can_assume(A, B) ∧ can_assume(B, _)` | Two consecutive assume-edges (start of a transitive chain) |
| V3 `unauth_cognito_s3_read` | `allows_unauthenticated(P, "true") ∧ maps_unauth_to(P, R) ∧ has_action(R, "s3:GetObject"\|"s3:*")` | Anonymous Cognito identity reaches S3 read |
| V4 `self_register_broad_s3` | `self_registration_unrestricted(P, "true") ∧ maps_auth_to(P, R) ∧ has_action(R, "s3:*")` | Self-registration enabled with broad authenticated grant |
| V5 `wildcard_action_resource` | `has_action(R, "s3:*") ∧ has_resource(R, "*")` | wildcard action on wildcard resource — broad over-permission |
| V6 `production_wildcard_pair` | `has_action(R, "s3:*") ∧ has_type(B, "aws_s3_bucket") ∧ has_tag(B, "environment=production")` | Coarse bybit-shape; SMT refines with `str.prefixof` |
| L `compute_trust_no_finding` | `has_type(R, "aws_iam_role") ∧ trusts_service(R, _) ∧ ¬contributed_by(R, _)` | Latent: would become V1 the moment any finding fires |

V6 is intentionally coarser than the SMT bybit query —
ASP's vocabulary is conjunction over ground atoms, no string
theory. Composing both engines in the comparison harness
recovers the precision: ASP does the cheap enumeration; SMT
does the expensive prefix proof on the candidates ASP
identifies.

## Output (live, recorded in `expected/output.txt`)

Run `bash run.sh` to produce:

```
=== multi-hop-vulnerable ===
 violation: privesc_chain_2hop (2)
 arn:aws:iam::444455556666:role/onboarding-role -> arn:aws:iam::444455556666:role/operator-role
 arn:aws:iam::444455556666:user/developer -> arn:aws:iam::444455556666:role/onboarding-role

=== multi-hop-remediated ===
 (clean)

=== rhino-vulnerable ===
 latent_risk (3)
 arn:aws:iam::111122223333:role/admin-ec2-role
 arn:aws:iam::111122223333:role/admin-lambda-role
 arn:aws:iam::111122223333:role/admin-multi-trust-role
...
```

The interesting reads:

- **multi-hop-vulnerable / remediated**: the privesc chain
 V2 fires twice on vulnerable (the (developer, onboarding)
 and (onboarding, operator) starting prefixes both have a
 next hop), zero on remediated where the middle trust admit
 is cut. Same fact base as `z3-multi-hop-can-assume`; ASP
 produces the prefix-set, Z3 finds one witness.

- **rhino-vulnerable**: V1 does **not** fire — none of the
 rhino admin roles carry `contributed_by` on themselves;
 the example controls attribute findings to the
 `rhino-attacker` user. The latent-risk rule catches them
 instead: three admin roles trust compute services
 (`ec2`, `lambda`, multi-service) without findings. They
 are latent V1s — one finding away from exploitable.

- **cognito-writeup / remediated**: V3
 (`unauth_cognito_s3_read`) and V5
 (`wildcard_action_resource`) both fire on writeup-config;
 both vanish on remediated. The remediation collapses both
 patterns simultaneously — that's the choke-point reveal
 the article describes, recovered without any
 CEL/SMT.

- **bybit-before / after**: V6 does not fire because the
 developer's policy uses specific actions
 (`s3:GetObject`, `s3:PutObject`) not `s3:*`. The bybit
 anomaly is the *resource* wildcard, not the *action*
 wildcard, and ASP's coarse rule doesn't capture string
 prefix-matching. The SMT bybit query catches it;
 comparison harness routes the case correctly.

## Run

```bash
# One-time tooling setup (Clingo ships only as a library):
python3 -m venv .tools-venv
.tools-venv/bin/pip install clingo

# Then any time:
cd stave
make build
bash examples/clingo-constraints/run.sh
```

If `CLINGO_VENV` is unset, the runner expects `.tools-venv`
at the repository root (sibling of `stave/`).

## Why ASP not just Datalog

Clingo + ASP carries:

- **Default negation** (`not contributed_by(R, _)`) — needed
 for L (latent risk: trusts compute and *no* finding fires).
 Plain Datalog does not have stable-model negation.
- **Closed-world assumption** identical to the SMT export.
- **Disjunction in heads** (not used here, but unlocks
 fixture generation in a follow-up — see the spec for
 `generate-fixtures.lp` design notes; deferred until an
 actual consumer lands).

## What this is not

- **Not a replacement for CEL.** CEL evaluates per-asset,
 per-control with rich runtime semantics (timestamps,
 duration windows, lifecycle states). ASP composes
 *findings* — the boolean output of CEL evaluation — to
 surface multi-asset compounds. The two compose: CEL
 produces the contributed_by facts; ASP enumerates the
 combinations.

- **Not a replacement for SMT.** ASP cannot do string
 reasoning (suffix/prefix), arithmetic over time, or
 bounded transitive closure with arbitrary depth. The
 bybit prefix-match needs SMT; the rhino 5-pattern
 disjunction needs SMT; the multi-hop closure beyond depth
 3 needs Datalog/Soufflé. ASP is the constraint-enumeration
 layer, not the universal reasoner.

- **Not a fixture generator (yet).** The original spec
 proposed a `generate-fixtures.lp` that produces minimal
 violating configurations as edge-case tests. Deferred:
 the use-case is real but the harness to consume the
 generated fixtures back into Stave's e2e tests doesn't
 exist yet, and shipping the generator alone produces
 artifacts with nowhere to land. Re-open when the consumer
 arrives.

- **Not a Soufflé replacement.** Soufflé scales further
 (millions of facts, native transitive closure, parallel
 evaluation) and is the right tool for blast-radius
 enumeration over the full control catalog. ASP wins on
 expressiveness (default negation, disjunction);
 Soufflé wins on scale. Both consume the same JSONL.
 Soufflé example is deferred until the souffle binary is
 available in the build environment.
