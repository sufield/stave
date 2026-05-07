# souffle-reachability

Soufflé Datalog reachability over Stave's JSONL fact export.
The fourth reasoning engine on top of the same fact base.

## What this answers that the other engines don't

Z3 finds **one witness** per query (SAT/UNSAT).
Clingo enumerates **violation triples** under stable-model semantics.
SAT scales **boolean compounds** of control verdicts.
Soufflé computes the **complete reachability graph** in one
bottom-up pass and reports **counts** per derived relation.

The CISO question Soufflé alone answers cleanly: "How wide
is the blast radius?" — a number, not an existence proof.
And the *delta* between vulnerable and remediated counts
is the quantified impact of the remediation.

## Output (live, recorded in `expected/output.txt`)

```
=== Cognito writeup-config ===
  reachable:                 42
  anonymous_reachable:       12
  self_register_reachable:   9
  ...

=== Cognito remediated ===
  reachable:                 12
  anonymous_reachable:       0
  self_register_reachable:   0
  ...

=== Multi-hop vulnerable ===
  reachable:                 10
  privesc_chain:             6

=== Multi-hop remediated ===
  reachable:                 6
  privesc_chain:             2

=== Rhino vulnerable ===
  reachable:                 58
  exploitable_overperm:      13

=== Rhino remediated ===
  reachable:                 9
  exploitable_overperm:      1
```

The delta is the value:

| Fixture | Before | After | Reduction |
|---|---|---|---|
| Cognito `reachable` | 42 | 12 | 71% narrower |
| Cognito `anonymous_reachable` | 12 | 0 | full collapse |
| Cognito `self_register_reachable` | 9 | 0 | full collapse |
| Multi-hop `privesc_chain` | 6 | 2 | 67% narrower |
| Multi-hop `reachable` | 10 | 6 | 40% narrower |
| Rhino `exploitable_overperm` | 13 | 1 | 92% narrower |
| Rhino `reachable` | 58 | 9 | 84% narrower |

The same Stave fact base flows into Z3 (witness),
Clingo (violation atoms), SAT (compound boolean check), and
Soufflé (transitive count). Each engine picks up something
the others can't see; the comparison harness composes them.

## How the queries map to predicates

Every input relation declared in `reachability.dl` matches
a predicate Stave's JSONL emits. `transform.sh` splits the
JSONL into per-predicate `.facts` TSVs; missing predicates
get empty files, which Soufflé treats as empty relations
(no warning). The six output relations are:

| Output | Computes |
|---|---|
| `reachable` | Every (principal, resource, action) — direct grants, identity-pool mediated, and transitive role chains. |
| `anonymous_reachable` | Subset where the principal enters via an unauthenticated identity pool (`allows_unauthenticated="true"`). |
| `self_register_reachable` | Subset where any user pool admits self-registration AND the identity pool maps an authenticated principal (the iter-16 conservative join — see below). |
| `production_reachable` | Subset where the resource has tag `environment=production`. Limited by literal join (see Bybit caveat below). |
| `exploitable_overperm` | Roles with both a CEL finding (`contributed_by`) AND a compute-service trust (`trusts_service`). The iter-13/15 PassRole-on-compute compound. |
| `privesc_chain` | Multi-hop assume chains with hop count, capped at depth 10 (matches the kernel's `MaxChainDepth`). |

## The cross-pool join in `self_register_reachable`

In AWS Cognito, **user pools** (sign-in / MFA / sign-up
gates) and **identity pools** (AWS-credential issuance)
are distinct ARNs. Stave's SIR emits
`self_registration_unrestricted` on the user pool and
`maps_auth_to` on the identity pool, with no projected
link between them.

The conservative reading is: if *any* user pool admits
self-registration, the linked identity pool's
authenticated mapping is fair game (the iter-16 reveal —
identity pools accept any token from any linked user
pool). The Datalog rule joins on existence:

```prolog
self_register_reachable(P, R, A) :-
    self_registration_unrestricted(_, "true"),
    maps_auth_to(P, Role),
    has_action(Role, A),
    has_resource(Role, R).
```

This fires on the writeup fixture (9 triples — 3 actions
× 3 resources for the auth role) and vanishes on
remediated. A future Stave projection could emit a
`pool_link(user_pool, identity_pool)` edge that would let
the rule join precisely; today the conservative form is
correct for security (it overcounts rather than missing
the iter-16 attack chain).

## The Bybit caveat: literal joins don't expand wildcards

Bybit-before has the developer's policy at
`Resource: arn:aws:s3:::company-frontend-*` (a wildcard
pattern). Bybit-after rescopes to specific ARNs that
*include* the production bucket (the alt-shape "after"
still permits prod access).

Soufflé does literal string joins. The wildcard
`company-frontend-*` does not literally equal
`company-frontend-prod`, so on bybit-before
`production_reachable` returns 0 — even though the
wildcard semantically does match prod. On bybit-after,
the explicit grant on `company-frontend-prod` literally
matches the production-tagged bucket, so
`production_reachable` returns 4.

That's an honest limitation: Soufflé enumerates the
literal closure, not the policy-evaluator closure. The
SMT bybit query (z3-bybit-tag-aware-compound) catches
the wildcard match via `str.prefixof` — that's why both
engines exist. Datalog scales further; SMT carries
richer semantics; the comparison harness routes each
case to the right tool.

## Run

```bash
# One-time tooling setup. Soufflé ships only as a system
# binary (no Python wheel). Extract the Ubuntu .deb without
# root:
mkdir -p ~/.local/bin
curl -fsSL https://github.com/souffle-lang/souffle/releases/download/2.5/x86_64-ubuntu-2404-souffle-2.5-Linux.deb -o /tmp/souffle.deb
dpkg-deb -x /tmp/souffle.deb /tmp/souffle-extract
cp /tmp/souffle-extract/usr/bin/souffle* ~/.local/bin/
export PATH=$HOME/.local/bin:$PATH

# Then any time:
cd stave
make build
bash examples/souffle-reachability/run.sh
```

The runner uses `--controls controls/` (full Stave catalog)
to exercise contributed_by edges across the rhino/cognito
fixtures. Per-example narrow controls dirs would silence
exploitable_overperm.

## What this is not

- **Not a security-policy engine.** Reachable counts
  describe the configuration's reach surface, not its
  policy compliance. CEL controls evaluate compliance;
  Soufflé measures reach. The two compose: CEL produces
  `contributed_by` edges; Soufflé enumerates the reach
  surface that intersects them.

- **Not a wildcard policy evaluator.** AWS resource
  wildcards (`arn:aws:s3:::*`,
  `arn:aws:s3:::company-frontend-*`) are literal strings
  in the SIR. Soufflé does literal joins. To reason about
  wildcard expansion, switch to SMT (string theory) or
  pre-expand wildcards in a different projection layer.

- **Not unbounded transitive closure.** `privesc_chain` is
  capped at depth 10 (matches the kernel's
  `MaxChainDepth`). For unbounded reachability, declare
  `transitive_role` without a depth bound — Soufflé will
  compute it but the hop-count annotation goes away.

- **Not a comparison-harness substitute.** The five
  engines' counts must agree on the questions they share
  (e.g., does a multi-hop chain exist?). Disagreement is
  the harness's job to flag, not Soufflé's. This example
  ships counts; the harness ships parity checks.
