# prolog-proof-trees

SWI-Prolog reasoning over the Stave fact base with **proof
trees** as the output. Z3 says "sat"; Soufflé says "6 paths";
Clingo lists violation atoms; Prolog produces the
**derivation chain** — the structured explanation of WHY the
unsafe path exists.

## What Prolog uniquely answers

| Engine | Output for "Can anonymous reach S3?" |
|---|---|
| Z3 | `sat` (one witness model exists) |
| Soufflé | `anonymous_reachable: 6 paths` |
| Clingo | `violation(pool, "unauth_cognito_s3_read")` |
| **Prolog** | step-by-step derivation: `pool --[allows_unauthenticated]--> true` then `pool --[maps_unauth_to]--> role` then `role --[grants]--> s3:GetObject` then `role --[on_resource]--> bucket` |

The proof tree is the reasoning trace. Each
`step(From, Relation, To)` maps to one evaluated fact in an
AI agent's structured trace; the chain identifies precisely
which configuration fact, if changed, breaks the derivation.

## How it works

`reasoning.pl` declares four rules; each carries a `Proof`
accumulator that records the derivation chain:

| Rule | Proof shape |
|---|---|
| `anonymous_access/4` | 4 steps: `allows_unauthenticated` → `maps_unauth_to` → `grants` → `on_resource` |
| `self_register_access/4` | 4 steps: `self_registration_unrestricted` (on user pool) → `maps_auth_to` (on identity pool) → `grants` → `on_resource` |
| `exploitable_role/4` | 2 steps + conclusion: `has_finding` → `trusts_compute` → `therefore role :: exploitable_via_passrole` |
| `privesc_path/3` | N steps: `assumes` chains, depth-bounded by `max_depth/1` (default 8), cycle-prevented via visited list |

Backtracking enumerates every successful proof. `forall/2`
in `run_queries/0` iterates the solution stream and renders
each tree with `print_proof/2` (indented step-by-step trace).

## Run

```bash
cd stave
make build
bash examples/prolog-proof-trees/run.sh
```

Requires `swipl` 9.x on PATH (apt: `swi-prolog`, brew:
`swi-prolog`). No venv needed — Prolog ships as a system
binary.

## Output (live, recorded in `expected/output.txt`)

Each fixture renders four sections — `Anonymous Access
Chains`, `Self-Registration Chains`, `Exploitable
Overpermissioned Roles`, `Privilege Escalation Paths`.
Sections with no proofs print `(none)` so absence is
explicit, not a silent gap.

Snippet (cognito writeup, anonymous chain):

```
=== Anonymous Access Chains ===

anonymous reaches arn:aws:s3:::app-public-assets via s3:GetObject:
arn:aws:cognito-identity:...:identitypool/us-east-1:abc-app-pool --[allows_unauthenticated]--> true
 arn:aws:cognito-identity:...:identitypool/us-east-1:abc-app-pool --[maps_unauth_to]--> arn:aws:iam::111122223333:role/Cognito_appUnauth_Role
 arn:aws:iam::111122223333:role/Cognito_appUnauth_Role --[grants]--> s3:GetObject
 arn:aws:iam::111122223333:role/Cognito_appUnauth_Role --[on_resource]--> arn:aws:s3:::app-public-assets
```

Multi-hop privesc (vulnerable fixture, 3-hop chain):

```
=== Privilege Escalation Paths ===

privesc developer -> admin-role:
developer --[assumes]--> onboarding-role
 onboarding-role --[assumes]--> operator-role
 operator-role --[assumes]--> admin-role
```

Six total privesc proofs on the vulnerable fixture: three
1-hop edges, two 2-hop chains, one 3-hop chain. The 3-hop
proof is the one Z3's existential query collapses to a
single witness; Prolog enumerates every prefix.

## What the action↔resource cartesian reveals

Stave's SIR projects `has_action(role, action)` and
`has_resource(role, resource)` as **independent** binary
predicates — there is no `grants(role, action, resource)`
ternary tying them together (the SMT serializer is
binary-only; the article on the Bybit example documents
this trade-off).

So when `Cognito_appUnauth_Role` has 4 actions and 3
resources, Prolog's anonymous_access enumerates all 12
(action, resource) pairs. Only some of those are real AWS
grants (s3:GetObject paired with the S3 ARN, dynamodb:Query
paired with the DDB ARN, etc.); the rest are
SMT-projection-faithful but semantically nonsensical
combinations.

This is the same limitation the Bybit SMT query mentions: a
ternary `statement_grants` predicate would tighten the join.
For the Prolog example's pedagogical goal — show what a
proof tree looks like — the over-enumeration is acceptable;
each tree is *individually* a valid composition the SIR
permits under its current vocabulary.

## Comparison harness integration

Verdict in the comparison harness:
Prolog's verdict:

- **UNSAFE** if any of the four sections produces a proof
 tree (any `--[` line)
- **SAFE** if every section prints `(none)`

Prolog covers the Cognito + Multi-hop + Rhino-vulnerable
fixtures in the harness. Bybit and Rhino-remediated are
out-of-scope for this engine because the rule set as written
doesn't compose Bybit's wildcard prefix-matching (SMT
territory) and rhino-remediated has no findings to derive
from.

## What this is not

- **Not a meta-interpreter.** Standard SWI-Prolog
 backtracking does the work; the proof tree is built by
 passing a list accumulator through the rule heads. No
 `solve/2` definition, no clause-walker. If a future
 iteration needs a meta-interpreter (e.g., to expose
 *why-not* proofs alongside successes), that's a separate
 exercise.

- **Not a counter.** Soufflé already counts paths; Prolog
 enumerates proofs. The two compose: Soufflé tells you
 there are 12 anonymous-reach triples; Prolog renders each
 one as a derivation an auditor can read. Use both.

- **Not a unsoundness detector.** A Prolog proof witnesses
 *a* derivation, not *the* derivation, and not *all*
 derivations. The SIR's binary projection of action and
 resource means some proofs are the cartesian artifact
 rather than a real AWS-policy match. Treat each proof as
 "the SIR permits this composition under its current
 vocabulary" — not "AWS would actually allow this call."

- **Not a tabled-evaluation example.** The privesc walker
 uses a depth bound + visited list for cycle prevention.
 For genuinely deep chains or graphs with cycles, switch
 to `:- table privesc_path/3.` (SWI-Prolog tabling) — the
 existing rules support it without modification.
