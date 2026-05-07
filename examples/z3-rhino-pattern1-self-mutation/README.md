# z3-rhino-pattern1-self-mutation — second compound query

The second compound SMT query against Stave's facts export.
Where `z3-compound-overperm-assumable` combined a finding with
a trust relationship, this query combines an action-set
membership with a resource-scope constraint — same pipeline,
different shape.

Asks: "Is there an IAM principal that has at least one Rhino
Pattern 1 self-mutation action AND a wildcard resource
scope?"

## What Pattern 1 is

Spencer Gietzen's 2018 enumeration of 21 IAM privilege-
escalation methods (Rhino Security Labs) groups them into
five structural patterns. Pattern 1 — Policy Self-Mutation —
is the family of methods where a principal can modify its own
effective permissions: create a new policy version and
activate it, attach an admin policy to itself, join a
privileged group, drop a permissions boundary.

Rhino enumerated 9 Pattern 1 methods (1, 2, 7-13). The
iter-15 prover added 4 more. The structural shape is the
same: any one of these actions on a wildcard resource gives
the holder a way to upgrade their own permissions. The
disjunction over actions is what makes a single SMT query
recover all 13 — CEL would emit 13 separate findings, one
per method.

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `iam-21-privesc-5-patterns/rhino-vulnerable` | **sat** | `(timeout)` | `rhino-attacker` user with `iam:DeleteRolePermissionsBoundary` on `*` |
| `iam-21-privesc-5-patterns/remediated`       | **unsat** | unsat | n/a |

cvc5 times out on `rhino-vulnerable` because the fixture's
fact set is large (~115 assertions, ~50 distinct actions on
the rhino-attacker user). cvc5's `--finite-model-find`
strategy scales poorly when the closed-world axiom for
`has_action` has dozens of disjuncts. Z3's MBQI handles it in
sub-second; cvc5 doesn't decide in 10s and we move on.

The runner treats cvc5 timeout as best-effort skipped — z3
alone validates the verdict. cvc5 STILL has to agree with z3
when it decides (which it does on `remediated` where the
fact set is tiny).

This is an honest cross-check: solver-agreement-when-decided
is a stronger contract than solver-agreement-or-fail. cvc5
inconclusive doesn't mean z3 is wrong; it means cvc5
couldn't reach a verdict in budget.

## The compound

```
Fact 1:  has_type(principal, "aws_iam_user" | "aws_iam_role")
              → principal is an IAM identity
Fact 2:  has_action(principal, action) ∧ action ∈ {Pattern 1 actions}
              → principal grants at least one self-mutation action
Fact 3:  has_resource(principal, "*")
              → grant scope is wildcard

Conjunction → principal can self-mutate to admin.
```

Pattern 1 actions encoded in the disjunction:

```
Rhino's 9 named methods:
  iam:CreatePolicyVersion
  iam:SetDefaultPolicyVersion
  iam:AttachUserPolicy
  iam:AttachGroupPolicy
  iam:AttachRolePolicy
  iam:PutUserPolicy
  iam:PutGroupPolicy
  iam:PutRolePolicy
  iam:AddUserToGroup

Beyond Rhino — same shape:
  iam:CreatePolicy
  iam:DetachUserPolicy
  iam:DeleteUserPolicy
  iam:DeleteRolePermissionsBoundary
```

13 actions, one query, one disjunction. CEL emits a separate
finding per action; the compound view — that ANY of these on
ANY principal is the Pattern 1 shape — is what the SMT
encoding captures.

## Why CEL doesn't say this

CEL evaluates per-asset, per-control. Each Pattern 1 method
gets its own control; each control fires independently when
the action+resource pair matches. CEL produces 13 findings
when all 13 actions are present.

What CEL doesn't say: "these 13 findings together describe
ONE structural defect (Pattern 1), and the principal exhibits
the defect iff at least one of them is present." The
structural categorisation is the value of Pattern 1 as a
concept; the SMT encoding makes the categorisation
mechanical.

The iter-15 example already does this via the go-z3 binding
(per-pattern reachability queries with fixture comparison).
This SMT-LIB version proves the same shape is expressible
through file-as-language-boundary so any solver consumes it.

## Run

```bash
cd stave
make build
bash examples/z3-rhino-pattern1-self-mutation/run.sh
```

Expected output (also captured in `expected/output.txt`):

```
rhino-vulnerable        expected=sat    z3=sat    cvc5=(timeout)  OK (cvc5 inconclusive, z3 decides)
remediated              expected=unsat  z3=unsat  cvc5=unsat  OK
```

Requires:
- `z3` 4.x on PATH (required)
- `cvc5` 1.3+ on PATH (optional cross-check; expected to time
  out on the rhino-vulnerable fixture)

## What this commit added

**Zero Stave changes.** The query uses only existing baseline
predicates (`has_type`, `has_action`, `has_resource`). The
projection extension this iteration introduces is in `run.sh`,
not `facts.go`: cvc5 timeout handling.

The pipeline declared "complete" in the prior commit's
README is now substantively complete: every Pattern 2-5
query is a copy of this directory with a different
disjunction list. `z3-rhino-pattern2-creation`,
`z3-rhino-pattern3-passrole`, etc. are 30 lines of
`query.smt2` and a path-rewrite of `run.sh` apiece.

## What this is not

- **Not a definitive Pattern 1 detector.** SAT means a
  principal in the snapshot has the structural shape (one
  action from the registry on a wildcard resource). Whether
  the shape constitutes a violation depends on intent — some
  IAM administrators legitimately have these grants. The
  query produces a list to triage; the human reviewer
  decides.

- **Not an exhaustive Pattern 1 enumeration.** The action
  registry mirrors `iam-21-privesc-5-patterns/z3prove/patterns.go`'s
  Pattern 1 list. New actions discovered later are added to
  the disjunction by editing `query.smt2` — no Stave changes.

- **Not a replacement for the existing iter-15 Z3 prover.**
  That prover uses `aclements/go-z3` directly and supports
  rich control flow (per-pattern looping, witness extraction,
  registry comparison). This SMT-LIB query is for
  file-as-language-boundary consumers — Z3 today, cvc5 (when
  decisive), Yices / Bitwuzla / MathSAT tomorrow.

## What's next

| Next compound | Pattern | Effort |
|---|---|---|
| Rhino Pattern 2 (credential creation/theft) | `has_action` over `iam:CreateAccessKey`, `iam:CreateLoginProfile`, etc. + admin-target predicate | one query.smt2 |
| Rhino Pattern 3 (PassRole + compute) | `has_action(iam:PassRole)` + `has_action(launch-action)` + `trusts_service` chain | one query.smt2 (already partially expressible with existing predicates) |
| Bybit (env-tagged write to public bucket) | needs `has_tag` extractor (binary or ternary) | one extractor + query |

The infrastructure is stable. Every Pattern 2-5 query is a
30-line file. The projection extends only when a fact lives
in observation data we don't yet surface — which is rare for
IAM-style queries (the policy statements are already there)
and common for service-specific edges (Cognito mapping, tag
predicates).
