# z3-compound-overperm-assumable — first compound query

The first SMT query that combines two independent CEL findings
into a single quantified question. Z3 asks: "is there a role
that BOTH triggered the overpermission control AND is
assumable by a compute service?" — the compound that turns a
broad-policy finding into an exploitable PassRole launchpad.

CEL evaluates each fact per asset and never asks the
conjunction. SMT asks it directly. Witnesses name the role.

## The compound

```
Fact 1: contributed_by(role, "CTL.IAM.POLICY.RESOURCE.WILDCARD.001")
 → role triggered the overpermission control
Fact 2: trusts_service(role, "lambda.amazonaws.com")
 OR ec2.amazonaws.com
 OR ecs-tasks.amazonaws.com
 OR codebuild / glue / sagemaker / states / cloudformation
 → role admits a compute / control-plane principal

Conjunction (Fact 1 ∧ Fact 2):
 → role is the canonical PassRole exploit shape:
 an attacker with iam:PassRole + the matching
 service's launch action becomes that role's
 full permission set on the next instance /
 function / task.
```

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `iam-overpermission-wildcard/before` | **sat** | **sat** | `arn:aws:iam::111122223333:role/DataProcessorLambdaRole` |
| `iam-overpermission-wildcard/after` | **unsat** | **unsat** | n/a |

Both solvers agree on both fixtures and pick the same witness
on `before`. The witness is the actual offending role — Z3
named it because that is the only role in the snapshot
satisfying both conjuncts.

## Why CEL doesn't say this

CEL evaluates per-asset, per-control:

- `CTL.IAM.POLICY.RESOURCE.WILDCARD.001` fires on
 `DataProcessorLambdaRole` because the role's policy has
 `s3:*` on `*`. CEL emits one finding.
- A separate per-asset check on the role's trust policy could
 emit a "Lambda-trusted role" finding. CEL would emit a
 second finding.

What CEL does NOT do: ask whether the same asset triggered
both findings AND those findings TOGETHER constitute a
PassRole exploit shape. The conjunction is the security
property; CEL produces two independent findings and leaves
the composition to the human reviewer.

The compound query makes the composition mechanically
expressible. Now any tool consuming the SMT output can
filter for "find me roles where the compound is satisfied"
without re-implementing per-domain join logic.

## Run

```bash
cd stave
make build
bash examples/z3-compound-overperm-assumable/run.sh
```

Expected (also captured in `expected/output.txt`):

```
before expected=sat z3=sat cvc5=sat OK
after expected=unsat z3=unsat cvc5=unsat OK
```

Requires:
- `z3` 4.x on PATH (required)
- `cvc5` 1.3+ on PATH (optional cross-check)

## What this is not

- **Not a definitive PassRole exploit detector.** SAT means
 the compound shape exists, not that the attacker
 necessarily has `iam:PassRole`. A real exploit also
 requires the attacker's principal to hold the launch
 action (`lambda:CreateFunction`, `ec2:RunInstances`, etc.)
 and `iam:PassRole` on the target role. Adding those
 conjuncts is the next iteration of this query — they're
 expressible with `has_action` (already a baseline
 predicate); the existing Z3 prover already does
 this end-to-end via the go-z3 binding. The SMT-LIB version
 shipped here proves the same composition is expressible
 through file-as-language-boundary.

- **Not a finding by itself.** The output is "a role with the
 shape." Whether that shape constitutes a violation depends
 on intent (compute roles legitimately trust their service
 principals). This query produces a list to triage — same
 contract as every other Z3 query against this export.

- **Not the only compound.** Three predicates tested in this
 commit are a subset of what `query.smt2` can ask. Adding
 conditions for resource sensitivity (e.g.
 `has_resource(role, sensitive_arn)`) tightens the
 precision; adding conditions for absence of MFA or IP
 conditions extends coverage. Each is a one-line edit to
 the disjunction list — no Stave changes needed.

## What's next

Each subsequent compound query is one `query.smt2` plus one
`run.sh`. The two-solver cross-check comes free. The pipeline
is now stable for compound queries — the work is purely
analytical.

| Next compound | Predicates combined | Effort |
|---|---|---|
| Add `iam:PassRole` requirement | + `has_action(attacker, "iam:PassRole")` | 5 lines in query.smt2 |
| Bybit (env=prod write to public CDN) | + `has_resource` prefix matching + tag predicates (need tag extractor) | new extractor + query |
| Rhino-21 self-mutation pattern | `has_action` over Pattern 1 method registry + `has_resource(role, role)` self-reference | one query.smt2 per pattern |
| Cognito → IAM → S3 with ternary statement-grants | needs `statement_grants(principal, action, resource)` ternary predicate (serializer extension) | extractor + serializer + query |
