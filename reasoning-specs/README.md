# reasoning-specs/

Formal reasoning specifications that define how external engines (Z3, Souffle, Clingo, Prolog, PRISM) answer security questions about Stave's exported fact bases. Each spec encodes a question, the input format, the reasoning steps, and the expected answer shape.

## Directory Layout

```
reasoning-specs/
├── fm-*.yaml               Failure-mode specs (question + reasoning chain + trial fixture pointer)
├── k8s-*.yaml              Kubernetes-specific specs
├── trials/                 Self-contained trial packages (one per engine test)
│   ├── z3-public-read-bucket/
│   ├── z3-iam-condition-key/
│   ├── souffle-anonymous-reachability/
│   ├── souffle-lambda-blast-radius/
│   ├── souffle-lambda-concurrency/
│   ├── souffle-lambda-event-source/
│   ├── souffle-az-redundancy/
│   ├── clingo-violation-atoms/
│   ├── prolog-proof-chain/
│   └── prism-risk-probability/
├── revisions/              Diffs from spec fixes discovered during trials
├── INVENTORY.md            Phase 1 engine inventory (which engines have working examples)
├── TRIAL-RESULTS.md        Phase 2 trial outcomes (5 engines, 2 defects caught and fixed)
├── BLIND-TRIAL-RESULTS.md  Phase 3 blind re-runs confirming fixes
└── gap-report.md           Phase 4 failure taxonomy and gap analysis
```

## Spec Format

Each `fm-*.yaml` or `k8s-*.yaml` file follows this structure:

```yaml
question: >
  The security question the engine answers.
context: >
  Why the question matters and what the input represents.
input:
  source: stave export-sir --format <smt2|jsonl>
  format: <smt-lib|jsonl>
  fixture: <path to trial input>
reasoning:
  steps: [...]    # Numbered reasoning chain the engine follows
expected_result:
  verdict: <SAT|UNSAT|count|probability>
validation:
  rules: [...]    # How to compare trial output against golden
```

## Trial Packages

Each directory under `trials/` is a self-contained test package:

- `spec.yaml` -- full reasoning spec (includes expected answer)
- `spec-trial.yaml` -- stripped spec (answer removed, for blind trials)
- `input.<ext>` -- fixture data (`input.smt2`, `input.jsonl`, or `vulnerable.jsonl`/`remediated.jsonl`)
- `golden.yaml` -- expected answer key
- `export-schema.md` -- Stave export format documentation

A trial agent receives only `spec-trial.yaml`, the input file, and `export-schema.md`. It must derive the answer from the reasoning steps without seeing the golden.

## Engines Covered

| Engine | Format | Question Type |
|--------|--------|---------------|
| Z3 (SMT) | `.smt2` | Satisfiability -- "does a forbidden state exist?" |
| Souffle (Datalog) | `.jsonl` triples | Reachability closure -- "what can an anonymous principal reach?" |
| Clingo (ASP) | `.jsonl` atoms | Constraint violation -- "which assets violate these rules?" |
| Prolog | `.jsonl` facts | Proof trees -- "trace the chain from anonymous to resource" |
| PRISM | `.jsonl` observations | Risk probability -- "what is P(exploitation) per attack shape?" |

## Failure-Mode Specs

The `fm-*` files map to failure modes from Stave's failure mode catalog:

| Spec | Failure Mode | Engine |
|------|-------------|--------|
| `fm-034` | Temporal degradation (snapshot freshness) | CEL |
| `fm-042` | Lambda role blast radius | Souffle |
| `fm-046` | Lambda event source exposure | Souffle |
| `fm-060` | IAM condition key complexity | Z3 |
| `fm-063` | Lambda concurrency cascade | Souffle |
| `fm-079` | Redundancy single-point failure | Souffle |

## Trial Results

All five original engine trials pass. Two defects were caught and fixed during the trial process:

- **Clingo** -- spec referenced wrong predicate name (`mfa_enforced` vs `has_mfa_enforced`)
- **Prolog** -- golden had a transcription error (6 proof trees vs actual 12)

Both fixes confirmed under blind re-run by fresh agents with no prior context. See `TRIAL-RESULTS.md` and `BLIND-TRIAL-RESULTS.md` for details.
