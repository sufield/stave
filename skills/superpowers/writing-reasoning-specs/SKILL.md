---
name: writing-reasoning-specs
description: Write a reasoning specification for an external solver (Z3, cvc5, Soufflé, Clingo, Prolog, PRISM) that consumes Stave's SIR fact export, then trial it with a fresh agent
triggers:
  - reasoning spec
  - SMT-LIB
  - Z3 verification
  - Soufflé Datalog
  - Clingo ASP
  - PRISM probability
  - Prolog proof tree
  - formal verification
  - solver query
  - reachability query
requires:
  - stave (go install github.com/sufield/stave@latest)
  - superpowers:test-driven-development (REQUIRED — same assertion-first discipline)
---

# Writing Reasoning Specs

Announce: *"I'm using the writing-reasoning-specs skill to author a
formal verification question."*

## When to use this skill

- Task asks for a *mathematical proof* / *reachability check* /
  *constructive counterexample* — these are SMT / Datalog / ASP shapes,
  not CEL controls
- The question is *"is X reachable in any configuration?"* (Soufflé,
  Z3)
- The question is *"what is the probability of exploit chain X?"* (PRISM)
- The question is *"why did this finding fire? show the trace"* (Prolog)
- The chain you want to verify spans multiple resources and the CEL
  catalog can find each member but not assert their composition

If the task is *"does this control fire on this fixture?"* → use
`stave:verifying-cloud-security`.

## Prerequisites

```bash
go install github.com/sufield/stave@latest
# At least one solver locally, matched to the reasoning type:
# Z3:      brew install z3
# cvc5:    download from https://cvc5.github.io/
# Soufflé: brew install souffle
# Clingo:  brew install clingo
# Prolog:  brew install swi-prolog
# PRISM:   download from https://www.prismmodelchecker.org/
```

## Workflow

This skill enforces the **test-first discipline from
`superpowers:test-driven-development`**. The spec without a known
expected answer is not a spec — it's a question. Write the answer
first, the steps second.

### Phase 1 — Define the security question

State the question in plain English, in **one sentence**, with no
verbs like *"analyze"* or *"check"*.

Good:
- *"Is there a principal that can read `arn:aws:s3:::phi-bucket` via
  any combination of trust-policy hops?"*
- *"What is the probability that an attacker reaching the public-facing
  Lambda also reaches the customer-data DynamoDB table?"*
- *"For the finding `CTL.IAM.GHOST.001` on role `<arn>`, what is the
  proof tree that justifies it?"*

Bad:
- *"Check IAM."* (no truth condition)
- *"Audit privilege escalation paths."* (no specific principal/target)
- *"Verify compliance."* (no formal statement)

If you cannot write the sentence in this shape, you cannot write a
spec for it.

### Phase 2 — Pick the engine

| Question shape | Engine | Output verdict |
|---|---|---|
| *Is X reachable?* / *Is there a configuration where X holds?* | Z3 / cvc5 / Yices (SMT) | `sat` (yes + witness) / `unsat` (provably no) |
| *Enumerate all configurations where X holds.* | Soufflé (Datalog) | List of grounded facts |
| *Find all violations matching pattern P.* | Clingo (ASP) | Stable models |
| *Why did finding F fire? Show the derivation.* | Prolog | Proof tree |
| *What is P(attack reaches state S)?* | PRISM | Real-valued probability |

The engine choice constrains the spec's shape. Don't pick the engine
after writing the spec; pick it from the question shape.

### Phase 3 — Write the spec YAML

Use the template at `spec-template.yaml`. The skeleton:

```yaml
question: >
  <the single-sentence question from Phase 1>

engine: z3                          # one of: z3 | cvc5 | souffle | clingo | prolog | prism
reasoning_kind: reachability        # reachability | enumeration | derivation | probability

input:
  fact_source: stave export-sir --format smt2 --observations <dir> --now <RFC3339> --allow-unknown-input
  query_file: query.smt2

reasoning:
  # Each step is a precise, executable rule. Do NOT use verbs like
  # "analyze", "evaluate", "consider". Use formal connectives: "if",
  # "then", "and", "exists", "for all".
  steps:
    - step: 1
      action: |
        For every (principal, action, resource) triple in the SIR,
        assert has_allow_action(principal, action, resource) when
        the corresponding statement has Effect="Allow".
    - step: 2
      action: |
        Define can_reach(p, r) :- has_allow_action(p, _, r).
    - step: 3
      action: |
        Define can_reach(p, r) :- has_assume(p, q), can_reach(q, r).
        (transitive trust closure)
    - step: 4
      action: |
        Query: (check-sat) of (and (can_reach P R)
                                   (= R "arn:aws:s3:::phi-bucket")
                                   (= P "<anonymous-principal>"))

output:
  expected_result: unsat            # or sat with witness shape
  expected_witness: null            # if sat, the shape of the constructive answer
```

### Phase 4 — Write the test fixture

Build a Stave observation snapshot whose **known answer** matches your
`expected_result`. Two snapshots are enough — one with the dangerous
shape (expect `sat`), one with the remediated shape (expect `unsat`).

```bash
# Generate facts for the dangerous snapshot.
# --allow-unknown-input is required on observations that don't carry
# generated_by.source_type (true of most fixtures and hand-authored
# test cases); omit it only when strict source-type provenance is a
# requirement.
stave export-sir --format smt2 \
    --observations fixtures/dangerous/observations \
    --now 2026-05-17T00:00:00Z \
    --allow-unknown-input > /tmp/dangerous.smt2

# Append the query
cat /tmp/dangerous.smt2 query.smt2 | z3 -in
# Expected: sat <constructive witness>

# Generate facts for the remediated snapshot
stave export-sir --format smt2 \
    --observations fixtures/remediated/observations \
    --now 2026-05-17T00:00:00Z \
    --allow-unknown-input > /tmp/remediated.smt2

cat /tmp/remediated.smt2 query.smt2 | z3 -in
# Expected: unsat
```

**Checkpoint 0 (pre-flight): grep the fact file for predicates AND
verify positive assertions BEFORE writing reasoning steps.**

```bash
# What predicates does the SIR declare?
grep '^(declare-fun' /tmp/dangerous.smt2 | head -20

# Which of those are universally negated (queryable but always false)?
grep '^(assert (forall' /tmp/dangerous.smt2 | head -10

# Positive assertions for your subjects of interest:
grep '"arn:aws:iam::.*role/your-role"' /tmp/dangerous.smt2 | head -5
```

The SIR's vocabulary is bounded twice: only declared predicates are
queryable, and many declared predicates carry closed-world axioms
that universally negate them
(`(assert (forall (x ...) (not (predicate x ...))))`). A query against
a universally-negated predicate always returns `unsat`, regardless of
whether the underlying chain is reachable in the configuration. The
verdict is meaningless — the solver isn't reasoning about your fixture,
just about the closed-world axiom.

Run **all three** greps above before writing reasoning steps. The
predicate names you plan to use must (a) appear in `declare-fun` AND
(b) NOT appear in a universally-negated `forall` AND (c) carry at
least one positive `(assert (...))` for the subjects your question
names.

What the SIR actually projects today is narrower than the chain
catalog suggests. Most reachability is currently expressible via
entity-level positive signals (`has_type`, `has_tag`,
`has_severity`, `contributed_by <control-id>`,
`has_exposure_window`) plus the policy-walk predicates the
specialised projectors emit (`has_action`, `has_resource`,
`has_permission_action`, `has_permission_resource`, `can_assume`,
`cross_account_assumes`). For the Cognito unauth→S3 chain
specifically, the positive signal is
`contributed_by CTL.COGNITO.IDPOOL.UNAUTH.S3.001` on the
identity-pool asset — *not* a higher-level `allows_unauthenticated`
or `unauth_role_has_s3` predicate (those are declared but universally
negated in this projection). Compose your query against the positive
signals; never trust a predicate name from the chain documentation
without running the three greps above against your fixture's SIR
export.

See the Fact Export reference in stave-guide for the full list of
predicates the SIR currently emits and their domain coverage.

**Checkpoint 1:** the dangerous fixture yields the dangerous verdict
(`sat`) AND the remediated fixture yields the safe verdict (`unsat`).
Both halves must hold. If only one does, your query is over- or
under-specified.

### Phase 5 — Trial the spec with a blind agent

This is the discipline that separates a spec from a wish.

1. Save the spec WITHOUT the `expected_result` field.
2. Hand the spec + the dangerous fixture's SIR export to a **fresh
   agent** (a sub-agent, or a different conversation).
3. The agent must produce a verdict from the spec alone.
4. Compare the agent's verdict against your `expected_result`.

If they match: the spec is reproducible. If they don't: the spec is
ambiguous — fix the spec (not the agent, not the expected result).
The trial is the test; passing without trialling is hope.

**Checkpoint 2:** blind-trialled agent reaches the same verdict as
your `expected_result` on both fixtures.

### Phase 6 — Document the proof scope

The SIR projects 13 top-level configuration domains (IAM, Cognito,
S3 policies, Bedrock AI, delegation, credentials, trail, network,
parts of compute/k8s). A `sat` / `unsat` verdict is valid **within
that exported scope**. State the scope explicitly in the spec's
output section:

```yaml
output:
  expected_result: unsat
  scope_caveat: >
    The unsat verdict is valid for chains the SIR can express in the
    13 covered domains. The verdict is silent about chains whose
    members live in uncovered domains (Azure, GCP, M365, databases,
    messaging, secrets, monitoring, plus 80+ smaller domains).
    See `stave export-sir --help` for the current domain list.
```

**Checkpoint 3:** the scope caveat is present in the spec and matches
the SIR's current coverage. Without the caveat, a `unsat` claim
overclaims.

## Key principles

- **Expected result before reasoning steps.** TDD for proofs.
- **Engine matches question shape.** SAT/UNSAT questions go to SMT;
  enumeration questions go to Datalog/ASP; derivation questions go
  to Prolog; probability questions go to PRISM. Cross-pairing wastes
  effort and produces unverifiable answers.
- **Trial the spec blind.** A spec that only the author can execute
  is not a spec. The blind-trial step from
  `superpowers:test-driven-development` applies here verbatim.
- **Name the scope.** Every UNSAT is conditioned on what the SIR
  projects. Without the scope caveat the proof claim overclaims.
- **The witness is the exploit.** When SMT returns `sat`, the
  constructive counterexample names the principal / action / resource
  that compose the attack path. Always include the witness in the
  output — it's the operational artefact, not just the verdict.

## Supporting files

- `spec-template.yaml` — fillable starter; one section per workflow phase

## Related skills

- `superpowers:test-driven-development` — the discipline this skill
  applies to formal verification
- `stave:verifying-cloud-security` — produce the SIR export the
  reasoning spec consumes
- `stave:writing-stave-controls` — when the question is better answered
  by a CEL predicate than a solver query
