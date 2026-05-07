# z3-overpermission-fixture — first end-to-end SMT consumer

This example is the first proof that Stave's
`stave export-sir --format smt2` round-trips through real SMT
solvers and produces mathematically correct verdicts. Two
independent solvers (Z3 + cvc5) agree on both fixtures; that
agreement is the validation the pipeline is solver-agnostic.
Every subsequent example, every Rhino-21 encoding, every
comparison harness — they all depend on this verdict pipeline
working.

## What it asks

A 27-line `query.smt2` answers one question against the
iter-7a iam-overpermission-wildcard fixture:

> Does any asset have an exposure window in this snapshot
> contributed by `CTL.IAM.POLICY.RESOURCE.WILDCARD.001`?

| Fixture | Stave verdict | Expected | Z3 | cvc5 | Witness |
|---|---|---|---|---|---|
| `before` (Lambda role with `s3:*` on `*`) | NON_COMPLIANT | sat   | sat   | sat   | `arn:aws:iam::111122223333:role/DataProcessorLambdaRole` |
| `after` (scoped policy)                   | COMPLIANT     | unsat | unsat | unsat | n/a |

`run.sh` runs both solvers (cvc5 is optional — if absent, the
cross-check is skipped with a notice and only z3 must pass).
Z3 is the canonical reference; cvc5 must match z3 on every
fixture or the script fails.

## Why this is the validation that matters

Without it, the SMT export is theoretical. With it, every claim
of "Stave's facts feed an external prover" has a 27-line proof.

The validation surfaces three properties at once:

1. **The serializer round-trips through Z3.** No syntactic drift,
   no missing declarations, no escaping bugs.
2. **Closed-world axioms work.** Without them, every existential
   query would be trivially `sat` because SMT-LIB predicates are
   unconstrained by default. The `after` fixture's `unsat`
   verdict is the proof that the axioms emit and constrain
   correctly.
3. **The baseline predicate set is portable.** The `after`
   fixture has no `has_exposure_window` facts, but the predicate
   is still declared (baseline) and its closed-world axiom
   asserts it false everywhere. Queries referencing it parse
   and evaluate consistently across fixtures.

## Run

```bash
cd stave
make build               # builds ./stave
cd examples/z3-overpermission-fixture
bash run.sh
```

Expected output (also captured in `expected/output.txt`):

```
before        expected=sat    z3=sat    cvc5=sat    OK
after         expected=unsat  z3=unsat  cvc5=unsat  OK
```

Requires:

- `z3` 4.x on PATH (`apt install z3` / `brew install z3`).
  Required.
- `cvc5` 1.3+ on PATH. Optional — if absent, the cvc5 column
  shows `(skipped)`, the script proceeds with z3-only
  validation, and exits 0.

The cvc5 invocation uses `--finite-model-find --produce-models`.
The default cvc5 quantifier strategy returns `unknown` on the
universal closed-world axioms; `--finite-model-find` treats the
fact base as a finite-model search, which decides both
directions correctly.

## What's in the file

```
examples/z3-overpermission-fixture/
├── README.md           # this file
├── query.smt2          # 27-line SMT-LIB query
├── run.sh              # exports facts, runs Z3, asserts verdict
└── expected/
    └── output.txt      # captured run.sh output for comparison
```

## Why no Go code

The whole point of `stave export-sir --format smt2` is that
external programs reason in the language they're written in.
This example is a 16-line shell script and a 27-line SMT
query. No Go binding, no library import, no cgo, no libz3
on Stave's build path. The boundary is files. That is the
contract.

## What this is not

- **Not a security finding the engine couldn't already produce.**
  Stave's CEL evaluator already detects this. The Z3 verdict
  agrees with CEL — that's the whole point of the validation.
  Where Z3 starts to add value is when queries ask compound
  questions across the asset graph (e.g., the iter-7a Bybit
  prefix-wildcard case where CEL stays silent and Z3 finds
  the prod-bucket witness, or the iter-15 Rhino-21 collapse
  where one structural query covers methods CEL would need
  21 separate controls for).

- **Not a closed-world reasoning demo.** The closed-world
  axiom is necessary plumbing for the verdict to be
  meaningful at all; it's not the demo itself. Future
  examples that ask reachability ("can principal X reach
  asset Y through any chain") put the closed-world axiom
  to genuine work.

- **Not the only consumer pattern.** Per-example sibling Go
  modules using the `aclements/go-z3` binding are still the
  preferred shape for examples that need rich Z3 control
  flow (see iter-7a's `z3prove/`, iter-15's `z3prove/`).
  This example is for the file-as-language-boundary case
  where any solver should work — Z3 and cvc5 today, Yices /
  Bitwuzla / MathSAT tomorrow — without changes to the query.

## Why two solvers, not one

Different SMT solvers exercise different code paths through
the same SMT-LIB input — different parsers, different
quantifier instantiation strategies, different decision
procedures. Agreement raises confidence the verdict reflects
the encoded semantics rather than a solver-specific quirk.
Disagreement either points at a real solver bug (rare) or —
far more common — at an encoding ambiguity Stave should fix.

The cvc5 cross-check caught one such issue during this
example's bring-up: cvc5's default quantifier strategy returns
`unknown` on the universal closed-world axioms. The fix wasn't
in Stave; it was the solver flag `--finite-model-find` which
treats the fact base as a finite-model search and decides both
directions. That tuning is documented in the script and is
solver-specific (Z3 doesn't need a flag to handle the same
input). Future solvers will likely need their own tuning; the
cross-check is what surfaces those issues early.

## Acceptance criteria

The verdict round-trip works iff `bash run.sh` exits 0 with
the captured expected output. If a future change breaks
either verdict, this script fails — that's the regression
gate for the SMT export contract.
