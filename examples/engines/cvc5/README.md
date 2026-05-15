# cvc5 — independent SMT cross-check

Reads the **same** SMT-LIB file Z3 reads. The point isn't a second
algorithm — both are decision procedures for the same logic
fragments — it's an independent implementation.

Two independent SAT solvers agreeing on UNSAT for the same SMT-LIB
bundle is the strongest confidence signal a multi-engine setup
produces. One solver returning UNSAT is a proof under that solver's
implementation; two solvers returning UNSAT is the same proof
verified by two unrelated codebases.

## Install

```bash
brew install cvc5                # macOS
# Linux / source: https://cvc5.github.io/
```

## Run

```bash
stave export-sir --format smt2 --observations ./my-snapshots > facts.smt2
bash run.sh facts.smt2

# Cross-check against Z3 on the same file:
bash ../z3/run.sh facts.smt2
```

## Why bother

A compiler bug in either solver is rare but possible. A logic-encoding
bug in **Stave's** SMT-LIB export — where the assertions don't quite
match what we think they assert — is more common. When Z3 and cvc5
disagree on the same input, the bug is in the input file or in one of
the solvers, not in your interpretation. That signal is worth the cost
of running two binaries.

## Zero Stave code needed

cvc5 has been an interoperability target from the start. The SMT-LIB
v2 format is solver-portable; adding cvc5 to the pipeline is one
extra `cvc5 facts.smt2` invocation — no Stave change.
