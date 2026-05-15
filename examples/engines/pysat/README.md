# PySAT — compound-chain satisfiability

Encodes each chain member as a boolean variable and asks
"can all members fail simultaneously?" — a focused
satisfiability check that's narrower than Z3's full
SMT-with-theories.

This directory ships a **starter template**, not a production
encoding. A real implementation would:

- Encode the chain's `escalation_threshold` as a cardinality
  constraint (Glucose3 supports `Card` via pysat.card).
- Model per-asset rather than catalog-wide satisfiability
  (the current script asks "can these predicates hold at all?"
  not "can they hold on the same asset?").
- Chain-walk role assumptions instead of treating each
  predicate independently.

The point of this example is to show the **pattern**: Stave's
JSONL is a flat triple stream, and any consumer can pick the
predicates it cares about and run a SAT solver on the resulting
boolean encoding. The example demonstrates the consumer-side
pipeline; the production encoding is a separate decision per
compound.

## Install

```bash
pip install python-sat
```

(The `python-sat` package ships several SAT backends; this
script uses Glucose3 by default.)

## Run

```bash
stave export-sir --format jsonl --observations ./my-snapshots > facts.jsonl
python3 compound_sat.py facts.jsonl

# Override the predicates checked:
python3 compound_sat.py facts.jsonl has_agent_lambda_scope_broad,has_agent_guardrail
```

## Output

- **SAT** — every named predicate has at least one supporting fact
  in the export. The compound chain's member conditions can hold
  simultaneously (the chain is triggerable from this snapshot).
- **UNSAT** — at least one named predicate has no supporting facts.
  The compound chain isn't triggerable from this snapshot.

## Why bother

SAT solvers shine on pure-boolean problems. When a chain's
question reduces to "are these N flags all set?", PySAT answers
in microseconds and the encoding is trivial to audit. It's the
right tool for boolean regressions over flag-style facts; Z3 is
the right tool when the question carries arithmetic, strings, or
quantifiers.
