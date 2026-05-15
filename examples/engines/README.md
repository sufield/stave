# External Reasoning Engines

Stave exports facts as JSONL triples and SMT-LIB assertions.
These examples show how to consume the export with five
independent reasoning engines — without Stave knowing or caring
which engine you use.

```
stave export-sir → facts.jsonl / facts.smt2 → engine of choice
```

## Quick start

```bash
# 1. Generate the fact export from any Stave observation set
stave export-sir --format jsonl --observations ./my-snapshots > facts.jsonl
stave export-sir --format smt2  --observations ./my-snapshots > facts.smt2

# 2. Run any engine (each directory has its own README + run.sh)
cd z3      && bash run.sh ../facts.smt2
cd cvc5    && bash run.sh ../facts.smt2
cd souffle && bash run.sh ../facts.jsonl
cd clingo  && bash run.sh ../facts.jsonl
cd pysat   && python3 compound_sat.py ../facts.jsonl
```

## What each engine answers

| Engine | Question | Answer shape |
|---|---|---|
| **Z3** | Is a forbidden state mathematically reachable? | SAT (with witness) or UNSAT (provably unreachable) |
| **cvc5** | Same question as Z3, independent solver | Cross-check: two solvers agreeing on UNSAT = high confidence |
| **Soufflé** | What reaches what? How wide is the blast radius? | Count + enumeration via complete transitive closure |
| **Clingo** | Which violation rules fire and on which atoms? | Named violations as answer-set atoms |
| **PySAT** | Can all N member conditions of a compound chain hold simultaneously? | SAT (all can fail at once) or UNSAT |

## The contract

Stave's stable inputs are two formats:

- **`facts.jsonl`** — one JSON object per line:
  ```json
  {"fact_id":"...","subject":"...","predicate":"...","object":"...","source":"...","evidence":"...","provenance":{...}}
  ```
  The `subject` / `predicate` / `object` fields are the load-bearing
  triple; the rest is provenance metadata.

- **`facts.smt2`** — SMT-LIB v2 declarations + assertions. Solver-portable
  across Z3, cvc5, Yices, Bitwuzla, MathSAT.

Each engine consumes one of those two formats. If an engine needs a
different shape (Soufflé's `.facts` TSV, Clingo's `.lp` atoms), the
conversion happens in the engine's own `convert.sh` — Stave's export
format never changes per consumer.

## No Stave code changes

Everything in this directory is consumer-side. The conversion scripts
are one-line `jq` invocations. The rule files are engine-native.
Stave's job ends at `export-sir`; the engines pick up from there.

## Related directories

Two pre-existing example directories carry fixture-tied worked examples
with golden expected outputs (deeper than the engine-agnostic skeletons
here):

- `examples/souffle-reachability/` — Soufflé reachability rules
  (`reachability.dl`, `delegation-reach.dl`, `shadow-admin-reach.dl`)
  with a `transform.sh` and an `expected/` directory pinning the
  output counts per fixture.
- `examples/clingo-constraints/` — Clingo violation rules
  (`ai-delegation-shadow.lp`, `constraints.lp`) with a `run.sh` /
  `run.py` orchestrator and an `expected/` directory.

The `souffle/` and `clingo/` subdirectories below ship copies of those
rule files so the umbrella `examples/engines/` works as a standalone
entry point. For the regression-tested versions with fixture goldens,
use the dedicated directories above.

## Installing the engines (none come with Stave)

```bash
# Z3
brew install z3                # macOS
apt install z3                 # Ubuntu

# cvc5
brew install cvc5              # macOS
# Linux: https://cvc5.github.io/

# Soufflé
brew install souffle           # macOS
apt install souffle            # Ubuntu

# Clingo
brew install clingo            # macOS
conda install -c potassco clingo

# PySAT
pip install python-sat
```

The `run.sh` scripts each check `command -v` and print the install
hint if the binary is missing — no script fails silently.
