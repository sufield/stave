# Z3 — SMT solver

Proves whether a forbidden state is mathematically reachable from
Stave's SMT-LIB export. SAT means reachable; UNSAT means provably
unreachable — the strongest answer Stave can offer when the export
fully captures the relevant facts.

## Install

```bash
brew install z3   # macOS
apt install z3    # Ubuntu
```

## Run

```bash
stave export-sir --format smt2 --observations ./my-snapshots > facts.smt2
bash run.sh facts.smt2
```

## Output

- **SAT** — a forbidden state is reachable. Z3 prints a model showing
  which variable assignment reaches it; that assignment is the
  counter-example you can hand to a remediation engineer.
- **UNSAT** — provably safe. No combination of the exported facts can
  reach the forbidden state.
- **unknown** — solver gave up. Rare with our schema; usually means
  the wall-clock timeout (`-T:30`) needs to be raised, or there's a
  syntax issue in the SMT-LIB file.

## Why an example here when 13 worked Z3 programs already exist?

The fixture-tied examples (`examples/z3-*`) each model a specific
compound — `z3-public-exposure/`, `z3-cognito-auth-chain/`, etc. —
and ship Go programs that link `aclements/go-z3` via cgo. They prove
Stave's facts work for those specific scenarios.

This directory is the engine-agnostic entry point: any SMT-LIB-format
fact bundle, any Stave-supported snapshot, one runner. If you want to
prove "can a forbidden state be reached?" for an arbitrary observation
set, start here. If you want a worked compound example with golden
expected output, use the dedicated `examples/z3-<compound>/` dir.
