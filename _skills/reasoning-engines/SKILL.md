---
name: stave-reasoning-engines
description: Export Stave observation facts to JSONL/SMT-LIB and derive compound cross-asset chains with Z3, Soufflé, or Prolog — detection CEL alone cannot express
triggers:
  - reasoning engine
  - Z3 / Soufflé / Prolog
  - compound chain detection
  - export-sir
  - graph traversal escalation
  - transitive closure of permissions
requires:
  - a built stave binary (run stave-setup first)
  - one engine — z3 (pip install z3-solver) | souffle (apt) | swi-prolog (apt)
---

# stave-reasoning-engines

## What this skill does
Exports Stave's raw observation properties as facts, then runs a reasoning
engine to compute a multi-hop chain (e.g. user → role → admin) by tracing the
specific ARN edges — not by control co-occurrence.

**Time:** ~30 minutes. **No AWS needed** (works off any observation dir).

## Steps

### 1. Export facts to JSONL (triples)
```
./stave export-sir --observations <your-obs-dir> --format jsonl --now 2026-01-02T00:00:00Z > facts.jsonl
grep -c '"source":"observation"' facts.jsonl    # raw observation primitives
```
Each line is `{subject, predicate, object, source}`; `predicate` is the
dot-joined property path (e.g. `identity.escalation.create_access_key.target_user_arn`).

### 2. Export SMT-LIB and check it's well-formed
```
./stave export-sir --observations <your-obs-dir> --format smt2 --now 2026-01-02T00:00:00Z > check.smt2
o=$(grep -o '(' check.smt2 | wc -l); c=$(grep -o ')' check.smt2 | wc -l)
[ "$o" = "$c" ] && echo "balanced ($o)" || echo "UNBALANCED"
```
The SMT-LIB declares **binary per-path predicates** (`(declare-fun <path> (String String) Bool)`)
and is facts-only (no `(check-sat)`) — you append your own query.

### 3. Install one engine
```
pip install z3-solver --break-system-packages   # OR: sudo apt install souffle | swi-prolog
```

### 4. Consume the facts
- **Soufflé / Prolog:** turn the JSONL observation triples into `observation(s,p,o)`
  facts (the 3 fields map directly), then write rules that chain edges, e.g.
  `escalates(U,T) :- observation(U,"identity.escalation.create_access_key.present","true"), observation(U,"identity.escalation.create_access_key.target_user_arn",T).`
- **Z3:** append a query over the emitted binary predicates and assert the
  NEGATION of the chain, then `(check-sat)`.

### 5. Run and interpret
- **Soufflé** emits a tuple → the chain is connected between those specific assets.
- **Prolog** proves the goal → a path was traversed.
- **Z3 `unsat`** → the chain is *forced* by the facts (it must exist).
- **Z3 `sat`** → not derivable (the edges don't connect).

This is graph-traversal compound detection: it fires only when the ARNs connect,
which per-resource rules cannot express.

## Success
You derived a compound chain from observation primitives with a reasoning
engine, independent of Stave's own conclusions.
