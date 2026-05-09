# Forbidden State: User-Defined Z3 Invariants in YAML

Define security invariants as "states that must never exist"
directly in control YAML. The compiler auto-generates SMT-LIB
satisfiability queries from the YAML — no Go or Python required
to add a new Z3-checkable invariant.

```
controls/*.yaml (forbidden_state)
   -> stave export-invariants --format json
   -> compile.py     (predicate tree -> SMT-LIB query)
   -> obs_to_facts.py (observation values -> SMT-LIB assertions)
   -> z3 -in
   -> sat (VIOLATION) | unsat (SAFE)
```

## Pitch

CEL checks what IS true about one resource right now.
`forbidden_state` checks what must NEVER be true across every
combination of properties an asset can carry.

| | CEL `unsafe_predicate` | Z3 `forbidden_state` |
|---|---|---|
| Question | "Is THIS bucket's policy too broad?" | "Can the forbidden configuration ever hold?" |
| Evaluation | Per asset, per snapshot | Symbolic, over the full predicate tree |
| Output | Finding | sat (reachable) / unsat (impossible) |

Both can coexist on the same control; `forbidden_state` is
optional.

## Pipeline

1. Author the invariant in YAML alongside `unsafe_predicate`:

   ```yaml
   forbidden_state:
     all:
       - field: properties.storage.kind
         op: eq
         value: bucket
       - field: properties.storage.tags.data-classification
         op: eq
         value: phi
       - field: properties.storage.access.external_account_ids
         op: present
   ```

2. Export the catalog as solver-ready invariants:

   ```bash
   stave export-invariants --format json > invariants.json
   ```

3. Compile every `forbidden_state` block into a `*.query.smt2`:

   ```bash
   python3 compile.py invariants.json queries/
   ```

4. Bind observation values to the variables the queries declare:

   ```bash
   python3 obs_to_facts.py invariants.json observations/ facts.smt2
   ```

5. Concatenate, append `(check-sat)`, run Z3:

   ```bash
   { cat queries/CTL.S3.ACCESS.EXTERNAL.ORG.001.query.smt2 facts.smt2;
     echo '(check-sat)'; } | z3 -in
   # sat   → forbidden state is reachable → VIOLATION
   # unsat → forbidden state is impossible → SAFE
   ```

`run.sh` does the full round trip across both fixtures.

## Operator vocabulary

The compiler maps the catalog's predicate operators to SMT-LIB:

| Operator | SMT-LIB rendering |
|---|---|
| `eq`        | `(= var "value")` |
| `ne`        | `(not (= var "value"))` |
| `present`   | `(not (= var "__absent__"))` |
| `absent`    | `(= var "__absent__")` |
| `contains`  | `(or (= var "a") (= var "b") ...)` |
| `in`        | `(or (= var "a") (= var "b") ...)` |
| (other)     | `true` (over-approximation; flagged as a comment) |

Unknown operators are deliberately over-approximated to keep the
query sound — the auditor sees "no constraint" rather than a
silent false positive. Mirrors the operator table in
`experiments/z3-solver/compiler/invariant.go`.

## Why a separate Z3 check at all

Stave's main evaluator is CEL: per-asset state checks against
concrete observations. CEL is fast, deterministic, and the right
fit for "is this single resource configured wrong right now?".
It does NOT answer "could ANY combination of inputs make this
unsafe?". That's what `forbidden_state` + Z3 are for.

The auto-compiled query stays sound w.r.t. the YAML: a SAT
verdict means the predicate's logical structure admits the
observed values; UNSAT means it cannot, regardless of property
ordering or evaluation timing. CEL and Z3 cross-check each other
— a SAT here matched by a CEL finding is a doubly-confirmed
breach; a UNSAT proves the invariant safe across the modelled
property space.

## Prerequisites

| OS | Command |
|---|---|
| Ubuntu | `sudo apt install -y z3 jq` |
| macOS  | `brew install z3 jq` |

The example uses the `z3` CLI (not the Python `z3-solver`
binding). Stave itself has no Z3 dependency; only this example
does.

## Run it

```bash
cd <repo-root>/stave
make build                    # produces ./stave
bash examples/z3-forbidden-state/run.sh
```

Expected output (matches `expected/output.txt`):

```
=== Forbidden State: Auto-Generated Z3 Queries ===
  ... invariants exported
  1 with forbidden_state blocks

--- fixture: writeup-config
  CTL.S3.ACCESS.EXTERNAL.ORG.001                VIOLATION   forbidden state is reachable

--- fixture: remediated-config
  CTL.S3.ACCESS.EXTERNAL.ORG.001                SAFE        forbidden state is impossible
```

## What the example does NOT cover

- **Cross-resource composition.** Each `forbidden_state` is
  evaluated against the first asset that supplies the
  referenced paths. Multi-asset chains (an IAM role + an S3
  bucket policy together) need the full SIR + Stave's policy
  graph; see `examples/z3-multi-hop-can-assume`.
- **Numeric / ordering operators.** The vocabulary covers
  string equality + presence + membership. `gt` / `lt` /
  `before` / `after` would need additional sort handling.
- **Counterexample extraction.** Z3 returns a satisfying
  assignment on SAT; the example only prints the verdict.

The point is to show how `forbidden_state` blocks in YAML
become Z3-ready queries with no per-control glue code.

## Adding a new forbidden_state

1. Open the control YAML.
2. Add a `forbidden_state:` block beside `unsafe_predicate`,
   reusing the same `any` / `all` shape.
3. Run `stave export-invariants` and `compile.py`.
4. Confirm the generated `*.query.smt2` looks right.
5. Validate against a fixture with `run.sh`.

No Go changes needed. The catalog ships the new query
automatically.
