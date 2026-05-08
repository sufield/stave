# H1 Fixture × Engine Matrix Harness

Runs every example fixture through every reasoning engine and
captures a per-cell verdict. The output drives
`examples/CATALOG.md` and the per-example
`multi-engine-results.md` files.

## Files

| File | Purpose |
|---|---|
| `run.py` | Iterates fixtures × engines, writes `matrix.json`. |
| `render.py` | Reads `matrix.json`, writes `examples/CATALOG.md` + per-example `multi-engine-results.md`. |
| `matrix.json` | Last captured matrix (committed for reference). Re-generate by running `run.py`. |

## Regenerating the catalog

From this directory:

```bash
# Phase 1: discover + run each engine on each fixture (a few minutes)
python3 run.py

# Phase 2: render the catalog + per-example files
python3 render.py
```

The harness uses the venv-installed Python at
`<repo>/.tools-venv/bin/python3` for Clingo + PySAT (those
engines bind to native libraries that aren't on the system
Python by default). Other engines are invoked through their
`run.sh` / `run.py` directly.

## What it does NOT do

- It does **not** modify Stave source, control YAML, or fixture
  observation files.
- It does **not** modify the engine examples themselves.
- It does **not** invent fixtures.

When a cell shows `empty` / `n/a` / `error`, that's the data —
the relevant gap is documented in the per-example file and in
the coverage summary at the bottom of `CATALOG.md`.

## Adding new fixtures

When a new example with `fixtures/` lands, the harness
discovers it on the next run automatically. If the new example
has a paired SMT-LIB query (a `z3-*` runner under
`examples/`), add the runner ↔ example mapping to the
`Z3_RUNNERS` dict at the top of `run.py`.
