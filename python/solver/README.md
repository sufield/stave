Stave Z3 Solver
===============

Z3-backed solver for the Stave Intermediate Representation (SIR).
Consumes SIR JSON via stdin, emits Stave-format findings via
stdout. Used as the optional Z3 backend behind Stave's
`STAVE_USE_SOLVER=true` toggle and as the secondary path in the
shadow finding source.

This README walks through one complete end-to-end example. By
the end you will:

1. Install the solver into a virtual environment.
2. Produce a real SIR document from a fixture that ships with
   the Stave repo.
3. Pipe that SIR through the solver and observe the findings it
   emits.
4. (Optional) Wire the solver into a full `stave apply` run via
   the Z3-backend toggle.

The walkthrough takes ~5 minutes from a fresh checkout.

---

## Prerequisites

- Python 3.11 or newer.
- The Stave Go binary built (the example uses `stave export-sir`
  to produce the SIR; the Go binary is the canonical SIR
  producer).
- A clone of the Stave repository — the fixture used in the
  walkthrough lives under `testdata/e2e/`.

Build the Stave binary if you do not have one yet:

```bash
cd <repo-root>/stave
make build         # produces ./stave at the repo root
./stave --version  # verify
```

---

## Step 1 — Install the solver

The solver is a regular Python package. The `z3-solver` PyPI
wheel bundles the native libz3 binary for your platform — no
system-level Z3 install is required.

Use a virtual environment so the install does not collide with
your system Python or with PEP 668 protections on managed
distributions:

```bash
cd <repo-root>/stave/python/solver

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

Verify the install. The console script `stave-solver` should be
on the venv's `PATH`:

```bash
which stave-solver
# /<repo-root>/stave/python/solver/.venv/bin/stave-solver

stave-solver --help
```

If `stave-solver` is not found, the venv is not activated;
`source .venv/bin/activate` before continuing.

---

## Step 2 — Produce a SIR document

The solver's stdin is a SIR JSON document. Stave's `export-sir`
subcommand produces one from a `(controls/, observations/)`
fixture. The Stave repo ships an S3 public-read fixture you can
use directly.

From the repo root (one level above `stave/`):

```bash
cd <repo-root>/stave

./stave export-sir \
  --controls testdata/e2e/e2e-h1-uber-361438-public-read-confidential/controls \
  --observations testdata/e2e/e2e-h1-uber-361438-public-read-confidential/observations \
  --now 2026-01-11T00:00:00Z \
  > /tmp/sir.json
```

`--now` pins the evaluation time so the SIR is deterministic;
this matters if you compare against a baseline.

Confirm the SIR is well-formed:

```bash
jq '.controls | length, .assets | length' /tmp/sir.json
```

You should see two integers — the count of controls and the
count of assets in the document. If either is zero, the
fixture pointers are wrong; double-check the `--controls` and
`--observations` paths.

---

## Step 3 — Run the solver

Pipe the SIR into `stave-solver`. The solver reads stdin,
applies its S3 composition model, and writes a JSON array of
findings to stdout:

```bash
stave-solver < /tmp/sir.json | jq .
```

For this fixture the solver produces a finding for the public
read exposure. The output is a JSON array; each element is a
Stave `Finding` object with the schema Stave's evaluation
pipeline already speaks:

```json
[
  {
    "control_id": "CTL.S3.PUBLIC.001",
    "asset_id": "arn:aws:s3:::uber-confidential-data",
    "severity": "critical",
    "evidence": { ... },
    "suggested_fix": {
      "id": "fix-...",
      "action": "..."
    }
  }
]
```

The `suggested_fix` block is what makes the Z3 backend
distinctive: it carries the specific principal / action /
condition tuple Z3 extracted from the satisfying assignment —
the minimal change that flips the unsafe predicate to safe. CEL
findings ship hand-written remediation text from the control
YAML; Z3 findings ship a model-derived diff.

If the solver finds nothing the array is empty (`[]`). If the
solver fails to parse the SIR or hits an internal error, it
writes a JSON error object to stderr and exits with code 2.

---

## Step 4 — One-line full pipeline

The `export-sir` and `stave-solver` invocations compose:

```bash
./stave export-sir \
  --controls testdata/e2e/e2e-h1-uber-361438-public-read-confidential/controls \
  --observations testdata/e2e/e2e-h1-uber-361438-public-read-confidential/observations \
  --now 2026-01-11T00:00:00Z \
| stave-solver | jq .
```

This is the most useful form for experimentation. Swap in any
fixture under `testdata/e2e/` (or your own `controls/` +
`observations/` directories) and you'll see the corresponding
findings.

---

## Step 5 (optional) — Integrate with `stave apply`

Step 4 was raw subprocess plumbing. To run the solver as part
of a normal `stave apply` workflow, set two environment
variables:

```bash
export STAVE_USE_SOLVER=true
export STAVE_SOLVER_CMD="stave-solver"

./stave apply \
  --controls testdata/e2e/e2e-h1-uber-361438-public-read-confidential/controls \
  --observations testdata/e2e/e2e-h1-uber-361438-public-read-confidential/observations \
  --max-unsafe 168h \
  --now 2026-01-11T00:00:00Z \
  --format json
```

Stave then routes evaluation through the Z3 backend, including
the suggested-fix path. Unset `STAVE_USE_SOLVER` to revert to
the default Google CEL backend.

For shadow mode (run both backends, log divergence — does not
affect the user-visible findings):

```bash
export STAVE_SHADOW_CMD="stave-solver"
./stave apply ...
```

---

## Subprocess contract

The contract is intentionally minimal so any solver
implementation can plug in.

| Channel | Direction | Format |
|---------|-----------|--------|
| stdin | host → solver | One JSON-encoded SIR document per invocation |
| stdout | solver → host | A JSON array of Stave Finding objects (`[]` when no violations) |
| stderr | solver → host | Free-form diagnostic text; a structured JSON `{"error": "..."}` object on internal failure |
| exit code | solver → host | `0` = success (findings produced; may be empty); `2` = parse error or other user-correctable failure |

stdin/stdout is the only IPC channel — no temp files, no
shared memory, no env-var-channel input. This keeps the
contract portable across local Python, containerised solvers,
and any future binary implementation.

---

## Development

The solver ships with a pytest suite covering the S3
composition model, condition encoders, and suggested-fix
extraction.

```bash
cd <repo-root>/stave/python/solver
source .venv/bin/activate

pytest tests/ -v
```

For iterative work:

```bash
pytest tests/test_s3_composition.py -v   # composition model
pytest tests/test_s3_conditions.py -v    # condition encoder
pytest tests/test_s3_fixes.py -v         # suggested-fix extraction
```

The `tests/conftest.py` disables Python bytecode caching so the
working tree stays clean (`__pycache__` directories are
gitignored regardless, but skipping them altogether avoids
clutter during commits).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `stave-solver: command not found` | venv not activated, or `pip install -e .` not run | `source .venv/bin/activate` then re-run install |
| `pip install -e .` fails with PEP 668 / "externally-managed-environment" | Trying to install into the system Python | Activate a venv first; do not install into the system interpreter |
| `pip install` fails on `z3-solver` | Old `pip` doesn't recognise the wheel for your platform | `python -m pip install -U pip`, then retry |
| Solver outputs `[]` on a fixture you expect to fail | The fixture's controls or observations don't activate the S3 model in the solver, or the SIR genuinely contains no violation | Run `./stave apply` against the same fixture to compare against the Google CEL backend's verdict |
| Solver times out | Default subprocess deadline is 30s | Set `STAVE_SOLVER_TIMEOUT=60s` (or longer) when invoking via `stave apply` |
| `unmarshal stdout: ...` from `stave apply` | Solver crashed and emitted text instead of JSON to stdout | Re-run with `STAVE_LOG_LEVEL=debug` to capture the solver's stderr |

---

## What the solver covers

The Z3 model in `stave_solver/models/s3.py` handles S3
public-exposure analysis: bucket policies, attached IAM
policies, PublicAccessBlock, and ACLs composed as one
constraint system.

Other service domains (IAM authorization beyond S3 reach, KMS
key policies, VPC endpoint policies, etc.) currently evaluate
through Stave's Google CEL backend even when
`STAVE_USE_SOLVER=true` is set. Adding a new service is a new
model file under `stave_solver/models/` plus a dispatcher entry
in `main.py`.

For the full split between what each backend covers, see
`stave-guide/explanation/z3-solver.md` in the Stave repo.
