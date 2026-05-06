Stave Z3 Solver
===============

Z3-backed solver for the Stave Intermediate Representation (SIR).
Consumes SIR JSON via stdin, emits Stave-format findings via
stdout. Used as the optional Z3 backend behind Stave's
`STAVE_USE_SOLVER=true` toggle and as the secondary path in the
shadow finding source.

This README walks through the full pipeline using the Stave
Docker image. The image already ships the solver and all
fixtures needed to demonstrate it — no host-side Python install
required.

The walkthrough takes ~3 minutes from a fresh checkout.

---

## Prerequisites

- Ubuntu 22.04 or later.
- Docker Engine 20.10+ and the Compose plugin
  (`sudo apt install docker.io docker-compose-plugin`).
- A clone of the Stave repository.

---

## Step 1 — Build the image

The repo ships `stave/docker-compose.yaml` and the Dockerfile
at `stave/build/docker/demo/Dockerfile`. The image bundles the
Stave Go binary, the Python Z3 solver (with libz3 inside the
`z3-solver` PyPI wheel), `jq`, and the demo scenarios.

```bash
cd <repo-root>/stave
docker compose build
```

First build downloads the Go and Python base images plus the
solver dependencies — expect 2–3 minutes on a typical
connection. Subsequent builds are cached.

Verify:

```bash
docker compose run --rm -T stave --help
```

You should see the help banner with `--z3-walkthrough` and
`--solver` listed in the command set.

---

## Step 2 — Run the canned Z3 walkthrough

The simplest way to see the solver running end-to-end is to
invoke the canned walkthrough mode. It uses scenario 1's bad
observations (an S3 bucket policy that grants public read
access) and runs them through the full pipeline:

```bash
docker compose run --rm -T stave --z3-walkthrough
```

The walkthrough prints, in order:

1. The scenario being analysed (control ID, severity, name).
2. The `stave export-sir` command that produces the SIR
   document.
3. A sanity-check of the SIR shape (control count, asset
   count).
4. The `stave-solver` invocation that consumes the SIR.
5. The findings it emits — JSON-formatted, with each finding's
   `suggested_fix` block visible.

Sample output (truncated):

```
================================================================
  Stave Z3 Solver — End-to-End Walkthrough
================================================================
Scenario: No Public S3 Bucket Read (CTL.S3.PUBLIC.001, critical)

Step 1. Produce a SIR document from the scenario:
  $ stave export-sir --observations observations \
                     --now 2026-03-21T12:00:00Z \
                     > /tmp/sir.json

Step 2. Sanity-check the SIR shape:
  Controls in SIR: 1
  Assets in SIR:   1

Step 3. Pipe the SIR through the Z3 solver:
  $ stave-solver < /tmp/sir.json | jq .

Findings:
[
  {
    "control_id": "CTL.S3.PUBLIC.001",
    "asset_id": "arn:aws:s3:::demo-public-bucket",
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
the minimal change that flips the unsafe predicate to safe.

---

## Step 3 — Run the solver against your own SIR

The image exposes `--solver` as a raw entrypoint that reads SIR
JSON from stdin and writes findings to stdout. Combine it with
a separate `stave export-sir` invocation:

```bash
cd <repo-root>/stave

# Produce a SIR document on the host using a fixture from the
# Stave repo:
docker compose run --rm -T stave --scenario 1 > /dev/null  # warms scenario state

# Or generate a SIR from any controls/observations pair:
docker compose run --rm -T -v $(pwd)/testdata:/data:ro stave \
  --solver < testdata/example.sir.json | jq .
```

For a fully self-contained interactive shell where you can pipe
the two commands directly:

```bash
docker compose run --rm -T --entrypoint bash stave -c '
  cd /scenarios/01 &&
  stave export-sir --observations bad --now 2026-03-21T12:00:00Z |
  stave-solver | jq .
'
```

This drops into a shell inside the container that has both
`stave` and `stave-solver` on `PATH`, runs the pipeline, and
exits. Use `--entrypoint bash` (no `-c`) to stay interactive
for exploration.

---

## Step 4 — Use the solver in `stave apply`

To run the solver as part of a normal `stave apply` workflow
(rather than as a raw subprocess), set two environment
variables when invoking the container:

```bash
docker compose run --rm -T \
  -e STAVE_USE_SOLVER=true \
  -e STAVE_SOLVER_CMD=stave-solver \
  stave \
  --scenario 1
```

Stave then routes evaluation through the Z3 backend, including
the suggested-fix path. Unset `STAVE_USE_SOLVER` (or omit the
`-e` flag) to revert to the default Google CEL backend.

For shadow mode (run both backends, log divergence — does not
affect the user-visible findings):

```bash
docker compose run --rm -T \
  -e STAVE_SHADOW_CMD=stave-solver \
  stave \
  --scenario 1
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

## Development outside the container

If you are modifying the solver itself rather than just running
it, install it into a virtual environment on the host so the
test suite is fast to iterate on. The image rebuilds the
package on every `docker compose build`; running tests in the
container is too slow for iterative work.

```bash
cd <repo-root>/stave/python/solver

# Use uv if you have it; falls back to python -m venv otherwise.
python3 -m venv z3
source z3/bin/activate

pip install -e .
pip install pytest

pytest tests/ -v
```

For per-area iteration:

```bash
pytest tests/test_s3_composition.py -v   # composition model
pytest tests/test_s3_conditions.py -v    # condition encoder
pytest tests/test_s3_fixes.py -v         # suggested-fix extraction
```

The `tests/conftest.py` disables Python bytecode caching so the
working tree stays clean.

After your changes pass tests, rebuild the image to validate
the docker pipeline still runs end-to-end:

```bash
cd <repo-root>/stave
docker compose build
docker compose run --rm -T stave --z3-walkthrough
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `docker: command not found` | Docker Engine not installed | `sudo apt install docker.io docker-compose-plugin`, then add yourself to the `docker` group: `sudo usermod -aG docker $USER` and log out/back in |
| `permission denied` on the docker socket | User not in `docker` group | Same fix as above; verify with `groups \| grep docker` |
| `docker compose build` hangs on `pip install` | Slow connection to PyPI | First build takes 2–3 minutes; subsequent builds are cached |
| `--z3-walkthrough` fails at `stave export-sir` step | The image's entrypoint script lost the `--z3-walkthrough` case | `docker compose build --no-cache` to rebuild from scratch |
| Solver outputs `[]` on a fixture you expect to fail | The SIR doesn't activate the S3 model in the solver, or the SIR genuinely contains no violation | Compare against the Google CEL backend: `docker compose run --rm stave --scenario 1` (without the `STAVE_USE_SOLVER` env var) |
| Solver times out under `stave apply` | Default subprocess deadline is 30s | Set `STAVE_SOLVER_TIMEOUT=60s` (or longer) via `-e STAVE_SOLVER_TIMEOUT=60s` |
| `unmarshal stdout: ...` from `stave apply` | Solver crashed and emitted text instead of JSON to stdout | Re-run with `-e STAVE_LOG_LEVEL=debug` to capture the solver's stderr |

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
