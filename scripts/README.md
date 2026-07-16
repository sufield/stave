# scripts/

Shell and Python helper scripts for snapshot collection, fixture capture, and development tooling.

## User-Facing Scripts

| Script | Purpose |
|--------|---------|
| `quickstart.sh` | From "I use these AWS services" to findings. Runs `stave discover` then `stave apply` against an observations directory. |
| `aws-snapshot.sh` | AWS snapshot collector. Gathers read-only AWS CLI JSON into `raw/`, then calls `stave transform` to produce `obs.v0.1` observations. Requires AWS CLI v2 with SecurityAudit credentials and `jq`. |

## Development Scripts

| Script | Purpose |
|--------|---------|
| `capture-fixture.sh` | Deploy a vulnerable lab (e.g. sadcloud), capture observations, tear down. Used by the fixture-refresh CI job. The only script that uses AWS credentials. |
| `gen-steampipe-mappings.py` | Generates Steampipe-to-Stave mapping YAMLs by joining the Steampipe column catalog (`steampipe-columns.json`) with per-asset JSON Schemas. |
| `steampipe-columns.json` | Cached Steampipe column catalog used by `gen-steampipe-mappings.py`. |

## h1-matrix/

Fixture-by-engine matrix harness. Runs every example fixture through every reasoning engine (Z3, Souffle, Clingo, Prolog, PRISM, PySAT) and captures per-cell verdicts. Outputs drive `examples/CATALOG.md` and per-example `multi-engine-results.md` files.

```bash
cd scripts/h1-matrix
python3 run.py      # discover + run engines on fixtures
python3 render.py   # render catalog + per-example files
```

See `h1-matrix/README.md` for details.
