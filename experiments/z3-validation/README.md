# z3-validation — per-service migration harness

`z3-validation` runs Z3 models alongside Stave's CEL predicates on
the same fixture corpus and reports agreement / disagreement. It
is the validation layer that has to clear before any CEL control
is migrated to Z3.

The harness lives in its own Go module so the main Stave build
never imports Z3.

## Five disciplines this harness enforces

1. **CEL is the oracle, never the other way around.** Stave's CEL
   findings are the reference; Z3 is validated against them.
2. **One service at a time, in dependency order.** S3 → IAM → KMS
   → Network → Cognito → cross-service. Each service must clear
   >95% agreement before the next starts.
3. **Every disagreement is classified.** `Z3_ONLY` and `CEL_ONLY`
   findings carry an investigation status (PENDING / CONFIRMED_GAP
   / MODEL_BUG / FALSE_POSITIVE / WONTFIX). No unclassified
   disagreements before moving on.
4. **Cross-service experiments run last.** A wrong individual
   model produces wrong composed queries.
5. **The collapse ratio is tracked but not acted on.** `8 CEL
   controls → 1 Z3 query` is reported; no CEL controls retire
   during the experiment phase.

## Layout

```
experiments/z3-validation/
├── cmd/                 CLI entry point
├── harness/             ServiceExperiment interface, runner, comparator,
│                        report types and writer
├── services/
│   ├── s3/              ⬅ implemented (3 queries)
│   ├── iam/             stub
│   ├── kms/             stub
│   ├── network/         stub
│   └── cognito/         stub
├── crossservice/        stub (runs last by design)
├── Makefile             one target per service
└── results/             generated; gitignored
```

## Prerequisites

- Go 1.22+ (the parent module is on a newer toolchain; this
  module follows).
- Z3 4.x on `PATH` and via `pkg-config` (the go-z3 binding uses
  CGO).
- A built `stave` binary somewhere on `PATH` or at
  `../../stave/stave`. The harness shells out to
  `stave apply --observations <fixture>/observations --format json`
  for each fixture, so the binary must accept those flags.

## Build

```bash
cd experiments/z3-validation
make build
```

The binary is `z3-validation` in this directory.

## Run a service

```bash
make experiment-s3
```

Per-service runs scan the entire repo `testdata/` tree by default
and feed every fixture into both engines. Override the corpus or
the binary with `FIXTURES=…` and `STAVE=…`:

```bash
make experiment-s3 FIXTURES=../../testdata/e2e STAVE=../../stave-dev
```

Read the report:

```bash
jq . results/s3/summary.json
jq . results/s3/z3_only.json
jq . results/s3/cel_only.json
```

## Adding a service implementation

A service satisfies `harness.ServiceExperiment`:

```go
type ServiceExperiment interface {
    Name() string
    ControlMapping() map[string]string  // CEL ID → Z3 query name
    RunZ3(ctx, fixtureDir) ([]Z3Finding, error)
    CollapseRatio() (celControls, z3Queries int)
    ModelCoverage() ModelCoverage
}
```

The `services/s3/` package is the reference implementation. New
services follow the same shape: one file per query, a control
mapping pinned to actual catalog IDs, and a model-coverage block
that lists what is and is not modeled.

To discover the actual catalog IDs for a service:

```bash
stave controls list --format json | jq '[.[] | select(.id | startswith("CTL.S3."))] | .[].id'
```

## Investigation workflow

Every comparison in `summary.json` carries an
`investigation: "PENDING"` field by default. After a manual
review against AWS documentation or the IAM Policy Simulator,
edit the entry's `investigation` field to one of:

| Status            | Meaning                                                                |
|-------------------|------------------------------------------------------------------------|
| `CONFIRMED_GAP`   | Z3 found something CEL didn't — file as a new Stave control.           |
| `MODEL_BUG`       | Z3 model is wrong — fix the model and re-run the experiment.          |
| `FALSE_POSITIVE`  | Z3 fired on a fixture artifact that does not represent real-world risk. |
| `WONTFIX`         | The control is a simple property check that intentionally stays as CEL. |

The harness re-runs idempotently; classified entries persist in
the JSON until you delete `results/`.

## Module isolation

```
github.com/sufield/stave/experiments/z3-validation
  → require github.com/sufield/stave (replace ../../)
  → require github.com/aclements/go-z3
```

The main Stave module never imports this experiment.
`go build ./...` from the repo root does not compile Z3.
