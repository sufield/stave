# stave-z3 — Z3 solver experiment

`stave-z3` is an experimental binary that consumes Stave's three
public exports — `pkg/stave.PolicyExport`, `pkg/stave.GraphExport`,
and `pkg/stave.InvariantExport` — and answers cloud-configuration
questions formally, with Z3 as the reasoning engine.

This is a **separate Go module**. The Stave core does not import
Z3, does not link to it, and does not know it exists. The
experiment lives here so the formal-methods work can iterate
freely without touching the engine.

## What the experiment proves

| Query | Question it answers |
|-------|--------------------|
| `compatibility` | Can principal X perform action Y on resource Z given all modeled policies? |
| `reachability` | Can principal X reach resource Y through any chain of role assumptions and policy grants? |
| `conflict` | Do the loaded policies contradict each other? Is there a (P, A, R) where one Allow matches and one Deny matches? |
| `choke-point` | After proving reachability, what's the minimum set of policy statements whose removal breaks the path? |
| `invariant` | Does Stave's unsafe predicate hold for ALL possible inputs, not just the snapshot's concrete values? |
| `shadow` | Where does Z3 disagree with Stave's CEL evaluator? |

## Prerequisites

- Go 1.22+ (the parent module is on 1.26 — `go.mod` follows).
- Z3 4.x available via `pkg-config` and on `PATH`.
  - macOS: `brew install z3`
  - Debian / Ubuntu: `apt install libz3-dev z3`
- Stave repo cloned. The replace directive in `go.mod` points at
  `../../` so the experiment resolves Stave directly from the
  workspace.

## Build

```bash
cd experiments/z3-solver
make build
```

The binary is `stave-z3` in this directory.

## Quick start

Pick any observation directory Stave can `apply`:

```bash
# Compatibility check
./stave-z3 \
  --observations testdata/known_answers/iam_deny_overrides_allow/observations \
  --query compatibility \
  --principal "arn:aws:iam::111122223333:role/ServiceB" \
  --action s3:GetObject \
  --resource "arn:aws:s3:::deny-test-bucket/*" | jq .

# Conflict check across the whole snapshot
./stave-z3 \
  --observations ../../testdata/e2e/aws-s3-obs-public/observations \
  --query conflict | jq .

# Invariant verification — symbolic check, not snapshot-bound
./stave-z3 \
  --observations ../../testdata/e2e/aws-s3-obs-private/observations \
  --query invariant \
  --invariant CTL.S3.ENCRYPT.001 | jq .

# Shadow mode: compare Z3 verdicts with Stave's CEL findings
./stave-z3 \
  --observations ../../testdata/e2e/e2e-01-violation/observations \
  --query shadow | jq .
```

## Architecture

```
       observations/                 control catalog
              │                           │
              ▼                           ▼
    ┌──────────────────┐         ┌──────────────────┐
    │  pkg/stave       │         │  pkg/stave       │
    │  ExportPolicies  │         │  ExportInvariants│
    │  ExportGraph     │         │                  │
    └──────────────────┘         └──────────────────┘
              │                           │
              └────────────┬──────────────┘
                           ▼
                  ┌──────────────────┐
                  │  loader.Stave    │
                  │  Exports bundle  │
                  └──────────────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │   compiler       │
                  │   (Z3 model)     │
                  └──────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        compatibility  reachability  invariant ...
              │            │            │
              └────────────┴────────────┘
                           ▼
                  ┌──────────────────┐
                  │   QueryResult    │
                  │   (JSON cert.)   │
                  └──────────────────┘
```

## Z3 binding

The compiler uses the `aclements/go-z3` CGO binding. The binding
exposes Z3's core sorts (Bool, Uninterpreted, BV, Int, Real,
Array) but **does not expose Z3's string theory**. The experiment
encodes IAM ARNs, action names, and resource patterns as constants
in three uninterpreted sorts (`Principal`, `Action`, `Resource`)
and expands wildcard patterns at compile time against the closed
universe of symbols seen in the loaded snapshot.

This is sound for "what is reachable in this snapshot?"; it is
unsound for "is there ANY future configuration that violates
this property?". The invariant-verify query uses an open
uninterpreted-string universe via `compiler.InvariantEnv` for
that case.

## Model coverage

Every `QueryResult` carries a `model_coverage` field with two
slices: `modeled` lists the policy/graph/invariant features the
query reasoned over; `not_modeled` lists what it ignored. A
verdict is sound only relative to the modeled fragment. Read the
field before quoting a result.

Today's coverage gaps include:

- AWS Organizations SCPs.
- IAM permissions boundaries.
- Session policies (STS).
- VPC endpoint policies.
- Condition value context (we treat `aws:PrincipalOrgID`,
  `aws:SourceVpc`, etc. as opaquely-satisfied at query time).
- Assume-role chain depth beyond 5 hops (configurable in
  `queries/reachability.go`).

## Layout

```
experiments/z3-solver/
├── cmd/stave-z3/        # CLI entry point
├── loader/              # pkg/stave bridge
├── compiler/            # PolicyExport / GraphExport / InvariantExport → Z3
├── queries/             # SAT/UNSAT-shaped questions
├── shadow/              # Z3 vs CEL comparator
└── testdata/known_answers/
    └── iam_deny_overrides_allow/    # pinned-verdict fixtures
```

## Adding a query

1. Add `queries/<name>.go` with a `Query<Name>(model, ...) *QueryResult` function.
2. Push your assertions onto a fresh `z3.NewSolver(model.Ctx)`.
3. Always populate `ModelCoverage.Modeled` and `ModelCoverage.NotModeled`.
4. Wire the new query into `cmd/stave-z3/main.go`'s switch.
5. Add a known-answer fixture under `testdata/known_answers/` and a test in `compiler/compiler_test.go`.

## Adding a known-answer fixture

A fixture is a directory under `testdata/known_answers/<name>/observations`
with at least two snapshot files (Stave's duration controls need
two timestamps). Each snapshot must validate against the
`obs.v0.1` schema. The fixture's expected verdict goes in
`compiler/compiler_test.go` as a `cases` entry.

## Limitations

The experiment does not modify any Stave source. If an export
field the experiment needs is missing, file an issue against
`pkg/stave` rather than reaching into `internal/`.

`go-z3` is CGO. The build needs a Z3 development headers package
(`libz3-dev` on Debian, the `z3` formula on macOS). The Makefile's
`check-z3` target verifies the CLI is on `PATH`; the Go binding
discovers Z3 via `pkg-config`.
