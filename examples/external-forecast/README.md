# external-forecast

Reproduces `internal/app/forecast`'s linear-extrapolation
posture forecast outside the core binary. Proves the
forecasting math doesn't need to live in Go core — it's pure
least-squares regression that any numerics environment can
compute.

The example closes a may8.md cleanup item: *"app/forecast/
needs an external example program before its core code can
be deprecated."* This is the first link in the deprecation
chain — once the math has an external reference and cmd/trend
has a path to call it (or its own minimal port), the core
package can shrink to zero.

## What it does

```
input.json (score + MTTR history)
  |
  +---> forecast.py        (stdlib least-squares fit)       --> external.json
  |
  +---> verify_against_core.go  (calls forecast.Compute)    --> core.json
                                                                |
                                                  semantic-equal compare
                                                  → matches after numeric normalization
```

`forecast.py` is a 100-line stdlib-only script that:

1. Reads a JSON file of score + MTTR history
2. Runs the same sum-x / sum-y / sum-xy / sum-x² least-squares
   formulation as `internal/app/forecast.linearFit` (no numpy
   dependency keeps the example runnable with just `python3`)
3. Projects forward by `horizon_days`
4. Applies the same clamps as core (score ∈ [0,100], MTTR
   ≥ 0)
5. Classifies each SLA series as ON_TRACK / AT_RISK /
   BREACHING using the same thresholds (`> deadline` →
   BREACHING; `> deadline * 0.8` → AT_RISK)
6. Emits JSON in the same shape `forecast.Result` produces

`verify_against_core.go` is a build-ignored Go program that
loads the same `input.json` and calls
`internal/app/forecast.Compute()`. The two outputs should
agree to within a small floating-point tolerance.

## Run

```bash
cd stave/examples/external-forecast
./run.sh
```

Output:

```
external matches core — semantic equality on normalized JSON
```

## Prerequisites

- Python 3.9+ (stdlib only — no `pip install` step)
- Go (any version that builds the rest of the repo)

## Semantic-vs-textual comparison

The two outputs disagree byte-for-byte: Python's `json.dumps`
emits whole-number floats as `24.0` while Go's `encoding/json`
emits them as `24`. The diff is purely serialization
formatting — the math is identical. `run.sh` normalizes
whole-number floats to ints before comparing so the
semantic equality survives the formatting quirk.

## Why this matters

`internal/app/forecast/` is one of the "bloat" items from
the May 8 core-audit. The package is 5,136 bytes (one .go
file + one test). The math it implements is universally
known (linear regression). The fact that it lives inside
Stave's core binary means:

- Every `stave` build pays the compile cost of the package
  even if `stave trend forecast` is never invoked
- The package adds API surface (`Input`, `Result`,
  `SLAProjection`, `StatusOnTrack/AtRisk/Breaching`,
  `Compute`) that has to be maintained
- New forecast variants (e.g. exponential, ARIMA) would
  expand the in-core surface further

This example demonstrates the math is portable. The follow-up
deprecation step is to either:

1. Make `cmd/trend/forecast.go` shell out to `forecast.py`
   (clean separation, requires Python at runtime)
2. Or inline the 50-line linear-fit + classification logic
   directly into `cmd/trend/forecast.go` (no runtime
   dependency, no package boundary)

Either way, `internal/app/forecast/` becomes deletable.
That is out-of-scope for this commit — the example proves
viability, not full migration.

## Fixture description

`input.json` is a deterministic 14-day score history rising
0.2 per day from 75 to 77.6, plus two SLA-MTTR series:

- **critical** — 7 days declining 30 → 24h. Projected MTTR
  goes negative under linear extrapolation; clamped to 0.
  Final deadline 24h → ON_TRACK.
- **high** — 7 days rising 120 → 150h. Projected MTTR is
  300h. Deadline 168h → BREACHING.

Two different status outcomes in one fixture so the
classification branches both exercise.

## Out of scope

- Non-linear forecast models (ARIMA, exponential smoothing).
  The core today only does linear; the external example
  matches.
- The actual deprecation commit. This example unblocks it
  without performing it.
