# Forecast Trend — External Replacement for `internal/app/forecast/`

External Python implementation of Stave's posture-score trend
forecaster. Reads the same `out.v0.1` assessment JSON files
that `stave apply --format json` emits, fits a linear trend, and
projects the score N days forward — same arithmetic as
`internal/app/forecast/forecast.go`, ported to pure-stdlib Python
so the projection lives outside Stave core.

This example closes item 5 in the core-audit migration tracking
table (`internal/app/forecast/` had no external equivalent at the
2026-05-08 audit; this is the equivalent).

## What it does

```
out.v0.1 assessments (one per day)         forecast.py
        (stave apply --format json)    →   posture trajectory
                                           + per-severity SLA status
```

- **Score series**: each assessment is reduced to a single posture
  score using severity-weighted finding counts (critical=20, high=10,
  medium=5, low=2 deducted from a 100 baseline, clamped to [0, 100]).
- **Linear fit**: closed-form least squares on the score series
  (`y = a + b*t`) — no NumPy, no statsmodels.
- **Projection**: `intercept + slope × (days-elapsed + horizon - 1)`,
  clamped.
- **SLA status**: per-severity MTTR series tracked across snapshots
  (close-time = first day a finding key disappears). Same linear-fit
  projection. Status vocabulary (`ON_TRACK` / `AT_RISK` / `BREACHING`)
  matches Stave's: `AT_RISK` when projected MTTR > 80% of deadline.

## Run

```bash
# Default: table output, 90-day horizon
./forecast.py fixtures/assessments

# 30-day horizon, JSON
./forecast.py fixtures/assessments --horizon 30 --format json

# Custom SLA deadlines (severity → hours)
./forecast.py fixtures/assessments --sla-profile sla.json

# Or via the bundled runner with the demo interpretation block
bash run.sh
```

The shipped fixture series shows a gentle decline (one extra finding
per day across 8 days). With the default severity weights the current
score lands at 55, slope is `-4.88 points/day`, and the 30-day
projection hits 0 — flagged as `declining`.

## Severity weights

The Python script's posture-score formula is intentionally simpler
than `internal/app/score/`:

| Severity | Weight (points deducted per finding) |
|---|---|
| critical | 20 |
| high | 10 |
| medium | 5 |
| low | 2 |

`internal/app/score/` adds chain bonuses, duration factors, and
exposure multipliers; the trend cares about slope direction, not
absolute calibration, so the simpler formula is sufficient. Edit
`SEVERITY_WEIGHT` in `forecast.py` to recalibrate.

## Why this lives outside core

Per the core-audit thin-core contract, Stave does two things:
**evaluate** (apply controls) and **export** (project facts). Trend
projection is reasoning over a *time series* of evaluations — fact
consumption, not fact production. The right home for it is an
external script that reads `stave apply --format json` output, like
this one.

| | Core (`internal/app/forecast/`) | This example |
|---|---|---|
| Reads observation snapshots | ❌ (works on assessments) | ❌ (same) |
| Reads `stave apply` JSON | ✅ | ✅ |
| Produces posture trajectory | ✅ | ✅ |
| Per-severity MTTR projection | ✅ | ✅ |
| ON_TRACK / AT_RISK / BREACHING vocabulary | ✅ | ✅ (matches) |
| Pure stdlib, zero deps | N/A (Go) | ✅ |
| Lives in core | ✅ | ❌ — that's the point |

Migration step: when `internal/app/forecast/` is deprecated, point
the `stave trend forecast` subcommand at this script (or document
the equivalent operator workflow in the deprecation notice).

## Layout

```
examples/forecast/
├── README.md                 — this file
├── forecast.py               — the projector (pure stdlib)
├── run.sh                    — demo runner with interpretation
├── expected/
│   └── output.json           — golden output (8-day fixture, --horizon 30)
└── fixtures/
    └── assessments/
        ├── 2026-04-01.json   — 3 findings (1 medium, 2 low)
        ├── 2026-04-02.json   — 4 findings
        ├── 2026-04-03.json   — 5 findings
        ├── 2026-04-04.json   — 6 findings (first high)
        ├── 2026-04-05.json   — 7 findings
        ├── 2026-04-06.json   — 8 findings
        ├── 2026-04-07.json   — 9 findings
        └── 2026-04-08.json   — 10 findings (second high)
```
