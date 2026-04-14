# Posture Trending

`stave trend` reads historical assessment output files and computes
posture metrics: violation rate, MTTR, severity distribution, framework
coverage trajectory, velocity, and projection.

## Who it's for

- **CISO** — board-level trend: "Are we getting safer over time?"
- **Engineering leadership** — MTTR and velocity for quarterly reviews
- **Auditors** — framework coverage trajectory for compliance evidence

## Setup

Run `stave apply` on a schedule to accumulate assessment output files:

```bash
# Daily assessment in CI/CD
stave apply --controls controls/ --observations obs/ --format json \
  > assessments/$(date +%Y-%m-%d).json
```

## Basic Usage

```bash
# Table output (default)
stave trend --history ./assessments/

# JSON output for dashboard integration
stave trend --history ./assessments/ --format json

# Framework coverage trajectory
stave trend --history ./assessments/ --compliance hipaa,soc2

# Last 10 runs only
stave trend --history ./assessments/ --window 10
```

## MTTR (Mean Time to Remediate)

MTTR is computed from **closed violation windows only** — a violation
that appears and then disappears between consecutive runs. Open
violations (still failing in the latest run) are excluded.

When no violations have been remediated yet, MTTR is omitted from
output with a note. This is not an error — it means no violation
windows have been closed yet.

MTTR is aggregated by severity: critical, high, medium, low.

## Velocity

Net violation change per run, computed as a rolling average over the
last 5 runs (configurable with `--window`).

- **Positive velocity** (net increase) = regression
- **Negative velocity** (net decrease) = improvement
- **Zero velocity** = steady state

## Projection

When velocity is negative (improving), `stave trend` estimates how
many runs until the violation rate reaches 5%.

**This is a linear extrapolation assuming constant improvement rate.**
Security posture is not linear. Treat this as directional guidance
only, not a guarantee.

## OpenMetrics Integration

Write metrics for Prometheus/VictoriaMetrics ingestion:

```bash
# Prometheus textfile collector
stave trend --history ./assessments/ --format openmetrics \
  --out /var/lib/node_exporter/textfile_collector/stave.prom

# Victoria Metrics file input
stave trend --history ./assessments/ --format openmetrics \
  --out /data/stave/metrics.prom
```

Five metric types: `stave_violations_total`, `stave_violation_rate`,
`stave_mttr_days`, `stave_framework_coverage`, `stave_velocity_per_run`.

## Governance Pipeline

```
stave apply (daily/per-deploy)
  → out.v0.1 files accumulate in ./assessments/
  → stave trend --history ./assessments/
  → stave export compliance --snapshot obs.json --profile hipaa
```

Each command does one thing. Together they give the CISO the trajectory,
the engineers the metrics, and the auditors the evidence.
