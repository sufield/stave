# Snapshot Model

Stave evaluates snapshots, not live cloud state. This is deliberate.

## Why snapshots

- **Reproducible**: same snapshot, same findings, every time
- **Offline**: no credentials at evaluation time, no network access
- **Auditable**: the snapshot is the evidence — archive it, re-evaluate later
- **Composable**: combine snapshots from multiple sources (AWS Config, Steampipe, aws+jq)
- **Safe**: read-only collection, read-only evaluation

## How it works

1. **Collect**: a collector captures cloud state as `obs.v0.1` JSON files
2. **Evaluate**: `stave apply` reads the snapshot directory, evaluates controls
3. **Archive**: the snapshot + findings form a tamper-evident evidence record

The collector needs read-only IAM access. The evaluator needs no credentials.
See [collector IAM policy](../trust/collector-policy.md).

## Two points in time

Duration-based controls (e.g., "S3 bucket was public for more than 7 days")
need at least two snapshots captured at different times. Place both in the
observations directory — the evaluation engine computes the duration
from `captured_at` timestamps.
