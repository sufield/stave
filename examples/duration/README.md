# Example: Duration-Based Violation

Demonstrates a duration control that fires when a bucket remains publicly readable beyond a threshold.

## Scenario

A bucket named `example-duration` stays publicly readable across three snapshots spanning 9 days:

| Snapshot | Date | public_read |
|----------|------|-------------|
| 1 | 2026-01-01 | `true` |
| 2 | 2026-01-05 | `true` |
| 3 | 2026-01-10 | `true` |

With `--max-unsafe 12h`, the 216-hour (9-day) continuous unsafe period exceeds the threshold.

## Files

```
duration/
├── observations/
│   ├── 2026-01-01T00:00:00Z.json   # public_read=true
│   ├── 2026-01-05T00:00:00Z.json   # public_read=true (still unsafe)
│   └── 2026-01-10T00:00:00Z.json   # public_read=true (still unsafe)
├── controls/
│   └── CTL.S3.PUBLIC.DURATION.001.yaml
└── README.md
```

## Run

```bash
cd stave

./stave plan \
  --controls examples/duration/controls \
  --observations examples/duration/observations \
  --max-unsafe 12h \
  --now 2026-01-10T00:00:00Z

./stave apply \
  --controls examples/duration/controls \
  --observations examples/duration/observations \
  --max-unsafe 12h \
  --now 2026-01-10T00:00:00Z \
  --allow-unknown-input
```

## Expected Result

- **Exit code:** 3 (violations found)
- **Finding:** `CTL.S3.PUBLIC.DURATION.001` on `res:aws:s3:bucket:example-duration`
- **Evidence:** Bucket has been publicly readable for 216 hours, exceeding the 12-hour threshold.

## Duration Semantics

- Duration is calculated from the first snapshot where the predicate matches to the last consecutive match.
- When a resource transitions from unsafe to safe, the episode closes and the streak resets.
- The threshold comparison is strict: duration must **exceed** `--max-unsafe`, not merely equal it.
- Use `--now` for deterministic output. Stave caps `--now` to the last snapshot's `captured_at`.
