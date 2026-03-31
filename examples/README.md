# Examples

Three self-contained examples you can run on your machine. Each has
its own observations, controls, and expected output.

## Prerequisites

Build stave from source:

```bash
cd stave
make build
```

## 1. Public bucket detection

A bucket with public read access. Stave detects the exposure.

```bash
./stave apply \
  --controls examples/public-bucket/controls \
  --observations examples/public-bucket/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input
```

Exit code 3 — violation found. The bucket has `public_read: true` for
24 hours, exceeding the 12-hour threshold.

## 2. Missing Public Access Block

A bucket without Public Access Block. Not currently public, but one
policy change away from exposure.

```bash
./stave apply \
  --controls examples/missing-pab/controls \
  --observations examples/missing-pab/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input
```

Exit code 3 — violation found. Public Access Block has been disabled
for 24 hours.

## 3. Duration tracking

A bucket stays publicly readable across three snapshots over 9 days.
Stave tracks the unsafe duration and fires when it exceeds the
threshold.

```bash
./stave apply \
  --controls examples/duration/controls \
  --observations examples/duration/observations \
  --max-unsafe 12h \
  --now 2026-01-10T00:00:00Z \
  --allow-unknown-input
```

Exit code 3 — violation found. The bucket has been publicly readable
for 216 hours (9 days), exceeding the 12-hour threshold.

## What each example contains

```
examples/<name>/
  controls/      One YAML control (the safety rule)
  observations/  Two or three JSON snapshots (the bucket state over time)
  README.md      Scenario details and expected output
```

## Flags explained

| Flag | Purpose |
|---|---|
| `--controls` | Directory containing YAML control definitions |
| `--observations` | Directory containing JSON observation snapshots |
| `--max-unsafe` | Maximum time a bucket may remain unsafe before violation |
| `--now` | Fixed timestamp for deterministic output |
| `--allow-unknown-input` | Accept observations with custom source types |
