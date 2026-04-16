# Tutorial: Temporal Investigation

Use time travel to find when a violation first appeared and what changed. Time: 20 minutes.

---

## What You Will Learn

- How snapshots in git enable time travel evaluation
- How to use `stave bisect` to find the exact moment a violation appeared
- How to use `git diff` to see the configuration change
- The difference between "evaluate, not guess"

## Set Up the Snapshot Repository

Stave snapshots are files. Put them in git:

```bash
mkdir -p snapshots
cd snapshots && git init

# Day 1: compliant state
stave apply --snapshot day1.json --format json > assessment-day1.json
git add . && git commit -m "day 1 assessment"

# Day 2: violation appears
stave apply --snapshot day2.json --format json > assessment-day2.json
git add . && git commit -m "day 2 assessment"

# Day 3: still violated
stave apply --snapshot day3.json --format json > assessment-day3.json
git add . && git commit -m "day 3 assessment"
```

## Find When the Violation Appeared

```bash
stave bisect \
  --history ./snapshots \
  --control CTL.S3.PUBLIC.001
```

Bisect evaluates each snapshot against the specified control and reports the exact transition point:

```
Bisect result: CTL.S3.PUBLIC.001
  First violation: day2.json (2026-01-02T03:00:00Z)
  Last pass:       day1.json (2026-01-01T03:00:00Z)
  Transition window: 24 hours
```

## See What Changed

```bash
git diff day1.json day2.json
```

The diff shows the exact property change — for example, `public_access_block.block_public_acls` changed from `true` to `false`.

This is what "evaluate, not guess" means. You are not reconstructing what happened from CloudTrail logs. You are running the exact same assessment engine against the exact snapshot from that day. The verdict is deterministic: same input, same engine, same result.

## Check for Recurrence

```bash
stave forensics \
  --history ./snapshots \
  --control CTL.S3.PUBLIC.001
```

If the violation has appeared, been fixed, and reappeared, forensics reports the recurrence pattern and score.

## What to Explore Next

- [Why snapshots are files](../explanation/snapshot-model.md) — the architectural decision
- [Why time travel matters](../explanation/time-travel.md) — evaluate vs reconstruct
- [Detect deployment regressions](../how-to/investigate/detect-regression.md) — find pipeline-introduced violations
