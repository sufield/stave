# How to Bisect a Violation

Find the exact snapshot when a control first failed.

---

## Run Bisect

```bash
stave bisect \
  --history ./snapshots \
  --control CTL.S3.PUBLIC.001
```

Bisect evaluates each snapshot and finds the transition from PASS to VIOLATION.

## Read the Result

```
Bisect result: CTL.S3.PUBLIC.001
  First violation: 2026-01-14.json
  Last pass:       2026-01-13.json
  Transition window: 24 hours
```

## See What Changed

```bash
diff snapshots/2026-01-13.json snapshots/2026-01-14.json
```

The diff shows the exact property that changed between the two snapshots.

## Correlate with Deployment History

```bash
git log --since="2026-01-13" --until="2026-01-14" --oneline
```
