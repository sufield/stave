# How to Detect Regressions

Identify controls that fail repeatedly in a pattern.

---

## Scan for All Violation Windows

```bash
stave bisect \
  --controls ./controls \
  --observations ./snapshots \
  --control-id CTL.S3.PUBLIC.001 \
  --mode scan
```

`--mode scan` walks the full history (O(N)) and reports every violation
window — each PASS → VIOLATION → PASS cycle — rather than just the most
recent transition. A control that repeatedly re-enters violation after
being fixed is a regression pattern: the more windows, the more frequent
the recurrence.

## Correlate with Git Log

```bash
git log --all --oneline snapshots/ | head -20
```

A recurrence pattern that aligns with deployment timestamps indicates a pipeline-introduced regression. A pattern with no corresponding deployment may indicate manual changes or attacker reversion.
