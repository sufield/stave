# How to Detect Regressions

Identify controls that fail repeatedly in a pattern.

---

## Run Forensics

```bash
stave forensics \
  --history ./snapshots \
  --control CTL.S3.PUBLIC.001
```

## Read the Recurrence Score

The recurrence score (0-10) indicates how frequently a violation appears, resolves, and reappears:

| Score | Meaning |
|-------|---------|
| 0-2 | One-time violation, likely a configuration error |
| 3-5 | Occasional recurrence, possible deployment regression |
| 6-8 | Frequent recurrence, systemic pipeline issue |
| 9-10 | Persistent recurrence, possible attacker activity |

## Correlate with Git Log

```bash
git log --all --oneline snapshots/ | head -20
```

A recurrence pattern that aligns with deployment timestamps indicates a pipeline-introduced regression. A pattern with no corresponding deployment may indicate manual changes or attacker reversion.
