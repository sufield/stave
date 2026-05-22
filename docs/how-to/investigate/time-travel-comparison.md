# How to Compare Infrastructure State Between Two Dates

Evaluate security posture at two points in time and see what changed.

---

## Evaluate a Past Snapshot

```bash
stave apply \
  --snapshot snapshots/2026-01-01.json \
  --controls controls \
  --now 2026-01-01T00:00:00Z \
  --format json \
  > assessment-jan-01.json
```

## Evaluate the Current Snapshot

```bash
stave apply \
  --snapshot snapshots/2026-03-31.json \
  --controls controls \
  --now 2026-03-31T00:00:00Z \
  --format json \
  > assessment-mar-31.json
```

## Compare Findings

```bash
diff <(jq '[.findings[].control_id] | sort' assessment-jan-01.json) \
     <(jq '[.findings[].control_id] | sort' assessment-mar-31.json)
```

## See Property Changes

```bash
diff snapshots/2026-01-01.json snapshots/2026-03-31.json | head -50
```

## Scan Every Transition Across the Full Period

```bash
stave bisect \
  --controls ./controls \
  --observations ./snapshots \
  --control-id CTL.S3.PUBLIC.001 \
  --mode scan
```

This shows every violation window (PASS → VIOLATION → PASS) across the full history for a specific control.

## Collect Evidence for an Investigation Period

```bash
stave verify \
  --archive ./evidence \
  --period 2026-01-01:2026-03-31 \
  --format json \
  --out investigation-evidence.json
```
