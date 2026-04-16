# Tutorial: Your First Assessment

Run an assessment against infrastructure snapshots and see your posture score. Time: 15 minutes.

---

## What You Will Learn

- How to run `stave apply` against observation snapshots
- How to read the findings output — each finding represents a violated System Invariant (e.g., "PHI data must be private and encrypted")
- What the posture score means

## What You Need

- The `stave` binary (built via `cd stave && make build`)
- A directory with at least two observation snapshot JSON files

If you don't have snapshots yet, use the included test fixtures:

```bash
mkdir -p observations
cp testdata/e2e/aws-s3-obs-public/observations.json observations/
```

## Run Your First Assessment

```bash
stave apply \
  --controls controls \
  --observations observations \
  --now 2026-01-15T00:00:00Z \
  --allow-unknown-input
```

You will see output like:

```
Evaluation Results
==================

Run: 2026-01-15 00:00:00 UTC (max-unsafe: 0h, snapshots: 2)

Summary
-------
  Assets evaluated:    2
  Attack surface:      2
  Violations:          8
```

## Read the Findings

Each finding tells you:
- **Control ID** — which security invariant is violated (e.g., `CTL.S3.PUBLIC.001`)
- **Asset ID** — which resource has the violation
- **Severity** — critical, high, medium, or low
- **Dwell time** — how long the violation has existed

## See Your Posture Score

```bash
stave score --output assessment.json
```

The score is a number from 0 to 100. Higher is better.

| Band | Score | Meaning |
|------|-------|---------|
| CRITICAL | < 40 | Immediate action required |
| POOR | 40-59 | Significant risk |
| FAIR | 60-69 | Moderate risk |
| GOOD | 70-84 | Manageable risk |
| STRONG | 85-94 | Strong posture |
| EXCELLENT | 95-100 | Exemplary |

## What to Explore Next

- [Write your first custom control](02-first-custom-control.md) — define your organization's specific requirements
- [How posture scoring works](../explanation/posture-score.md) — understand the four dimensions
- [Run assessments in CI/CD](../how-to/run-assessments/in-cicd.md) — fail pipelines on violations
