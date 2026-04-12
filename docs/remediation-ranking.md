# Remediation Ranking

`stave rank` transforms assessment findings into a prioritized
remediation roadmap. It answers the hardest question in security:
"I have 1,000 findings; what do I fix first to make the environment
safest?"

## Usage

```bash
# Pipe from stave apply
stave apply --format json | stave rank --top 10

# Read from file
stave rank --in assessment.json --top 5

# JSON output for automation
stave rank --in assessment.json --format json
```

## Priority score formula

```
PriorityScore = BaseScore × DurationFactor × BlastMultiplier × ExposureMultiplier × SLAUrgency
```

### SLA urgency multiplier

A finding about to breach its SLA deadline ranks higher than a
finding with weeks remaining, regardless of base severity:

| Condition | Multiplier |
|---|---|
| Overdue (breached SLA) | 3.0 |
| Due within 24 hours | 2.5 |
| Due within 72 hours | 2.0 |
| Due within 7 days | 1.5 |
| Otherwise | 1.0 |

A "High" finding 2 hours from breach (75 x 2.5 = 187.5) correctly
ranks above a "Critical" finding with 29 days remaining (100 x 1.0
= 100).

## Risk impact percentage

Each finding shows what percentage of total environment risk it
represents:

```
Risk Impact = (finding score / total risk sum) × 100
```

This gives the security engineer the data to justify priorities:
"Fixing this one finding reduces total environment risk by 42%."

## Strategic narratives

Each finding includes a human-readable narrative explaining the
reasoning behind its rank:

| Category | Example |
|---|---|
| Legacy Exposure | "phi-records-prod has been misconfigured for 1826 days" |
| SLA Urgency | "phi-bucket has breached the remediation policy. Immediate action required" |
| Detection Blindness | "Disabling CTL.CLOUDTRAIL.ENABLED.001 blinds detection across the account" |
| Aging Exposure | "vpc-abc123 misconfigured for 120 days, approaching threshold" |

## Remediation bundles

Findings sharing the same fix action are grouped into bundles
ranked by total risk reduction:

```
REMEDIATION BUNDLES (Highest ROI)
----------------------------------------
  1. Resolve 12 findings (risk reduced: 4500, efficiency: 375.0)
     Restrict access to authorized principals only.
  2. Resolve 3 findings (risk reduced: 1500, efficiency: 500.0)
     Enable encryption at rest.
```

The **efficiency score** is total risk reduced divided by number of
findings — higher efficiency means more risk reduction per fix.

## Text output

```
REMEDIATION STRATEGY (Top 5 Actions)
==================================================

[#1]  PRIORITY: 2500.0 (CRITICAL)
      CTL.S3.PUBLIC.001 on phi-records-prod
      Legacy exposure: phi-records-prod has been misconfigured for 1826 days.
      Risk Impact: 42% of total environment risk
      Score: base=100 × duration=5.0 × blast=2.5 × exposure=2.0
      Fix: aws s3api put-public-access-block --bucket phi-records-prod ...

[#2]  PRIORITY: 450.0 (HIGH)
      CTL.CLOUDTRAIL.ENABLED.001 on account-prod
      SLA urgency: account-prod has breached the remediation policy.
      Risk Impact: 15% of total environment risk
      Score: base=75 × duration=2.0 × blast=1.0 × exposure=1.0 × sla=3.0
```

## JSON output

```json
{
  "entries": [
    {
      "rank": 1,
      "control_id": "CTL.S3.PUBLIC.001",
      "asset_id": "phi-records-prod",
      "priority_score": 2500.0,
      "risk_impact_percent": 42.0,
      "breakdown": {
        "base_score": 100,
        "duration_factor": 5.0,
        "blast_multiplier": 2.5,
        "exposure_multiplier": 2.0,
        "days_blind": 1826.0
      },
      "sla_urgency_multiplier": 1.0,
      "silent_killer": true,
      "narrative": "Legacy exposure: phi-records-prod has been misconfigured for 1826 days."
    }
  ],
  "remediation_bundles": [...],
  "total_risk": 5952.0
}
```

## CI/CD workflow

```bash
# Generate assessment and rank in one pipeline
stave apply --format json | stave rank --top 3

# Save assessment, rank, and create evidence bundle
stave apply --format json > assessment.json
stave rank --in assessment.json --top 10
stave bundle --controls ./controls --observations ./observations
```

## Key files

| File | Purpose |
|---|---|
| `cmd/rank/cmd.go` | Top-level rank command |
| `internal/app/rank/priority.go` | BuildRoadmap, PriorityEntry, RemediationBundle |
| `internal/core/evaluation/risk/exposure_rank.go` | Underlying ExposureRank scoring |
