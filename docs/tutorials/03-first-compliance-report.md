# Tutorial: Your First Compliance Report

Produce an executive report and team remediation plans from an assessment. Time: 15 minutes.

---

## What You Will Learn

- How to generate a posture report
- How to produce team-routed remediation plans
- How to verify an evidence archive

## Generate a HIPAA Assessment

```bash
stave apply \
  --profile hipaa \
  --input observations.json \
  --format json \
  --now 2026-01-15T00:00:00Z \
  > findings.json
```

## Produce the Executive Report

```bash
stave report \
  --history ./history \
  --snapshot observations.json \
  --sla-profile-file sla-policy.yaml \
  --format markdown \
  --out report.md
```

The report contains: posture score, findings summary, SLA compliance, top findings, active chains, ATT&CK coverage, and an executive summary paragraph.

## What to Explore Next

- [Compliance gap analysis](../how-to/report/compliance-gap.md) — compare HIPAA vs FedRAMP
- [Custom compliance profiles](../how-to/write-controls/custom-profile.md) — create a DORA profile
- [How posture scoring works](../explanation/posture-score.md) — understand the score dimensions
