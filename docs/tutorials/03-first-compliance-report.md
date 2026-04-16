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

## Generate Team Remediation Plans

First, create a team manifest (`team-manifest.yaml`):

```yaml
owner_tag_key: team
teams:
  - id: platform
    display_name: Platform Team
    contact: platform@company.com
    resource_patterns:
      - "arn:aws:s3:::*"
      - "arn:aws:ec2:*"
```

Then generate plans:

```bash
stave plan \
  --assessment findings.json \
  --team-manifest team-manifest.yaml \
  --sla-profile-file sla-policy.yaml \
  --out ./plans/
```

Each team gets a file: `plans/platform-remediation-plan.md` with their specific findings, remediation commands, and SLA deadlines.

## Verify the Evidence Archive

If you have collected evidence over time with `stave collect`:

```bash
stave verify \
  --archive ./evidence \
  --period 2026-Q1
```

This produces an attestation document proving continuous monitoring with no gaps.

## What to Explore Next

- [Compliance gap analysis](../how-to/report/compliance-gap.md) — compare HIPAA vs FedRAMP
- [Custom compliance profiles](../how-to/write-controls/custom-profile.md) — create a DORA profile
- [How posture scoring works](../explanation/posture-score.md) — understand the score dimensions
