# How to Generate an Executive Report

Produce a single document aggregating all assessment dimensions.

---

## Generate the Report

```bash
stave report \
  --history ./history \
  --snapshot ./snapshots/latest.json \
  --sla-profile-file sla-policy.yaml \
  --team-manifest team-manifest.yaml \
  --out report.json
```

## Markdown for Confluence or GitHub

```bash
stave report \
  --history ./history \
  --snapshot ./snapshots/latest.json \
  --format markdown \
  --out report.md
```

## What the Report Contains

- Posture score with band classification and trend sparkline
- Findings summary by severity
- SLA compliance breakdown (when `--sla-profile-file` provided)
- Top 10 findings ranked by severity and burn rate
- Active compound chains with narratives
- ATT&CK tactic coverage
- Framework readiness percentages
- Per-team posture (when `--team-manifest` provided)
- Machine-generated executive summary paragraph

## Minimal Report (No SLA or Teams)

```bash
stave report \
  --history ./history \
  --snapshot latest.json
```

The SLA and teams sections are omitted when the corresponding flags are not provided.
