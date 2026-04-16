# How to Generate Team Remediation Plans

Route findings to the teams that own the affected resources.

---

## Generate Plans for All Teams

```bash
stave plan \
  --assessment findings.json \
  --team-manifest team-manifest.yaml \
  --sla-profile-file sla-policy.yaml \
  --out ./plans/
```

Each team gets a separate file: `plans/<team-id>-remediation-plan.md`.

## Single Team

```bash
stave plan \
  --assessment findings.json \
  --team-manifest team-manifest.yaml \
  --team identity \
  --out identity-plan.md
```

## Filter by Severity

```bash
# Critical and high only
stave plan \
  --assessment findings.json \
  --team-manifest team-manifest.yaml \
  --severity high
```

## JSON for Ticketing Automation

```bash
stave plan \
  --assessment findings.json \
  --team-manifest team-manifest.yaml \
  --format json \
  --out plans.json
```

## Plain Text for Secure File Transfer

```bash
stave plan \
  --assessment findings.json \
  --team-manifest team-manifest.yaml \
  --format text \
  --out plan.txt
```
