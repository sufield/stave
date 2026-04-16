# How to Create a Custom Compliance Profile

Define your own compliance framework as a YAML file.

---

## Create the Profile File

```yaml
# dora-profile.yaml
schema_version: "1"
id: dora_ict_risk
name: "DORA ICT Risk Management Framework"
version: "2025-01"

sections:
  - id: "dora.art5"
    title: "Article 5 — ICT Risk Management Framework"
    priority: critical
    required_controls:
      - control_id: CTL.CLOUDTRAIL.ENABLED.001
        rationale: "Audit logging for risk monitoring"
      - control_id: CTL.GUARDDUTY.ENABLED.001
        rationale: "Threat detection"

  - id: "dora.art9"
    title: "Article 9 — Data Protection"
    priority: critical
    required_controls:
      - control_id: CTL.S3.ENCRYPT.001
        rationale: "Data at rest encryption"
      - control_id: CTL.KMS.ROTATION.001
        rationale: "Key management"
```

## Use with stave apply

```bash
stave apply --profile-file dora-profile.yaml --input observations.json
```

## Use with stave export

```bash
stave export compliance --profile-file dora-profile.yaml --snapshot observations.json
```

## Inherit from a Built-In Profile

```yaml
extends: hipaa
# All HIPAA sections are inherited.
# Sections below are added or override by ID.
sections:
  - id: "custom.additional"
    title: "Additional requirement"
    required_controls:
      - control_id: CTL.CUSTOM.001
```

## Add SLA Deadlines

```yaml
sla_deadlines:
  critical: 24h
  high: 168h
  medium: 720h
  low: 2160h
```

## Validate the Profile

```bash
stave export compliance --profile-file dora-profile.yaml --snapshot obs.json
```

If a referenced control ID does not exist in the catalog, a warning is emitted and the control is skipped.
