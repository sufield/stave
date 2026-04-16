# How to Write a New Control

Create a control YAML file for a custom security requirement.

---

## Create the Control File

```bash
# Place in controls/<service>/<domain>/
mkdir -p controls/custom/governance
```

Create `controls/custom/governance/CTL.CUSTOM.EXAMPLE.001.yaml`:

```yaml
dsl_version: ctrl.v1
id: CTL.CUSTOM.EXAMPLE.001
name: Description of What Must Be True
description: >
  Detailed explanation of the security requirement.
domain: governance
severity: medium
scope_tags:
  - aws
  - s3
type: unsafe_state
params:
  attack_stage: detection_evasion
remediation:
  description: What is wrong when this control fires.
  action: >
    aws cli command to fix the issue
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.some_property
      op: eq
      value: false
```

## Control ID Convention

`CTL.<SERVICE>.<CATEGORY>.<SEQUENCE>`

- Service: `S3`, `EC2`, `IAM`, `EKS`, `CUSTOM`, etc.
- Category: `PUBLIC`, `ENCRYPT`, `LOG`, etc.
- Sequence: `001`, `002`, etc.

## Available Operators

| Operator | Meaning |
|----------|---------|
| `eq` | Field equals value |
| `ne` | Field does not equal value |
| `gt`, `lt`, `gte`, `lte` | Numeric comparisons |
| `missing` | Field does not exist |
| `present` | Field exists |
| `in` | Field value is in a list |

## Add Test Cases

```yaml
tests:
  - name: "compliant resource passes"
    verdict: PASS
    asset:
      asset_id: "test-1"
      asset_type: s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          some_property: true

  - name: "non-compliant resource fails"
    verdict: VIOLATION
    asset:
      asset_id: "test-2"
      asset_type: s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          some_property: false
```

## Validate

```bash
stave test --control controls/custom/governance/CTL.CUSTOM.EXAMPLE.001.yaml
```

## Severity Guidelines

| Severity | When to Use |
|----------|-------------|
| critical | Active exploitation likely, data exposure imminent |
| high | Exploitation possible, significant blast radius |
| medium | Exploitation requires additional conditions |
| low | Theoretical risk, best practice improvement |
