# Tutorial: Your First Custom Control

Write a control, test it, and see it fire against a snapshot. Time: 20 minutes.

---

## What You Will Learn

- How to write a control YAML file
- How to add embedded test cases
- How to run `stave test` to verify behavior
- How to see the control fire in an assessment

## Write a Minimal Control

Create `controls/custom/CTL.CUSTOM.TEAM.TAG.001.yaml`:

```yaml
dsl_version: ctrl.v1
id: CTL.CUSTOM.TEAM.TAG.001
name: All S3 Buckets Must Have a Team Tag
description: >
  Every S3 bucket must have a "team" tag assigned for ownership
  attribution. Untagged buckets cannot be attributed to a team
  for remediation routing.
domain: governance
severity: medium
scope_tags:
  - aws
  - s3
type: unsafe_state
params:
  attack_stage: discovery
remediation:
  description: S3 bucket is missing the required "team" tag.
  action: >
    aws s3api put-bucket-tagging --bucket <name>
    --tagging 'TagSet=[{Key=team,Value=<team-name>}]'
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.tags.team
      op: missing
      value: true
```

This control checks: for any asset where `properties.storage.kind == "bucket"`, the tag `team` must exist. If it is missing, the control fires a VIOLATION.

## Add Test Cases

Add a `tests:` block at the end of the same file:

```yaml
tests:
  - name: "bucket with team tag passes"
    verdict: PASS
    asset:
      asset_id: "tagged-bucket"
      asset_type: s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          tags:
            team: platform

  - name: "bucket without team tag fails"
    verdict: VIOLATION
    asset:
      asset_id: "untagged-bucket"
      asset_type: s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          tags: {}
```

## Run the Tests

```bash
stave test --control controls/custom/CTL.CUSTOM.TEAM.TAG.001.yaml --verbose
```

Expected output:

```
STAVE CONTROL TEST
Controls with tests: 1  (2 test cases)

  ok  CTL.CUSTOM.TEAM.TAG.001 :: bucket with team tag passes
  ok  CTL.CUSTOM.TEAM.TAG.001 :: bucket without team tag fails

All 2 tests passed.
```

## Run Against a Real Snapshot

```bash
stave apply \
  --controls controls/custom \
  --observations observations
```

Any S3 bucket in your snapshot without a `team` tag will produce a VIOLATION finding with your control ID.

## What to Explore Next

- [Control YAML schema reference](../reference/control-schema.md) — all available fields
- [CEL predicate reference](../reference/cel-predicates.md) — operators and functions
- [How to write custom compliance profiles](../how-to/write-controls/custom-profile.md) — group controls into frameworks
