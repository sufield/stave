# How to Test Controls

Run embedded test cases to verify control behavior.

---

## Test a Single Control

```bash
stave test --control controls/s3/access/CTL.S3.PUBLIC.001.yaml
```

## Test All Controls

```bash
stave test --controls ./controls
```

## Filter by Pattern

```bash
stave test --controls ./controls --filter "CTL.S3.*"
```

## Stop on First Failure

```bash
stave test --controls ./controls --fail-fast
```

## Show Passing Tests

```bash
stave test --controls ./controls --verbose
```

## TAP Output for CI

```bash
stave test --controls ./controls --format tap
```

## Adding Test Cases to a Control

Add a `tests:` block at the end of the control YAML:

```yaml
tests:
  - name: "compliant resource passes"
    verdict: PASS
    asset:
      asset_id: "test-resource"
      asset_type: s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          controls:
            block_public_acls: true

  - name: "non-compliant resource fails"
    verdict: VIOLATION
    asset:
      asset_id: "test-resource"
      asset_type: s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          controls:
            block_public_acls: false
```

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `PASS` | Predicate evaluates to safe — no violation |
| `VIOLATION` | Predicate evaluates to unsafe — violation found |
| `INCONCLUSIVE` | Required field missing or CEL error |
