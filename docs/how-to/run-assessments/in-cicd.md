# How to Run Assessments in CI/CD

Fail a CI/CD pipeline when security violations exist.

---

## GitHub Actions

```yaml
name: Security Assessment
on: [push]

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Stave
        run: cd stave && make build

      - name: Run assessment
        run: |
          ./stave/stave apply \
            --controls stave/controls \
            --observations observations/ \
            --format json \
            --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
            > assessment.json

      # Exit code 3 = violations found
      # Exit code 0 = no violations
      # Exit code 2 = input error
```

## GitLab CI

```yaml
security-assessment:
  stage: test
  script:
    - cd stave && make build
    - ./stave apply --controls controls --observations ../observations/
  allow_failure: false
```

## Exit Codes

| Code | Meaning | Pipeline Action |
|------|---------|-----------------|
| 0 | No violations | Pass |
| 1 | Security audit threshold exceeded | Fail |
| 2 | Input error (bad paths, invalid files) | Fail |
| 3 | Violations found | Fail |
| 4 | Internal error | Fail |
| 130 | SIGINT (Ctrl+C) | Abort |

## Severity Thresholds

Fail only on high and critical:

```bash
stave apply \
  --controls controls \
  --observations observations/ \
  --fail-on high
```

## SLA Gating

Fail when a finding is overdue against its SLA deadline:

```bash
stave ci gate \
  --policy fail_on_overdue_upcoming \
  --controls controls \
  --observations observations/ \
  --max-unsafe 168h
# Exit code 3 if any finding is overdue
```
