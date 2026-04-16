# How to Verify an Evidence Archive

Prove continuous monitoring over a compliance audit period.

---

## Verify a Quarter

```bash
stave verify --archive ./evidence/ --period 2026-Q1
```

## Verify a Specific Date Range

```bash
stave verify --archive ./evidence/ --period 2026-01-01:2026-03-31
```

## Strict Mode (Zero Gap Tolerance)

```bash
stave verify --archive ./evidence/ --period 2026-Q1 --strict
```

## Produce an Attestation Document

```bash
# JSON attestation
stave verify --archive ./evidence/ --period 2026-Q1 \
  --format json --out attestation.json

# Markdown for audit package
stave verify --archive ./evidence/ --period 2026-Q1 \
  --format markdown --out attestation.md
```

## Period Formats

| Format | Example | Meaning |
|--------|---------|---------|
| Quarter | `2026-Q1` | Jan 1 to Mar 31 |
| Month | `2026-01` | Jan 1 to Jan 31 |
| Day | `2026-01-15` | Single day |
| Range | `2026-01-01:2026-03-31` | Explicit start:end |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | PASS — all bundles valid, no gaps |
| 1 | FAIL — invalid bundles or gaps |
| 2 | Invalid input |
