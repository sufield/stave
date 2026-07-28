# S3 Lifecycle Controls

Controls in this directory enforce data retention policies via S3 lifecycle rules, with stricter requirements for PHI data.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.LIFECYCLE.001 | Retention-Tagged Buckets Must Have Lifecycle Rules | Bucket tagged with `data-retention` has no enabled lifecycle rules |
| CTL.S3.LIFECYCLE.002 | PHI Buckets Must Not Expire Data Before Minimum Retention | PHI bucket has a lifecycle expiration shorter than 2190 days (6 years) |

## Why Two Controls

Lifecycle enforcement has two tiers:

1. **Presence (LIFECYCLE.001):** Any bucket tagged with `data-retention` must have at least one lifecycle rule configured. Without rules, data persists indefinitely -- increasing exposure surface and violating retention policy.

2. **Minimum period (LIFECYCLE.002):** PHI buckets must not delete data before the HIPAA minimum of 6 years (2190 days). This catches rules that expire data too early. The threshold is parameterized via `min_retention_days`.

## Parameterized Threshold

LIFECYCLE.002 uses `params.min_retention_days` (default 2190). The predicate compares `min_expiration_days < params.min_retention_days`. To customize, copy the control to your controls directory and change the value.

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.tags.data-retention` | string | LIFECYCLE.001 |
| `properties.storage.lifecycle.rules_configured` | bool | LIFECYCLE.001 |
| `properties.storage.tags.data-classification` | string | LIFECYCLE.002 |
| `properties.storage.lifecycle.has_expiration` | bool | LIFECYCLE.002 |
| `properties.storage.lifecycle.min_expiration_days` | int | LIFECYCLE.002 |

LIFECYCLE.001 gates on `data-retention` tag being present. LIFECYCLE.002 gates on `data-classification == "phi"` and `has_expiration == true`.
