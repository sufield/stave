# S3 Governance Controls

Controls in this directory enforce tagging policies that gate downstream controls.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.GOVERNANCE.001 | Data Classification Tag Required | Bucket is missing the `data-classification` tag |

## Why This Matters

Many controls gate on `data-classification` (ENCRYPT.003, ENCRYPT.004, LIFECYCLE.002, LOCK.002, LOCK.003, PUBLIC.002). Without the tag, those controls silently pass regardless of actual content sensitivity. GOVERNANCE.001 is the backstop -- it ensures the tag exists so downstream controls can evaluate.

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | GOVERNANCE.001 |
| `properties.storage.tags.data-classification` | string | GOVERNANCE.001 |

GOVERNANCE.001 gates on `kind == "bucket"` and fires when `data-classification` is missing.
