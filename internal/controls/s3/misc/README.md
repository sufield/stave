# S3 Miscellaneous Controls

Controls in this directory cover foundational safety checks that do not fit into a specific domain category: Public Access Block enforcement and incomplete observation data detection.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.CONTROLS.001 | Public Access Block Must Be Enabled | Public Access Block is not fully enabled (all four settings) |
| CTL.S3.INCOMPLETE.001 | Complete Data Required for Safety Assessment | Policy or ACL data is missing from the observation snapshot |

## How These Controls Work

1. **CONTROLS.001:** Detects the *enabling condition* for public access, not the exposure itself. When PAB is disabled, the bucket has no safety net against accidental public exposure from policy or ACL changes. This is a high-severity preventive control.

2. **INCOMPLETE.001:** Fires when observation data is incomplete -- the collector could not read the bucket's policy or ACL (usually due to missing IAM permissions). Safety cannot be proven, so the bucket is flagged. This is an `unsafe_duration` control with `max_unsafe_duration: 0h`, meaning any duration of missing data is a finding.

## Compliance Mapping

| Control | CIS AWS 1.4.0 | PCI DSS 3.2.1 | SOC 2 |
|---------|---------------|---------------|-------|
| CONTROLS.001 | 2.1.5 | 1.3.6 | CC6.1 |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | CONTROLS.001 |
| `properties.storage.controls.public_access_fully_blocked` | bool | CONTROLS.001 |
| `properties.safety_provable` | bool | INCOMPLETE.001 |

CONTROLS.001 gates on `kind == "bucket"`. INCOMPLETE.001 uses an `any` predicate and fires on `safety_provable == false`.
