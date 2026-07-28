# S3 Object Ownership Controls

Controls in this directory enforce S3 Object Ownership settings that disable ACLs.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.OWNERSHIP.001 | S3 Object Ownership Must Be Bucket Owner Enforced | Bucket does not have BucketOwnerEnforced set, leaving ACLs active |

## Why This Control

Since April 2023, new S3 buckets default to BucketOwnerEnforced, which disables ACLs entirely. However, buckets created before this date may still have ACLs enabled. BucketOwnerEnforced eliminates the entire ACL attack surface:

- **No public ACL grants:** AllUsers and AuthenticatedUsers ACL grants become impossible
- **No object-level ACL overrides:** Individual objects cannot be made public via ACL in an otherwise private bucket
- **No privilege escalation via WRITE_ACP:** Cannot modify ACLs if ACLs are disabled
- **Simpler access model:** All access governed by IAM and bucket policies only

This control supersedes ACL detection controls (CTL.S3.ACL.*) by eliminating the root cause rather than detecting symptoms. Both should be active: OWNERSHIP.001 for prevention, ACL controls for detection when ownership is not yet enforced.

## Compliance Mapping

| Control | CIS AWS 3.0 | SOC 2 | NIST 800-53 | FedRAMP | ISO 27001 |
|---------|-------------|-------|-------------|---------|-----------|
| OWNERSHIP.001 | 2.1.2 | CC6.1 | AC-3 | AC-3 | A.8.3 |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.kind` | string | OWNERSHIP.001 |
| `properties.storage.object_ownership.rule` | string | OWNERSHIP.001 |

OWNERSHIP.001 fires when `object_ownership.rule` is not `BucketOwnerEnforced`. Valid values are `BucketOwnerEnforced`, `BucketOwnerPreferred`, and `ObjectWriter`.
