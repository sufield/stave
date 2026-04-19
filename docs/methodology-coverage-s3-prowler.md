# Prowler S3 Coverage

> **Generated file** — do not edit directly. This document is
> regenerated from the embedded control catalog and the inventory at
> `data/alternatives/prowler-s3.yaml` by `go run ./internal/tools/genmethodologycoverage`.

Cross-reference of Prowler's 21 S3 checks against Stave's S3 control catalog.

## Summary

- **Prowler S3 checks surveyed:** 21
- **COVERED:** 17
- **PARTIAL:** 3
- **NOT COVERED:** 1

## Coverage table

| # | Alternative check | Stave status | Stave control(s) | Notes |
|---|---|:---:|---|---|
| 1 | `s3_access_point_public_access_block` | COVERED | `CTL.S3.AP.PAB.001` | Stave umbrella requires all 4 access-point PAB flags; Prowler matches. |
| 2 | `s3_account_level_public_access_blocks` | COVERED | `CTL.S3.ACCOUNT.PAB.001` | Stave requires all 4 flags vs Prowler's 2 (ignore_public_acls + restrict_public_buckets). Stave is stricter. |
| 3 | `s3_bucket_acl_prohibited` | COVERED | `CTL.S3.OWNERSHIP.001` | Both check object_ownership.rule = BucketOwnerEnforced. |
| 4 | `s3_bucket_cross_account_access` | COVERED | `CTL.S3.ACCESS.001` | Stave fires on non-empty external_account_ids; matches Prowler's policy-principal analysis. |
| 5 | `s3_bucket_cross_region_replication` | PARTIAL | `CTL.S3.REPLICATION.002` | Stave's cross-region replication is PHI-tag-gated; Prowler requires it account-wide. |
| 6 | `s3_bucket_default_encryption` | COVERED | `CTL.S3.ENCRYPT.001` | Both check storage.encryption.at_rest_enabled. |
| 7 | `s3_bucket_event_notifications_enabled` | NOT COVERED | — |  |
| 8 | `s3_bucket_kms_encryption` | PARTIAL | `CTL.S3.ENCRYPT.003`, `CTL.S3.ENCRYPT.004` | Stave requires KMS only for PHI/sensitive-tagged buckets; Prowler requires it for all. Posture-policy difference, not a technical gap. |
| 9 | `s3_bucket_level_public_access_block` | COVERED | `CTL.S3.CONTROLS.001`, `CTL.S3.PAB.BLOCKPUBLICACLS.001`, `CTL.S3.PAB.BLOCKPUBLICPOLICY.001`, `CTL.S3.PAB.IGNOREPUBLICACLS.001`, `CTL.S3.PAB.RESTRICTPUBLICBUCKETS.001` | Stave umbrella requires all 4 flags vs Prowler's 2; per-flag controls give actionable remediation. |
| 10 | `s3_bucket_lifecycle_enabled` | COVERED | `CTL.S3.LIFECYCLE.001`, `CTL.S3.LIFECYCLE.002` | Both check presence of a lifecycle configuration with at least one enabled rule. |
| 11 | `s3_bucket_no_mfa_delete` | COVERED | `CTL.S3.MFADELETE.001` | Both check storage.versioning.mfa_delete_enabled on versioned buckets. |
| 12 | `s3_bucket_object_lock` | COVERED | `CTL.S3.LOCK.001`, `CTL.S3.LOCK.002`, `CTL.S3.LOCK.003` | Stave splits enablement, mode, and retention-days into three controls; Prowler covered by enablement. |
| 13 | `s3_bucket_object_versioning` | COVERED | `CTL.S3.VERSION.001` | Both check storage.versioning.enabled. |
| 14 | `s3_bucket_policy_public_write_access` | COVERED | `CTL.S3.POLICY.WRITE.001` | Both check for s3:PutObject / s3:Delete* / s3:* grants to non-narrow principals in the bucket policy. |
| 15 | `s3_bucket_public_access` | COVERED | `CTL.S3.ACCESS.004`, `CTL.S3.PUBLIC.001`, `CTL.S3.PUBLIC.004` | Stave splits public-access detection across composite, policy, and effective-public views; union covers Prowler. |
| 16 | `s3_bucket_public_list_acl` | COVERED | `CTL.S3.ACL.FULLCONTROL.001`, `CTL.S3.ACL.RECON.001`, `CTL.S3.PUBLIC.LIST.001` | Stave splits ACL-list detection across public-list composite, READ_ACP (recon), and FULL_CONTROL paths. |
| 17 | `s3_bucket_public_write_acl` | COVERED | `CTL.S3.ACL.ESCALATION.001`, `CTL.S3.ACL.FULLCONTROL.001`, `CTL.S3.PUBLIC.003` | Stave splits ACL-write detection across public-write composite, FULL_CONTROL grants, and WRITE_ACP (escalation) grants. |
| 18 | `s3_bucket_secure_transport_policy` | COVERED | `CTL.S3.ENCRYPT.002` | Both check storage.encryption.in_transit_enforced (Deny on aws:SecureTransport = false). |
| 19 | `s3_bucket_server_access_logging_enabled` | COVERED | `CTL.S3.LOG.001` | Both check storage.logging.enabled. |
| 20 | `s3_bucket_shadow_resource_vulnerability` | PARTIAL | `CTL.S3.BUCKET.TAKEOVER.001` | Stave catches dangling/wrong-owner via s3_ref.bucket_exists + s3_ref.bucket_owned; Prowler additionally enumerates predictable service-name patterns. |
| 21 | `s3_multi_region_access_point_public_access_block` | COVERED | `CTL.S3.MRAP.PAB.001` | Both check that all 4 MRAP PAB flags are enabled. |

## Source

- Inventory: `data/alternatives/prowler-s3.yaml`
- Coverage annotations: `alternatives:` blocks on individual control YAMLs under `controls/`
