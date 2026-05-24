# KMS compound coverage map

Maps the AWS compound control authoring plan's Phase 3 (KMS) 5
sub-families against existing Stave controls and chains.

## Headline finding

KMS has **45 atomic controls and 0 compound-scope controls today**
per the classifier. KMS observations are per-key (`cryptography.kind`,
`cryptography.policy`, `cryptography.lifecycle`, etc.) — no
cross-asset prefix in the predicate AST.

**The KMS compound surface lives in 18 chains today** (with this
commit, 19):

- `chains/crypto_concentration_failure.yaml`
- `chains/cryptographic_boundary_collapse.yaml`
- `chains/ghost_principal_encryption_bypass.yaml`
- `chains/iam_kms_governance.yaml`
- `chains/iam_implicit_kms_takeover.yaml`
- `chains/kms_access_change_undetected.yaml`
- `chains/kms_access_ungoverned.yaml`
- `chains/kms_alias_broken.yaml`
- `chains/kms_cascading_failure.yaml`
- `chains/kms_crossaccount_risk.yaml`
- `chains/kms_destructive_undetected.yaml`
- `chains/kms_dormant_access.yaml`
- `chains/kms_exfiltration_undetected.yaml`
- `chains/kms_grant_ungoverned.yaml`
- `chains/kms_key_unusable.yaml`
- `chains/kms_lifecycle_ungoverned.yaml`
- (+ 2 more cross-service)

## Plan sub-family coverage

| # | Sub-family | Status | Existing chain(s) |
|---|---|---|---|
| 1 | Key policy + grant composition | covered | `kms_grant_ungoverned`, `kms_access_ungoverned` |
| 2 | Key alias indirection | covered | `kms_alias_broken` |
| 3 | Multi-region key replica drift | covered (this commit) | **NEW** `kms_multiregion_replica_drift` (POLICY.MISMATCH + NOREPLICA + NONCOMPLIANT.REGION) |
| 4 | Customer-managed key + IAM + downstream resource | covered | `kms_crossaccount_risk`, `ghost_principal_encryption_bypass`, `iam_kms_governance` |
| 5 | Encryption SDK and provider chain | observation-contract gap | no SDK-side observations exist; the application-layer encryption SDK behavior is outside the snapshot's scope |

**Summary:** 4 covered, 0 partial, 1 observation-contract gap.

## What this commit ships for KMS

- **1 net-new chain:** `chains/kms_multiregion_replica_drift.yaml`
  (sub-family 3 — POLICY.MISMATCH + NOREPLICA + NONCOMPLIANT.REGION
  conjunction). Threshold 2; severity high; preconditions
  kms_encryption_configured; postconditions encryption_bypass.

## Why ~20 net-new wasn't the right target

KMS already has 18 chains substantiating compound risk across 4
of 5 plan sub-families. Sub-family 5 (SDK + provider chain) is
genuinely out of scope — application-layer SDK behavior isn't
in the observation contract and shouldn't be (Stave evaluates
infrastructure config snapshots, not runtime SDK call traces).

## Notes for follow-up

- **Sub-family 5 deferral:** legitimate. Application-layer
  encryption library behavior belongs to APM / runtime
  observability, not infrastructure snapshot analysis. The
  KMS-side observations Stave has (key policy, grant,
  multi-region state, lifecycle) cover the infrastructure
  layer fully.
- **Compound-share trajectory:** unchanged at 6.77%
  (chains aren't classifier-counted). KMS chain count
  18 → 19 with this commit.
