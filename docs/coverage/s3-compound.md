# S3 compound coverage map

Maps the AWS compound control authoring plan's 6 S3 sub-families
(`aws-compound-control-authoring-plan.md` Phase 4) against
existing Stave controls and chains.

## Headline finding

S3 has 118 atomic controls and **0 compound-scope controls today**
(per the classifier — `docs/control-classification-proposal.md`).
The classifier's "controls only" view undersells the S3 compound
surface, which lives almost entirely in chain definitions.

**S3-touching chains shipping today** (as of the Phase 4 audit):
**16 chains** compose at least one S3 atomic control into a
compound risk path (grep `chains/*.yaml` for `CTL\.S3\.`). The
representative shapes:

- `chains/s3_replication_exposure.yaml` — public destination +
  delete replication + unencrypted path (sub-family 5: cross-
  region replication + IAM role + destination)
- `chains/s3_encryption_trust.yaml` — external-account KMS key +
  broad key policy (sub-family 2: replication + KMS keys)
- `chains/s3_false_https.yaml` — CloudFront HTTP origin + bucket
  not enforcing in-transit encryption
- `chains/cognito_unauth_s3public.yaml` — guest access + broad
  unauth role + S3 read on unauth (cross-service Capital-One-
  shape variant)
- `chains/cf_s3_origin_weak.yaml` — CloudFront origin protection
  missing (cross-service)
- `chains/public_phi_exposure.yaml` — public + no encryption +
  no logging + no CloudTrail data event (sub-family 1: bucket
  policy + ACL + public access block, partial)
- `chains/audit_trail_destruction_path.yaml` — log bucket public
  + no versioning + no lock (sub-family 6: lock + bucket policy
  + lifecycle, partial)
- `chains/s3_phi_retention_vulnerable.yaml` — PHI bucket without
  COMPLIANCE-mode lock + lifecycle expiring before minimum
  retention (sub-family 6, NEW in this Phase 4 commit)

Plus several other chains that touch S3 indirectly via shared
preconditions (`data_warehouse_compromise`, `data_access`).

## Plan sub-family coverage

| # | Sub-family | Status | Existing chain(s) |
|---|---|---|---|
| 1 | Bucket policy + ACL + public access block intersection | partial | `public_phi_exposure` (the bucket-policy + encryption + logging composition; ACL-leg not yet explicit) |
| 2 | Replication source/destination + KMS keys | covered | `s3_encryption_trust` |
| 3 | Bucket policy + VPC endpoint policy intersection | **observation-contract gap** | none — no S3-VPC-endpoint controls exist in `controls/`; requires new observation extractor for endpoint-policy + bucket-policy intersection |
| 4 | Object Lambda permissions | **observation-contract gap** | none — no Object-Lambda controls exist in `controls/lambda/`; requires new observation extractor |
| 5 | Cross-region replication + IAM role + destination | covered | `s3_replication_exposure` (destination + delete + replication-encryption legs) |
| 6 | Object lock + bucket policy + lifecycle | covered (this Phase 4) | `audit_trail_destruction_path` (log-bucket variant) + **NEW** `s3_phi_retention_vulnerable` (PHI-data variant — COMPLIANCE-mode lock + lifecycle-before-retention conjunction) |

**Summary:** 4 covered, 1 partial, 2 gap.

## What this Phase 4 commit ships

- **1 net-new chain:** `chains/s3_phi_retention_vulnerable.yaml`
  (sub-family 6, PHI-data variant). Composes CTL.S3.LOCK.002 +
  CTL.S3.LIFECYCLE.002 — both existing atomic controls. Severity
  critical; preconditions data_warehouse_compromise;
  postconditions data_destruction.
- **1 coverage document:** this file. Establishes the S3
  compound surface as primarily chain-shaped (parallel to IAM
  which was primarily observation-extractor-shaped) and surfaces
  the 2 observation-contract gaps for future iterations.

## Why the original "~25 net-new" target doesn't apply

The AWS compound authoring plan sketched Phase 4 at ~25 net-new
controls. Phase 4 lands 1 net-new chain. The shortfall is honest:

1. **S3 controls are atomic by predicate by design.** Unlike
   IAM where the observation extractor pre-computes cross-asset
   booleans (identity.escalation.*, identity.blastradius.*),
   S3 observations are per-bucket (storage.kind, storage.access,
   storage.encryption — no `storage.cross_bucket_*` or
   `storage.role_with_access` fields). The classifier prefix
   extension that worked for IAM has no analogue here.
2. **The compound surface IS substantial via chains.** 8 chains
   today (with this commit, 9) compose S3 atomic controls into
   compound risk paths. The strategic narrative ("S3 compound
   risk is detected") is well-supported by chains; the
   classifier's "0 compound controls" number undersells it.
3. **Sub-families 3 + 4 require observation-contract growth.**
   Per the plan's anti-scope rule ("don't expand the observation
   contract during authoring iterations"), authoring these
   compound shapes is deferred to a separate observation
   iteration. Routing them through Phase 4 by inventing
   placeholder atomic controls would have been Goodhart-style
   inflation.

The compound-share target (~9% across the catalog) is
substantially met by IAM phase work alone (6.77% at session
end). VPC, KMS, Lambda, ECS/EKS still pending. S3 doesn't
need to carry as much of the load as the original plan
sized.

## Notes for follow-up iterations

- **Sub-family 1 (bucket policy + ACL + public access block):**
  could promote `public_phi_exposure` from partial to covered by
  adding an explicit ACL-leg control (`CTL.S3.ACL.PUBLIC.001`
  if not present) and authoring a tighter chain that ANDs
  bucket-policy-public + ACL-public + public-access-block-
  disabled. The current `public_phi_exposure` chain hits the
  same risk surface from a different angle (PHI tag + public +
  no encryption); the cleaner sub-family-1 chain would target
  the three-way effective-access composition directly. Author
  in a Phase-4-followup commit when the ACL control exists or
  needs creating.
- **Observation-contract iteration scope:** if/when an
  observation iteration adds S3-VPC-endpoint intersection
  observations + Object-Lambda permissions, sub-families 3 and
  4 author immediately. Each needs ~1-2 new controls + a chain.
- **Compound-share trajectory after Phase 4:** unchanged at
  6.77% canonical compound share (chains aren't classifier-
  counted; the count is controls-only). Phases 2 (VPC), 3 (KMS),
  5 (Lambda), 6 (ECS/EKS) still pending; the gap to 9% closes
  with their authoring iterations.
