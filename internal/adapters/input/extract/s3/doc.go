// Package s3 extracts and normalizes AWS S3 configuration evidence for evaluation.
//
// # File Naming Convention
//
// Keep files grouped by stable prefix to avoid "god files" and reduce cross-cutting edits:
//
//   - snapshot_*:
//     Snapshot-bundle extraction path (AWS CLI JSON inputs).
//     Includes wire models, sub-extractor manifest, extraction orchestration, and snapshot mapping.
//
//   - storage_*:
//     Storage model assembly path for Terraform extraction.
//     Includes analysis aggregation, controls/PAB modeling, and storage object construction.
//
//   - exposure_context_*:
//     Exposure classification context pipeline.
//     Split into types/state, policy inspection, ACL inspection, and resolution stages.
//
//   - policy_*:
//     Bucket policy analysis pipeline.
//     Split into document types/constants, logic/registries, principal handling, and analyzer flow.
//
//   - visibility_*:
//     Effective visibility resolution (policy + ACL + PAB) and result model.
//
//   - terraform_*:
//     Terraform plan/state collection, parsing, and hydration helpers.
//
// Maintenance Rules
//
//   - New features should be added to the closest existing prefix group.
//   - If a file exceeds ~250-300 LOC, split by pipeline phase, not by arbitrary utility buckets.
//   - Keep "inspect/collect" logic separate from "resolve/classify" logic.
package s3
