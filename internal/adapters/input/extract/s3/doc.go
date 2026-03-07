// Package s3 extracts and normalizes AWS S3 configuration evidence for evaluation.
//
// The root package provides [Extractor] (the entry point) and [Scope] for
// selecting extraction targets. Extraction logic is split across subpackages
// by concern:
//
//   - snapshot/: AWS CLI JSON extraction — asset mapping, sub-extractors, wire types.
//   - terraform/: Terraform plan/state parsing, resource picking, and hydration.
//   - storage/: Storage model assembly — controls, evidence, exposure models.
//   - policy/: Bucket policy analysis — principal handling, condition evaluation, IAM manifests.
//   - acl/: ACL grant inspection — access permissions, principal tokens, analysis.
//   - resource/: Resource mapping helpers and builder utilities.
package s3
