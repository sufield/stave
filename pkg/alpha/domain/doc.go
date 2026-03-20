// TODO(v1.0): Promote internal/domain to pkg/stave once the evaluation API is stable.
// This will allow external consumers (stave-extractor, third-party tools) to import
// the evaluation engine directly. Until then, internal/ prevents premature API commitment.

// Package domain contains the core business logic for Stave's safety evaluation.
//
// This package is a namespace for domain subpackages; it has no Go source files
// of its own beyond this doc.go. See the subpackages for all domain types:
//
//   - [kernel]: Shared value objects — control IDs, asset types, schema versions,
//     time windows, classification, and sanitization contracts.
//   - [predicate]: Operator semantics for unsafe-predicate evaluation (eq, missing,
//     in, not_subset_of_field, etc.) and type-aware comparison logic.
//   - [asset]: Snapshot and asset models representing point-in-time observations.
//   - [policy]: Control definitions, exemption rules, and pack metadata.
//   - [ports]: Dependency-injection interfaces (Clock, Verifier).
//   - [evaluation]: Evaluation runtime and sub-engines:
//   - [evaluation/engine]: Timeline processing, finding generation, coverage metrics.
//   - [evaluation/diagnosis]: Post-evaluation root-cause analysis.
//   - [evaluation/remediation]: Machine-readable remediation plan generation.
//   - [evaluation/exposure]: Visibility and exposure classification (public/private).
//   - [evaluation/risk]: Security-risk scoring and predictive threshold analysis.
//   - [diag]: Diagnostic issue codes, signals, and translation from domain errors.
//   - [validation]: Readiness prerequisite checks before evaluation.
//   - [securityaudit]: Security-audit report and finding structures.
//
// # Evaluation Flow
//
// The evaluation engine processes snapshots to detect violations:
//
//  1. Snapshots are sorted by captured_at timestamp
//  2. For each control, asset timelines are built tracking unsafe periods
//  3. Duration violations fire when unsafe_duration exceeds threshold
//  4. Recurrence violations fire when episode_count exceeds limit within window
//
// # Predicate Evaluation
//
// Unsafe predicates support flexible matching with operators including eq, gt,
// missing, present, in, not_subset_of_field, not_in_field, neq_field, and
// list_empty. Predicates combine with "any" (OR) and "all" (AND) logic.
package domain
