// Package domain contains the core business logic for Stave's safety evaluation.
//
// This package lives under pkg/alpha/domain/ to signal that the API is
// importable by adopters but still evolving. It has zero imports from
// internal/, so external consumers can use the evaluation engine, snapshot
// planner, policy analyzer, and exposure classifier directly.
//
// This package is a namespace for domain subpackages; it has no Go source files
// of its own beyond this doc.go and integration tests. See the subpackages:
//
//   - [kernel]: Shared value objects — control IDs, asset types, schema versions,
//     time windows, classification, sanitization contracts, and predicate combinators.
//   - [predicate]: Operator semantics for unsafe-predicate evaluation (eq, missing,
//     in, not_subset_of_field, etc.) and type-aware comparison logic.
//   - [asset]: Snapshot and asset models representing point-in-time observations.
//   - [policy]: Control definitions, exemption rules, and pack metadata.
//   - [ports]: Dependency-injection interfaces (Clock, Verifier).
//   - [maps]: Typed map parsing utilities for observation properties.
//   - [retention]: Snapshot retention policies and candidate selection.
//   - [snapshot]: Snapshot retention planning — multi-tier plan building and rendering.
//   - [evaluation]: Evaluation runtime and sub-engines:
//   - [evaluation/engine]: Timeline processing, finding generation, coverage metrics.
//   - [evaluation/diagnosis]: Post-evaluation root-cause analysis.
//   - [evaluation/remediation]: Machine-readable remediation plan generation.
//   - [evaluation/exposure]: Visibility and exposure classification (public/private).
//   - [evaluation/risk]: Security-risk scoring and predictive threshold analysis.
//   - [diag]: Diagnostic issue codes, signals, and translation from domain errors.
//   - [validation]: Readiness prerequisite checks before evaluation.
//   - [s3/policy]: S3 bucket policy analysis (parse, assess, evaluate).
//   - [s3/acl]: S3 ACL grant analysis.
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
