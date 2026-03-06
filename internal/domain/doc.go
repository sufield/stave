// Package domain contains the core business logic for Stave's safety evaluation.
//
// This package defines the domain model and evaluation algorithms for detecting
// assets that remain in unsafe states for too long. It is independent of
// external concerns like file formats or CLI interfaces.
//
// # Navigation Guide
//
// The package is organized by file-prefix groups:
//
//   - `control_*`: control model, params, IDs, store, and type taxonomy
//   - predicate files: unsafe predicate model/evaluation, rule matching, and field access
//   - `evaluator_*`: timeline processing and finding generation
//   - `validation_*`: validation orchestration, issue schema/codes, and validation rules
//   - diagnostics models: diagnostic input/output and case types
//   - entity/value files: snapshots/assets/identities/evidence/findings and small value objects
//
// Start points by task:
//
//   - Add or modify validation checks:
//     `validation_runner.go`, `predicate_checks.go`, `control_definition.go`, `snapshot.go`
//   - Add predicate operator behavior:
//     `predicate_rule.go`, `predicate_fields.go`, `predicate.go`
//   - Modify finding generation/evaluation flow:
//     `evaluator.go`, `evaluator_timelines.go`, `finding_generation.go`, `evaluator_run.go`
//   - Investigate diagnostics processing:
//     `internal/domain/evaluation/diagnosis/`
//
// # Core Types
//
// Main domain types:
//
//   - [Snapshot]: A point-in-time observation of infrastructure assets
//   - [Asset]: A single infrastructure component with properties
//   - [CloudIdentity]: An IAM identity for tenant isolation checks
//   - [ControlDefinition]: A safety rule loaded from YAML
//   - [UnsafePredicate]: Conditions that mark an asset as unsafe
//   - [Finding]: A detected violation with evidence
//   - Evaluation engine (internal/domain/evaluation): The main evaluation runtime
//   - [diagnosis.Report]: Analysis of evaluation inputs and results for troubleshooting
//
// # Evaluation Flow
//
// The evaluation engine processes snapshots to detect violations:
//
//  1. Snapshots are sorted by captured_at timestamp
//  2. For each control, asset timelines are built tracking unsafe periods
//  3. When an asset transitions safe→unsafe, an episode starts
//  4. When an asset transitions unsafe→safe, the episode closes
//  5. Duration violations are emitted when unsafe_duration exceeds threshold
//  6. Recurrence violations are emitted when episode_count exceeds limit within window
//
// # Diagnostics
//
// Diagnostics services analyze evaluation inputs and results to identify
// common issues and provide troubleshooting guidance:
//
//   - Threshold mismatches between configuration and actual durations
//   - Time span issues when snapshots don't cover enough history
//   - Predicate matching problems when no assets match unsafe conditions
//   - Clock skew issues when evaluation time differs from snapshot times
//
// # Predicate Evaluation
//
// [UnsafePredicate] supports flexible matching with operators:
//
//   - eq: equality comparison
//   - gt: greater than (numeric)
//   - missing: field absent, nil, or empty
//   - present: field exists and non-empty
//   - in: value in list
//   - not_subset_of_field: check if list is not subset of another field
//   - not_in_field: check if value is not in another field's list
//   - neq_field: check if field values are not equal
//   - list_empty: check if list field is empty
//
// Predicates can be combined with "any" (OR) and "all" (AND) logic.
//
// # Control Catalog
//
// The source of truth for all control definitions is the YAML files under
// controls/s3/. There is no hard-coded catalog in Go code. Controls are
// loaded at runtime via [ControlRepository], validated against the schema,
// and passed to the evaluation engine. To review or audit the complete set of safety
// rules, inspect the YAML files directly.
//
// # Control Types
//
// Stave supports multiple control types with different violation detection:
//
//   - Duration controls: Detect assets unsafe longer than threshold
//   - Recurrence controls: Detect frequent safety violations within time windows
//   - Per-control params override global defaults (e.g., max_unsafe_duration)
//
// # Evidence & Remediation
//
// Violations are purely factual (evidence + classification). Remediation guidance
// is added separately by the app layer for clean separation of concerns:
//
//   - [Evidence] contains violation proof with timestamps and metrics
//   - Duration evidence: first_unsafe_at, unsafe_duration_hours, threshold_hours
//   - Recurrence evidence: episode_count, window_days, first/last_episode_at
//   - [RemediationSpec] (app layer) suggests immediate risk reduction steps
//
// # Source Tracking
//
// [SourceRef] tracks findings back to original observations for auditability.
// Includes schema versions, file paths, and line numbers for traceability.
//
// # Clock Abstraction
//
// The [Clock] interface allows deterministic testing by injecting time.
// Use concrete implementations from `internal/domain/ports` for production/tests.
//
// # Ports & Adapters
//
// Repository and writer interfaces are defined in the app layer. The domain
// keeps only the [Clock] abstraction for deterministic evaluation.
package domain
