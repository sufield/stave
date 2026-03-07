// Package app provides the application layer that orchestrates use cases.
//
// This package is a namespace for app-layer subpackages; the root contains
// only integration and architecture tests. See the subpackages for all
// application logic:
//
//   - [eval]: Evaluation use-case orchestration (load controls/snapshots,
//     run domain engine, write findings).
//   - [diagnose]: Diagnosis use-case orchestration (analyze inputs/results
//     for common issues).
//   - [validation]: Validate-command orchestration (schema and DSL checks).
//   - [service]: Cross-cutting services — evaluation, readiness, validation,
//     and finding-detail enrichment (traces, exposure, remediation).
//   - [capabilities]: Capability registry advertising supported observation
//     schemas, control DSL versions, source types, and control packs.
//   - [contracts]: Dependency-injection interfaces (ObservationRepository,
//     ControlRepository, FindingMarshaler).
//   - [ingest]: Snapshot ingestion and persistence for S3 observations.
//
// # Version Support
//
// The package tracks supported versions for observation schemas (e.g., "obs.v0.1"),
// control DSL versions (e.g., "ctrl.v1"), and input source types.
package app
