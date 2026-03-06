// Package app provides the application layer that orchestrates use cases.
//
// This package connects domain logic with adapters, coordinating the evaluation
// workflow without containing business rules itself. It implements the
// "use case" layer in hexagonal architecture.
//
// # Main Components
//
//   - [diagnose.Run]: Orchestrates the diagnose command workflow
//   - [diagnose.Config]: Configuration for a diagnose run
//   - [validation.Run]: Orchestrates validate command artifact checks
//   - [Capabilities]: Describes supported formats and control packs
//
// # Evaluation Workflow
//
// The `eval.EvaluateRun.Execute` method:
//
//  1. Loads control definitions from YAML files
//  2. Loads observation snapshots from JSON files
//  3. Validates schema and DSL versions
//  4. Runs evaluation through app services over domain logic
//  5. Writes findings to the configured output
//
// # Diagnosis Workflow
//
// The [DiagnoseRun.Execute] method:
//
//  1. Loads control definitions and observation snapshots
//  2. Either loads existing evaluation results or runs evaluation internally
//  3. Analyzes inputs and results for common issues
//  4. Returns a diagnostic report with findings and recommendations
//
// # Version Support
//
// The package tracks supported versions for:
//
//   - Observation schema versions (e.g., "obs.v0.1")
//   - Control DSL versions (e.g., "ctrl.v1")
//   - Input source types (e.g., "terraform.plan_json")
//
// Use [IsSourceTypeSupported] to check compatibility for source_type fields.
//
// # Capabilities Discovery
//
// Use [GetCapabilities] to retrieve the complete set of supported formats,
// versions, and available control packs for this version of Stave.
//
// # Construction
//
// Use constructors in subpackages:
//
//   - `eval.NewEvaluateRun(...)`
//   - `diagnose.NewRun(...)`
//   - `validation.NewRun(...)`
package app
